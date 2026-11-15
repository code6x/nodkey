package store

import (
	"context"
	"errors"

	"github.com/code6x/nodkey/internal/config"
)

// The steps of a project secret (DESIGN.md section 16).
const (
	stepListSecrets = "bws secret list" //nolint:gosec // G101: the name of a step, not a credential.
	stepGetSecret   = "bws secret get"
)

// ErrOtherSecret is the error of a "bws secret get" answer whose key or
// project is not the one that "bws secret list" gave for the ID: the
// secret was renamed or moved between the two runs.
var ErrOtherSecret = errors.New("the secret's key or project changed since it was listed")

// ProjectSecret is what nodkey reads from one secret of a list: its ID in
// lower case, its key, and its project's ID in lower case. Never a value.
type ProjectSecret struct {
	ID      string
	Key     string
	Project string
}

// ProjectStore is a store that hands out the secrets of a Bitwarden
// Secrets Manager project (DESIGN.md section 14, "Projects"). Only the
// bws store is one.
type ProjectStore interface {
	// ListSecrets runs "bws secret list PROJECT" and returns the ID, the
	// key and the project of each secret whose key follows the name rule
	// (config.ValidKey). Other secrets are left out, and their key is not
	// kept. The answer holds the values of all the secrets; it is cleared.
	ListSecrets(ctx context.Context, project string) ([]ProjectSecret, error)
	// FetchListed runs "bws secret get" for s.ID and returns the value. It
	// is ErrOtherSecret when the answer's key or projectId is not s.Key
	// and s.Project.
	FetchListed(ctx context.Context, s ProjectSecret) (Value, error)
}

// ListSecrets implements ProjectStore.
func (s *bwsStore) ListSecrets(ctx context.Context, project string) ([]ProjectSecret, error) {
	if !isUUID(project) {
		return nil, stepError(s.run.store, stepListSecrets, ErrBadID)
	}
	out, err := s.bws(ctx, stepListSecrets, "secret", "list", project, "--output", "json", "--color", "no")
	if err != nil {
		return nil, err
	}
	list, err := readList(out, project)
	if err != nil {
		return nil, stepError(s.run.store, stepListSecrets, err)
	}
	return list, nil
}

// readList reads the answer of "bws secret list" with parseBWSList, and
// clears it: it holds the value of every secret of the project.
func readList(out []byte, project string) ([]ProjectSecret, error) {
	defer clear(out)
	return parseBWSList(out, project)
}

// FetchListed implements ProjectStore.
func (s *bwsStore) FetchListed(ctx context.Context, ps ProjectSecret) (Value, error) {
	if !isUUID(ps.ID) || !isUUID(ps.Project) || !config.ValidKey(ps.Key) {
		return Value{}, stepError(s.run.store, stepGetSecret, ErrBadID)
	}
	out, err := s.bws(ctx, stepGetSecret, "secret", "get", ps.ID, "--output", "json", "--color", "no")
	if err != nil {
		return Value{}, err
	}
	defer clear(out)
	v, err := parseBWSListed(out, ps)
	if err != nil {
		return Value{}, stepError(s.run.store, stepGetSecret, err)
	}
	return v, nil
}

// bws takes a slot and runs bws with args and the token, as Fetch does.
// The caller must clear the answer.
func (s *bwsStore) bws(ctx context.Context, step string, args ...string) ([]byte, error) {
	if err := acquire(ctx, s.slots); err != nil {
		return nil, stepError(s.run.store, step, err)
	}
	defer func() { <-s.slots }()
	env, err := s.tokenEnv()
	if err != nil {
		return nil, stepError(s.run.store, step, err)
	}
	return s.run.run(ctx, step, args, env)
}

// listedFields are the fields that nodkey reads from one secret.
type listedFields struct {
	id, project       string
	key               string
	keyOK             bool // the key follows the name rule
	idSet, projectSet bool
	keySet            bool
}

// readListedField reads the field key of a secret into f. It reads "id",
// "key" and "projectId", and skips the others, the value and the note
// among them. A key that breaks the name rule is read, checked and
// cleared, never kept.
func readListedField(r *jsonReader, key string, f *listedFields) error {
	switch key {
	case "id":
		s, err := r.text(maxIDLen)
		f.id, f.idSet = s, true
		return err
	case "projectId":
		if r.peek() == 'n' {
			return r.null() // a secret in no project
		}
		s, err := r.text(maxIDLen)
		f.project, f.projectSet = s, true
		return err
	case "key":
		b, err := r.secret()
		defer clear(b)
		if err != nil {
			return err
		}
		f.keySet = true
		if len(b) <= config.MaxNameLen && config.ValidKey(string(b)) {
			f.key, f.keyOK = string(b), true
		}
		return nil
	}
	return r.skip()
}

// parseBWSList reads the answer of "bws secret list PROJECT --output
// json": one JSON array of secrets. Each must have a UUID "id", a "key",
// and "projectId" equal to project; else the whole answer is
// ErrBadAnswer. Secrets with a key that breaks the name rule are left out.
func parseBWSList(data []byte, project string) ([]ProjectSecret, error) {
	r := &jsonReader{data: data}
	r.space()
	var list []ProjectSecret
	err := r.arrayEach(func(r *jsonReader) error {
		var f listedFields
		if err := r.object(func(r *jsonReader, key string) error { return readListedField(r, key, &f) }); err != nil {
			return err
		}
		if !f.idSet || !f.keySet || !f.projectSet || !isUUID(f.id) || !sameUUID(f.project, project) {
			return ErrBadAnswer
		}
		if f.keyOK {
			list = append(list, ProjectSecret{ID: lowerASCII(f.id), Key: f.key, Project: lowerASCII(f.project)})
		}
		return nil
	})
	if err == nil {
		r.space()
		if r.pos != len(r.data) {
			err = ErrBadAnswer
		}
	}
	if err != nil {
		return nil, err
	}
	return list, nil
}

// parseBWSListed reads the answer of "bws secret get ID --output json" for
// the listed secret ps: one JSON object. It reads "id", "key",
// "projectId" and "value". The id must be ps.ID, else it is an answer for
// another secret. The key must be ps.Key exactly, and the projectId
// ps.Project, else it is ErrOtherSecret.
func parseBWSListed(data []byte, ps ProjectSecret) (Value, error) {
	var f listedFields
	var value []byte
	err := readAnswer(data, func(r *jsonReader, key string) error {
		if key != "value" {
			return readListedField(r, key, &f)
		}
		switch r.peek() {
		case 'n':
			return r.null()
		case '"':
			b, err := r.secret()
			value = b
			return err
		}
		return ErrBadAnswer
	})
	switch {
	case err != nil:
	case !f.idSet || !sameUUID(f.id, ps.ID):
		err = errOtherItem
	case !f.keyOK || f.key != ps.Key || !f.projectSet || !sameUUID(f.project, ps.Project):
		err = ErrOtherSecret
	}
	return keepValue(value, err)
}

// lowerASCII returns s with the ASCII letters in lower case.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		b[i] = lower(c)
	}
	return string(b)
}
