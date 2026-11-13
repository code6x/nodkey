package store

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Limits of the login fields that nodkey reads from bw (DESIGN.md
// section 21). An answer over a limit is ErrBadAnswer: nodkey never cuts
// a field.
const (
	maxLoginName     = 1024 // bytes of an item name or a username
	maxLoginURI      = 2048 // bytes of one URI
	maxLoginURIs     = 100  // URIs of one item
	maxLoginItems    = 500  // items in one collection; the answer must also fit in maxStdout
	maxCollectionIDs = 100  // collections of one item
	bwTypeLogin      = 1    // "type" of a login item
	stepListItems    = "bw list items"
)

// ErrNotLogin is returned for an item that is not a login item.
var ErrNotLogin = errors.New("the item is not a login item")

// LoginStore is a store that hands out website logins from a collection
// (DESIGN.md section 21). Only the bw store is one.
type LoginStore interface {
	// ListLogins runs "bw sync --force" and returns the login items of
	// the collection, with no password and no TOTP seed. Items in the
	// trash, archived items, items that are not logins and items whose
	// collectionIds do not hold the collection are left out.
	ListLogins(ctx context.Context, collection string) ([]LoginItem, error)
	// FetchLogin runs "bw sync --force" and returns the login item id,
	// with its password and its TOTP seed. An item in the trash is
	// ErrTrashed, an archived item ErrArchived, an item that is not a
	// login ErrNotLogin, and an item with no password ErrNoValue. The
	// caller must Clear the login.
	FetchLogin(ctx context.Context, id string) (Login, error)
}

// LoginURI is one URI of a login item: login.uris[].uri, and
// login.uris[].match (nil when the item has none).
type LoginURI struct {
	URI   string
	Match *int
}

// LoginItem is what nodkey reads from a login item, without its secrets.
type LoginItem struct {
	ID          string
	Name        string
	Username    string
	URIs        []LoginURI
	Collections []string // collectionIds
	// Reprompt is true when the item asks for the master password again
	// in Bitwarden's apps ("reprompt": 1). The broker then asks for a tap
	// for each login (DESIGN.md section 21.3).
	Reprompt bool
}

// Login is a login item with its password and its TOTP seed. TOTP is
// empty when the item has none. Login hides both in every format.
type Login struct {
	LoginItem
	Password Value
	TOTP     Value
}

// Clear overwrites the password and the TOTP seed.
func (l *Login) Clear() {
	l.Password.Clear()
	l.TOTP.Clear()
	l.Password, l.TOTP = Value{}, Value{}
}

// String names the item, without its secrets.
func (l Login) String() string { return fmt.Sprintf("login %s %s", l.ID, hidden) }

// GoString names the item, without its secrets.
func (l Login) GoString() string { return l.String() }

// Format writes String for every verb.
func (l Login) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, l.String()) }

// ListLogins implements LoginStore.
func (s *bwStore) ListLogins(ctx context.Context, collection string) ([]LoginItem, error) {
	if !isUUID(collection) {
		return nil, stepError(s.run.store, stepListItems, ErrBadID)
	}
	out, err := s.synced(ctx, stepListItems, "list", "items", "--collectionid", collection)
	if err != nil {
		return nil, err
	}
	defer clear(out) // it holds every password and TOTP seed of the collection
	items, err := parseBWLoginList(out, collection)
	if err != nil {
		return nil, stepError(s.run.store, stepListItems, err)
	}
	return items, nil
}

// FetchLogin implements LoginStore.
func (s *bwStore) FetchLogin(ctx context.Context, id string) (Login, error) {
	if !isUUID(id) {
		return Login{}, stepError(s.run.store, stepGetItem, ErrBadID)
	}
	out, err := s.synced(ctx, stepGetItem, "get", "item", id)
	if err != nil {
		return Login{}, err
	}
	defer clear(out)
	l, err := parseBWLogin(out, id)
	if err != nil {
		return Login{}, stepError(s.run.store, stepGetItem, err)
	}
	return l, nil
}

// synced takes the store's turn, unlocks if needed, runs
// "bw sync --force" and then bw with args, as Fetch does. The caller must
// clear the answer.
func (s *bwStore) synced(ctx context.Context, step string, args ...string) ([]byte, error) {
	if err := acquire(ctx, s.lock); err != nil {
		return nil, stepError(s.run.store, step, err)
	}
	defer s.release()
	if s.closed {
		return nil, stepError(s.run.store, step, ErrClosed)
	}
	if s.session.Bytes() == nil {
		if err := s.unlock(ctx); err != nil {
			return nil, err
		}
	}
	out, err := s.runWithSession(ctx, stepSync, "sync", "--force")
	if err != nil {
		return nil, err
	}
	clear(out)
	return s.runWithSession(ctx, step, args...)
}

// loginFields is what parseBWLoginItem read from one item.
type loginFields struct {
	item              LoginItem
	typ               int
	typeSet           bool
	trashed, archived bool
	password, totp    []byte
	wantSecrets       bool
}

func (f *loginFields) clearSecrets() {
	clear(f.password)
	clear(f.totp)
	f.password, f.totp = nil, nil
}

// readLoginItem reads one item object. It keeps "id", "type", "name",
// "reprompt", "deletedDate", "archivedDate", "collectionIds", "login.username" and
// "login.uris[].uri" and ".match". It keeps "login.password" and
// "login.totp" only when f.wantSecrets; else it checks and drops them. It
// skips every other field without keeping it: "notes", "fields" and
// "passwordHistory" can hold secrets too.
func readLoginItem(r *jsonReader, f *loginFields) error {
	return r.object(func(r *jsonReader, key string) error {
		switch key {
		case "id":
			id, err := r.text(maxIDLen)
			f.item.ID = id
			return err
		case "type":
			n, err := readSmallInt(r)
			f.typ, f.typeSet = n, err == nil
			return err
		case "name":
			return readOptText(r, maxLoginName, &f.item.Name)
		case "reprompt":
			if r.peek() == 'n' {
				return r.null()
			}
			n, err := readSmallInt(r)
			f.item.Reprompt = n != 0
			return err
		case "deletedDate":
			return readDate(r, &f.trashed)
		case "archivedDate":
			return readDate(r, &f.archived)
		case "collectionIds":
			if r.peek() == 'n' {
				return r.null()
			}
			return r.arrayEach(func(r *jsonReader) error {
				if len(f.item.Collections) >= maxCollectionIDs {
					return ErrBadAnswer
				}
				id, err := r.text(maxIDLen)
				f.item.Collections = append(f.item.Collections, id)
				return err
			})
		case "login":
			if r.peek() == 'n' {
				return r.null()
			}
			return r.object(func(r *jsonReader, key string) error { return readLoginField(r, key, f) })
		}
		return r.skip()
	})
}

func readLoginField(r *jsonReader, key string, f *loginFields) error {
	switch key {
	case "username":
		return readOptText(r, maxLoginName, &f.item.Username)
	case "uris":
		if r.peek() == 'n' {
			return r.null()
		}
		return r.arrayEach(func(r *jsonReader) error {
			if len(f.item.URIs) >= maxLoginURIs {
				return ErrBadAnswer
			}
			var u LoginURI
			err := r.object(func(r *jsonReader, key string) error {
				switch key {
				case "uri":
					return readOptText(r, maxLoginURI, &u.URI)
				case "match":
					if r.peek() == 'n' {
						return r.null()
					}
					n, err := readSmallInt(r)
					u.Match = &n
					return err
				}
				return r.skip()
			})
			f.item.URIs = append(f.item.URIs, u)
			return err
		})
	case "password", "totp":
		switch r.peek() {
		case 'n':
			return r.null()
		case '"':
			if !f.wantSecrets {
				_, err := r.str(nil) // checks it, keeps nothing
				return err
			}
			b, err := r.secret()
			if key == "password" {
				f.password = b
			} else {
				f.totp = b
			}
			return err
		}
		return ErrBadAnswer
	}
	return r.skip()
}

// readOptText reads a string of at most limit bytes, or null.
func readOptText(r *jsonReader, limit int, out *string) error {
	if r.peek() == 'n' {
		return r.null()
	}
	s, err := r.text(limit)
	*out = s
	return err
}

// readSmallInt reads a whole number from 0 to 99.
func readSmallInt(r *jsonReader) (int, error) {
	start := r.pos
	if err := r.number(); err != nil {
		return 0, err
	}
	b := r.data[start:r.pos]
	if len(b) == 0 || len(b) > 2 {
		return 0, ErrBadAnswer
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, ErrBadAnswer
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// parseBWLoginList reads the answer of "bw list items --collectionid C":
// one JSON array of items. It never keeps a password or a TOTP seed.
func parseBWLoginList(data []byte, collection string) ([]LoginItem, error) {
	r := &jsonReader{data: data}
	r.space()
	var items []LoginItem
	err := r.arrayEach(func(r *jsonReader) error {
		var f loginFields
		if err := readLoginItem(r, &f); err != nil {
			return err
		}
		if !isUUID(f.item.ID) {
			return ErrBadAnswer
		}
		if !f.typeSet || f.typ != bwTypeLogin || f.trashed || f.archived || !hasID(f.item.Collections, collection) {
			return nil
		}
		if len(items) >= maxLoginItems {
			return ErrBadAnswer
		}
		items = append(items, f.item)
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
	return items, nil
}

// parseBWLogin reads the answer of "bw get item ID" for a login. "id" must
// be id. It keeps the password and the TOTP seed.
func parseBWLogin(data []byte, id string) (Login, error) {
	f := loginFields{wantSecrets: true}
	r := &jsonReader{data: data}
	r.space()
	err := readLoginItem(r, &f)
	if err == nil {
		r.space()
		if r.pos != len(r.data) {
			err = ErrBadAnswer
		}
	}
	switch {
	case err != nil:
	case !sameUUID(f.item.ID, id):
		err = errOtherItem
	case f.trashed:
		err = ErrTrashed
	case f.archived:
		err = ErrArchived
	case !f.typeSet || f.typ != bwTypeLogin:
		err = ErrNotLogin
	}
	if err != nil {
		f.clearSecrets()
		return Login{}, err
	}
	totp := f.totp
	f.totp = nil
	password, err := keepValue(f.password, nil)
	f.password = nil
	if err != nil {
		clear(totp)
		return Login{}, err
	}
	l := Login{LoginItem: f.item, Password: password}
	if len(totp) > 0 {
		l.TOTP = newValue(totp)
	}
	return l, nil
}

// hasID reports whether ids holds id, in upper or lower case.
func hasID(ids []string, id string) bool {
	for _, x := range ids {
		if sameUUID(x, id) {
			return true
		}
	}
	return false
}
