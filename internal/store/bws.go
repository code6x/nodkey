package store

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/code6x/nodkey/internal/config"
)

// bwsParallel is the most runs of bws at the same time for one store.
// bws keeps no state that two runs could break; the limit only caps the
// processes that many requests can start.
const bwsParallel = 4

// bwsStore gets values from Bitwarden Secrets Manager with bws.
type bwsStore struct {
	run   runner
	slots chan struct{} // one place for each run of bws

	mu     sync.Mutex
	token  Value // the machine account's access token
	closed bool
}

// newBWS reads the token file of a bws store and returns the store.
func newBWS(cfg config.Store, r runner, d deps) (*bwsStore, error) {
	data, err := d.readPrivateFile(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("store %q: token_file: %w", cfg.Name, err) // the error names the path, never the content
	}
	defer clear(data)
	token, ok := parseKey(data, maxTokenLen)
	if !ok {
		return nil, fmt.Errorf("store %q: token_file %s: it holds no access token, or a character that "+
			"a token never has (the content is not shown here)", cfg.Name, cfg.TokenFile)
	}
	return &bwsStore{run: r, slots: make(chan struct{}, bwsParallel), token: token}, nil
}

// Start does nothing for bws: the token is read, and bws logs in on each
// run.
func (s *bwsStore) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return stepError(s.run.store, "start", ErrClosed)
	}
	return nil
}

// Fetch runs "bws secret get ID --output json --color no" with the token
// in BWS_ACCESS_TOKEN, and returns the field "value" of the answer. bws
// gets no PATH: it starts no other program.
func (s *bwsStore) Fetch(ctx context.Context, id string) (Value, error) {
	const step = "bws secret get"
	if !isUUID(id) {
		return Value{}, stepError(s.run.store, step, ErrBadID)
	}
	if err := acquire(ctx, s.slots); err != nil {
		return Value{}, stepError(s.run.store, step, err)
	}
	defer func() { <-s.slots }()
	env, err := s.tokenEnv()
	if err != nil {
		return Value{}, stepError(s.run.store, step, err)
	}
	out, err := s.run.run(ctx, step, []string{"secret", "get", id, "--output", "json", "--color", "no"}, env)
	if err != nil {
		return Value{}, err
	}
	defer clear(out)
	v, err := parseBWSSecret(out, id)
	if err != nil {
		return Value{}, stepError(s.run.store, step, err)
	}
	return v, nil
}

// tokenEnv returns the environment variable with the token. The string
// is a copy that cannot be cleared; so is the copy that os/exec makes for
// the system call.
func (s *bwsStore) tokenEnv() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	return []string{"BWS_ACCESS_TOKEN=" + string(s.token.Bytes())}, nil
}

// Close clears the token.
func (s *bwsStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token.Clear()
	s.closed = true
}

// String names the store, without its token.
func (s *bwsStore) String() string { return fmt.Sprintf("bws store %q", s.run.store) }

// GoString names the store, without its token.
func (s *bwsStore) GoString() string { return s.String() }

// Format writes String for every verb.
func (s *bwsStore) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
