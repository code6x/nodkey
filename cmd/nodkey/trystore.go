package main

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/code6x/nodkey/internal/store"
)

// tryValuePrefix starts each fake value of the trial store, so a person
// who sees one knows that it is fake.
const tryValuePrefix = "TRY-"

// trySecretNames are the secrets of the trial: the [secret.*] names of its
// config, and the item IDs in its store.
var trySecretNames = []string{"demo-token", "demo-password", "demo-api-key"}

// errTryUnknown is the error of tryStore.Fetch for an ID it does not hold.
var errTryUnknown = errors.New("the trial store has no such item")

// tryStore is the store of nodkey try: it holds only fake values, made at
// random when the trial starts. It lives only in the code of nodkey try:
// no [store.*] section of a broker config can name it, so nodkey broker
// can never use it (store.New knows only bws and bw).
type tryStore struct {
	mu     sync.Mutex
	values map[string][]byte // by item ID; nil after Close
}

// newTryStore makes the trial store with a new random value for each name
// in trySecretNames.
func newTryStore() *tryStore {
	s := &tryStore{values: make(map[string][]byte, len(trySecretNames))}
	for _, name := range trySecretNames {
		s.values[name] = []byte(tryValuePrefix + rand.Text())
	}
	return s
}

// Start does nothing: the values are made in newTryStore.
func (s *tryStore) Start(context.Context) error { return nil }

// Fetch returns a copy of the value of the item id.
func (s *tryStore) Fetch(ctx context.Context, id string) (store.Value, error) {
	if err := ctx.Err(); err != nil {
		return store.Value{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		return store.Value{}, store.ErrClosed
	}
	v, ok := s.values[id]
	if !ok {
		return store.Value{}, errTryUnknown
	}
	return store.NewValue(append([]byte(nil), v...)), nil
}

// Close clears the values.
func (s *tryStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.values {
		clear(v)
	}
	s.values = nil
}
