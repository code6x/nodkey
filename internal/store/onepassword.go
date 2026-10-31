package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/1password/onepassword-sdk-go"

	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/version"
)

// The errors of a 1password store. As every store error, they are fixed
// texts: the SDK's error text is never shown, because it may repeat a
// request (THREAT-MODEL.md T19).
var (
	ErrOPFailed    = errors.New("1Password refused the request, or could not be reached")
	ErrRateLimited = errors.New("1Password's rate limit is reached; the service account must wait")
	ErrNoField     = errors.New("the item has no field with this ID or title")
	ErrManyFields  = errors.New("the item has more than one field with this title; name the field by its ID")
	ErrTooLarge    = errors.New("the item is larger than 1 MiB")
)

const (
	// opParallel is the most calls to 1Password at the same time, for all
	// 1password stores together. The SDK runs every call in one core,
	// under one lock; more places would only make calls wait there,
	// beyond the time limit.
	opParallel = 1
	// maxOPItem is the largest item, in bytes of its fields and notes:
	// 1 MiB, as the output of a store program.
	maxOPItem = maxStdout
	// opIntegration is the name that the SDK sends to 1Password, as the
	// User-Agent that nodkey sends to GitHub (THREAT-MODEL.md T34).
	opIntegration = "nodkey"
)

// opItems is the part of the 1Password SDK that the store uses. Tests
// replace it with a fake 1Password.
type opItems interface {
	Get(ctx context.Context, vaultID, itemID string) (onepassword.Item, error)
}

// opConnect logs in to 1Password with a service account token and returns
// its items.
type opConnect func(ctx context.Context, token string) (opItems, error)

// opSlots are the places for calls to the SDK, shared by every 1password
// store.
var opSlots = make(chan struct{}, opParallel)

// sdkMu guards the first load of the SDK's WebAssembly core: the SDK
// loads it without a lock.
var sdkMu sync.Mutex

// sdkConnect is the opConnect of the real SDK. The SDK's calls do not
// stop when ctx ends; Fetch stops waiting for them instead.
func sdkConnect(ctx context.Context, token string) (opItems, error) {
	sdkMu.Lock()
	defer sdkMu.Unlock()
	c, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(opIntegration, version.Running))
	if err != nil {
		return nil, err
	}
	return c.ItemsAPI, nil
}

// opStore gets values from 1Password with a service account, through the
// 1Password SDK, in the broker's process. It has no program.
type opStore struct {
	name    string
	vault   string
	connect opConnect
	timeout time.Duration
	slots   chan struct{} // opSlots; tests give each store its own

	mu     sync.Mutex
	token  Value   // the service account token
	items  opItems // nil until a login works
	closed bool
}

// newOP reads the token file of a 1password store and returns the store.
func newOP(cfg config.Store, d deps) (*opStore, error) {
	if !opID(cfg.Vault) {
		return nil, fmt.Errorf("store %q: vault: is not a 1Password ID", cfg.Name)
	}
	if !cleanAbs(cfg.TokenFile) {
		return nil, fmt.Errorf("store %q: token_file: %s", cfg.Name, cleanAbsRule)
	}
	data, err := d.readPrivateFile(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("store %q: token_file: %w", cfg.Name, err) // the error names the path, never the content
	}
	defer clear(data)
	token, ok := parseKey(data, maxTokenLen)
	if !ok {
		return nil, fmt.Errorf("store %q: token_file %s: it holds no service account token, or a character that "+
			"a token never has (the content is not shown here)", cfg.Name, cfg.TokenFile)
	}
	connect := d.opConnect
	if connect == nil {
		connect = sdkConnect
	}
	return &opStore{name: cfg.Name, vault: cfg.Vault, connect: connect, timeout: d.timeout,
		slots: opSlots, token: token}, nil
}

// Start logs in to 1Password. If it fails, Fetch tries again.
func (s *opStore) Start(ctx context.Context) error {
	const step = "1password login"
	_, err := s.call(ctx, func(ctx context.Context) (Value, error) {
		_, err := s.login(ctx)
		return Value{}, err
	})
	if err != nil {
		return stepError(s.name, step, err)
	}
	return nil
}

// Fetch gets one field of the item: ref is "ITEM_ID/FIELD", where FIELD
// is the field's ID or title. A field ID wins over a title; two fields
// with the title are an error. The item must be in the store's vault.
func (s *opStore) Fetch(ctx context.Context, ref string) (Value, error) {
	const step = "1password item get"
	id, field, ok := strings.Cut(ref, "/")
	if !ok || !opID(id) || field == "" {
		return Value{}, stepError(s.name, step, ErrBadID)
	}
	v, err := s.call(ctx, func(ctx context.Context) (Value, error) {
		items, err := s.login(ctx)
		if err != nil {
			return Value{}, err
		}
		item, err := items.Get(ctx, s.vault, id)
		if err != nil {
			return Value{}, sdkError(err)
		}
		v, err := pickField(&item, s.vault, id, field)
		item = onepassword.Item{} // drops the other fields; Go cannot clear a string
		return v, err
	})
	if err != nil {
		return Value{}, stepError(s.name, step, err)
	}
	return v, nil
}

// call runs f in its own goroutine, with a place in s.slots and the time
// limit of the store. The SDK's calls do not stop when their context ends,
// so call stops waiting instead: it returns at the time limit, and a value
// that f returns later is cleared. The place is freed when f ends, not
// when call gives up: a call that hangs holds its place, and calls never
// pile up.
func (s *opStore) call(ctx context.Context, f func(context.Context) (Value, error)) (Value, error) {
	if err := acquire(ctx, s.slots); err != nil {
		return Value{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	type answer struct {
		v   Value
		err error
	}
	done := make(chan answer, 1)
	go func() {
		defer func() { <-s.slots }()
		defer cancel()
		v, err := f(ctx)
		if err != nil {
			err = ctxError(ctx, err) // before cancel ends ctx
		}
		done <- answer{v, err}
	}()
	var a answer
	select {
	case a = <-done:
	case <-ctx.Done():
		// f sends its answer before it cancels ctx: when f ended, the
		// answer is here.
		select {
		case a = <-done:
		default:
			go func() { a := <-done; a.v.Clear() }()
			return Value{}, ctxError(ctx, ctx.Err())
		}
	}
	if a.err != nil {
		a.v.Clear()
		return Value{}, a.err
	}
	return a.v, nil
}

// login returns the items of the logged-in client, and logs in first if
// no login worked yet. It runs only in call, which holds the place: so
// two logins of one store never run at the same time. It does not hold
// s.mu while it waits for 1Password, so Close never waits for it.
func (s *opStore) login(ctx context.Context) (opItems, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if s.items != nil {
		items := s.items
		s.mu.Unlock()
		return items, nil
	}
	token := string(s.token.Bytes())
	s.mu.Unlock()
	items, err := s.connect(ctx, token)
	if err != nil {
		return nil, sdkError(err)
	}
	if items == nil {
		return nil, ErrOPFailed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	s.items = items
	return items, nil
}

// sdkError turns an error of the SDK into a fixed error. The SDK's text is
// dropped.
func sdkError(err error) error {
	if _, ok := errors.AsType[*onepassword.RateLimitExceededError](err); ok {
		return ErrRateLimited
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ErrTimeout
	case errors.Is(err, context.Canceled):
		return context.Canceled
	}
	return ErrOPFailed
}

// ctxError returns ErrTimeout when ctx passed its deadline, the context's
// error when it was cancelled, and err otherwise.
func ctxError(ctx context.Context, err error) error {
	switch ctx.Err() {
	case nil:
		return err
	case context.DeadlineExceeded:
		return ErrTimeout
	default:
		return ctx.Err()
	}
}

// pickField returns the value of the field of item. It checks that the
// item is the asked one, in the asked vault, and not too large.
func pickField(item *onepassword.Item, vault, id, field string) (Value, error) {
	if item.ID != id || item.VaultID != vault {
		return Value{}, errOtherItem
	}
	size := len(item.Notes)
	for i := range item.Fields {
		size += len(item.Fields[i].Value) + len(item.Fields[i].Title) + len(item.Fields[i].ID)
	}
	if size > maxOPItem {
		return Value{}, ErrTooLarge
	}
	pick := -1
	for i := range item.Fields {
		if item.Fields[i].ID == field {
			pick = i
			break
		}
	}
	if pick < 0 {
		for i := range item.Fields {
			if item.Fields[i].Title != field {
				continue
			}
			if pick >= 0 {
				return Value{}, ErrManyFields
			}
			pick = i
		}
	}
	if pick < 0 {
		return Value{}, ErrNoField
	}
	return keepValue([]byte(item.Fields[pick].Value), nil)
}

// opID reports whether id is a 1Password ID: 26 small letters and digits.
func opID(id string) bool {
	if len(id) != 26 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// Close clears the token and drops the client.
func (s *opStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token.Clear()
	s.items = nil
	s.closed = true
}

// String names the store, without its token.
func (s *opStore) String() string { return fmt.Sprintf("1password store %q", s.name) }

// GoString names the store, without its token.
func (s *opStore) GoString() string { return s.String() }

// Format writes String for every verb.
func (s *opStore) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
