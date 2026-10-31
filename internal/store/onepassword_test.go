package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1password/onepassword-sdk-go"

	"github.com/code6x/nodkey/internal/config"
)

const (
	opVault = "abcdefghijklmnopqrstuvwxyz"
	opItem  = "0123456789abcdefghijklmnop"
)

// fakeOP is a fake 1Password: the items of one service account.
type fakeOP struct {
	mu       sync.Mutex
	token    string // the token that a login needs
	loginErr error  // the error of every login, when set
	items    map[string]onepassword.Item
	getErr   error         // the error of every Get, when set
	block    bool          // Get waits until its context ends
	hang     chan struct{} // Get waits for this, and ignores its context
	logins   int
	gets     int
}

func (f *fakeOP) connect(_ context.Context, token string) (opItems, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins++
	if f.loginErr != nil {
		return nil, f.loginErr
	}
	if token != f.token {
		// The real SDK's text may repeat the request: here it does.
		return nil, fmt.Errorf("invalid service account token %q", token)
	}
	return f, nil
}

func (f *fakeOP) Get(ctx context.Context, vaultID, itemID string) (onepassword.Item, error) {
	f.mu.Lock()
	f.gets++
	block, hang, err := f.block, f.hang, f.getErr
	item, ok := f.items[vaultID+"/"+itemID]
	f.mu.Unlock()
	if hang != nil {
		<-hang
	}
	if block {
		<-ctx.Done()
		return onepassword.Item{}, ctx.Err()
	}
	if err != nil {
		return onepassword.Item{}, err
	}
	if !ok {
		return onepassword.Item{}, fmt.Errorf("item %s in vault %s not found", itemID, vaultID)
	}
	return item, nil
}

// opTestItem is an item with a password, a field with a title, and notes.
func opTestItem(password, apiKey, other string) onepassword.Item {
	return onepassword.Item{
		ID: opItem, VaultID: opVault, Title: "an item",
		Fields: []onepassword.ItemField{
			{ID: "username", Title: "username", Value: other},
			{ID: "password", Title: "password", Value: password},
			{ID: "x7k2m4q9w1e3r5t6y8u0i2o4p6", Title: "API key", Value: apiKey},
		},
		Notes: other,
	}
}

// newOPTest makes a 1password store with the fake behind it.
func newOPTest(t *testing.T, f *fakeOP, timeout time.Duration) Store {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "op-token")
	writeFile(t, tokenFile, f.token+"\n")
	d := testDeps()
	d.opConnect = f.connect
	d.timeout = timeout
	s, err := newStore(config.Store{Name: "op", Type: config.StoreOnePassword, Vault: opVault, TokenFile: tokenFile}, dir, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func opFake(token string, items ...onepassword.Item) *fakeOP {
	f := &fakeOP{token: token, items: map[string]onepassword.Item{}}
	for _, it := range items {
		f.items[it.VaultID+"/"+it.ID] = it
	}
	return f
}

func TestOPFetch(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	f := opFake(c.token, opTestItem(c.value, c.password, c.other))
	s := newOPTest(t, f, 5*time.Second)
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ field, want string }{
		{"password", c.value},
		{"API key", c.password},                    // by title
		{"x7k2m4q9w1e3r5t6y8u0i2o4p6", c.password}, // by ID
	} {
		v, err := s.Fetch(t.Context(), opItem+"/"+tt.field)
		if err != nil {
			t.Fatalf("field %q: %v", tt.field, err)
		}
		if string(v.Bytes()) != tt.want {
			t.Errorf("field %q: the wrong value", tt.field)
		}
		v.Clear()
	}
	if f.logins != 1 {
		t.Errorf("logins = %d, want 1: the client is kept", f.logins)
	}
	if got := fmt.Sprintf("%v %+v %#v %s", s, s, s, s); strings.Contains(got, c.token) {
		t.Errorf("the printed store holds the token")
	}
}

// TestOPDenies runs the cases where a 1password store must deny. No error
// holds the token, a value, or the SDK's text.
func TestOPDenies(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	big := opTestItem(c.value, "", "")
	big.Notes = strings.Repeat("n", maxOPItem)
	empty := opTestItem("", c.password, c.other)
	nul := opTestItem("a\x00b", c.password, c.other)
	twice := opTestItem(c.value, c.password, c.other)
	twice.Fields = append(twice.Fields, onepassword.ItemField{ID: "z9", Title: "API key", Value: c.other})
	otherVault := opTestItem(c.value, c.password, c.other)
	otherVault.VaultID = "zzzzzzzzzzzzzzzzzzzzzzzzzz"
	wrongID := opTestItem(c.value, c.password, c.other)
	wrongID.ID = "zzzzzzzzzzzzzzzzzzzzzzzzzz"
	tests := []struct {
		name  string
		setup func(f *fakeOP)
		item  *onepassword.Item
		ref   string
		want  error
	}{
		{"missing item", nil, nil, opItem + "/password", ErrOPFailed},
		{"missing field", nil, &twice, opItem + "/no such field", ErrNoField},
		{"field title twice", nil, &twice, opItem + "/API key", ErrManyFields},
		{"empty value", nil, &empty, opItem + "/password", ErrNoValue},
		{"NUL byte", nil, &nul, opItem + "/password", ErrBadValue},
		{"too large", nil, &big, opItem + "/password", ErrTooLarge},
		{"item of another vault", nil, &otherVault, opItem + "/password", ErrBadAnswer},
		{"answer for another item", nil, &wrongID, opItem + "/password", ErrBadAnswer},
		{"expired token", func(f *fakeOP) {
			f.loginErr = errors.New("service account token expired: " + c.token)
		}, nil, opItem + "/password", ErrOPFailed},
		{"rate limit at login", func(f *fakeOP) {
			f.loginErr = &onepassword.RateLimitExceededError{}
		}, nil, opItem + "/password", ErrRateLimited},
		{"rate limit", func(f *fakeOP) {
			f.getErr = fmt.Errorf("wrapped: %w", &onepassword.RateLimitExceededError{})
		}, nil, opItem + "/password", ErrRateLimited},
		{"SDK error with a value", func(f *fakeOP) {
			f.getErr = errors.New("request failed: " + c.value + " " + c.token)
		}, nil, opItem + "/password", ErrOPFailed},
		{"time-out", func(f *fakeOP) { f.block = true }, nil, opItem + "/password", ErrTimeout},
		{"no field", nil, nil, opItem, ErrBadID},
		{"empty field", nil, nil, opItem + "/", ErrBadID},
		{"a name for the item", nil, nil, "GitHub token/password", ErrBadID},
		{"a UUID for the item", nil, nil, "00000000-0000-0000-0000-000000000001/password", ErrBadID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := opFake(c.token)
			if tt.item != nil {
				f.items[opVault+"/"+opItem] = *tt.item
			}
			if tt.setup != nil {
				tt.setup(f)
			}
			s := newOPTest(t, f, 200*time.Millisecond)
			v, err := s.Fetch(t.Context(), tt.ref)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if v.Bytes() != nil {
				t.Error("a value with the error")
			}
			text := err.Error()
			c.check(t, "the error", text)
			for _, sdk := range []string{"expired", "request failed", "not found", "wrapped", "invalid"} {
				if strings.Contains(text, sdk) {
					t.Errorf("the error %q holds the SDK's text %q", text, sdk)
				}
			}
			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, nil)).Warn("x", slog.Any("error", err), slog.Any("store", s), slog.Any("value", v))
			c.check(t, "a log line", buf.String())
		})
	}
}

// TestOPWrongToken: the SDK's error repeats the token; the store's error
// does not.
func TestOPWrongToken(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	f := opFake(c.token, opTestItem(c.value, "", ""))
	s := newOPTest(t, f, 5*time.Second)
	f.token = c.other
	err := s.Start(t.Context())
	if !errors.Is(err, ErrOPFailed) {
		t.Fatalf("err = %v", err)
	}
	c.check(t, "the error", err.Error())
}

// TestOPTimeoutWhenTheSDKHangs: Fetch denies on time even when the SDK
// ignores the context, and the hung call keeps its place.
func TestOPTimeoutWhenTheSDKHangs(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	f := opFake(c.token, opTestItem(c.value, "", ""))
	f.hang = make(chan struct{})
	s := newOPTest(t, f, 100*time.Millisecond)
	for range opParallel {
		if _, err := s.Fetch(t.Context(), opItem+"/password"); !errors.Is(err, ErrTimeout) {
			t.Fatalf("err = %v, want ErrTimeout", err)
		}
	}
	// Every place is held by a hung call: the next Fetch waits, and its
	// context ends.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Fetch(ctx, opItem+"/password"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context's deadline", err)
	}
	close(f.hang)
	f.mu.Lock()
	f.hang = nil
	f.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, err := s.Fetch(t.Context(), opItem+"/password")
		if err == nil {
			v.Clear()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the places were not freed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestOPLoginAgain: a failed login at Start is tried again by Fetch.
func TestOPLoginAgain(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	f := opFake(c.token, opTestItem(c.value, "", ""))
	f.loginErr = errors.New("offline")
	s := newOPTest(t, f, 5*time.Second)
	if err := s.Start(t.Context()); !errors.Is(err, ErrOPFailed) {
		t.Fatalf("Start: %v", err)
	}
	f.mu.Lock()
	f.loginErr = nil
	f.mu.Unlock()
	v, err := s.Fetch(t.Context(), opItem+"/password")
	if err != nil {
		t.Fatal(err)
	}
	v.Clear()
}

func TestOPClose(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	f := opFake(c.token, opTestItem(c.value, "", ""))
	s := newOPTest(t, f, 5*time.Second)
	s.Close()
	if _, err := s.Fetch(t.Context(), opItem+"/password"); !errors.Is(err, ErrClosed) {
		t.Errorf("Fetch after Close: %v", err)
	}
	if err := s.Start(t.Context()); !errors.Is(err, ErrClosed) {
		t.Errorf("Start after Close: %v", err)
	}
	if f.logins != 0 {
		t.Errorf("logins = %d after Close", f.logins)
	}
}

func TestOPTokenFile(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	dir := t.TempDir()
	d := testDeps()
	d.opConnect = opFake(c.token).connect
	cfg := config.Store{Name: "op", Type: config.StoreOnePassword, Vault: opVault, TokenFile: filepath.Join(dir, "op-token")}
	for _, tt := range []struct{ name, content, want string }{
		{"missing", "", "token_file"},
		{"empty", "\n", "holds no service account token"},
		{"two lines", c.token + "\n" + c.other + "\n", "holds no service account token"},
	} {
		if tt.name != "missing" {
			writeFile(t, cfg.TokenFile, tt.content)
		}
		_, err := newStore(cfg, dir, d)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
		if err != nil {
			c.check(t, "the error", err.Error())
		}
		_ = os.Remove(cfg.TokenFile)
	}
	bad := cfg
	bad.Vault = "nodkey"
	if _, err := newStore(bad, dir, d); err == nil {
		t.Error("a vault name was taken")
	}
}
