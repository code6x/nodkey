package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/client"
	"github.com/code6x/nodkey/internal/store"
)

// The login item of the slow fake bw, its collection and its page.
const (
	slowItem = "11111111-1111-4111-8111-111111111111"
	slowColl = "22222222-2222-4222-8222-222222222222"
	slowPage = "https://example.com/sign-in"
)

// slowBWPause is how long each run of the slow fake bw takes: about the
// time that one run of bw takes on a small host (issue #190).
const slowBWPause = 5 * time.Second

// TestBrokerLoginWithSlowStore: on a host where each run of bw takes 5 s
// (a fake bw store, slowLoginStore: a real bw store would need a PATH that
// a CI host may not have),
// a login after "nodkey preapprove --login" is answered from the
// broker's memory, through nodkey agent-browser-plugin, in under 2 s and
// with no run of bw (DESIGN.md section 21.3, issue #190).
func TestBrokerLoginWithSlowStore(t *testing.T) {
	if testing.Short() {
		t.Skip("each run of the fake bw takes 5 s")
	}
	e := newBrokerEnv(t, brokerOptions{updatesOff: true})
	pw := madeUp("shop-password")
	calls := filepath.Join(e.dir, "bw-calls")
	writeTestFile(t, calls, nil, 0o600)
	writeTestFile(t, filepath.Join(e.dir, "bw-password-of-item"), []byte(pw), 0o600)
	// The config names a bw program and a password file, as for a real bw
	// store; the seam puts the slow fake in its place.
	writeTestFile(t, filepath.Join(e.dir, "bin", "bw"), []byte("#!/bin/sh\nexit 1\n"), 0o700)
	writeTestFile(t, filepath.Join(e.dir, "creds", "bw-password"), []byte(madeUp("master")+"\n"), 0o600)
	cfg, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg = append(cfg, fmt.Sprintf(`
[store.web]
type = "bw"
program = %q
password_file = "${CREDENTIALS_DIRECTORY}/bw-password"

[logins.web]
store = "web"
collection = %q
clients = ["laptop"]
ask = "always"
preapprove = true
`, filepath.Join(e.dir, "bin", "bw"), slowColl)...)
	writeTestFile(t, e.cfgPath, cfg, 0o600)
	e.start(seamSlowLoginStore)
	e.stderr.wait(t, lineListenOpen)

	// The tap of the pre-approval: the broker fetches the item before and
	// after it.
	c := e.httpClient()
	mustStatus(t, e.approve(c, api.PathPreapprove, api.PreapproveRequest{Login: slowItem, URL: slowPage, Uses: 1}), http.StatusOK)
	before := bwCalls(t, calls)

	// agent-browser's credential.resolve, through the plugin.
	home := filepath.Join(e.dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".config", "nodkey"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(home, ".config", "nodkey", "client.toml"), []byte(fmt.Sprintf(
		"broker = %q\nbroker_pin = %q\ntls_key = %q\n", e.addr, e.brokerPin.String(), filepath.Join(e.dir, "client.key"))), 0o600)
	t.Setenv("HOME", home)
	req, err := json.Marshal(map[string]any{
		"capability": "credential.read", "protocol": "agent-browser.plugin.v1", "type": "credential.resolve",
		"request": map[string]string{"itemRef": slowItem, "url": slowPage},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := client.AgentBrowserPlugin(nil, bytes.NewReader(req), &stdout, &stderr, "dev")
	took := time.Since(start)
	// Only the status and fields with no secret are printed: the answer
	// holds the password.
	var out struct {
		Success    bool   `json:"success"`
		Error      string `json:"error"`
		Credential struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"credential"`
	}
	jerr := json.Unmarshal(stdout.Bytes(), &out)
	if code != 0 || jerr != nil || !out.Success {
		t.Fatalf("the plugin: exit %d, success %v, error %q (JSON: %v)", code, out.Success, out.Error, jerr != nil)
	}
	if out.Credential.Username != "alice@example.com" {
		t.Error("the answer has another username")
	}
	if out.Credential.Password != pw {
		t.Error("the answer has another password")
	}
	if took >= 2*time.Second {
		t.Errorf("credential.resolve took %s; want under 2s", took)
	}
	if after := bwCalls(t, calls); after != before {
		t.Errorf("the login ran bw %d times; want 0", after-before)
	}
	if strings.Contains(e.stderr.text(), pw) {
		t.Error("the password is in the journal")
	}
}

// bwCalls returns the number of runs of the fake bw so far.
func bwCalls(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the file of the test's fake bw.
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}

// slowLoginStore is a fake bw store for logins in the child broker: each
// "run of bw" (sync, get item, list items) sleeps slowBWPause and adds a
// line to the file bw-calls. Its one item is slowItem; the password is in
// the file bw-password-of-item. Both files are next to the bin directory
// of the program in the config.
type slowLoginStore struct {
	calls, password string
}

func newSlowLoginStore(program string) (store.Store, error) {
	dir := filepath.Dir(filepath.Dir(program))
	return &slowLoginStore{calls: filepath.Join(dir, "bw-calls"), password: filepath.Join(dir, "bw-password-of-item")}, nil
}

// run is one run of the fake bw.
func (s *slowLoginStore) run(ctx context.Context, step string) error {
	f, err := os.OpenFile(s.calls, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(step + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	select {
	case <-time.After(slowBWPause):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *slowLoginStore) item() store.LoginItem {
	return store.LoginItem{ID: slowItem, Name: "Example shop", Username: "alice@example.com",
		URIs: []store.LoginURI{{URI: "https://example.com"}}, Collections: []string{slowColl}}
}

func (s *slowLoginStore) Start(context.Context) error { return nil }

func (s *slowLoginStore) Fetch(context.Context, string) (store.Value, error) {
	return store.Value{}, store.ErrFailed
}

func (s *slowLoginStore) Close() {}

func (s *slowLoginStore) ListLogins(ctx context.Context, collection string) ([]store.LoginItem, error) {
	for _, step := range []string{"sync", "list items"} {
		if err := s.run(ctx, step); err != nil {
			return nil, err
		}
	}
	if collection != slowColl {
		return nil, nil
	}
	return []store.LoginItem{s.item()}, nil
}

func (s *slowLoginStore) FetchLogin(ctx context.Context, id string) (store.Login, error) {
	if err := s.run(ctx, "sync"); err != nil {
		return store.Login{}, err
	}
	return s.FetchLoginNoSync(ctx, id)
}

func (s *slowLoginStore) FetchLoginNoSync(ctx context.Context, id string) (store.Login, error) {
	if err := s.run(ctx, "get item"); err != nil {
		return store.Login{}, err
	}
	if id != slowItem {
		return store.Login{}, fmt.Errorf("fake bw: not found: %w", store.ErrFailed)
	}
	pw, err := os.ReadFile(s.password)
	if err != nil {
		return store.Login{}, err
	}
	return store.Login{LoginItem: s.item(), Password: store.NewValue(pw)}, nil
}
