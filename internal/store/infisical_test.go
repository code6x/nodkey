package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

const (
	infClientID = "11111111-2222-3333-4444-555555555555"
	infProject  = "66666666-7777-8888-9999-000000000000"
	// The two forms of a server: the cloud, and a self-hosted server
	// under a path. Both reach the fake.
	infCloud      = "https://app.infisical.com"
	infSelfHosted = "https://secrets.example.com:8443/infisical"
)

// fakeInfSecret is one secret of the fake Infisical.
type fakeInfSecret struct {
	project, environment, path, name, value string
}

// fakeInf is a fake Infisical server: Universal Auth login, and the read
// of one secret, as the SDK calls them.
type fakeInf struct {
	t      *testing.T
	prefix string // "/api", or the path of a self-hosted server and "/api"

	mu         sync.Mutex
	secret     string // the client secret that a login needs
	tokenBase  string // access tokens are tokenBase and a number
	expiresIn  int64
	tokens     map[string]bool // the access tokens that work
	secrets    []fakeInfSecret
	projects   map[string]bool // the projects that the identity may read
	loginCode  int             // when set, every login answers it
	readCodes  []int           // the answers of the next reads, before the secret
	readHook   func(w http.ResponseWriter, r *http.Request) bool
	loginHook  func(w http.ResponseWriter, r *http.Request) bool
	logins     int
	reads      int
	badQueries []string
}

func newFakeInf(t *testing.T, c canaries, prefix string) *fakeInf {
	return &fakeInf{
		t: t, prefix: prefix, secret: c.token, tokenBase: c.session, expiresIn: 600,
		tokens: map[string]bool{}, projects: map[string]bool{infProject: true},
		secrets: []fakeInfSecret{{infProject, "prod", "/", "GITHUB_TOKEN", c.value},
			{infProject, "prod", "/ci", "DEPLOY_KEY", c.password}},
	}
}

// fail writes an error of Infisical, which repeats what it got: the
// store must never show it.
func (f *fakeInf) fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": msg, "reqId": "req-" + msg, "statusCode": code})
}

func (f *fakeInf) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == f.prefix+"/v1/auth/universal-auth/login":
		f.login(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, f.prefix+"/v3/secrets/raw/"):
		f.read(w, r, strings.TrimPrefix(r.URL.Path, f.prefix+"/v3/secrets/raw/"))
	default:
		f.fail(w, http.StatusNotFound, "no route "+r.URL.Path)
	}
}

func (f *fakeInf) login(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.logins++
	hook, code := f.loginHook, f.loginCode
	f.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.fail(w, http.StatusBadRequest, "bad body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if code != 0 {
		f.fail(w, code, "login refused for "+req.ClientSecret)
		return
	}
	if req.ClientID != infClientID || req.ClientSecret != f.secret {
		f.fail(w, http.StatusUnauthorized, "invalid credentials "+req.ClientSecret)
		return
	}
	token := f.tokenBase + "." + strconv.Itoa(f.logins)
	f.tokens[token] = true
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accessToken": token, "expiresIn": f.expiresIn, "accessTokenMaxTTL": f.expiresIn * 2, "tokenType": "Bearer",
	})
}

func (f *fakeInf) read(w http.ResponseWriter, r *http.Request, name string) {
	f.mu.Lock()
	f.reads++
	hook := f.readHook
	var code int
	if len(f.readCodes) > 0 {
		code, f.readCodes = f.readCodes[0], f.readCodes[1:]
	}
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	ok := f.tokens[token]
	f.mu.Unlock()
	if !ok {
		f.fail(w, http.StatusUnauthorized, "Token expired: "+token)
		return
	}
	if code != 0 {
		f.fail(w, code, "refused for "+token)
		return
	}
	if hook != nil && hook(w, r) {
		return
	}
	q := r.URL.Query()
	if q.Get("expandSecretReferences") != "false" || q.Get("include_imports") != "false" || q.Get("type") != "shared" {
		f.mu.Lock()
		f.badQueries = append(f.badQueries, r.URL.RawQuery)
		f.mu.Unlock()
		f.fail(w, http.StatusBadRequest, "bad query")
		return
	}
	project, env, path := q.Get("workspaceId"), q.Get("environment"), q.Get("secretPath")
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.projects[project] {
		f.fail(w, http.StatusForbidden, "You are not allowed to read secrets of "+project+" with "+token)
		return
	}
	for _, s := range f.secrets {
		if s.project == project && s.environment == env && s.path == path && s.name == name {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{
				"id": "1", "workspace": s.project, "environment": s.environment, "version": 1, "type": "shared",
				"secretKey": s.name, "secretValue": s.value, "secretComment": "a comment", "secretPath": s.path,
			}})
			return
		}
	}
	f.fail(w, http.StatusNotFound, "Secret with name '"+name+"' not found; token "+token)
}

func (f *fakeInf) counts() (logins, reads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins, f.reads
}

func (f *fakeInf) set(fn func(f *fakeInf)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// infClock is a clock that tests move.
type infClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *infClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *infClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type infTest struct {
	store *infStore
	fake  *fakeInf
	clock *infClock
	dir   string
}

// newInfTest makes an infisical store with server, and the fake behind
// it. Every connection goes to the fake, whatever the host; TLS checks
// the fake's certificate.
func newInfTest(t *testing.T, c canaries, server string, timeout time.Duration) *infTest {
	t.Helper()
	prefix := "/api"
	if server == infSelfHosted {
		prefix = "/infisical/api"
	}
	f := newFakeInf(t, c, prefix)
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = "example.com" // a name in the certificate of httptest
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	t.Cleanup(tr.CloseIdleConnections)
	dir := t.TempDir()
	file := filepath.Join(dir, "infisical-secret")
	writeFile(t, file, c.token+"\n")
	clock := &infClock{now: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
	d := testDeps()
	d.infTransport = tr
	d.now = clock.Now
	d.timeout = timeout
	s, err := newStore(config.Store{Name: "inf", Type: config.StoreInfisical, Server: server,
		ClientID: infClientID, ClientSecretFile: file}, dir, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return &infTest{store: s.(*infStore), fake: f, clock: clock, dir: dir}
}

var infGitHub = InfisicalRef(infProject, "prod", "/", "GITHUB_TOKEN")

func TestInfisicalRef(t *testing.T) {
	for _, tt := range []struct{ project, env, path, name string }{
		{infProject, "prod", "/", "A"},
		{infProject, "dev", "/ci/deploy", "a.b-c"},
	} {
		got, ok := parseInfRef(InfisicalRef(tt.project, tt.env, tt.path, tt.name))
		if !ok || got != (infRef{tt.project, tt.env, tt.path, tt.name}) {
			t.Errorf("%+v: got %+v, %v", tt, got, ok)
		}
	}
	for _, id := range []string{"", infProject, infProject + "/prod", infProject + "/prod/A", "x/prod/A/",
		infProject + "/prod/../", infProject + "/prod/A//ci", infProject + "/prod/A/ci/", infProject + "/pr od/A/",
		infProject + "/prod/A?x/", "00000000-0000-0000-0000-000000000001"} {
		if r, ok := parseInfRef(id); ok {
			t.Errorf("%q taken: %+v", id, r)
		}
	}
}

// TestInfisicalFetch reads secrets from the cloud and from a self-hosted
// server, and keeps the access token for the next read.
func TestInfisicalFetch(t *testing.T) {
	t.Parallel()
	for _, server := range []string{infCloud, infSelfHosted} {
		t.Run(server, func(t *testing.T) {
			t.Parallel()
			c := newCanaries()
			e := newInfTest(t, c, server, 5*time.Second)
			if err := e.store.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, tt := range []struct{ ref, want string }{
				{infGitHub, c.value},
				{InfisicalRef(infProject, "prod", "/ci", "DEPLOY_KEY"), c.password},
				{infGitHub, c.value},
			} {
				v, err := e.store.Fetch(t.Context(), tt.ref)
				if err != nil {
					t.Fatalf("%s: %v", tt.ref, err)
				}
				if string(v.Bytes()) != tt.want {
					t.Errorf("%s: the wrong value", tt.ref)
				}
				v.Clear()
			}
			if logins, reads := e.fake.counts(); logins != 1 || reads != 3 {
				t.Errorf("logins = %d, reads = %d; want 1 and 3: the token is kept", logins, reads)
			}
			if len(e.fake.badQueries) != 0 {
				t.Errorf("queries without the fixed options: %q", e.fake.badQueries)
			}
		})
	}
}

// TestInfisicalTokenTimeUp: when the time of the access token is up, the
// store logs in again before it reads.
func TestInfisicalTokenTimeUp(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	e := newInfTest(t, c, infCloud, 5*time.Second)
	e.fake.set(func(f *fakeInf) { f.expiresIn = 60 })
	for i := range 2 {
		v, err := e.store.Fetch(t.Context(), infGitHub)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		v.Clear()
	}
	if logins, _ := e.fake.counts(); logins != 1 {
		t.Fatalf("logins = %d, want 1", logins)
	}
	e.clock.add(55 * time.Second) // within the margin before the end
	v, err := e.store.Fetch(t.Context(), infGitHub)
	if err != nil {
		t.Fatal(err)
	}
	v.Clear()
	if logins, reads := e.fake.counts(); logins != 2 || reads != 3 {
		t.Errorf("logins = %d, reads = %d; want 2 and 3", logins, reads)
	}
}

// TestInfisicalTokenEnded: Infisical refuses a token that the store
// kept (it ended early, or was revoked). The store logs in again once
// and reads once more; a second refusal denies.
func TestInfisicalTokenEnded(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	e := newInfTest(t, c, infCloud, 5*time.Second)
	if err := e.store.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.fake.set(func(f *fakeInf) { clear(f.tokens) })
	v, err := e.store.Fetch(t.Context(), infGitHub)
	if err != nil {
		t.Fatalf("after one refusal: %v", err)
	}
	v.Clear()
	if logins, reads := e.fake.counts(); logins != 2 || reads != 2 {
		t.Errorf("logins = %d, reads = %d; want 2 and 2", logins, reads)
	}

	// The token is refused, and so is the next one.
	e.fake.set(func(f *fakeInf) { f.readCodes = []int{http.StatusUnauthorized, http.StatusUnauthorized} })
	_, err = e.store.Fetch(t.Context(), infGitHub)
	if !errors.Is(err, ErrInfDenied) {
		t.Fatalf("err = %v, want ErrInfDenied", err)
	}
	if logins, reads := e.fake.counts(); logins != 3 || reads != 4 {
		t.Errorf("logins = %d, reads = %d; want 3 and 4: one login again, no more", logins, reads)
	}
	c.check(t, "the error", err.Error())
}

// TestInfisicalFreshTokenRefused: a token that the call just got and that
// Infisical refuses denies, without another login.
func TestInfisicalFreshTokenRefused(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	e := newInfTest(t, c, infCloud, 5*time.Second)
	e.fake.set(func(f *fakeInf) { f.readCodes = []int{http.StatusUnauthorized} })
	if _, err := e.store.Fetch(t.Context(), infGitHub); !errors.Is(err, ErrInfDenied) {
		t.Fatalf("err = %v, want ErrInfDenied", err)
	}
	if logins, reads := e.fake.counts(); logins != 1 || reads != 1 {
		t.Errorf("logins = %d, reads = %d; want 1 and 1", logins, reads)
	}
}

// infDenyCases are the cases where an infisical store must deny.
func infDenyCases(c canaries) []struct {
	name  string
	setup func(f *fakeInf)
	ref   string
	want  error
} {
	big := strings.Repeat("v", maxInfAnswer)
	return []struct {
		name  string
		setup func(f *fakeInf)
		ref   string
		want  error
	}{
		{"wrong project", nil, InfisicalRef("00000000-0000-0000-0000-000000000009", "prod", "/", "GITHUB_TOKEN"), ErrInfDenied},
		{"missing secret", nil, InfisicalRef(infProject, "prod", "/", "NO_SUCH"), ErrInfNotFound},
		{"wrong environment", nil, InfisicalRef(infProject, "dev", "/", "GITHUB_TOKEN"), ErrInfNotFound},
		{"wrong path", nil, InfisicalRef(infProject, "prod", "/ci", "GITHUB_TOKEN"), ErrInfNotFound},
		{"empty value", func(f *fakeInf) { f.secrets[0].value = "" }, infGitHub, ErrNoValue},
		{"NUL byte", func(f *fakeInf) { f.secrets[0].value = "a\x00" + c.value }, infGitHub, ErrBadValue},
		{"a reference", func(f *fakeInf) { f.secrets[0].value = "${prod.OTHER}" }, infGitHub, ErrInfReference},
		{"a reference in a value", func(f *fakeInf) { f.secrets[0].value = c.value + "${OTHER}" }, infGitHub, ErrInfReference},
		{"refused login", func(f *fakeInf) { f.secret = c.other }, infGitHub, ErrInfLogin},
		{"login 403", func(f *fakeInf) { f.loginCode = http.StatusForbidden }, infGitHub, ErrInfLogin},
		{"login 500", func(f *fakeInf) { f.loginCode = http.StatusInternalServerError }, infGitHub, ErrInfLogin},
		{"rate limit at login", func(f *fakeInf) { f.loginCode = http.StatusTooManyRequests }, infGitHub, ErrRateLimited},
		{"rate limit", func(f *fakeInf) { f.readCodes = []int{http.StatusTooManyRequests} }, infGitHub, ErrInfRateLimited},
		{"server error", func(f *fakeInf) { f.readCodes = []int{http.StatusBadGateway} }, infGitHub, ErrInfFailed},
		{"login without a token", func(f *fakeInf) {
			f.loginHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"accessToken":"","expiresIn":60}`))
				return true
			}
		}, infGitHub, ErrInfLogin},
		{"login token with a space", func(f *fakeInf) {
			f.loginHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"accessToken":"%s x","expiresIn":60}`, c.session)
				return true
			}
		}, infGitHub, ErrInfLogin},
		{"answer for another secret", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"secret":{"secretKey":"OTHER","secretValue":"%s"}}`, c.value)
				return true
			}
		}, infGitHub, ErrBadAnswer},
		{"answer for another project", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"secret":{"secretKey":"GITHUB_TOKEN","workspace":"x","secretValue":"%s"}}`, c.value)
				return true
			}
		}, infGitHub, ErrBadAnswer},
		{"answer for another environment", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"secret":{"secretKey":"GITHUB_TOKEN","environment":"dev","secretValue":"%s"}}`, c.value)
				return true
			}
		}, infGitHub, ErrBadAnswer},
		{"a personal secret", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"secret":{"secretKey":"GITHUB_TOKEN","type":"personal","secretValue":"%s"}}`, c.value)
				return true
			}
		}, infGitHub, ErrBadAnswer},
		{"not JSON", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				_, _ = w.Write([]byte(c.value))
				return true
			}
		}, infGitHub, ErrBadAnswer},
		{"a redirect", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, r *http.Request) bool {
				http.Redirect(w, r, "https://192.0.2.1/steal", http.StatusFound)
				return true
			}
		}, infGitHub, ErrBadAnswer},
		{"too large", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"secret":{"secretKey":"GITHUB_TOKEN","secretValue":"%s%s"}}`, c.value, big)
				return true
			}
		}, infGitHub, ErrInfTooLarge},
		{"too large without a length", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"secret":{"secretKey":"GITHUB_TOKEN","secretValue":"%s`, c.value)
				w.(http.Flusher).Flush() // chunked: no Content-Length
				for range 3 {
					_, _ = w.Write([]byte(big[:maxInfAnswer/2]))
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(`"}}`))
				return true
			}
		}, infGitHub, ErrInfTooLarge},
		{"an encoded answer", func(f *fakeInf) {
			f.readHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "br") // Go's transport does not decode it
				_, _ = fmt.Fprintf(w, `{"secret":{"secretKey":"GITHUB_TOKEN","secretValue":"%s"}}`, c.value)
				return true
			}
		}, infGitHub, ErrInfFailed},
		{"login answer too large", func(f *fakeInf) {
			f.loginHook = func(w http.ResponseWriter, _ *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"accessToken":"%s","expiresIn":60,"x":"%s"}`, c.session, big)
				return true
			}
		}, infGitHub, ErrInfTooLarge},
		{"time-out", func(f *fakeInf) {
			f.readHook = func(_ http.ResponseWriter, r *http.Request) bool {
				<-r.Context().Done()
				return true
			}
		}, infGitHub, ErrTimeout},
		{"login time-out", func(f *fakeInf) {
			f.loginHook = func(_ http.ResponseWriter, r *http.Request) bool {
				_, _ = io.Copy(io.Discard, r.Body) // the server sees the end of the connection only after the body
				<-r.Context().Done()
				return true
			}
		}, infGitHub, ErrTimeout},
		{"a bad ref", nil, "GITHUB_TOKEN", ErrBadID},
		{"a ref with ..", nil, infProject + "/prod/../", ErrBadID},
	}
}

// TestInfisicalDenies runs the cases where an infisical store must deny.
// No error and no log line holds the client secret, the access token, a
// value, or the server's text.
func TestInfisicalDenies(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	for _, tt := range infDenyCases(c) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newInfTest(t, c, infCloud, 300*time.Millisecond)
			if tt.setup != nil {
				e.fake.set(tt.setup)
			}
			v, err := e.store.Fetch(t.Context(), tt.ref)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if v.Bytes() != nil {
				t.Error("a value with the error")
			}
			checkInfCanaries(t, c, e.store, err, v)
		})
	}
}

// checkInfCanaries checks the error, a log line of it, and the printed
// store for the canaries and the server's text.
func checkInfCanaries(t *testing.T, c canaries, s *infStore, err error, v Value) {
	t.Helper()
	text := err.Error()
	c.check(t, "the error", text)
	for _, server := range []string{"expired", "not found", "refused for", "invalid credentials", "not allowed",
		"req-", "Secret with", "APIError", "http", "status", "steal"} {
		if strings.Contains(text, server) {
			t.Errorf("the error %q holds the SDK's or the server's text %q", text, server)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Warn("x", slog.Any("error", err), slog.Any("store", s), slog.Any("value", v))
	c.check(t, "a log line", buf.String())
	c.check(t, "the printed store", fmt.Sprintf("%v %+v %#v %s %q", s, s, s, s, s))
}

// TestInfisicalCanaries runs every path of an infisical store with a
// client secret and access tokens made at run time, and looks for them in
// every error, log line and printed form of the store, and on stderr.
func TestInfisicalCanaries(t *testing.T) { //nolint:paralleltest // it reads stderr of the process
	c := newCanaries()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr //nolint:forbidigo // the test checks that nothing goes to stderr
	os.Stderr = w       //nolint:forbidigo // as above
	var out bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = out.ReadFrom(r); close(done) }()
	defer func() {
		os.Stderr = stderr //nolint:forbidigo // as above
		_ = w.Close()
		<-done
		c.check(t, "stderr", out.String())
	}()

	e := newInfTest(t, c, infCloud, 5*time.Second)
	if err := e.store.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	v, err := e.store.Fetch(t.Context(), infGitHub)
	if err != nil {
		t.Fatal(err)
	}
	c.check(t, "the printed value", fmt.Sprintf("%v %+v %#v %s", v, v, v, v))
	v.Clear()
	c.check(t, "the printed store", fmt.Sprintf("%v %+v %#v %s", e.store, e.store, e.store, e.store))
	e.fake.set(func(f *fakeInf) { f.readCodes = []int{http.StatusUnauthorized, http.StatusUnauthorized} })
	_, err = e.store.Fetch(t.Context(), infGitHub)
	if err == nil {
		t.Fatal("no error")
	}
	checkInfCanaries(t, c, e.store, err, Value{})
	for _, tt := range infDenyCases(c) {
		e := newInfTest(t, c, infCloud, 300*time.Millisecond)
		if tt.setup != nil {
			e.fake.set(tt.setup)
		}
		if err := e.store.Start(t.Context()); err != nil {
			checkInfCanaries(t, c, e.store, err, Value{})
		}
		v, err := e.store.Fetch(t.Context(), tt.ref)
		if err == nil {
			t.Fatalf("%s: no error", tt.name)
		}
		checkInfCanaries(t, c, e.store, err, v)
	}
	// The broker's log of a store error, as secrets.go writes it.
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Warn("broker: a store failed", slog.String("error", err.Error()))
	c.check(t, "the broker's log", buf.String())
}

func TestInfisicalClose(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	e := newInfTest(t, c, infCloud, 5*time.Second)
	e.store.Close()
	if _, err := e.store.Fetch(t.Context(), infGitHub); !errors.Is(err, ErrClosed) {
		t.Errorf("Fetch after Close: %v", err)
	}
	if err := e.store.Start(t.Context()); !errors.Is(err, ErrClosed) {
		t.Errorf("Start after Close: %v", err)
	}
	if logins, reads := e.fake.counts(); logins != 0 || reads != 0 {
		t.Errorf("logins = %d, reads = %d after Close", logins, reads)
	}

	// Close after a login clears the token, and a later Fetch fails.
	e = newInfTest(t, c, infCloud, 5*time.Second)
	if err := e.store.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.store.Close()
	if e.store.token.Bytes() != nil || e.store.secret.Bytes() != nil {
		t.Error("a key is left after Close")
	}
	if _, err := e.store.Fetch(t.Context(), infGitHub); !errors.Is(err, ErrClosed) {
		t.Errorf("Fetch after Close: %v", err)
	}
}

// TestInfisicalCloseDuringRead: a read that ends after Close hands out
// nothing.
func TestInfisicalCloseDuringRead(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	e := newInfTest(t, c, infCloud, 5*time.Second)
	e.fake.set(func(f *fakeInf) {
		f.readHook = func(http.ResponseWriter, *http.Request) bool {
			e.store.Close()
			return false
		}
	})
	if _, err := e.store.Fetch(t.Context(), infGitHub); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

// TestInfisicalLoginAgain: a failed login at Start is tried again by Fetch.
func TestInfisicalLoginAgain(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	e := newInfTest(t, c, infCloud, 5*time.Second)
	e.fake.set(func(f *fakeInf) { f.loginCode = http.StatusServiceUnavailable })
	if err := e.store.Start(t.Context()); !errors.Is(err, ErrInfLogin) {
		t.Fatalf("Start: %v", err)
	}
	e.fake.set(func(f *fakeInf) { f.loginCode = 0 })
	v, err := e.store.Fetch(t.Context(), infGitHub)
	if err != nil {
		t.Fatal(err)
	}
	v.Clear()
}

// TestInfisicalParallel: reads at the same time share one login.
func TestInfisicalParallel(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	e := newInfTest(t, c, infCloud, 5*time.Second)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			v, err := e.store.Fetch(t.Context(), infGitHub)
			if err != nil {
				t.Error(err)
				return
			}
			v.Clear()
		})
	}
	wg.Wait()
	if logins, _ := e.fake.counts(); logins != 1 {
		t.Errorf("logins = %d, want 1", logins)
	}
}

func TestInfisicalConfig(t *testing.T) {
	t.Parallel()
	c := newCanaries()
	dir := t.TempDir()
	d := testDeps()
	file := filepath.Join(dir, "infisical-secret")
	cfg := config.Store{Name: "inf", Type: config.StoreInfisical, Server: infCloud, ClientID: infClientID, ClientSecretFile: file}
	for _, tt := range []struct{ name, content, want string }{
		{"missing", "", "client_secret_file"},
		{"empty", "\n", "holds no client secret"},
		{"two lines", c.token + "\n" + c.other + "\n", "holds no client secret"},
	} {
		if tt.name != "missing" {
			writeFile(t, file, tt.content)
		}
		_, err := newStore(cfg, dir, d)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
		if err != nil {
			c.check(t, "the error", err.Error())
		}
		_ = os.Remove(file)
	}
	writeFile(t, file, c.token+"\n")
	for name, edit := range map[string]func(s *config.Store){
		"http server":        func(s *config.Store) { s.Server = "http://app.infisical.com" },
		"server with a /":    func(s *config.Store) { s.Server = infCloud + "/" },
		"server with a user": func(s *config.Store) { s.Server = "https://u:p@app.infisical.com" },
		"client ID":          func(s *config.Store) { s.ClientID = "nodkey" },
		"relative file":      func(s *config.Store) { s.ClientSecretFile = "infisical-secret" },
	} {
		bad := cfg
		edit(&bad)
		if _, err := newStore(bad, dir, d); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
