package release

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/version"
)

// own is the version of the nodkey of the tests.
var own = rel(0, 2, 0)

// canary is text in the answers of the fake GitHub that no error may
// hold.
const canary = "CANARY-made-up-text"

// releaseJSON returns an answer of GitHub with the tag, and a few of the
// other fields that GitHub sends, with the canary in them.
func releaseJSON(tag string) string {
	return fmt.Sprintf(`{"url":"https://example.com/%[2]s","html_url":"https://example.com/%[2]s",`+
		`"tag_name":%[1]q,"name":"%[2]s","draft":false,"prerelease":false,"body":"<b>%[2]s</b>",`+
		`"assets":[{"name":"%[2]s","size":1}]}`, tag, canary)
}

// fakeGitHub is a fake of GitHub's API: a TLS server on the loopback
// address. It keeps each request, and answers with its handler.
type fakeGitHub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
}

// newFakeGitHub starts a fake GitHub whose handler is h, and returns it
// with a Client that asks it and trusts its certificate. The Client is
// the real one, with its own HTTP client: only the address and the CA
// certificates differ.
func newFakeGitHub(t *testing.T, h http.HandlerFunc) (*fakeGitHub, *Client) {
	t.Helper()
	f := &fakeGitHub{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Clone(context.Background()))
		f.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f, f.client()
}

// client returns a Client that asks the fake.
func (f *fakeGitHub) client() *Client {
	c := New(own)
	c.base = f.srv.URL
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	c.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return c
}

// requests returns the requests that the fake got.
func (f *fakeGitHub) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.reqs...)
}

// answer returns a handler that answers with status and body.
func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// checkErr fails unless err holds want, and holds neither the canary nor
// the address of the fake.
func checkErr(t *testing.T, what string, err error, want string) {
	t.Helper()
	switch {
	case err == nil:
		t.Errorf("%s: no error, want %q", what, want)
	case !strings.Contains(err.Error(), want):
		t.Errorf("%s: error %q, want %q", what, err, want)
	case strings.Contains(err.Error(), canary), strings.Contains(err.Error(), "127.0.0.1"):
		t.Errorf("%s: the error holds text of the answer or an address: %q", what, err)
	}
}

// TestLatest: the lookup takes the version from the tag. It does not
// compare: a newer, the same and an older release than its own come back
// as they are. The other fields of the answer do not matter.
func TestLatest(t *testing.T) {
	for tag, want := range map[string]version.Release{
		"v0.3.0":                rel(0, 3, 0),
		"v0.2.0":                rel(0, 2, 0),
		"v0.1.0":                rel(0, 1, 0),
		"v1.10.0":               rel(1, 10, 0),
		"v0.0.0":                rel(0, 0, 0),
		"v999999.999999.999999": rel(999999, 999999, 999999),
	} {
		_, c := newFakeGitHub(t, answer(http.StatusOK, releaseJSON(tag)))
		got, err := c.Latest(t.Context())
		if err != nil || got != want {
			t.Errorf("%s: %v, %v; want %v", tag, got, err, want)
		}
	}
	// Only the exact keys count. Go's decoder would take any case for a
	// field of a struct.
	_, c := newFakeGitHub(t, answer(http.StatusOK,
		`{"TAG_NAME":"v9.9.9","Draft":true,"tag_name":"v0.3.0","draft":false,"prerelease":false,"Prerelease":true}`))
	if got, err := c.Latest(t.Context()); err != nil || got != (rel(0, 3, 0)) {
		t.Errorf("keys in other cases: %v, %v; want 0.3.0", got, err)
	}
}

// TestLatestRequest: one GET to the path of the newest release, with the
// headers that GitHub asks for, the version of nodkey in the User-Agent,
// and no login, no cookie and no body.
func TestLatestRequest(t *testing.T) {
	f, c := newFakeGitHub(t, answer(http.StatusOK, releaseJSON("v0.3.0")))
	if _, err := c.Latest(t.Context()); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != http.MethodGet || r.URL.Path != "/repos/code6x/nodkey/releases/latest" || r.URL.RawQuery != "" ||
		r.Proto != "HTTP/1.1" || r.ContentLength != 0 {
		t.Errorf("the request: %s %s?%s %s, %d bytes", r.Method, r.URL.Path, r.URL.RawQuery, r.Proto, r.ContentLength)
	}
	for name, want := range map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-Github-Api-Version": "2022-11-28",
		"User-Agent":           "nodkey/0.2.0",
		"Authorization":        "",
		"Cookie":               "",
	} {
		if got := r.Header.Values(name); strings.Join(got, ",") != want || len(got) > 1 {
			t.Errorf("header %s: %q, want %q", name, got, want)
		}
	}
	if !r.Close {
		t.Error("the request keeps its connection open")
	}
}

// TestLatestRefusesAnswers: every answer that is not a release in the
// expected form is an error, with a fixed text: never the text of the
// answer. 403 and 429 are ErrRateLimit; any other status but 200 is an
// error with only the status.
func TestLatestRefusesAnswers(t *testing.T) {
	const (
		badTag   = "the tag of the newest release on GitHub is not vX.Y.Z"
		notValid = "the answer of GitHub is not a valid release"
	)
	tests := []struct {
		name      string
		status    int
		body      string
		want      string
		rateLimit bool
	}{
		{"403", http.StatusForbidden, `{"message":"API rate limit exceeded ` + canary + `"}`,
			"GitHub limits the calls from this address for now (HTTP 403); try again later", true},
		{"429", http.StatusTooManyRequests, canary, "GitHub limits the calls from this address for now (HTTP 429)", true},
		{"500", http.StatusInternalServerError, canary, "GitHub answered with HTTP 500", false},
		{"502", http.StatusBadGateway, releaseJSON("v0.3.0"), "GitHub answered with HTTP 502", false},
		{"404", http.StatusNotFound, `{"message":"Not Found"}`, "GitHub answered with HTTP 404", false},
		{"401", http.StatusUnauthorized, releaseJSON("v0.3.0"), "GitHub answered with HTTP 401", false},
		{"201", http.StatusCreated, releaseJSON("v0.3.0"), "GitHub answered with HTTP 201", false},
		{"204", http.StatusNoContent, "", "GitHub answered with HTTP 204", false},
		{"draft", 200, `{"tag_name":"v0.3.0","draft":true,"prerelease":false}`, "the newest release on GitHub is a draft", false},
		{"prerelease", 200, `{"tag_name":"v0.3.0","draft":false,"prerelease":true}`,
			"the newest release on GitHub is a prerelease", false},
		{"no draft", 200, `{"tag_name":"v0.3.0","prerelease":false}`, notValid, false},
		{"draft null", 200, `{"tag_name":"v0.3.0","draft":null,"prerelease":false}`, notValid, false},
		{"draft as text", 200, `{"tag_name":"v0.3.0","draft":"false","prerelease":false}`, notValid, false},
		{"no prerelease", 200, `{"tag_name":"v0.3.0","draft":false}`, notValid, false},
		{"prerelease null", 200, `{"tag_name":"v0.3.0","draft":false,"prerelease":null}`, notValid, false},
		{"no tag", 200, `{"name":"v0.3.0","draft":false,"prerelease":false}`, notValid, false},
		{"tag null", 200, `{"tag_name":null,"draft":false,"prerelease":false}`, notValid, false},
		{"tag as a number", 200, `{"tag_name":3,"draft":false,"prerelease":false}`, notValid, false},
		{"tag as a list", 200, `{"tag_name":["v0.3.0"],"draft":false,"prerelease":false}`, notValid, false},
		{"tag in upper case only", 200, `{"TAG_NAME":"v0.3.0","draft":false,"prerelease":false}`, notValid, false},
		{"empty", 200, "", notValid, false},
		{"not JSON", 200, "<html>" + canary + "</html>", notValid, false},
		{"cut", 200, `{"tag_name":"v0.3.0","draft":false`, notValid, false},
		{"more after the object", 200, releaseJSON("v0.3.0") + "x", notValid, false},
		{"two objects", 200, releaseJSON("v0.3.0") + releaseJSON("v0.4.0"), notValid, false},
		{"null", 200, "null", notValid, false},
		{"a list", 200, "[" + releaseJSON("v0.3.0") + "]", notValid, false},
		{"a string", 200, `"v0.3.0"`, notValid, false},
	}
	for _, tag := range []string{
		"0.3.0", "v", "", "v01.2.3", "v1.02.3", "v1.2.03", "v00.1.2", "vjunk", "v1.2", "v1.2.3.4", "v1..3",
		"v1.2.3-rc.1", "v1.2.3+build", "V1.2.3", " v1.2.3", "v1.2.3 ", "v1.2.3\n", "vv1.2.3", "v-1.2.3",
		"v1000000.0.0", "v1.2.x", "v١.٢.٣", "v<b>" + canary + "</b>", "refs/tags/v1.2.3", "nodkey-v1.2.3",
		"v999999.999999.9999990", "v1.2.3" + strings.Repeat(" ", 100),
	} {
		tests = append(tests, struct {
			name      string
			status    int
			body      string
			want      string
			rateLimit bool
		}{"tag " + tag, 200, releaseJSON(tag), badTag, false})
	}
	for _, tt := range tests {
		_, c := newFakeGitHub(t, answer(tt.status, tt.body))
		got, err := c.Latest(t.Context())
		checkErr(t, tt.name, err, tt.want)
		if errors.Is(err, ErrRateLimit) != tt.rateLimit {
			t.Errorf("%s: ErrRateLimit is %v, want %v", tt.name, errors.Is(err, ErrRateLimit), tt.rateLimit)
		}
		if got != (version.Release{}) {
			t.Errorf("%s: a version with the error: %v", tt.name, got)
		}
	}
}

// TestLatestLongTag: a tag longer than the longest release tag,
// "v999999.999999.999999" (21 bytes), is refused before it is parsed. A
// tag of almost 1 MiB of dots then costs about 2 MiB (the answer is
// decoded twice), not the 17 MiB that version.ParseRelease takes for it.
func TestLatestLongTag(t *testing.T) {
	if maxTag != 21 {
		t.Errorf("maxTag = %d, want 21", maxTag)
	}
	head, tail := `{"tag_name":"v`, `","draft":false,"prerelease":false}`
	body := []byte(head + strings.Repeat(".", maxAnswer-len(head)-len(tail)) + tail)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := parseLatest(body)
	runtime.ReadMemStats(&after)
	checkErr(t, "a tag of 1 MiB of dots", err, "the tag of the newest release on GitHub is not vX.Y.Z")
	if n := after.TotalAlloc - before.TotalAlloc; n > 6<<20 {
		t.Errorf("a tag of 1 MiB of dots took %d MiB, want at most 6", n>>20)
	}
}

// TestLatestSize: an answer of 1 MiB is read; one byte more is an error,
// with a length in the header and without one.
func TestLatestSize(t *testing.T) {
	body := releaseJSON("v0.3.0")
	full := body + strings.Repeat(" ", maxAnswer-len(body)) // JSON allows space after the value
	_, c := newFakeGitHub(t, answer(http.StatusOK, full))
	if got, err := c.Latest(t.Context()); err != nil || got != (rel(0, 3, 0)) {
		t.Errorf("an answer of 1 MiB: %v, %v", got, err)
	}
	_, c = newFakeGitHub(t, answer(http.StatusOK, full+" "))
	checkErr(t, "an answer of 1 MiB and 1 byte", errOf(c.Latest(t.Context())), "the answer of GitHub is too large")
	// Without a length, the server sends the answer in chunks.
	_, c = newFakeGitHub(t, func(w http.ResponseWriter, _ *http.Request) {
		for range 2 * maxAnswer / 4096 {
			_, _ = io.WriteString(w, strings.Repeat(" ", 4096))
			w.(http.Flusher).Flush()
		}
	})
	checkErr(t, "an answer in chunks of 2 MiB", errOf(c.Latest(t.Context())), "the answer of GitHub is too large")
}

// errOf returns only the error.
func errOf(_ version.Release, err error) error { return err }

// TestLatestFollowsNoRedirect: a redirect is an error with its status.
// The client does not follow it, also not to the same server.
func TestLatestFollowsNoRedirect(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		f, c := newFakeGitHub(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != latestPath {
				answer(http.StatusOK, releaseJSON("v9.0.0"))(w, r)
				return
			}
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(status)
		})
		checkErr(t, fmt.Sprint(status), errOf(c.Latest(t.Context())), fmt.Sprintf("GitHub answered with HTTP %d", status))
		if n := len(f.requests()); n != 1 {
			t.Errorf("%d: %d requests, want 1: the client followed the redirect", status, n)
		}
	}
}

// TestLatestTimeout: a server that does not answer, or stops in the
// middle of its answer, makes the lookup fail after its time limit, also
// a limit of the caller.
func TestLatestTimeout(t *testing.T) {
	// The client closes the connection when its time is up, and the
	// server then ends the context of the request.
	hang := func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	hangInBody := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"tag_name":"v0.3.0",`)
		w.(http.Flusher).Flush()
		hang(w, r)
	}
	for _, tt := range []struct {
		name    string
		h       http.HandlerFunc
		limit   time.Duration // the limit of the Client
		caller  time.Duration // the limit of the caller's context; 0 for none
		wantErr string
	}{
		{"no answer", hang, 300 * time.Millisecond, 0, "cannot reach GitHub: the lookup timed out"},
		{"no answer, the caller's limit", hang, time.Minute, 300 * time.Millisecond,
			"cannot reach GitHub: the lookup timed out"},
		{"a cut answer", hangInBody, 300 * time.Millisecond, 0, "cannot read the answer of GitHub: the lookup timed out"},
	} {
		_, c := newFakeGitHub(t, tt.h)
		c.timeout = tt.limit
		ctx, cancel := t.Context(), context.CancelFunc(func() {})
		if tt.caller > 0 {
			ctx, cancel = context.WithTimeout(t.Context(), tt.caller)
		}
		start := time.Now()
		_, err := c.Latest(ctx)
		cancel()
		checkErr(t, tt.name, err, tt.wantErr)
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: the lookup took %s", tt.name, d)
		}
	}

	// A context that ended before the lookup.
	_, c := newFakeGitHub(t, answer(http.StatusOK, releaseJSON("v0.3.0")))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	checkErr(t, "a cancelled context", errOf(c.Latest(ctx)), "cannot reach GitHub: the lookup was cancelled")
}

// TestLatestEndsItsDial: a lookup that ends during its dial ends the dial
// too, such as when the broker stops while the proxy has not answered the
// CONNECT yet. Go's HTTP client goes on with a dial after its request
// ended. Without the end, the dial would wait for the proxy up to a
// minute, and then make a TLS handshake with GitHub, after the check
// stopped.
func TestLatestEndsItsDial(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	connect, closed := make(chan struct{}, 1), make(chan struct{}, 1)
	// The proxy takes the CONNECT and never answers it.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		connect <- struct{}{}
		// The client sends nothing more before the answer, so this read
		// ends only when the client closes the connection.
		_, _ = br.ReadByte()
		closed <- struct{}{}
	}()
	_, c := newFakeGitHub(t, answer(http.StatusOK, releaseJSON("v0.3.0")))
	c.http.Transport.(*http.Transport).Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errs := make(chan error, 1)
	go func() {
		_, err := c.Latest(ctx)
		errs <- err
	}()
	select {
	case <-connect:
	case <-time.After(10 * time.Second):
		t.Fatal("no CONNECT came to the proxy")
	}
	cancel()
	checkErr(t, "a lookup that ends during its dial", <-errs, "cannot reach GitHub: the lookup was cancelled")
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the dial goes on after the lookup ended")
	}
}

// TestLatestTLS: the lookup needs a certificate that the CA certificates
// of the client trust, and TLS 1.2 or newer. Without them, no request is
// sent.
func TestLatestTLS(t *testing.T) {
	f, c := newFakeGitHub(t, answer(http.StatusOK, releaseJSON("v0.3.0")))
	c.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = x509.NewCertPool() // trusts nothing
	checkErr(t, "an untrusted certificate", errOf(c.Latest(t.Context())),
		"cannot reach GitHub: the TLS certificate of the server is not valid")

	old := httptest.NewUnstartedServer(answer(http.StatusOK, releaseJSON("v0.3.0")))
	//nolint:gosec // G402: a test server that offers only TLS 1.0 and 1.1, which the client must refuse.
	old.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	old.StartTLS()
	t.Cleanup(old.Close)
	f2 := &fakeGitHub{srv: old}
	checkErr(t, "TLS 1.1", errOf(f2.client().Latest(t.Context())), "cannot reach GitHub: ")
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests reached the server with the untrusted certificate", n)
	}
}

// TestLatestNoServer: when nothing listens at the address, the lookup
// fails with a fixed reason.
func TestLatestNoServer(t *testing.T) {
	f, c := newFakeGitHub(t, answer(http.StatusOK, releaseJSON("v0.3.0")))
	f.srv.Close()
	checkErr(t, "no server", errOf(c.Latest(t.Context())), "cannot reach GitHub: cannot connect to the server")
}

// TestNetReason: each kind of error of the HTTP client gets a fixed
// reason, whatever its text: the text can name the proxy, or hold the
// status line that the proxy sent.
func TestNetReason(t *testing.T) {
	wrap := func(err error) error {
		return &url.Error{Op: "Get", URL: "https://api.github.com" + latestPath, Err: err}
	}
	for _, tt := range []struct {
		err  error
		want string
	}{
		{wrap(context.Canceled), "the lookup was cancelled"},
		{wrap(&net.DNSError{Err: "no such host " + canary, Name: canary}), "cannot find the address of the server"},
		{wrap(&tls.CertificateVerificationError{Err: errors.New(canary)}), "the TLS certificate of the server is not valid"},
		{wrap(context.DeadlineExceeded), "the lookup timed out"},
		{wrap(&net.OpError{Op: "proxyconnect", Net: "tcp", Err: errors.New(canary)}), "cannot connect to the proxy"},
		{wrap(&net.OpError{Op: "dial", Net: "tcp", Err: errors.New(canary)}), "cannot connect to the server"},
		{wrap(errors.New("Forbidden " + canary)), "the connection failed"},
		{errors.New(canary), "the connection failed"},
	} {
		if got := netReason(tt.err); got != tt.want {
			t.Errorf("netReason(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

// TestPageURL: the link to a release is made from its version.
func TestPageURL(t *testing.T) {
	if got := PageURL(rel(1, 10, 2)); got != "https://github.com/code6x/nodkey/releases/tag/v1.10.2" {
		t.Errorf("PageURL = %q", got)
	}
}

// TestNewClient: the real client asks GitHub's API, follows no redirect,
// keeps no connection, and takes the proxy from the environment
// (TestLatestThroughProxy shows that it uses it).
func TestNewClient(t *testing.T) {
	c := New(rel(1, 2, 3))
	tr, ok := c.http.Transport.(*http.Transport)
	switch {
	case c.base != "https://api.github.com", c.userAgent != "nodkey/1.2.3", c.timeout != 30*time.Second:
		t.Errorf("base %q, User-Agent %q, timeout %s", c.base, c.userAgent, c.timeout)
	case !ok || tr.Proxy == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.TLSClientConfig.InsecureSkipVerify ||
		tr.TLSClientConfig.RootCAs != nil || !tr.DisableKeepAlives || tr.TLSHandshakeTimeout != 10*time.Second ||
		tr.ResponseHeaderTimeout != 10*time.Second:
		t.Errorf("the transport: %+v", tr)
	case c.http.CheckRedirect == nil:
		t.Error("the client follows redirects")
	}
}
