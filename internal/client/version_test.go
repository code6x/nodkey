package client

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
)

// The warnings of the tests below.
const (
	warnClientOlder = `nodkey: warning: this machine runs nodkey 0.1.0, which is older than nodkey 0.2.0 on the ` +
		`broker; to update this machine, run "nodkey update" as root`
	warnBrokerOlder = `nodkey: warning: the broker runs nodkey 0.1.0, which is older than nodkey 0.2.0 on this ` +
		`machine; to update the broker, run "nodkey update" as root on the broker host`
	warnNotSent = `nodkey: warning: the broker runs an older nodkey that does not send its version, and this ` +
		`machine runs nodkey 0.2.0; to update the broker, follow section 13 of docs/setup.md`
)

// withVersion wraps handler so that each answer has these values in the
// header api.VersionHeader, and records the versions of the requests.
type withVersion struct {
	mu      sync.Mutex
	answer  []string   // the values for the answers; nil for none
	claimed [][]string // the values of each request
}

func (v *withVersion) set(values ...string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.answer = values
}

func (v *withVersion) requests() [][]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.claimed)
}

func (v *withVersion) wrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.claimed = append(v.claimed, r.Header.Values(api.VersionHeader))
		for _, value := range v.answer {
			w.Header().Add(api.VersionHeader, value)
		}
		v.mu.Unlock()
		handler(w, r)
	}
}

// TestRunVersion: nodkey run sends its version, and prints one warning
// line when the broker runs another release, or sends no valid version.
// The line comes before the command runs, or before the last line. It
// says which side is older and what to run. It never shows a value from
// the broker that is not a release version, it does not go into the
// environment of the command, and builds from the source get none.
func TestRunVersion(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	ok := secretsAnswer(t, "GH_TOKEN", value)
	tests := []struct {
		name   string
		own    string   // the client's version
		broker []string // the values of the broker's header
		status int      // the status of the answer
		want   string   // the warning line, or ""
	}{
		{"the same version", "0.2.0", []string{"0.2.0"}, 200, ""},
		{"an older client", "0.1.0", []string{"0.2.0"}, 200, warnClientOlder},
		{"an older broker", "0.2.0", []string{"0.1.0"}, 200, warnBrokerOlder},
		{"a broker without the header", "0.2.0", nil, 200, warnNotSent},
		{"an older broker that denies", "0.2.0", []string{"0.1.0"}, 403, warnBrokerOlder},
		{"a broker without the header that fails", "0.2.0", nil, 400, warnNotSent},
		{"markup", "0.2.0", []string{"0.3.0<b>BAD</b>"}, 200, warnNotSent},
		{"a space", "0.2.0", []string{"0.3.0 BAD"}, 200, warnNotSent},
		{"too long", "0.2.0", []string{strings.Repeat("9", 65)}, 200, warnNotSent},
		{"two headers", "0.2.0", []string{"0.1.0", "0.3.0"}, 200, warnNotSent},
		{"an empty header", "0.2.0", []string{""}, 200, warnNotSent},
		{"a client from the source", "dev", []string{"0.2.0"}, 200, ""},
		{"a client from the source, a broker without the header", "dev", nil, 200, ""},
		{"a client without a version", "", nil, 200, ""},
		{"a client with a version that is not valid", "0.1.0 beta", []string{"0.2.0"}, 200, ""},
		{"a broker from the source", "0.2.0", []string{"dev"}, 200, ""},
		{"a broker at a commit", "0.2.0", []string{"1a2b3c4"}, 200, ""},
		{"a broker with a release candidate", "0.2.0", []string{"0.3.0-rc.1"}, 200, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &withVersion{answer: tt.broker}
			body := ok
			if tt.status != http.StatusOK {
				body = `{"error":"` + http.StatusText(tt.status) + `"}`
			}
			fb := newFakeBroker(t, v.wrap(answer(tt.status, body)))
			fx := &fakeExec{}
			r := testRunner(fb.b, []string{"HOME=/home/dev"}, fx)
			r.version = tt.own
			code, stderr := runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--", self(t))
			lines := linesOf(stderr)
			if tt.status == http.StatusOK {
				if code != exitOK || len(fx.ran()) != 1 {
					t.Fatalf("exit code %d, stderr %q; want the command to run", code, safe(stderr))
				}
				if tt.want == "" && len(lines) != 0 || tt.want != "" && !slices.Equal(lines, []string{tt.want}) {
					t.Errorf("stderr %q, want only %q", safe(stderr), tt.want)
				}
				if env := fx.ran()[0].envv; !slices.Equal(env, []string{"HOME=/home/dev", "GH_TOKEN=" + value}) {
					t.Errorf("the environment of the command: %q", safe(strings.Join(env, " ")))
				}
			} else {
				last := map[int]string{
					http.StatusForbidden:  "nodkey: denied (exit 77)",
					http.StatusBadRequest: "nodkey: the broker answered 400 Bad Request (exit 69)",
				}[tt.status]
				if !slices.Equal(lines, []string{tt.want, last}) || len(fx.ran()) != 0 {
					t.Errorf("stderr %q, want the warning %q, then %q", safe(stderr), tt.want, last)
				}
			}
			if strings.Contains(stderr, "BAD") || strings.Contains(stderr, "<b>") ||
				strings.Contains(stderr, strings.Repeat("9", 65)) {
				t.Errorf("stderr shows a value of the header that is not a version: %q", safe(stderr))
			}
			mustNotLeak(t, value, stderr)
		})
	}
}

// TestPostSendsVersion: each request has the client's version in the
// header api.VersionHeader, once, when it is a valid version, also from a
// build from the source. A client without a valid version sends none, and
// its requests still work.
func TestPostSendsVersion(t *testing.T) {
	t.Parallel()
	for own, want := range map[string][]string{
		"0.2.0":      {"0.2.0"},
		"dev":        {"dev"},
		"1a2b3c4":    {"1a2b3c4"},
		"":           nil,
		"0.2.0 beta": nil,
		"0.2.0\nX":   nil,
		"0.2.0<b>":   nil,
	} {
		v := &withVersion{answer: []string{"0.2.0"}}
		fb := newFakeBroker(t, v.wrap(answer(http.StatusOK, `{"keys":[]}`)))
		fb.b.warnVersions(own, func(string) {})
		for range 2 {
			if _, err := Post[api.KeysAnswer](t.Context(), fb.b, api.PathKeys, []byte("{}"), nil); err != nil {
				t.Fatalf("version %q: %v", own, err)
			}
		}
		if got := v.requests(); len(got) != 2 || !slices.Equal(got[0], want) || !slices.Equal(got[1], want) {
			t.Errorf("version %q: the requests had %q, want %q each", own, got, want)
		}
	}
	// A Broker that was not told its version sends none.
	v := &withVersion{}
	fb := newFakeBroker(t, v.wrap(answer(http.StatusOK, `{"keys":[]}`)))
	if _, err := Post[api.KeysAnswer](t.Context(), fb.b, api.PathKeys, []byte("{}"), nil); err != nil {
		t.Fatal(err)
	}
	if got := v.requests(); len(got) != 1 || got[0] != nil {
		t.Errorf("the request had %q, want no version", got)
	}
}

// TestSSHGrantVersion: nodkey ssh-grant prints the warning before its
// last line, which stays the last line.
func TestSSHGrantVersion(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		broker []string
		answer http.HandlerFunc
		code   int
	}{
		{[]string{"0.1.0"}, answer(http.StatusOK, `{"minutes":15}`), exitOK},
		{[]string{"0.1.0"}, answer(http.StatusForbidden, `{"error":"Forbidden"}`), exitDenied},
	} {
		v := &withVersion{answer: tt.broker}
		fb := newFakeBroker(t, v.wrap(tt.answer))
		g := testGranter(fb.b, nil)
		g.version = "0.2.0"
		code, stderr := grantIn(t.Context(), g, grantArgs()...)
		lines := linesOf(stderr)
		if code != tt.code || len(lines) != 2 || lines[0] != warnBrokerOlder ||
			!strings.HasSuffix(lines[1], "(exit "+strconv.Itoa(tt.code)+")") {
			t.Errorf("exit code %d, stderr %q; want %d, the warning, and the last line", code, stderr, tt.code)
		}
		if got := v.requests(); len(got) != 1 || !slices.Equal(got[0], []string{"0.2.0"}) {
			t.Errorf("the request had %q", got)
		}
	}
}

// TestSSHAgentVersion: nodkey ssh-agent prints the warning once for each
// version that the broker sends, so an update of the broker gives one new
// line, and the same version again gives none. A value of the header that
// is not a version counts as none, and is never shown.
func TestSSHAgentVersion(t *testing.T) {
	t.Parallel()
	v := &withVersion{}
	fb := newFakeBroker(t, v.wrap(answer(http.StatusOK, `{"keys":[]}`)))
	xdg := shortTempDir(t)
	r := testAgentRunner(fb.b, xdg)
	r.version = "0.2.0"
	ready := make(chan string, 1)
	r.ready = func(p string) { ready <- p }
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var stderr syncBuffer
	codes := make(chan int, 1)
	go func() { codes <- r.run(ctx, nil, &stderr) }()
	var path string
	select {
	case path = <-ready:
	case <-time.After(waitLimit):
		t.Fatal("the agent does not listen")
	}
	for _, values := range [][]string{
		// An older broker: one line for both answers.
		{"0.1.0"}, {"0.1.0"},
		// A new version: one more line.
		{"0.1.1"},
		// No version: one line for all of them.
		nil, nil, {"<b>BAD</b>"}, {"0.3.0", "0.3.1"},
		// Nothing to say, and versions with a line before.
		{"0.2.0"}, {"dev"}, {"1a2b3c4"}, {"0.1.0"}, {"0.1.1"},
		// A newer broker.
		{"0.3.0"},
	} {
		v.set(values...)
		if _, err := listKeys(t, path); err != nil {
			t.Fatalf("list with %q: %v", values, err)
		}
	}
	cancel(interrupted{sig: syscall.SIGTERM})
	select {
	case <-codes:
	case <-time.After(waitLimit):
		t.Fatal("the agent did not stop")
	}
	want := []string{
		"nodkey: the SSH agent listens on " + path + "; set SSH_AUTH_SOCK to this path for ssh",
		warnBrokerOlder,
		strings.Replace(warnBrokerOlder, "0.1.0", "0.1.1", 1),
		warnNotSent,
		`nodkey: warning: this machine runs nodkey 0.2.0, which is older than nodkey 0.3.0 on the broker; ` +
			`to update this machine, run "nodkey update" as root`,
		"nodkey: stopped by SIGTERM (exit 143)",
	}
	if got := linesOf(stderr.String()); !slices.Equal(got, want) {
		t.Errorf("stderr:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if strings.Contains(stderr.String(), "BAD") {
		t.Error("the agent shows a value of the header that is not a version")
	}
	for i, got := range v.requests() {
		if !slices.Equal(got, []string{"0.2.0"}) {
			t.Errorf("request %d had the version %q, want 0.2.0", i, got)
		}
	}
}

// TestVersionWarningsAreBounded: however many versions a broker sends,
// one Broker prints at most maxVersionWarnings lines.
func TestVersionWarningsAreBounded(t *testing.T) {
	t.Parallel()
	b := &Broker{}
	var lines []string
	b.warnVersions("9.0.0", func(text string) { lines = append(lines, text) })
	for i := range 3 * maxVersionWarnings {
		b.versions.check(http.Header{api.VersionHeader: {"1.0." + strconv.Itoa(i)}})
	}
	if len(lines) != maxVersionWarnings {
		t.Errorf("%d lines, want %d", len(lines), maxVersionWarnings)
	}
}

// TestVersionWithTheRealBroker: the real broker service sends its version
// on its answers, and nodkey run warns about an older broker, before its
// last line.
func TestVersionWithTheRealBroker(t *testing.T) {
	t.Parallel()
	tb := newTestBrokerWith(t, "0.1.0")
	fx := &fakeExec{}
	r := testRunner(tb.client(t), nil, fx)
	r.version = "0.2.0"
	tb.approver.Auto(audit.AnswerDeny)
	code, stderr := runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--", self(t))
	lines := linesOf(stderr)
	if code != exitDenied || len(lines) != 3 || len(waitingCodes(stderr)) != 1 || lines[1] != warnBrokerOlder ||
		lines[2] != "nodkey: denied (exit 77)" {
		t.Errorf("exit code %d, stderr %q", code, safe(stderr))
	}
}

// warnSecurity is the line about the security release 0.3.1 for a client
// on 0.3.0.
const warnSecurity = "nodkey: SECURITY UPDATE: nodkey 0.3.1 fixes a security problem. This is nodkey 0.3.0. " +
	"Ask the owner of the broker host to update this host: run nodkey update as root."

// TestSecurityWarning: the client takes the header api.SecurityUpdateHeader
// only when it holds one release version that is newer than the client's
// release. It ignores any other value, and a client that is not a
// release. The line holds only fixed text and the two versions.
func TestSecurityWarning(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		own    string
		values []string
		want   string
	}{
		{"0.3.0", []string{"0.3.1"}, "SECURITY UPDATE: nodkey 0.3.1 fixes a security problem. This is nodkey " +
			"0.3.0. Ask the owner of the broker host to update this host: run nodkey update as root."},
		{"0.3.0", []string{"1.0.0"}, "SECURITY UPDATE: nodkey 1.0.0 fixes a security problem. This is nodkey " +
			"0.3.0. Ask the owner of the broker host to update this host: run nodkey update as root."},
		{"0.3.0", []string{"0.3.0"}, ""},
		{"0.3.0", []string{"0.2.9"}, ""},
		{"0.3.0", []string{"0.3.1-rc1"}, ""},
		{"0.3.0", []string{"v0.3.1"}, ""},
		{"0.3.0", []string{"1.2"}, ""},
		{"0.3.0", []string{"0.3.01"}, ""},
		{"0.3.0", []string{" 0.3.1"}, ""},
		{"0.3.0", []string{"0.3.1<b>BAD</b>"}, ""},
		{"0.3.0", []string{"BAD"}, ""},
		{"0.3.0", []string{""}, ""},
		{"0.3.0", []string{"0.3." + strings.Repeat("9", 4096)}, ""},
		{"0.3.0", []string{"0.3.1", "0.3.1"}, ""},
		{"0.3.0", nil, ""},
		{"dev", []string{"0.3.1"}, ""},
		{"", []string{"0.3.1"}, ""},
		{"1a2b3c4", []string{"0.3.1"}, ""},
	} {
		b := &Broker{}
		var lines []string
		b.warnVersions(tt.own, func(text string) { lines = append(lines, text) })
		h := http.Header{api.VersionHeader: {tt.own}}
		if tt.values != nil {
			h[api.SecurityUpdateHeader] = tt.values
		}
		b.versions.check(h)
		var want []string
		if tt.want != "" {
			want = []string{tt.want}
		}
		if !slices.Equal(lines, want) {
			t.Errorf("client %q, header %.40q: lines %q, want %q", tt.own, tt.values, lines, want)
		}
	}
}

// TestSecurityWarningOnce: the line comes at most once, also for many
// answers and for another security release later.
func TestSecurityWarningOnce(t *testing.T) {
	t.Parallel()
	b := &Broker{}
	var lines []string
	b.warnVersions("0.3.0", func(text string) { lines = append(lines, text) })
	for _, v := range []string{"0.3.1", "0.3.1", "0.3.2", "0.4.0"} {
		b.versions.check(http.Header{api.VersionHeader: {"0.3.0"}, api.SecurityUpdateHeader: {v}})
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "nodkey 0.3.1 fixes") {
		t.Errorf("lines %q, want one about 0.3.1", lines)
	}
}

// TestRunSecurityWarning: nodkey run prints the line on stderr, once, and
// the command still runs; a denied request prints it too, before the last
// line.
func TestRunSecurityWarning(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		body := secretsAnswer(t, "GH_TOKEN", madeUp("value"))
		if status != http.StatusOK {
			body = `{"error":"` + http.StatusText(status) + `"}`
		}
		inner := answer(status, body)
		fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(api.VersionHeader, "0.3.0")
			w.Header().Set(api.SecurityUpdateHeader, "0.3.1")
			inner(w, r)
		})
		fx := &fakeExec{}
		r := testRunner(fb.b, []string{"HOME=/home/dev"}, fx)
		r.version = "0.3.0"
		code, stderr := runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--", self(t))
		lines := linesOf(stderr)
		want := []string{warnSecurity}
		if status != http.StatusOK {
			want = append(want, "nodkey: denied (exit 77)")
		} else if code != exitOK || len(fx.ran()) != 1 {
			t.Fatalf("exit code %d, stderr %q; want the command to run", code, safe(stderr))
		}
		if !slices.Equal(lines, want) {
			t.Errorf("status %d: stderr %q, want %q", status, safe(stderr), want)
		}
	}
}
