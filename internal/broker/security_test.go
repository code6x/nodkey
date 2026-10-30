package broker

import (
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/version"
)

// waitSecurityTry waits until no try of the notice about a security
// release for client runs.
func (s *Service) waitSecurityTry(t testing.TB, client string) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		s.mu.Lock()
		busy := s.securityNotes[client].sending
		s.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a try of the notice about a security release for %s still runs", client)
		}
		time.Sleep(time.Millisecond)
	}
}

// securityOf returns the values of the header api.SecurityUpdateHeader of
// res.
func securityOf(res answer) []string { return res.header.Values(api.SecurityUpdateHeader) }

// TestSecurityHeader: the broker puts the newest security release in the
// answers to a client that claims an older release, whatever the status.
// A client that claims the same release or a newer one, or no release,
// gets no header, and neither does any client when the check found no
// security release.
func TestSecurityHeader(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.3.0"})
	laptop := e.httpClient("laptop")
	if got := securityOf(e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.2.0")); got != nil {
		t.Errorf("no security release known: header %q, want none", got)
	}
	e.svc.SetSecurity(version.Release{Major: 0, Minor: 3, Patch: 1}, true)
	for _, path := range []string{api.PathKeys, "/v1/nope"} {
		for _, c := range []string{"0.3.0", "0.2.0", "0.1.0"} {
			if got := securityOf(e.claim(laptop, path, api.KeysRequest{}, c)); !slices.Equal(got, []string{"0.3.1"}) {
				t.Errorf("%s, client %s: header %q, want 0.3.1", path, c, got)
			}
		}
	}
	for _, c := range [][]string{{"0.3.1"}, {"0.4.0"}, {"0.10.0"}, nil, {"dev"}, {"1a2b3c4"}, {"v0.3.0"},
		{"0.3.0-rc.1"}, {"0.3"}, {"0.3.0", "0.3.0"}} {
		if got := securityOf(e.claim(laptop, api.PathKeys, api.KeysRequest{}, c...)); got != nil {
			t.Errorf("client %q: header %q, want none", c, got)
		}
	}
	e.svc.SetSecurity(version.Release{}, false)
	if got := securityOf(e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.2.0")); got != nil {
		t.Errorf("after the check found none: header %q, want none", got)
	}
	if len(e.audit.all()) != 0 || len(e.approver.Asked()) != 0 {
		t.Error("the flag made an audit entry or a message")
	}
}

// TestSecurityNotice: an older client gets one notice that names it in
// each round, however many requests it makes. A call of SetSecurity
// within 23 hours, as after a failed notice of the broker, or after a
// call that found none, starts no round; the next daily check starts one.
// A client on the security release gets none.
func TestSecurityNotice(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.3.0"})
	e.svc.setNow(e.clock.Now)
	laptop, ci := e.httpClient("laptop"), e.httpClient("ci")
	fix := version.Release{Major: 0, Minor: 3, Patch: 1}
	request := func() {
		t.Helper()
		mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.3.0"), http.StatusOK)
		e.svc.waitSecurityTry(t, "laptop")
		mustAnswer(t, e.claim(ci, api.PathKeys, api.KeysRequest{}, "0.3.1"), http.StatusOK)
		e.svc.waitSecurityTry(t, "ci")
	}
	request() // nothing known yet
	e.svc.SetSecurity(fix, true)
	request()
	request()
	e.clock.Advance(time.Hour)
	e.svc.SetSecurity(fix, true) // a check 1 hour later
	request()
	e.svc.SetSecurity(version.Release{}, false)
	e.svc.SetSecurity(fix, true)
	request()
	e.clock.Advance(securityRound - time.Hour)
	e.svc.SetSecurity(fix, true) // the next daily check
	request()
	request()
	// ci, on a newer release than the broker, gets only the notice about
	// its version.
	got := slices.DeleteFunc(e.waitNotices(), func(n string) bool { return !strings.HasPrefix(n, "SECURITY UPDATE") })
	text := "SECURITY UPDATE: the client laptop says that it runs nodkey 0.3.0, which is older than nodkey " +
		"0.3.1, a security release. This flag comes from GitHub's answer and is not checked: read the " +
		"checked notes with nodkey update --notes. To update laptop, run there as root: nodkey update. This " +
		"notice comes again after the next daily check while laptop runs an older nodkey."
	if !slices.Equal(got, []string{text, text}) {
		t.Errorf("notices:\n%s\nwant 2 of:\n%s", strings.Join(got, "\n"), text)
	}
	logs := e.logs.String()
	if n := strings.Count(logs, `client=laptop client_version=0.3.0 newest_security=0.3.1`); n != 2 {
		t.Errorf("%d log lines about laptop, want 2:\n%s", n, logs)
	}
	if strings.Contains(logs, "security release; update nodkey there\" client=ci") || strings.Contains(text, "sudo") {
		t.Errorf("the log:\n%s", logs)
	}
}

// TestSecurityNoticeRetry: a try that fails is tried again only with a
// request of that client at least versionRetry later. Once it went out,
// no more tries come until the next call of SetSecurity.
func TestSecurityNoticeRetry(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.3.0"})
	e.svc.setNow(e.clock.Now)
	var failing atomic.Bool
	failing.Store(true)
	e.notices.set(func(n *noticeLog) { n.fail = failWith(&failing) })
	e.svc.SetSecurity(version.Release{Major: 0, Minor: 3, Patch: 1}, true)
	laptop := e.httpClient("laptop")
	request := func() {
		t.Helper()
		mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.3.0"), http.StatusOK)
		e.svc.waitSecurityTry(t, "laptop")
	}
	tries := func(want int) {
		t.Helper()
		if got, _ := e.notices.tried(); len(got) != want {
			t.Fatalf("%d tries, want %d", len(got), want)
		}
	}
	request() // fails
	tries(1)
	e.clock.Advance(versionRetry - time.Second)
	request()
	tries(1)
	e.clock.Advance(time.Second)
	failing.Store(false)
	request() // goes out
	tries(2)
	e.clock.Advance(10 * versionRetry)
	request()
	tries(2)
	if got := e.waitNotices(); len(got) != 1 || !strings.Contains(got[0], "the client laptop ") {
		t.Errorf("notices %q, want one for laptop", got)
	}
	if n := strings.Count(e.logs.String(), "the notice about a security release for a client did not go out; "+
		"a request of the client a minute later or more tries again\" client=laptop"); n != 1 {
		t.Errorf("%d log lines about a failed try, want 1:\n%s", n, e.logs.String())
	}
}

// TestSecurityNoticeNeedsRun: before Run there is no notice, but the
// header still comes.
func TestSecurityNoticeNeedsRun(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.3.0", noRun: true})
	e.svc.SetSecurity(version.Release{Major: 0, Minor: 3, Patch: 1}, true)
	res := e.claim(e.httpClient("laptop"), api.PathKeys, api.KeysRequest{}, "0.3.0")
	if got := securityOf(res); !slices.Equal(got, []string{"0.3.1"}) {
		t.Errorf("before Run: header %q, want 0.3.1", got)
	}
	if got := e.waitNotices(); len(got) != 0 {
		t.Errorf("before Run: notices %q, want none", got)
	}
}

// TestSecurityNoticeNewRelease: a newer security release starts a new
// round at once.
func TestSecurityNoticeNewRelease(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.3.0"})
	e.svc.setNow(e.clock.Now)
	laptop := e.httpClient("laptop")
	for _, fix := range []version.Release{{Major: 0, Minor: 3, Patch: 1}, {Major: 0, Minor: 3, Patch: 2}} {
		e.svc.SetSecurity(fix, true)
		res := e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.3.0")
		if got := securityOf(res); !slices.Equal(got, []string{fix.String()}) {
			t.Errorf("header %q, want %s", got, fix)
		}
		e.svc.waitSecurityTry(t, "laptop")
	}
	got := e.waitNotices()
	if len(got) != 2 || !strings.Contains(got[0], "nodkey 0.3.1, a security") ||
		!strings.Contains(got[1], "nodkey 0.3.2, a security") {
		t.Errorf("notices %q, want one for 0.3.1 and one for 0.3.2", got)
	}
}

// TestSecurityNoticeHangs: a try that hangs does not hold the requests,
// and Close ends it. Its log line says that no new try comes.
func TestSecurityNoticeHangs(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.3.0"})
	e.notices.set(func(n *noticeLog) { n.gate = make(chan struct{}) }) // never opens
	e.svc.SetSecurity(version.Release{Major: 0, Minor: 3, Patch: 1}, true)
	laptop := e.httpClient("laptop")
	start := time.Now()
	for range 3 {
		mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.3.0"), http.StatusOK)
	}
	if d := time.Since(start); d > waitLimit/2 {
		t.Errorf("the requests took %s while the notice hung", d)
	}
	closed := make(chan struct{})
	go func() {
		e.svc.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(waitLimit):
		t.Fatal("Close waits for a notice that hangs")
	}
	waitLog(t, e.logs, "the notice about a security release for a client did not go out; the broker is "+
		"stopping, so no new try comes")
	if got, _ := e.notices.tried(); len(got) != 1 {
		t.Errorf("%d tries of the notice, want 1", len(got))
	}
}
