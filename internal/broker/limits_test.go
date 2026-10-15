package broker

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
)

// TestBodyPlaces: the broker reads and decodes at most maxBodiesPerClient
// bodies of one client at the same time, and at most maxBodies in all. A
// request waits for a place; after bodyWait it is denied for a limit
// (429), and the audit log records it.
func TestBodyPlaces(t *testing.T) {
	old := bodyWait
	bodyWait = 300 * time.Millisecond
	t.Cleanup(func() { bodyWait = old })
	e := newEnv(t, envOptions{})
	laptop, ci := e.httpClient("laptop"), e.httpClient("ci")

	// The client's places are taken: its request waits, and goes on when
	// a place is free. Another client is not held up.
	mine := e.svc.clientBodies["laptop"]
	for range maxBodiesPerClient {
		mine <- struct{}{}
	}
	p := e.start(laptop, api.PathKeys, api.KeysRequest{})
	select {
	case r := <-p.done:
		t.Fatalf("the request was read without a place: %d", r.status)
	case <-time.After(bodyWait / 3):
	}
	mustStatus(t, e.post(t.Context(), ci, api.PathKeys, api.KeysRequest{}), http.StatusOK)
	<-mine
	mustStatus(t, p.wait(t), http.StatusOK)

	// Too long a wait: 429, recorded as a limit.
	mine <- struct{}{} // all places of the client are taken again
	res := e.post(t.Context(), laptop, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	mustStatus(t, res, http.StatusTooManyRequests)
	mustEvents(t, e.audit.all(), "request denied:limit")
	for range maxBodiesPerClient {
		<-mine
	}

	// All places are taken: every client waits.
	for range maxBodies {
		e.svc.bodies <- struct{}{}
	}
	mustStatus(t, e.post(t.Context(), ci, api.PathKeys, api.KeysRequest{}), http.StatusTooManyRequests)
	for range maxBodies {
		<-e.svc.bodies
	}
	mustStatus(t, e.post(t.Context(), ci, api.PathKeys, api.KeysRequest{}), http.StatusOK)
	if len(e.approver.Asked()) != 0 || e.main.fetched() != 0 {
		t.Error("a request that waited for a place was shown or fetched")
	}
}

// TestRefusedEntriesAreLimited: requests that the broker refuses for a
// limit, which do not count toward the cap, write their entries for at
// most refusedEntriesPerMinute requests of a client a minute. The log
// counts the others. Another client has its own count.
func TestRefusedEntriesAreLimited(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.svc.setMaxPerClient(0) // every request is over the cap
	for range refusedEntriesPerMinute + 5 {
		mustStatus(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("A", "github-token")),
			http.StatusTooManyRequests)
	}
	mustStatus(t, e.post(t.Context(), e.httpClient("ci"), api.PathSecrets, secretsRequest("A", "backup-token")),
		http.StatusTooManyRequests)
	if got := strings.Count(eventNames(e.audit.all()), "denied:limit"); got != refusedEntriesPerMinute+1 {
		t.Errorf("%d denied entries, want %d", got, refusedEntriesPerMinute+1)
	}
	e.svc.Close() // the count goes to the log at the end of the minute, or now
	logs := waitLog(t, e.logs, "did not write the audit entries of refused requests")
	if !strings.Contains(logs, "client=laptop requests=5") {
		t.Errorf("the log does not count the requests without entries:\n%s", logs)
	}
}

// TestRefusedLoginLinesAreLimited: an agent can send many sign requests
// that a check refuses; the log gets at most refusedLinesPerMinute lines
// about them a minute, and the count of the others.
func TestRefusedLoginLinesAreLimited(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	for range refusedLinesPerMinute + 5 {
		req := e.signRequest(t, "deploy", "web-1", "deploy")
		req.Binds = nil
		mustStatus(t, e.post(t.Context(), c, api.PathSign, req), http.StatusForbidden)
	}
	if n := strings.Count(e.logs.String(), "refused an SSH login request"); n != refusedLinesPerMinute {
		t.Errorf("%d lines about refused logins, want %d", n, refusedLinesPerMinute)
	}
	e.svc.Close()
	logs := waitLog(t, e.logs, "did not log refused requests")
	if !strings.Contains(logs, "dropped=5") {
		t.Errorf("the log does not count the lines it dropped:\n%s", logs)
	}
}

// TestRateLimit: the limiter lets n events through in a window, counts the
// others, and reports the count once: at the next window, or at stop.
func TestRateLimit(t *testing.T) {
	var reports []int
	l := newRateLimit(2, func(n int) { reports = append(reports, n) })
	got := []bool{l.allow(), l.allow(), l.allow(), l.allow()}
	if !got[0] || !got[1] || got[2] || got[3] {
		t.Errorf("allow = %v, want two true", got)
	}
	l.mu.Lock()
	l.start = l.start.Add(-rateWindow) // the window ends
	window := l.window
	l.mu.Unlock()
	if !l.allow() {
		t.Error("a new window does not allow")
	}
	l.flush(window) // a late timer of the old window
	l.stop()
	if len(reports) != 1 || reports[0] != 2 {
		t.Errorf("reports %v, want one of 2", reports)
	}
}
