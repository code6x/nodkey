package broker

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/grantkey"
)

// standingOn turns on [standing] with the default limits and standing = true
// for the secrets github-token and npm-token.
func standingOn(cfg *config.Broker) {
	cfg.Standing = config.DefaultStanding()
	cfg.Standing.MaxUses = 3
	for _, name := range []string{"github-token", "npm-token"} {
		s := cfg.Secrets[name]
		s.Rule.Standing = true
		cfg.Secrets[name] = s
	}
}

// standReq is a request for a standing grant for the secrets: daily from
// 03:00 to 05:00, 2 uses in each window, until 2026-11-14.
func standReq(names ...string) api.PreapproveRequest {
	return api.PreapproveRequest{
		Secrets: names, From: "2026-10-14T12:00:00Z", Until: "2026-11-14T00:00:00Z", Uses: 2,
		Reason:  "job nightly-backup",
		Windows: []api.Window{{Kind: api.WindowDaily, From: "03:00", To: "05:00"}},
	}
}

// TestStandingGrantIsMade: the message, the answer with a token, the
// entries, and the token nowhere but in the answer.
func TestStandingGrantIsMade(t *testing.T) {
	e := newEnv(t, envOptions{config: standingOn})
	c := e.httpClient("laptop")
	r := standReq("github-token", "npm-token")
	r.Windows = append(r.Windows, api.Window{Kind: api.WindowWeekly, Days: []string{"thu", "mon"}, From: "10:30", To: "11:00"})
	p := e.start(c, api.PathPreapprove, r)
	pr := e.waitAsked(1)[0].Prompt
	if pr.Kind != audit.KindStanding || strings.Join(pr.Secrets, ",") != "github-token,npm-token" || pr.Uses != 2 ||
		!pr.Once || pr.WindowMinutes != 0 || !pr.From.Equal(noon) || !pr.Until.Equal(time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)) ||
		strings.Join(pr.Windows, "|") != "daily 03:00-05:00|mon,thu 10:30-11:00" || pr.Claim.Reason != "job nightly-backup" {
		t.Errorf("the message shows %+v", pr)
	}
	p.waitCode(t)
	e.tap(pr.RequestID, audit.AnswerApproveOnce)
	res := p.wait(t)
	mustStatus(t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.PreapproveAnswer](bytes.NewReader(res.body))
	if err != nil || len(ans.ID) != 22 {
		t.Fatalf("the answer was not read: %v", err)
	}
	tok, err := grantkey.Parse(ans.GrantToken)
	if err != nil {
		t.Fatalf("the token does not parse: %v", err)
	}
	events := requestEvents(e.audit.waitFor(t, 2), pr.RequestID)
	mustEvents(t, events, "request decision:approve_once")
	d := events[1].(audit.Decision)
	if d.Kind != audit.KindStanding || d.Uses != 2 || d.NotBefore != "2026-10-14T12:00:00Z" || d.NotAfter != "2026-11-14T00:00:00Z" ||
		strings.Join(d.Windows, "|") != "daily 03:00-05:00|mon,thu 10:30-11:00" || d.GrantID != ans.ID {
		t.Errorf("the decision entry is %+v", d.Subject)
	}
	for name, text := range map[string]string{
		"the audit log": encodeEvents(t, e.audit.all()), "the approver": e.approverTexts(),
		"the logs": e.logs.String(), "the notices": strings.Join(e.notices.wentOut(), "\n"),
	} {
		if strings.Contains(text, tok.Reveal()) || strings.Contains(text, ans.GrantToken) {
			t.Errorf("the token is in %s", name)
		}
	}
	if n := e.main.fetched(); n != 0 {
		t.Errorf("a standing grant fetched %d values", n)
	}
	// The client can cancel its own standing grant, but not that of another.
	if _, ok := e.core.CancelGrant("ci", ans.ID); ok {
		t.Error("another client cancelled the grant")
	}
	if end, ok := e.core.CancelGrant("laptop", ans.ID); !ok || end.Cause != audit.EndCancelled {
		t.Errorf("the cancel of a standing grant: %+v, %v", end, ok)
	}
}

// TestStandingRefusals: each check is a deny, with no message and no grant.
func TestStandingRefusals(t *testing.T) {
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) {
		standingOn(cfg)
		s := cfg.Secrets["npm-token"]
		s.Rule.Standing = false
		cfg.Secrets["npm-token"] = s
	}})
	c := e.httpClient("laptop")
	with := func(change func(*api.PreapproveRequest)) api.PreapproveRequest {
		r := standReq("github-token")
		change(&r)
		return r
	}
	win := func(kind, from, to string, days ...string) []api.Window {
		return []api.Window{{Kind: kind, Days: days, From: from, To: to}}
	}
	tests := []struct {
		name string
		r    api.PreapproveRequest
	}{
		{"a secret without standing = true", standReq("npm-token")},
		{"one secret without standing = true", standReq("github-token", "npm-token")},
		{"a never rule", standReq("backup-token")},
		{"an unknown secret", standReq("nope")},
		{"no secret", standReq()},
		{"a key", with(func(r *api.PreapproveRequest) { r.Key, r.User, r.Hosts = "web", "deploy", []string{"web-1"} })},
		{"no uses", with(func(r *api.PreapproveRequest) { r.Uses = 0 })},
		{"too many uses", with(func(r *api.PreapproveRequest) { r.Uses = 4 })},
		{"the end after max_days", with(func(r *api.PreapproveRequest) { r.Until = "2027-01-12T12:00:01Z" })},
		{"the end in the past", with(func(r *api.PreapproveRequest) { r.Until = "2026-10-14T11:00:00Z"; r.From = "2026-10-14T10:00:00Z" })},
		{"the end before the start", with(func(r *api.PreapproveRequest) { r.From = "2026-12-01T00:00:00Z" })},
		{"no end", with(func(r *api.PreapproveRequest) { r.Until = "" })},
		{"a window longer than max_window", with(func(r *api.PreapproveRequest) { r.Windows = win(api.WindowDaily, "03:00", "11:01") })},
		{"a window that is backwards", with(func(r *api.PreapproveRequest) { r.Windows = win(api.WindowDaily, "05:00", "03:00") })},
		{"a window of one clock time", with(func(r *api.PreapproveRequest) { r.Windows = win(api.WindowDaily, "05:00", "05:00") })},
		{"a window with a bad kind", with(func(r *api.PreapproveRequest) { r.Windows = win("monthly", "03:00", "05:00") })},
		{"a weekly window with no day", with(func(r *api.PreapproveRequest) { r.Windows = win(api.WindowWeekly, "03:00", "05:00") })},
		{"a weekly window with a bad day", with(func(r *api.PreapproveRequest) { r.Windows = win(api.WindowWeekly, "03:00", "05:00", "xyz") })},
		{"a daily window with days", with(func(r *api.PreapproveRequest) { r.Windows = win(api.WindowDaily, "03:00", "05:00", "mon") })},
		{"a window that is not a time", with(func(r *api.PreapproveRequest) { r.Windows = win(api.WindowDaily, "3am", "05:00") })},
	}
	for _, tt := range tests {
		before := len(e.audit.all())
		res := e.post(t.Context(), c, api.PathPreapprove, tt.r)
		if res.err != nil || res.status != http.StatusForbidden && res.status != http.StatusBadRequest || res.code != "" {
			t.Errorf("%s: %d, %v; want a deny without a wait", tt.name, res.status, res.err)
			continue
		}
		if res.status == http.StatusBadRequest {
			continue // the protocol refused the body before any check
		}
		got := e.audit.waitFor(t, before+2)[before:]
		mustEvents(t, got, "request denied:not_allowed")
		if k := subjectOf(got[0]).Kind; k != audit.KindStanding {
			t.Errorf("%s: kind %q", tt.name, k)
		}
	}
	if len(e.approver.Asked()) != 0 {
		t.Error("a refused request was shown")
	}
}

// TestStandingOffByDefault: without [standing], no standing grant.
func TestStandingOffByDefault(t *testing.T) {
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) {
		standingOn(cfg)
		cfg.Standing = config.StandingLimits{}
	}})
	mustStatus(t, e.post(t.Context(), e.httpClient("laptop"), api.PathPreapprove, standReq("github-token")), http.StatusForbidden)
	if len(e.approver.Asked()) != 0 {
		t.Error("a message was sent")
	}
}

// TestStandingMaxGrants: a client with max_grants live grants gets a deny
// for the next one, before any message.
func TestStandingMaxGrants(t *testing.T) {
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) {
		standingOn(cfg)
		cfg.Standing.MaxGrants = 2
	}})
	c := e.httpClient("laptop")
	e.preapprove(c, standReq("github-token"), 1)
	e.preapprove(c, standReq("npm-token"), 2)
	before := len(e.audit.all())
	res := e.post(t.Context(), c, api.PathPreapprove, standReq("github-token"))
	mustStatus(t, res, http.StatusTooManyRequests)
	mustEvents(t, e.audit.waitFor(t, before+2)[before:], "request denied:limit")
	if n := len(e.approver.Asked()); n != 2 {
		t.Errorf("%d messages, want 2", n)
	}
}

// TestStandingRevokeAndStop: Revoke ends a
// standing grant; a stop drops one and lists it in the stop notice.
func TestStandingRevokeAndStop(t *testing.T) {
	e := newEnv(t, envOptions{config: standingOn})
	c := e.httpClient("laptop")
	revoked := e.preapprove(c, standReq("github-token"), 1)
	before := len(e.audit.all())
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerRevoke)
	events := e.audit.waitFor(t, before+1)[before:]
	mustEvents(t, events, "grant_ended:revoked")
	if end := events[0].(audit.GrantEnded); end.GrantID != revoked.ID || end.Kind != audit.KindStanding {
		t.Errorf("entry %+v", end)
	}

	kept := e.preapprove(c, standReq("npm-token"), 2)
	e.stopAndWait()
	sent := e.notices.wentOut()
	if len(sent) != 1 || !strings.Contains(sent[0], kept.ID+": laptop, npm-token") || strings.Contains(sent[0], revoked.ID) {
		t.Errorf("the stop notice: %q", sent)
	}
	var stopped bool
	for _, ev := range e.audit.all() {
		if g, ok := ev.(audit.GrantEnded); ok && g.GrantID == kept.ID && g.Cause == audit.EndStopped {
			stopped = true
		}
	}
	if !stopped {
		t.Error("no grant_ended:stopped for the standing grant")
	}
}

// TestStandingCancel: the client can cancel its own standing grant, the
// token stops working, and another client or an unknown ID finds nothing.
func TestStandingCancel(t *testing.T) {
	e, tok, id := useEnv(t)
	cancel := func(client, id string) *result {
		return e.post(t.Context(), e.httpClient(client), api.PathPreapproveCancel, api.PreapproveCancelRequest{ID: id})
	}
	mustStatus(t, cancel("ci", id), http.StatusForbidden)
	mustStatus(t, cancel("laptop", "AAAAAAAAAAAAAAAAAAAAAA"), http.StatusForbidden)
	before := len(e.audit.all())
	mustStatus(t, cancel("laptop", id), http.StatusOK)
	events := e.audit.waitFor(t, before+1)[before:]
	mustEvents(t, events, "grant_ended:cancelled")
	if end := events[0].(audit.GrantEnded); end.GrantID != id || end.Kind != audit.KindStanding {
		t.Errorf("entry %+v", end)
	}
	mustStatus(t, cancel("laptop", id), http.StatusForbidden)
	// The token is unknown now: denied, and no use.
	res, _ := e.useToken("laptop", tok)
	mustStatus(t, res, http.StatusForbidden)
}

// TestStandingAnswerNotWritten: the answer with the token cannot be
// written, so nobody has the token. The broker cancels the grant.
func TestStandingAnswerNotWritten(t *testing.T) {
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == api.PathPreapprove {
				w = failWriter{w}
			}
			next.ServeHTTP(w, r)
		})
	}
	e := newEnv(t, envOptions{wrap: wrap, config: standingOn})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathPreapprove, standReq("github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerApproveOnce)
	p.wait(t)
	events := e.audit.waitFor(t, 3)
	mustEvents(t, events, "request decision:approve_once grant_ended:cancelled")
	e.clock.Advance(time.Hour)
	if n := len(e.alarmEntries()); n != 0 {
		t.Errorf("%d alarms", n)
	}
}
