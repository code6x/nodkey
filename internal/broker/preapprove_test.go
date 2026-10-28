package broker

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// preapproveOn turns on preapprove for the secrets github-token and
// npm-token and for the keys deploy and web, with the default limits.
func preapproveOn(cfg *config.Broker) {
	cfg.Preapprove = config.DefaultPreapprove()
	for _, name := range []string{"github-token", "npm-token"} {
		s := cfg.Secrets[name]
		s.Rule.Preapprove = true
		cfg.Secrets[name] = s
	}
	for _, name := range []string{"deploy", "web"} {
		k := cfg.Keys[name]
		k.Rule.Preapprove = true
		cfg.Keys[name] = k
	}
}

// preReq is a request for a scheduled grant for secrets, from one hour to
// two hours after noon, the start of the fake clock.
func preReq(uses int64, names ...string) api.PreapproveRequest {
	return api.PreapproveRequest{
		Secrets: names, From: "2026-10-14T13:00:00Z", Until: "2026-10-14T14:00:00Z", Uses: uses,
		Reason: "job nightly-backup",
	}
}

// preapprove asks for the scheduled grant r as the client c and approves
// it. It returns the answer.
func (e *env) preapprove(c *http.Client, r api.PreapproveRequest, n int) *api.PreapproveAnswer {
	e.t.Helper()
	p := e.start(c, api.PathPreapprove, r)
	pr := e.waitAsked(n)[n-1].Prompt
	e.tap(pr.RequestID, audit.AnswerApproveOnce)
	res := p.wait(e.t)
	mustStatus(e.t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.PreapproveAnswer](bytes.NewReader(res.body))
	if err != nil {
		e.t.Fatalf("the answer: %v", err)
	}
	return ans
}

// TestPreapprove: the whole way. The message, the answer, the entries, the
// uses without a tap with a notice each, and the last use that ends the
// grant.
func TestPreapprove(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathPreapprove, preReq(2, "github-token", "npm-token", "npm-token"))
	pr := e.waitAsked(1)[0].Prompt
	if pr.Kind != audit.KindPreapprove || strings.Join(pr.Secrets, ",") != "github-token,npm-token" || pr.Uses != 2 ||
		!pr.Once || pr.WindowMinutes != 0 || !pr.From.Equal(noon.Add(time.Hour)) || !pr.Until.Equal(noon.Add(2*time.Hour)) ||
		pr.Claim.Reason != "job nightly-backup" {
		t.Errorf("the message shows %+v", pr)
	}
	if code := p.waitCode(t); code != pr.ShortCode {
		t.Errorf("the client got the short code %q, the message has %q", code, pr.ShortCode)
	}
	e.tap(pr.RequestID, audit.AnswerApproveOnce)
	res := p.wait(t)
	mustStatus(t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.PreapproveAnswer](bytes.NewReader(res.body))
	if err != nil || len(ans.ID) != 22 || ans.From != "2026-10-14T13:00:00Z" || ans.Until != "2026-10-14T14:00:00Z" {
		t.Fatalf("the answer: %+v, %v", ans, err)
	}
	mustEvents(t, requestEvents(e.audit.all(), pr.RequestID), "request decision:approve_once")
	if n := e.main.fetched(); n != 0 {
		t.Errorf("a pre-approval fetched %d values", n)
	}

	// Before the start: asked.
	early := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	e.waitAsked(2)
	early.cancel()
	early.wait(t)
	e.audit.waitFor(t, 4) // the pre-approval and the cancelled request
	e.clock.Advance(time.Hour)
	for i := range 2 {
		before := 4 + 3*i
		secrets := e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
		got := secretsOf(t, secrets)
		if got["GH_TOKEN"] != e.values["github-token"] {
			t.Error("the secret is not the value of the store")
		}
		n := 3 + i
		events := e.audit.waitFor(t, before+n)[before:]
		want := "request grant_used:scheduled secret_sent"
		if i == 1 {
			want = "request grant_used:scheduled grant_ended:used_up secret_sent"
		}
		// The entry of the end names the request of the pre-approval.
		mustEvents(t, events, want)
		if used := events[1].(audit.GrantUsed); used.GrantID != ans.ID {
			t.Errorf("grant_used names the grant %q, want %q", used.GrantID, ans.ID)
		}
		if n := len(e.approver.Notices()); n != i+1 {
			t.Errorf("%d notices, want %d", n, i+1)
		}
	}
	if n := len(e.approver.Asked()); n != 2 {
		t.Errorf("%d messages, want 2", n)
	}
	again := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	e.waitAsked(3)
	again.cancel()
	again.wait(t)
}

// TestPreapproveKey: a scheduled grant for a key. Each login takes one use.
func TestPreapproveKey(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	ans := e.preapprove(c, api.PreapproveRequest{
		Key: "web", User: "deploy", Hosts: []string{"web-1"}, From: "2026-10-14T12:00:00Z",
		Until: "2026-10-14T13:00:00Z", Uses: 1, Reason: "r",
	}, 1)
	res := e.post(t.Context(), c, api.PathSign, e.signRequest(t, "web", "web-1", "deploy"))
	mustStatus(t, res, http.StatusOK)
	events := e.audit.waitFor(t, 6)[2:]
	mustEvents(t, events, "request grant_used:scheduled grant_ended:used_up signed")
	if events[1].(audit.GrantUsed).GrantID != ans.ID {
		t.Error("grant_used does not name the grant")
	}
	p := e.start(c, api.PathSign, e.signRequest(t, "web", "web-1", "deploy"))
	e.waitAsked(2)
	p.cancel()
	p.wait(t)
}

// TestPreapproveRefusals: the broker refuses a request that does not fit
// the config, before any message. The audit log names what passed.
func TestPreapproveRefusals(t *testing.T) {
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) {
		preapproveOn(cfg)
		s := cfg.Secrets["npm-token"]
		s.Rule.Preapprove = false
		cfg.Secrets["npm-token"] = s
	}})
	c := e.httpClient("laptop")
	key := func() api.PreapproveRequest {
		return api.PreapproveRequest{Key: "web", User: "deploy", Hosts: []string{"web-1"},
			From: "2026-10-14T13:00:00Z", Until: "2026-10-14T14:00:00Z", Uses: 1}
	}
	tests := []struct {
		name   string
		r      api.PreapproveRequest
		status int
		sub    audit.Subject
	}{
		{"preapprove is off for the secret", preReq(1, "npm-token"), 403, audit.Subject{}},
		{"a never rule", func() api.PreapproveRequest { r := preReq(1, "backup-token"); return r }(), 403, audit.Subject{}},
		{"an unknown secret", preReq(1, "nope"), 403, audit.Subject{}},
		{"a secret that passed and one that did not", preReq(1, "github-token", "nope"), 403,
			audit.Subject{Secrets: []string{"github-token"}}},
		{"no uses", preReq(0, "github-token"), 403, audit.Subject{Secrets: []string{"github-token"}}},
		{"too many uses", preReq(11, "github-token"), 403, audit.Subject{Secrets: []string{"github-token"}}},
		{"a time that is not a time", func() api.PreapproveRequest {
			r := preReq(1, "github-token")
			r.From = "tomorrow"
			return r
		}(), 403, audit.Subject{Secrets: []string{"github-token"}}},
		{"end before start", func() api.PreapproveRequest {
			r := preReq(1, "github-token")
			r.Until = "2026-10-14T12:30:00Z"
			return r
		}(), 403, audit.Subject{Secrets: []string{"github-token"}}},
		{"open longer than 8 hours", func() api.PreapproveRequest {
			r := preReq(1, "github-token")
			r.Until = "2026-10-14T21:00:01Z"
			return r
		}(), 403, audit.Subject{Secrets: []string{"github-token"}}},
		{"further ahead than 7 days", func() api.PreapproveRequest {
			r := preReq(1, "github-token")
			r.From, r.Until = "2026-10-21T12:00:01Z", "2026-10-21T13:00:00Z"
			return r
		}(), 403, audit.Subject{Secrets: []string{"github-token"}}},
		{"part of a second", func() api.PreapproveRequest {
			r := preReq(1, "github-token")
			r.From = "2026-10-14T13:00:00.5Z"
			return r
		}(), 403, audit.Subject{Secrets: []string{"github-token"}}},
		{"secrets and a key", func() api.PreapproveRequest { r := key(); r.Secrets = []string{"github-token"}; return r }(), 403,
			audit.Subject{Secrets: []string{"github-token"}}},
		{"secrets and a user", func() api.PreapproveRequest { r := preReq(1, "github-token"); r.User = "deploy"; return r }(), 403,
			audit.Subject{Secrets: []string{"github-token"}}},
		{"no secret, no key", preReq(1), 403, audit.Subject{}},
		{"a key of another client", func() api.PreapproveRequest { r := key(); r.Key = "backup"; return r }(), 403,
			audit.Subject{RemoteUser: "deploy", Hosts: []string{"web-1"}}},
		{"a key whose preapprove is off", func() api.PreapproveRequest { r := key(); r.Key = "admin"; return r }(), 403,
			audit.Subject{Key: "admin", RemoteUser: "deploy"}},
		{"a host that the key does not list", func() api.PreapproveRequest { r := key(); r.Hosts = []string{"db-1"}; return r }(), 403,
			audit.Subject{Key: "web", RemoteUser: "deploy"}},
		{"a bad user name", func() api.PreapproveRequest { r := key(); r.User = "a b"; return r }(), 403,
			audit.Subject{Key: "web", Hosts: []string{"web-1"}}},
		{"no host", func() api.PreapproveRequest { r := key(); r.Hosts = nil; return r }(), 403,
			audit.Subject{Key: "web", RemoteUser: "deploy"}},
	}
	for _, tt := range tests {
		before := len(e.audit.all())
		res := e.post(t.Context(), c, api.PathPreapprove, tt.r)
		if res.err != nil || res.status != tt.status || res.code != "" {
			t.Errorf("%s: %d, %v; want %d without a wait", tt.name, res.status, res.err, tt.status)
			continue
		}
		got := e.audit.waitFor(t, before+2)[before:]
		mustEvents(t, got, "request denied:not_allowed")
		s := subjectOf(got[0])
		if s.Kind != audit.KindPreapprove || strings.Join(s.Secrets, ",") != strings.Join(tt.sub.Secrets, ",") ||
			s.Key != tt.sub.Key || s.RemoteUser != tt.sub.RemoteUser || strings.Join(s.Hosts, ",") != strings.Join(tt.sub.Hosts, ",") {
			t.Errorf("%s: the audit log names %+v, want %+v", tt.name, s, tt.sub)
		}
	}
	if len(e.approver.Asked()) != 0 {
		t.Error("a refused request was shown")
	}
	// More than 32 secrets is over the cap of the protocol.
	many := preReq(1, make([]string, api.MaxSecrets+1)...)
	if res := e.post(t.Context(), c, api.PathPreapprove, many); res.status != http.StatusBadRequest {
		t.Errorf("33 secrets: %d, want 400", res.status)
	}
	// A body with a field that is not known, and a get.
	if res := e.postRaw(t.Context(), c, api.PathPreapprove, []byte(`{"secrets":[]}`)); res.status != http.StatusBadRequest {
		t.Errorf("a short body: %d, want 400", res.status)
	}
}

// TestPreapproveOffByDefault: with the default config, no secret and no
// key allow a scheduled grant.
func TestPreapproveOffByDefault(t *testing.T) {
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) { cfg.Preapprove = config.DefaultPreapprove() }})
	c := e.httpClient("laptop")
	for _, r := range []api.PreapproveRequest{
		preReq(1, "github-token"),
		{Key: "web", User: "deploy", Hosts: []string{"web-1"}, From: "2026-10-14T13:00:00Z", Until: "2026-10-14T14:00:00Z", Uses: 1},
	} {
		mustStatus(t, e.post(t.Context(), c, api.PathPreapprove, r), http.StatusForbidden)
	}
	if len(e.approver.Asked()) != 0 {
		t.Error("a message was sent")
	}
}

// TestPreapproveCancel: the client cancels its own grant without a tap.
// The answer for the grant of another client is the same as for an ID that
// is not known.
func TestPreapproveCancel(t *testing.T) {
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) {
		preapproveOn(cfg)
		s := cfg.Secrets["github-token"]
		s.Clients = []string{"laptop", "ci"}
		cfg.Secrets["github-token"] = s
	}})
	c := e.httpClient("laptop")
	ci := e.httpClient("ci")
	ans := e.preapprove(c, preReq(3, "github-token"), 1)
	cancel := func(c *http.Client, id string) *result {
		return e.post(t.Context(), c, api.PathPreapproveCancel, api.PreapproveCancelRequest{ID: id})
	}
	other, unknown := cancel(ci, ans.ID), cancel(c, "AAAAAAAAAAAAAAAAAAAAAA")
	mustStatus(t, other, http.StatusForbidden)
	mustStatus(t, unknown, http.StatusForbidden)
	if !bytes.Equal(other.body, unknown.body) {
		t.Errorf("a grant of another client is answered as %q, an unknown one as %q", other.body, unknown.body)
	}
	mustStatus(t, cancel(c, "not an ID"), http.StatusForbidden)
	before := len(e.audit.all())
	res := cancel(c, ans.ID)
	mustStatus(t, res, http.StatusOK)
	got, err := api.ReadAnswer[api.PreapproveCancelAnswer](bytes.NewReader(res.body))
	if err != nil || got.ID != ans.ID {
		t.Fatalf("the answer: %+v, %v", got, err)
	}
	events := e.audit.waitFor(t, before+1)[before:]
	mustEvents(t, events, "grant_ended:cancelled")
	if s := subjectOf(events[0]); s.GrantID != ans.ID || s.Kind != audit.KindPreapprove {
		t.Errorf("the entry names %+v", s)
	}
	mustStatus(t, cancel(c, ans.ID), http.StatusForbidden)
	if n := len(e.audit.all()); n != before+1 {
		t.Errorf("a cancel that found nothing wrote an entry (%d entries)", n)
	}
	e.clock.Advance(time.Hour)
	p := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	e.waitAsked(2)
	p.cancel()
	p.wait(t)
	// The cancel needs no tap and no message.
	if len(e.approver.Notices()) != 0 {
		t.Error("a notice went out")
	}
}

// TestPreapproveEndsByItself: at its end the grant writes grant_ended with
// the uses that were left. A stop of the broker writes the entry with
// cause stopped.
func TestPreapproveEndsByItself(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	c := e.httpClient("laptop")
	a := e.preapprove(c, preReq(3, "github-token"), 1)
	b := e.preapprove(c, preReq(2, "npm-token"), 2)
	before := len(e.audit.all())
	e.clock.Advance(2 * time.Hour)
	events := e.audit.waitFor(t, before+2)[before:]
	mustEvents(t, events, "grant_ended:ended grant_ended:ended")
	for _, ev := range events {
		s := subjectOf(ev)
		end := ev.(audit.GrantEnded)
		if (s.GrantID != a.ID || end.UsesLeft != 3) && (s.GrantID != b.ID || end.UsesLeft != 2) {
			t.Errorf("entry %+v", end)
		}
	}
	e.preapprove(c, api.PreapproveRequest{Secrets: []string{"github-token"}, From: "2026-10-14T14:00:00Z",
		Until: "2026-10-14T15:00:00Z", Uses: 1}, 3)
	before = len(e.audit.all())
	e.stopRun()
	select {
	case err := <-e.runErr:
		_ = err
		e.runErr <- nil // the cleanup waits for it
	case <-time.After(waitLimit):
		t.Fatal("Run did not return")
	}
	events = e.audit.waitFor(t, before+1)[before:]
	mustEvents(t, events, "grant_ended:stopped")
}

// TestPreapproveAuditFailure: when the decision entry cannot be written,
// the grant does not start.
func TestPreapproveAuditFailure(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	e.approver.Auto(audit.AnswerApproveOnce)
	c := e.httpClient("laptop")
	e.audit.setFail(func(ev audit.Event) error {
		if _, ok := ev.(audit.Decision); ok {
			return errors.New("made-up disk error")
		}
		return nil
	})
	mustStatus(t, e.post(t.Context(), c, api.PathPreapprove, preReq(1, "github-token")), http.StatusServiceUnavailable)
	e.audit.setFail(nil)
	e.approver.Auto("")
	e.clock.Advance(time.Hour)
	p := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	e.waitAsked(2)
	p.cancel()
	p.wait(t)
}

// TestPreapproveHangUpBeforeGrant: the person approves, and the client
// hangs up while the decision entry is written. No grant starts.
func TestPreapproveHangUpBeforeGrant(t *testing.T) {
	wrap, contexts := requestContexts()
	e := newEnv(t, envOptions{wrap: wrap, config: preapproveOn})
	gate := make(chan struct{})
	e.audit.setFail(func(ev audit.Event) error {
		if _, ok := ev.(audit.Decision); ok {
			<-gate
		}
		return nil
	})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathPreapprove, preReq(1, "github-token"))
	ctx := <-contexts
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerApproveOnce)
	time.Sleep(100 * time.Millisecond)
	p.cancel()
	p.wait(t)
	waitDone(t, ctx)
	close(gate)
	mustEvents(t, requestEvents(e.audit.waitFor(t, 3), id), "request decision:approve_once denied:cancelled")
	e.clock.Advance(time.Hour)
	use := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	<-contexts
	e.waitAsked(2)
	use.cancel()
	use.wait(t)
}

// failWriter is a response writer whose body cannot be written.
type failWriter struct{ http.ResponseWriter }

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("made-up write error") }

// TestPreapproveAnswerNotWritten: the person approves, the grant starts,
// and the answer cannot be written. Nobody has the ID, so the broker
// cancels the grant and writes its grant_ended entry.
func TestPreapproveAnswerNotWritten(t *testing.T) {
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == api.PathPreapprove {
				w = failWriter{w}
			}
			next.ServeHTTP(w, r)
		})
	}
	e := newEnv(t, envOptions{wrap: wrap, config: preapproveOn})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathPreapprove, preReq(1, "github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerApproveOnce)
	p.wait(t)
	events := e.audit.waitFor(t, 3)
	mustEvents(t, events, "request decision:approve_once grant_ended:cancelled")
	e.clock.Advance(time.Hour)
	use := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	e.waitAsked(2)
	use.cancel()
	use.wait(t)
}

// TestPreapproveHangUpAfterStart: the client hangs up after the core
// started the grant, before the answer. The broker cancels the grant and
// writes its grant_ended entry.
func TestPreapproveHangUpAfterStart(t *testing.T) {
	wrap, contexts := requestContexts()
	e := newEnv(t, envOptions{wrap: wrap, config: preapproveOn})
	reached, proceed := make(chan struct{}), make(chan struct{})
	e.svc.startHook = func(point string) {
		if point == "after" {
			close(reached)
			select {
			case <-proceed:
			case <-time.After(waitLimit):
				t.Error("the test did not let the request go on") // not Fatal: another goroutine
			}
		}
	}
	c := e.httpClient("laptop")
	p := e.start(c, api.PathPreapprove, preReq(1, "github-token"))
	ctx := <-contexts
	e.tap(e.waitAsked(1)[0].Prompt.RequestID, audit.AnswerApproveOnce)
	select {
	case <-reached:
	case <-time.After(waitLimit):
		t.Fatal("the grant did not start")
	}
	p.cancel()
	p.wait(t)
	waitDone(t, ctx)
	close(proceed)
	mustEvents(t, e.audit.waitFor(t, 3), "request decision:approve_once grant_ended:cancelled")
	e.clock.Advance(time.Hour)
	use := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	<-contexts
	e.waitAsked(2)
	use.cancel()
	use.wait(t)
}

// TestPreapproveCoreStoppedBeforeStart: the approver stops after the tap,
// before the grant starts. No grant starts, and the request is an error
// (503), not a limit.
func TestPreapproveCoreStoppedBeforeStart(t *testing.T) {
	e := newEnv(t, envOptions{config: preapproveOn})
	e.svc.startHook = func(point string) {
		if point == "before" {
			e.approver.Stop(errors.New("made-up: the approver cannot get answers"))
			select {
			case err := <-e.runErr:
				e.runErr <- err
			case <-time.After(waitLimit):
				t.Error("Run did not return") // not Fatal: another goroutine
			}
		}
	}
	c := e.httpClient("laptop")
	p := e.start(c, api.PathPreapprove, preReq(1, "github-token"))
	e.tap(e.waitAsked(1)[0].Prompt.RequestID, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusServiceUnavailable)
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)),
		"request decision:approve_once error:approver_failed denied:error")
}

// flushErrWriter writes, but its flush fails, as when the client has gone.
type flushErrWriter struct{ http.ResponseWriter }

func (flushErrWriter) FlushError() error { return errors.New("made-up flush error") }

// noFlushWriter has no Flush at all.
type noFlushWriter struct{ http.ResponseWriter }

// TestPreapproveFlush: the write works. A failed flush cancels the grant,
// as a failed write does. A writer that cannot flush counts as written, and
// the grant stays.
func TestPreapproveFlush(t *testing.T) {
	tests := map[string]struct {
		wrap   func(http.ResponseWriter) http.ResponseWriter
		events string
	}{
		"flush fails": {func(w http.ResponseWriter) http.ResponseWriter { return flushErrWriter{w} },
			"request decision:approve_once grant_ended:cancelled"},
		"no flush": {func(w http.ResponseWriter) http.ResponseWriter { return noFlushWriter{w} },
			"request decision:approve_once"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			wrap := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == api.PathPreapprove {
						w = tc.wrap(w)
					}
					next.ServeHTTP(w, r)
				})
			}
			e := newEnv(t, envOptions{wrap: wrap, config: preapproveOn})
			c := e.httpClient("laptop")
			p := e.start(c, api.PathPreapprove, preReq(1, "github-token"))
			e.tap(e.waitAsked(1)[0].Prompt.RequestID, audit.AnswerApproveOnce)
			res := p.wait(t)
			events := e.audit.waitFor(t, len(strings.Fields(tc.events)))
			mustEvents(t, events, tc.events)
			e.clock.Advance(time.Hour)
			if tc.events == "request decision:approve_once" {
				mustStatus(t, res, http.StatusOK)
				secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")))
				return
			}
			use := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
			e.waitAsked(2)
			use.cancel()
			use.wait(t)
		})
	}
}
