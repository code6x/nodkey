package approval_test

// Tests of scheduled grants (DESIGN.md section 8): nodkey preapprove.
// Times are relative to noon, the start of the fake clock.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// preEnv starts a core whose limits are the defaults of [preapprove], and
// whose rules allow preapprove on the secrets github-token, npm-token and
// db-password and on the keys deploy and web.
func preEnv(t *testing.T, edit ...func(*config.Broker)) *env {
	t.Helper()
	return newEnv(t, func(cfg *config.Broker) {
		cfg.Preapprove = config.DefaultPreapprove()
		for _, name := range []string{"github-token", "npm-token", "db-password"} {
			s := cfg.Secrets[name]
			s.Rule.Preapprove = true
			cfg.Secrets[name] = s
		}
		for _, name := range []string{"deploy", "web"} {
			k := cfg.Keys[name]
			k.Rule.Preapprove = true
			cfg.Keys[name] = k
		}
		for _, f := range edit {
			f(cfg)
		}
	})
}

// preSecrets asks for a scheduled grant for secrets, from and until
// counted from noon.
func preSecrets(client string, uses int, from, until time.Duration, names ...string) *approval.Request {
	return &approval.Request{
		Client: client, Kind: audit.KindPreapprove, Secrets: names, Uses: uses,
		NotBefore: noon.Add(from), NotAfter: noon.Add(until),
		Claim: approval.Claim{Reason: "job nightly-backup"},
	}
}

// preKey asks for a scheduled grant for a key.
func preKey(client, key, user string, uses int, from, until time.Duration, hostNames ...string) *approval.Request {
	return &approval.Request{
		Client: client, Kind: audit.KindPreapprove, Key: key, RemoteUser: user, Hosts: hostNames, Uses: uses,
		NotBefore: noon.Add(from), NotAfter: noon.Add(until),
		Claim: approval.Claim{Reason: "job nightly-backup"},
	}
}

// grant asks for the scheduled grant r, which must be the message n, taps
// Approve, and starts the grant as the broker does.
func (e *env) grant(r *approval.Request, n int) *approval.Result {
	e.t.Helper()
	ch := e.decide(r)
	mustWait(e.t, ch)
	e.asked(n)
	e.tap(n, audit.AnswerApproveOnce)
	res := mustResult(e.t, ch)
	checkAllowed(e.t, res)
	res.StartGrants()
	if !res.GrantStarted() {
		e.t.Fatal("the grant did not start")
	}
	return res
}

// refuses checks that the core denies r for cause without a message.
func (e *env) refuses(r *approval.Request, cause audit.Cause) {
	e.t.Helper()
	before := len(e.fake.Asked())
	checkDenied(e.t, e.now(r), cause)
	if got := len(e.fake.Asked()); got != before {
		e.t.Fatalf("the core asked for %d messages, want %d", got, before)
	}
}

// needsMessage checks that r is not covered: the core asks for message n.
// Then the client hangs up. It makes no Deny, so no grant ends.
func (e *env) needsMessage(r *approval.Request, n int) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ch := e.decideCtx(ctx, r)
	mustWait(e.t, ch)
	e.asked(n)
	cancel()
	checkDenied(e.t, mustResult(e.t, ch), audit.CauseCancelled)
}

// uses checks that r is allowed by a scheduled grant: the request entry,
// a grant_used entry with via scheduled and the ID of the grant, and one
// silent notice. It returns the result.
func (e *env) uses(r *approval.Request, id string) *approval.Result {
	e.t.Helper()
	before := len(e.fake.Notices())
	res := e.now(r)
	checkAllowed(e.t, res)
	var used *audit.GrantUsed
	for _, ev := range res.Events() {
		if u, ok := ev.(audit.GrantUsed); ok {
			used = &u
		}
	}
	if used == nil || used.Via != audit.ViaScheduled || used.GrantID != id {
		e.t.Fatalf("events %v; want one grant_used with via scheduled and the grant ID", eventNames(res))
	}
	notices := e.fake.Notices()
	if len(notices) != before+1 || notices[before].Via != audit.ViaScheduled {
		e.t.Fatalf("%d notices, want %d, the last with via scheduled", len(notices), before+1)
	}
	return res
}

// endedRecorder collects the entries that the core hands out for the
// grants that end by themselves.
type endedRecorder struct {
	mu  sync.Mutex
	evs []audit.GrantEnded
}

func (r *endedRecorder) add(ev audit.GrantEnded) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
}

func (r *endedRecorder) all() []audit.GrantEnded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.GrantEnded(nil), r.evs...)
}

func lastEnded(t *testing.T, res *approval.Result) audit.GrantEnded {
	t.Helper()
	evs := res.Events()
	end, ok := evs[len(evs)-1].(audit.GrantEnded)
	if !ok {
		t.Fatalf("events %v; want grant_ended last", eventNames(res))
	}
	return end
}

// TestPreapproveMessageAndEntries: the request shows the secrets, the
// uses and the span, with Approve and Deny only. The entries are the
// request, the decision and nothing else: the grant hands out nothing.
func TestPreapproveMessageAndEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		res := e.grant(preSecrets("laptop", 2, time.Hour, 2*time.Hour, "github-token"), 1)
		p := e.fake.Asked()[0].Prompt
		if p.Kind != audit.KindPreapprove || p.Client != "laptop" || len(p.Secrets) != 1 || p.Secrets[0] != "github-token" ||
			p.Uses != 2 || !p.From.Equal(noon.Add(time.Hour)) || !p.Until.Equal(noon.Add(2*time.Hour)) ||
			!p.Once || p.WindowMinutes != 0 || p.Claim.Reason != "job nightly-backup" {
			t.Errorf("prompt %+v", p)
		}
		checkEvents(t, res, "request", "decision:approve_once")
		if len(res.GrantID) != 22 || res.Subject.GrantID != res.GrantID {
			t.Errorf("grant ID %q, subject %q", res.GrantID, res.Subject.GrantID)
		}
		s := res.Subject
		if s.Kind != audit.KindPreapprove || s.Uses != 2 || s.NotBefore != "2026-10-14T13:00:00Z" ||
			s.NotAfter != "2026-10-14T14:00:00Z" || s.Reason != "job nightly-backup" {
			t.Errorf("subject %+v", s)
		}
		if !res.GrantFrom.Equal(noon.Add(time.Hour)) || !res.GrantUntil.Equal(noon.Add(2*time.Hour)) {
			t.Errorf("grant span %v to %v", res.GrantFrom, res.GrantUntil)
		}
	})
}

// TestScheduledGrantTime: a grant is used from its start, with the first
// moment inside, until its end, which is outside: at the exact end time it
// is gone.
func TestScheduledGrantTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 5, time.Hour, 2*time.Hour, "github-token"), 1)
		req := secretsReq("laptop", "github-token")
		e.needsMessage(req, 2) // now: before the start
		e.clock.Advance(time.Hour - time.Nanosecond)
		e.needsMessage(req, 3) // one nanosecond before the start
		e.clock.Advance(time.Nanosecond)
		e.uses(req, g.GrantID) // exactly the start
		e.clock.Advance(time.Hour - time.Second)
		e.uses(req, g.GrantID) // one second before the end
		e.clock.Advance(time.Second - time.Nanosecond)
		e.uses(req, g.GrantID) // the last nanosecond
		e.clock.Advance(time.Nanosecond)
		e.needsMessage(req, 4) // exactly the end: gone
	})
}

// TestScheduledGrantUses: a grant allows at most N uses. The last use ends
// it, and its result holds the grant_ended entry with cause used_up.
func TestScheduledGrantUses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 2, 0, time.Hour, "github-token"), 1)
		req := secretsReq("laptop", "github-token")
		first := e.uses(req, g.GrantID)
		checkEvents(t, first, "request", "grant_used:scheduled")
		last := e.uses(req, g.GrantID)
		checkEvents(t, last, "request", "grant_used:scheduled", "audit.GrantEnded")
		end := lastEnded(t, last)
		if end.Cause != audit.EndUsedUp || end.UsesLeft != 0 || end.GrantID != g.GrantID || end.Kind != audit.KindPreapprove ||
			end.RequestID != g.RequestID || end.Uses != 2 {
			t.Errorf("grant_ended %+v", end)
		}
		e.needsMessage(req, 2)
	})
}

// TestScheduledGrantScope: only the same client, and only the named
// secrets, use the grant.
func TestScheduledGrantScope(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 5, 0, time.Hour, "github-token"), 1)
		e.needsMessage(secretsReq("build", "github-token"), 2) // another client
		e.needsMessage(secretsReq("laptop", "npm-token"), 3)   // another secret
		e.needsMessage(secretsReq("laptop", "db-password"), 4) // another secret
		e.uses(secretsReq("laptop", "github-token"), g.GrantID)
		// A login is not a run for secrets.
		e.needsMessage(loginReq("laptop", "deploy", e.hosts.web1, "deploy"), 5)
	})
}

// TestScheduledGrantSeveralSecrets: one tap makes one grant for all the
// secrets, with one counter. A run with some of them takes one use. A run
// with a secret outside the grant is not covered at all.
func TestScheduledGrantSeveralSecrets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token", "npm-token"), 1)
		e.uses(secretsReq("laptop", "github-token", "npm-token"), g.GrantID) // 2 left
		e.uses(secretsReq("laptop", "npm-token"), g.GrantID)                 // 1 left
		// A secret outside the grant: the whole request asks, and no use goes.
		e.needsMessage(secretsReq("laptop", "github-token", "db-password"), 2)
		last := e.uses(secretsReq("laptop", "npm-token", "github-token"), g.GrantID)
		if lastEnded(t, last).Cause != audit.EndUsedUp {
			t.Error("the last use did not end the grant")
		}
	})
}

// TestScheduledGrantDoesNotMix: a scheduled grant is not mixed with a
// grant of "Approve N min" or a "never" rule in one request: the request
// asks as a whole.
func TestScheduledGrantDoesNotMix(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 3, 0, time.Hour, "npm-token"), 1)
		e.approveWindow(secretsReq("laptop", "github-token"), 2)
		e.needsMessage(secretsReq("laptop", "github-token", "npm-token"), 3)
		e.uses(secretsReq("laptop", "npm-token"), g.GrantID) // the grant alone still works
		e.now(secretsReq("laptop", "github-token"))          // so does the window
	})
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t, func(cfg *config.Broker) {
			s := cfg.Secrets["npm-token"]
			s.Clients = []string{"laptop", "ci"}
			cfg.Secrets["npm-token"] = s
		})
		defer e.stop()
		g := e.grant(preSecrets("ci", 3, 0, time.Hour, "npm-token"), 1)
		e.needsMessage(secretsReq("ci", "npm-token", "backup-token"), 2)
		e.uses(secretsReq("ci", "npm-token"), g.GrantID)
		// The never rule alone needs no grant and sends its own notice.
		res := e.now(secretsReq("ci", "backup-token"))
		checkAllowed(t, res)
		checkEvents(t, res, "request", "grant_used:never_rule")
	})
}

// TestScheduledGrantKey: a key grant covers the named hosts (all their host
// keys) and the one remote user. Each login takes one use.
func TestScheduledGrantKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preKey("laptop", "web", "deploy", 3, 0, time.Hour, "web-1"), 1)
		e.uses(loginReq("laptop", "web", e.hosts.web1, "deploy"), g.GrantID)
		e.uses(loginReq("laptop", "web", e.hosts.web1ecdsa, "deploy"), g.GrantID)
		e.needsMessage(loginReq("laptop", "web", e.hosts.web2, "deploy"), 2)    // a host that is not listed
		e.needsMessage(loginReq("laptop", "web", e.hosts.web1, "root"), 3)      // another user
		e.needsMessage(loginReq("laptop", "deploy", e.hosts.web1, "deploy"), 4) // another key
		last := e.uses(loginReq("laptop", "web", e.hosts.web1, "deploy"), g.GrantID)
		if lastEnded(t, last).Cause != audit.EndUsedUp {
			t.Error("the third login did not end the grant")
		}
		e.needsMessage(loginReq("laptop", "web", e.hosts.web1, "deploy"), 5)
	})
}

// TestPreapproveLimits: each limit, with the defaults of [preapprove], at
// the border and one step over it. A request over a limit is denied before
// any message.
func TestPreapproveLimits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		def := config.DefaultPreapprove()
		if def.MaxAhead != 7*24*time.Hour || def.MaxOpen != 8*time.Hour || def.MaxUses != 10 || def.MaxGrants != 5 {
			t.Fatalf("defaults %+v", def)
		}
		sec := func(uses int, from, until time.Duration) *approval.Request {
			return preSecrets("laptop", uses, from, until, "npm-token")
		}
		for _, tc := range []struct {
			name string
			r    *approval.Request
			ok   bool
		}{
			{"max_ahead", sec(1, def.MaxAhead, def.MaxAhead+time.Hour), true},
			{"over max_ahead", sec(1, def.MaxAhead+time.Second, def.MaxAhead+time.Hour), false},
			{"max_open", sec(1, time.Hour, time.Hour+def.MaxOpen), true},
			{"over max_open", sec(1, time.Hour, time.Hour+def.MaxOpen+time.Second), false},
			{"max_uses", sec(def.MaxUses, 0, time.Hour), true},
			{"over max_uses", sec(def.MaxUses+1, 0, time.Hour), false},
			{"no uses", sec(0, 0, time.Hour), false},
			{"negative uses", sec(-1, 0, time.Hour), false},
			{"end before start", sec(1, time.Hour, time.Minute), false},
			{"end is start", sec(1, time.Hour, time.Hour), false},
			{"end in the past", sec(1, -2*time.Hour, -time.Hour), false},
			{"end is now", sec(1, -time.Hour, 0), false},
			{"start in the past", sec(1, -time.Hour, time.Hour), true},
			{"started long ago", sec(1, -def.MaxOpen, time.Hour), false},
			{"no times", &approval.Request{Client: "laptop", Kind: audit.KindPreapprove, Secrets: []string{"npm-token"}, Uses: 1}, false},
			{"part of a second", &approval.Request{Client: "laptop", Kind: audit.KindPreapprove, Secrets: []string{"npm-token"},
				Uses: 1, NotBefore: noon.Add(time.Hour + 1), NotAfter: noon.Add(2 * time.Hour)}, false},
		} {
			if !tc.ok {
				e.refuses(tc.r, audit.CauseNotAllowed)
				continue
			}
			e.needsMessage(tc.r, len(e.fake.Asked())+1) // it gets a message
		}
	})
}

// TestPreapproveLimitsFromConfig: the limits of the config count, and a
// config without them (all zero) allows no scheduled grant.
func TestPreapproveLimitsFromConfig(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t, func(cfg *config.Broker) {
			cfg.Preapprove = config.PreapproveLimits{MaxAhead: time.Hour, MaxOpen: 30 * time.Minute, MaxUses: 2, MaxGrants: 1}
		})
		defer e.stop()
		e.refuses(preSecrets("laptop", 1, time.Hour+time.Second, 90*time.Minute, "npm-token"), audit.CauseNotAllowed)
		e.refuses(preSecrets("laptop", 1, 0, 31*time.Minute, "npm-token"), audit.CauseNotAllowed)
		e.refuses(preSecrets("laptop", 3, 0, 30*time.Minute, "npm-token"), audit.CauseNotAllowed)
		e.grant(preSecrets("laptop", 2, time.Hour, 90*time.Minute, "npm-token"), 1)
		e.refuses(preSecrets("laptop", 1, 0, time.Minute, "npm-token"), audit.CauseLimit)
	})
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t, func(cfg *config.Broker) { cfg.Preapprove = config.PreapproveLimits{} })
		defer e.stop()
		e.refuses(preSecrets("laptop", 1, 0, time.Minute, "npm-token"), audit.CauseNotAllowed)
	})
}

// TestPreapproveMaxGrants: a client has at most max_grants approved
// grants that have not ended plus waiting requests. The limit is per
// client, and a grant that ended makes room.
func TestPreapproveMaxGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		max := config.DefaultPreapprove().MaxGrants
		var first *approval.Result
		for i := range 2 {
			res := e.grant(preSecrets("laptop", 1, time.Hour, 2*time.Hour, "npm-token"), i+1)
			if i == 0 {
				first = res
			}
		}
		// The rest wait for a tap.
		var waiting []<-chan *approval.Result
		for i := 2; i < max; i++ {
			waiting = append(waiting, e.decide(preSecrets("laptop", 1, time.Hour, 2*time.Hour, "npm-token")))
		}
		synctest.Wait()
		e.refuses(preSecrets("laptop", 1, time.Hour, 2*time.Hour, "npm-token"), audit.CauseLimit)
		// Another client is not counted.
		ch := e.decide(preSecrets("build", 1, time.Hour, 2*time.Hour, "github-token"))
		mustWait(t, ch)
		e.tap(len(e.fake.Asked()), audit.AnswerApproveOnce)
		checkAllowed(t, mustResult(t, ch))
		// A grant that is cancelled makes room for a request.
		if _, ok := e.core.CancelGrant("laptop", first.GrantID); !ok {
			t.Fatal("cancel failed")
		}
		ch = e.decide(preSecrets("laptop", 1, time.Hour, 2*time.Hour, "npm-token"))
		mustWait(t, ch)
		e.refuses(preSecrets("laptop", 1, time.Hour, 2*time.Hour, "npm-token"), audit.CauseLimit)
		// Taps on the waiting requests start their grants, up to the limit.
		for i := 1; i <= len(e.fake.Asked()); i++ {
			_ = e.fake.Tap(e.fake.Asked()[i-1].Prompt.RequestID, audit.AnswerApproveOnce)
		}
		started := 0
		for _, c := range append(waiting, ch) {
			if res := mustResult(t, c); res.Allowed {
				res.StartGrants()
				if res.GrantStarted() {
					started++
				}
			}
		}
		if started != max-1 {
			t.Errorf("%d grants started from the waiting requests, want %d (the limit is %d; one grant was cancelled)",
				started, max-1, max)
		}
	})
}

// TestPreapproveRules: a secret or key allows a scheduled grant only with
// preapprove = true, and never with a "never" rule. Names, clients and
// kinds of field are checked again.
func TestPreapproveRules(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t, func(cfg *config.Broker) {
			// backup-token and backup have the flag on a never rule, as a
			// hand-made config could: the core still refuses them.
			s := cfg.Secrets["backup-token"]
			s.Rule.Preapprove = true
			cfg.Secrets["backup-token"] = s
			k := cfg.Keys["backup"]
			k.Rule.Preapprove = true
			cfg.Keys["backup"] = k
		})
		defer e.stop()
		for name, r := range map[string]*approval.Request{
			"a never rule":                 preSecrets("ci", 1, 0, time.Hour, "backup-token"),
			"a never rule for a key":       preKey("ci", "backup", "backup", 1, 0, time.Hour, "db-1"),
			"an unknown secret":            preSecrets("laptop", 1, 0, time.Hour, "nope"),
			"a client that may not use it": preSecrets("build", 1, 0, time.Hour, "npm-token"),
			"an unknown client":            preSecrets("nobody", 1, 0, time.Hour, "npm-token"),
			"no secrets, no key":           preSecrets("laptop", 1, 0, time.Hour),
			"a key and secrets": {Client: "laptop", Kind: audit.KindPreapprove, Secrets: []string{"npm-token"}, Key: "web",
				RemoteUser: "deploy", Hosts: []string{"web-1"}, Uses: 1, NotBefore: noon, NotAfter: noon.Add(time.Hour)},
			"secrets and a user": {Client: "laptop", Kind: audit.KindPreapprove, Secrets: []string{"npm-token"},
				RemoteUser: "deploy", Uses: 1, NotBefore: noon, NotAfter: noon.Add(time.Hour)},
			"a key without hosts":      preKey("laptop", "web", "deploy", 1, 0, time.Hour),
			"a host of another key":    preKey("laptop", "web", "deploy", 1, 0, time.Hour, "web-3"),
			"an unknown host":          preKey("laptop", "web", "deploy", 1, 0, time.Hour, "nope"),
			"a bad remote user":        preKey("laptop", "web", "de ploy", 1, 0, time.Hour, "web-1"),
			"a key without the flag":   preKey("laptop", "admin", "deploy", 1, 0, time.Hour, "web-1"),
			"a window for the request": {Client: "laptop", Kind: audit.KindPreapprove, Secrets: []string{"npm-token"}, For: time.Hour, Uses: 1, NotBefore: noon, NotAfter: noon.Add(time.Hour)},
		} {
			t.Log(name)
			e.refuses(r, audit.CauseNotAllowed)
		}
		// Preapprove is off by default: a config without the flag refuses.
		e2 := newEnv(t, func(cfg *config.Broker) { cfg.Preapprove = config.DefaultPreapprove() })
		defer e2.stop()
		e2.refuses(preSecrets("laptop", 1, 0, time.Hour, "github-token"), audit.CauseNotAllowed)
		e2.refuses(preKey("laptop", "web", "deploy", 1, 0, time.Hour, "web-1"), audit.CauseNotAllowed)
	})
}

// TestScheduledGrantAlways: a secret with the rule "always" can be
// pre-approved, and the grant does not turn the rule into "never": a
// different secret still asks.
func TestScheduledGrantAlways(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 1, 0, time.Hour, "db-password"), 1)
		e.uses(secretsReq("laptop", "db-password"), g.GrantID)
		e.needsMessage(secretsReq("laptop", "db-password"), 2)
	})
}

// TestScheduledGrantCancel: the client that has a grant ends it without a
// tap. Another client's ID and an unknown ID give the same answer. A grant
// that ended cannot be cancelled again.
func TestScheduledGrantCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 3, time.Hour, 2*time.Hour, "github-token"), 1)
		for _, tc := range []struct{ client, id string }{
			{"build", g.GrantID}, {"ci", g.GrantID}, {"laptop", "AAAAAAAAAAAAAAAAAAAAAA"}, {"laptop", ""},
			{"laptop", g.GrantID + "x"}, {"nobody", g.GrantID},
		} {
			if ev, ok := e.core.CancelGrant(tc.client, tc.id); ok || ev.GrantID != "" {
				t.Errorf("CancelGrant(%q, %q) = %+v, %v; want no grant", tc.client, tc.id, ev, ok)
			}
		}
		e.clock.Advance(time.Hour)
		e.uses(secretsReq("laptop", "github-token"), g.GrantID) // still there
		ev, ok := e.core.CancelGrant("laptop", g.GrantID)
		if !ok || ev.Cause != audit.EndCancelled || ev.UsesLeft != 2 || ev.GrantID != g.GrantID || ev.RequestID != g.RequestID {
			t.Fatalf("CancelGrant = %+v, %v", ev, ok)
		}
		if _, ok := e.core.CancelGrant("laptop", g.GrantID); ok {
			t.Error("a grant was cancelled twice")
		}
		e.needsMessage(secretsReq("laptop", "github-token"), 2)
	})
}

// TestScheduledGrantEndsByTime: at its end time a grant is gone, and the
// core hands its grant_ended entry out, with the uses that were left. A
// grant that has not started yet ends the same way.
func TestScheduledGrantEndsByTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		a := e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token"), 1)
		b := e.grant(preSecrets("laptop", 2, 2*time.Hour, 3*time.Hour, "npm-token"), 2)
		e.uses(secretsReq("laptop", "github-token"), a.GrantID)
		e.clock.Advance(time.Hour - time.Nanosecond)
		synctest.Wait()
		if got := rec.all(); len(got) != 0 {
			t.Fatalf("grants ended before their end: %+v", got)
		}
		e.clock.Advance(time.Nanosecond)
		synctest.Wait()
		got := rec.all()
		if len(got) != 1 || got[0].Cause != audit.EndEnded || got[0].UsesLeft != 2 || got[0].GrantID != a.GrantID {
			t.Fatalf("ended entries %+v", got)
		}
		e.clock.Advance(2 * time.Hour)
		synctest.Wait()
		got = rec.all()
		if len(got) != 2 || got[1].Cause != audit.EndEnded || got[1].UsesLeft != 2 || got[1].GrantID != b.GrantID {
			t.Fatalf("ended entries %+v", got)
		}
		// Gone: cancel finds nothing.
		if _, ok := e.core.CancelGrant("laptop", a.GrantID); ok {
			t.Error("an ended grant was cancelled")
		}
	})
}

// TestScheduledGrantStops: a stop of the core ends every scheduled grant
// with cause stopped. A new core has none of them.
func TestScheduledGrantStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		a := e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token"), 1)
		b := e.grant(preKey("laptop", "web", "deploy", 1, time.Hour, 2*time.Hour, "web-1"), 2)
		e.stop()
		got := rec.all()
		if len(got) != 2 {
			t.Fatalf("ended entries %+v", got)
		}
		for _, ev := range got {
			if ev.Cause != audit.EndStopped || (ev.GrantID != a.GrantID && ev.GrantID != b.GrantID) {
				t.Errorf("entry %+v", ev)
			}
		}
		// A restart: a new core has no grant, and asks.
		e2 := preEnv(t)
		defer e2.stop()
		e2.needsMessage(secretsReq("laptop", "github-token"), 1)
	})
}

// TestScheduledGrantDeny: a later Deny for a secret of the grant, from the
// same client, ends it, also a grant that has not started yet. The entries
// come with the result of the Deny. Another client's Deny ends nothing.
func TestScheduledGrantDeny(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		started := e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token", "npm-token"), 1)
		waiting := e.grant(preSecrets("laptop", 3, 3*time.Hour, 4*time.Hour, "db-password"), 2)
		// Another client's Deny.
		ch := e.decide(secretsReq("build", "github-token"))
		mustWait(t, ch)
		e.tap(3, audit.AnswerDeny)
		checkDenied(t, mustResult(t, ch), audit.CauseApprover)
		e.uses(secretsReq("laptop", "github-token"), started.GrantID) // 2 left
		// The client's own Deny, for a request that the grants do not cover
		// as a whole, ends both grants that name a secret of it.
		ch = e.decide(secretsReq("laptop", "npm-token", "db-password"))
		mustWait(t, ch)
		e.tap(4, audit.AnswerDeny)
		res := mustResult(t, ch)
		checkDenied(t, res, audit.CauseApprover)
		checkEvents(t, res, "request", "decision:deny", "denied:approver", "audit.GrantEnded", "audit.GrantEnded")
		evs := res.Events()
		first, second := evs[3].(audit.GrantEnded), evs[4].(audit.GrantEnded)
		if first.Cause != audit.EndDenied || first.UsesLeft != 2 || first.GrantID != started.GrantID ||
			second.Cause != audit.EndDenied || second.UsesLeft != 3 || second.GrantID != waiting.GrantID {
			t.Errorf("entries %+v and %+v", first, second)
		}
		e.clock.Advance(approval.DenyPause)
		e.needsMessage(secretsReq("laptop", "github-token"), 5)
		e.clock.Advance(3 * time.Hour)
		e.needsMessage(secretsReq("laptop", "db-password"), 6)
	})
}

// TestScheduledGrantDenyBeforeStart: a Deny that comes after the tap, but
// before StartGrants, stops the grant from starting.
func TestScheduledGrantDenyBeforeStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		ch := e.decide(preSecrets("laptop", 3, 0, time.Hour, "github-token"))
		mustWait(t, ch)
		e.tap(1, audit.AnswerApproveOnce)
		res := mustResult(t, ch)
		checkAllowed(t, res)
		ch = e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.tap(2, audit.AnswerDeny)
		checkDenied(t, mustResult(t, ch), audit.CauseApprover)
		res.StartGrants()
		if res.GrantStarted() {
			t.Error("the grant started after a Deny")
		}
		e.clock.Advance(approval.DenyPause)
		e.needsMessage(secretsReq("laptop", "github-token"), 3)
	})
}

// TestScheduledGrantNotStartedWithoutStartGrants: the grant starts only
// when StartGrants runs, which the broker does after the decision entry
// is on disk and when the client is still there. A second call changes
// nothing. A result of another kind starts nothing.
func TestScheduledGrantNotStartedWithoutStartGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		ch := e.decide(preSecrets("laptop", 3, 0, time.Hour, "github-token"))
		mustWait(t, ch)
		e.tap(1, audit.AnswerApproveOnce)
		res := mustResult(t, ch)
		checkAllowed(t, res)
		if res.GrantStarted() {
			t.Error("the grant started before StartGrants")
		}
		e.needsMessage(secretsReq("laptop", "github-token"), 2)
		e.clock.Advance(approval.DenyPause)
		res.StartGrants()
		res.StartGrants()
		if !res.GrantStarted() {
			t.Fatal("the grant did not start")
		}
		e.uses(secretsReq("laptop", "github-token"), res.GrantID)
		// A Deny of the person for the preapprove request itself starts nothing.
		ch = e.decide(preSecrets("laptop", 3, 0, time.Hour, "npm-token"))
		mustWait(t, ch)
		e.tap(len(e.fake.Asked()), audit.AnswerDeny)
		deny := mustResult(t, ch)
		checkDenied(t, deny, audit.CauseApprover)
		deny.StartGrants()
		if deny.GrantStarted() || deny.GrantID != "" {
			t.Error("a denied request has a grant")
		}
	})
}

// TestScheduledGrantEndPassedBeforeStart: a tap that comes after the end
// is not possible (the request ends at the end time), so no grant starts
// after it.
func TestScheduledGrantEndPassedBeforeStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		ch := e.decide(preSecrets("laptop", 3, 0, 10*time.Minute, "github-token"))
		mustWait(t, ch)
		e.clock.Advance(10 * time.Minute)
		res := mustResult(t, ch)
		checkDenied(t, res, audit.CauseExpired)
	})
}

// TestScheduledUseNoticeFails: a use whose notice cannot be sent is
// denied. An unclear failure keeps the use counted; a limit of the
// approver means nothing was sent, so the use is not taken.
func TestScheduledUseNoticeFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 2, 0, time.Hour, "github-token"), 1)
		req := secretsReq("laptop", "github-token")
		e.fake.FailNotify(errors.New("telegram is down"))
		res := e.now(req)
		checkDenied(t, res, audit.CauseError)
		checkEvents(t, res, "request", "error:approver_failed", "denied:error")
		// The use counted: one is left.
		e.fake.FailNotify(fmt.Errorf("busy: %w", approval.ErrLimit))
		res = e.now(req)
		checkDenied(t, res, audit.CauseLimit)
		e.fake.FailNotify(nil)
		last := e.uses(req, g.GrantID) // the limit did not take the last use
		if lastEnded(t, last).Cause != audit.EndUsedUp {
			t.Error("the last use did not end the grant")
		}
		e.needsMessage(req, 2)
	})
}

// TestScheduledUseNoticeFailsOnLastUse: if the last use is taken and its
// notice fails, the use still counts and the grant ends, with its entry in
// the denied result.
func TestScheduledUseNoticeFailsOnLastUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 1)
		e.fake.FailNotify(errors.New("telegram is down"))
		res := e.now(secretsReq("laptop", "github-token"))
		checkDenied(t, res, audit.CauseError)
		if ev := lastEnded(t, res); ev.Cause != audit.EndUsedUp || ev.GrantID != g.GrantID {
			t.Errorf("entry %+v", ev)
		}
		e.fake.FailNotify(nil)
		e.needsMessage(secretsReq("laptop", "github-token"), 2)
		// A limit on the last use gives it back, and the grant stays.
		e3 := preEnv(t)
		defer e3.stop()
		g3 := e3.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 1)
		e3.fake.FailNotify(fmt.Errorf("busy: %w", approval.ErrLimit))
		checkDenied(t, e3.now(secretsReq("laptop", "github-token")), audit.CauseLimit)
		e3.fake.FailNotify(nil)
		e3.uses(secretsReq("laptop", "github-token"), g3.GrantID)
	})
}

// TestScheduledUseNoticeRateLimit: the notices of scheduled uses count
// toward the 6 per client in 60 seconds, together with those of "never
// ask" uses. A use that the limit stops is denied with cause limit and is
// not taken.
func TestScheduledUseNoticeRateLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 8, 0, time.Hour, "github-token"), 1)
		req := secretsReq("laptop", "github-token")
		for range approval.MaxNoticesPerMinute {
			e.uses(req, g.GrantID)
		}
		before := len(e.fake.Notices())
		checkDenied(t, e.now(req), audit.CauseLimit)
		if len(e.fake.Notices()) != before {
			t.Error("a notice went out over the limit")
		}
		e.clock.Advance(time.Minute)
		e.uses(req, g.GrantID) // 7th use: not taken by the limit
		last := e.uses(req, g.GrantID)
		if lastEnded(t, last).Cause != audit.EndUsedUp {
			t.Error("the 8th use did not end the grant: a use was taken by the limit")
		}
	})
}

// TestScheduledUseClockSetBack: the uses that were made still count when
// the wall clock is set back inside the time of the grant. A wall clock
// set back before the start stops the use, and cannot make the grant last
// beyond its end on the monotonic clock.
func TestScheduledUseClockSetBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 2, time.Hour, 2*time.Hour, "github-token"), 1)
		req := secretsReq("laptop", "github-token")
		e.clock.Advance(90 * time.Minute)
		e.uses(req, g.GrantID)
		e.clock.JumpWall(-20 * time.Minute) // still inside
		last := e.uses(req, g.GrantID)
		if lastEnded(t, last).Cause != audit.EndUsedUp {
			t.Error("the count started again after the clock was set back")
		}
		e.needsMessage(req, 2)
	})
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		g := e.grant(preSecrets("laptop", 3, time.Hour, 2*time.Hour, "github-token"), 1)
		req := secretsReq("laptop", "github-token")
		e.clock.Advance(90 * time.Minute)
		e.uses(req, g.GrantID)
		e.clock.JumpWall(-3 * time.Hour) // before the start
		e.needsMessage(req, 2)
		e.clock.JumpWall(3 * time.Hour)
		e.uses(req, g.GrantID) // the count was kept: 1 left
		// The wall clock goes back inside the time; the monotonic end holds.
		e.clock.JumpWall(-time.Hour)
		e.clock.Advance(31 * time.Minute) // the monotonic clock is at 2h01m
		synctest.Wait()
		e.needsMessage(req, 3)
		if got := rec.all(); len(got) != 1 || got[0].Cause != audit.EndEnded || got[0].UsesLeft != 1 {
			t.Errorf("ended entries %+v", got)
		}
	})
}

// TestScheduledUseWallClockForward: a wall clock that jumps past the end
// ends the grant, as for other grants.
func TestScheduledUseWallClockForward(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token"), 1)
		e.uses(secretsReq("laptop", "github-token"), g.GrantID)
		e.clock.JumpWall(time.Hour)
		e.needsMessage(secretsReq("laptop", "github-token"), 2)
	})
}

// TestScheduledUseConcurrent: many requests at the same time take no more
// uses than the grant has.
func TestScheduledUseConcurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		e.fake.Auto("")
		e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token"), 1)
		ctx, cancel := context.WithCancel(context.Background())
		var chans []<-chan *approval.Result
		for range 8 {
			chans = append(chans, e.decideCtx(ctx, secretsReq("laptop", "github-token")))
		}
		synctest.Wait()
		cancel()
		allowed := 0
		for _, ch := range chans {
			if mustResult(t, ch).Allowed {
				allowed++
			}
		}
		if allowed != 3 {
			t.Errorf("%d requests were allowed, want 3 (the uses of the grant)", allowed)
		}
	})
}

// TestScheduledGrantNotStartedAfterStop: a handler that is between Decide
// and StartGrants when the core stops starts no grant, because the stop
// already ended the grants and a new one would never get its grant_ended
// entry.
func TestScheduledGrantNotStartedAfterStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		ch := e.decide(preSecrets("laptop", 3, 0, time.Hour, "github-token"))
		mustWait(t, ch)
		e.tap(1, audit.AnswerApproveOnce)
		res := mustResult(t, ch)
		checkAllowed(t, res)
		e.stop()
		res.StartGrants()
		if res.GrantStarted() {
			t.Error("a grant started after the core stopped")
		}
		if got := rec.all(); len(got) != 0 {
			t.Errorf("ended entries %+v", got)
		}
	})
}
