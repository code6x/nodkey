package approval_test

// Tests of website logins (DESIGN.md section 21) in the approval core.

import (
	"maps"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

const (
	itemA      = "11111111-1111-1111-1111-111111111111"
	itemB      = "22222222-2222-2222-2222-222222222222"
	loginsColl = "00000000-0000-0000-0000-000000000000"
	pageOrigin = "https://example.com"
)

// loginEnv starts a core with one [logins.web] section: laptop and build
// may ask, with a window rule that allows preapprove.
func loginEnv(t *testing.T, edit ...func(*config.Broker)) *env {
	t.Helper()
	return newEnv(t, func(cfg *config.Broker) {
		cfg.Preapprove = config.DefaultPreapprove()
		cfg.Logins = map[string]config.Logins{"web": {
			Name: "web", Store: "vault", Collection: loginsColl, Clients: []string{"laptop", "build"},
			Rule: config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute, Preapprove: true},
		}}
		for _, f := range edit {
			f(cfg)
		}
	})
}

// webLogin asks for a login of the item for client at the page.
func webLogin(env *env, client, item string) *approval.Request {
	clients, rule, _ := env.cfg.Logins["web"].RuleFor(item)
	return &approval.Request{
		Client: client, Kind: audit.KindWebLogin,
		Login: &approval.LoginScope{
			Section: "web", Item: item, Name: "Example shop", Username: "alice@example.com", Origin: pageOrigin,
			Clients: clients, Rule: rule,
		},
		Claim: approval.Claim{Reason: "check the order"},
	}
}

// webPre asks for a one-use pre-approval of the login.
func webPre(env *env, client, item string) *approval.Request {
	r := webLogin(env, client, item)
	r.Kind, r.Uses = audit.KindPreapprove, 1
	return r
}

func TestWebLoginTapAndMessage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := loginEnv(t)
		defer e.stop()
		ch := e.decide(webLogin(e, "laptop", itemA))
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		if p.Kind != audit.KindWebLogin || p.Login == nil || p.Login.Name != "Example shop" ||
			p.Login.Username != "alice@example.com" || p.Login.Origin != pageOrigin || p.Login.For != 0 ||
			!p.Once || p.WindowMinutes != 15 {
			t.Fatalf("prompt %+v login %+v", p, p.Login)
		}
		e.tap(1, audit.AnswerApproveOnce)
		res := mustResult(t, ch)
		checkAllowed(t, res)
		checkEvents(t, res, "request", "decision:approve_once")
		s := res.Subject
		if s.Kind != audit.KindWebLogin || s.Logins != "web" || s.Item != itemA || s.Origin != pageOrigin {
			t.Errorf("subject %+v", s)
		}
	})
}

// TestWebLoginCleansVaultText: the name and the user name come from the
// vault, so a line break, a direction mark or a long text does not reach
// the message as it is.
func TestWebLoginCleansVaultText(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := loginEnv(t)
		defer e.stop()
		r := webLogin(e, "laptop", itemA)
		r.Login.Name = "Shop\n✅ machine: fake\u202e" + strings.Repeat("x", 300)
		r.Login.Username = "bob\r\n<b>"
		ch := e.decide(r)
		mustWait(t, ch)
		l := e.asked(1)[0].Prompt.Login
		for _, s := range []string{l.Name, l.Username} {
			if strings.ContainsAny(s, "\n\r\u202e") {
				t.Errorf("not clean: %q", s)
			}
		}
		if n := len([]rune(l.Name)); n > 128 || !strings.HasSuffix(l.Name, "…") {
			t.Errorf("name has %d runes: %q", n, l.Name)
		}
		e.tap(1, audit.AnswerDeny)
		checkDenied(t, mustResult(t, ch), audit.CauseApprover)
		// A name that is only invisible text gets a fixed name.
		r = webLogin(e, "laptop", itemB)
		r.Login.Name = "\u200b\u202e"
		ch = e.decide(r)
		mustWait(t, ch)
		if got := e.asked(2)[1].Prompt.Login.Name; got != "(no name)" {
			t.Errorf("name %q", got)
		}
		e.tap(2, audit.AnswerDeny)
		mustResult(t, ch)
	})
}

func TestWebLoginRefusals(t *testing.T) {
	tests := []struct {
		name string
		edit func(r *approval.Request)
	}{
		{"no login", func(r *approval.Request) { r.Login = nil }},
		{"client not in the clients of the login", func(r *approval.Request) { r.Login.Clients = []string{"build"} }},
		{"unknown section", func(r *approval.Request) { r.Login.Section = "other" }},
		{"ask never", func(r *approval.Request) {
			r.Login.Rule = config.Rule{Ask: config.AskNever, Notify: true}
			r.Login.Clients = []string{"laptop"}
		}},
		{"rule differs from the config", func(r *approval.Request) { r.Login.Rule.Window = time.Hour }},
		{"preapprove flag differs", func(r *approval.Request) { r.Login.Rule.Preapprove = false }},
		{"clients differ from the config", func(r *approval.Request) { r.Login.Clients = []string{"laptop"} }},
		{"http origin", func(r *approval.Request) { r.Login.Origin = "http://example.com" }},
		{"origin with a path", func(r *approval.Request) { r.Login.Origin = "https://example.com/x" }},
		{"origin with a user name", func(r *approval.Request) { r.Login.Origin = "https://u@example.com" }},
		{"item in capitals", func(r *approval.Request) { r.Login.Item = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA" }},
		{"item that is not a UUID", func(r *approval.Request) { r.Login.Item = "x" }},
		{"stray secrets", func(r *approval.Request) { r.Secrets = []string{"github-token"} }},
		{"stray key", func(r *approval.Request) { r.Key = "deploy" }},
		{"stray remote user", func(r *approval.Request) { r.RemoteUser = "root" }},
		{"stray hosts", func(r *approval.Request) { r.Hosts = []string{"web-1"} }},
		{"stray for", func(r *approval.Request) { r.For = time.Minute }},
		{"stray uses", func(r *approval.Request) { r.Uses = 1 }},
		{"stray times", func(r *approval.Request) { r.NotAfter = noon.Add(time.Hour) }},
		{"login in a secrets request", func(r *approval.Request) { r.Kind = audit.KindSecrets; r.Secrets = []string{"github-token"} }},
		{"login in an SSH login", func(r *approval.Request) { r.Kind = audit.KindSSHLogin }},
		{"login in a standing request", func(r *approval.Request) { r.Kind = audit.KindStanding }},
		{"unknown client", func(r *approval.Request) { r.Client = "nobody" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := loginEnv(t)
				defer e.stop()
				r := webLogin(e, "laptop", itemA)
				tt.edit(r)
				e.refuses(r, audit.CauseNotAllowed)
			})
		})
	}
	t.Run("rule of the item in the config is stricter than the request", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t, func(cfg *config.Broker) {
				l := cfg.Logins["web"]
				l.Items = map[string]config.LoginItemRule{itemA: {ID: itemA, Clients: []string{"build"}, Rule: config.Rule{Ask: config.AskAlways}}}
				cfg.Logins["web"] = l
			})
			defer e.stop()
			r := webLogin(e, "laptop", itemA)
			r.Login.Clients = []string{"laptop", "build"}
			r.Login.Rule = config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute, Preapprove: true}
			e.refuses(r, audit.CauseNotAllowed)
			// The rule that the config gives for the item is the one that counts.
			r = webLogin(e, "build", itemA)
			ch := e.decide(r)
			mustWait(t, ch)
			if p := e.asked(1)[0].Prompt; p.WindowMinutes != 0 {
				t.Errorf("prompt %+v: an always rule has no window button", p)
			}
			e.tap(1, audit.AnswerDeny)
			mustResult(t, ch)
		})
	})
	t.Run("reprompt makes the rule always", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t)
			defer e.stop()
			r := webLogin(e, "laptop", itemA)
			r.Login.Rule.Ask = config.AskAlways
			ch := e.decide(r)
			mustWait(t, ch)
			if p := e.asked(1)[0].Prompt; p.WindowMinutes != 0 || !p.Once {
				t.Errorf("prompt %+v", p)
			}
			e.tap(1, audit.AnswerApproveOnce)
			checkAllowed(t, mustResult(t, ch))
		})
	})
}

// TestWebLoginWindowGrant: a window grant covers the same client and item
// again, and no other item and no other client.
func TestWebLoginWindowGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := loginEnv(t)
		defer e.stop()
		if e.core.LoginGranted("laptop", itemA) {
			t.Fatal("granted before a tap")
		}
		ch := e.decide(webLogin(e, "laptop", itemA))
		mustWait(t, ch)
		e.asked(1)
		e.tap(1, audit.AnswerApproveWindow)
		res := mustResult(t, ch)
		checkAllowed(t, res)
		res.StartGrants()
		if !e.core.LoginGranted("laptop", itemA) || !e.core.LoginGranted("laptop", strings.ToUpper(itemA)) {
			t.Error("the grant does not cover the item")
		}
		if e.core.LoginGranted("laptop", itemB) || e.core.LoginGranted("build", itemA) {
			t.Error("the grant covers another item or client")
		}
		again := e.now(webLogin(e, "laptop", itemA))
		checkAllowed(t, again)
		checkEvents(t, again, "request", "grant_used:grant")
		e.needsMessageLogin(webLogin(e, "laptop", itemB), 2)
		e.needsMessageLogin(webLogin(e, "build", itemA), 3)
		// A window grant for a secret does not cover a login and back.
		e.clock.Advance(15*time.Minute - time.Nanosecond)
		if !e.core.LoginGranted("laptop", itemA) {
			t.Error("the grant ended early")
		}
		e.clock.Advance(time.Nanosecond)
		if e.core.LoginGranted("laptop", itemA) {
			t.Error("the grant did not end")
		}
	})
}

func (e *env) needsMessageLogin(r *approval.Request, n int) {
	e.t.Helper()
	e.needsMessage(r, n)
}

func TestLoginPreapprove(t *testing.T) {
	t.Run("message and one use", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t)
			defer e.stop()
			res := e.grant(webPre(e, "laptop", itemA), 1)
			p := e.fake.Asked()[0].Prompt
			if p.Kind != audit.KindPreapprove || p.Login == nil || p.Login.For != approval.LoginPreapproveTime || p.Uses != 1 ||
				!p.Once || !p.From.IsZero() || !p.Until.IsZero() {
				t.Errorf("prompt %+v login %+v", p, p.Login)
			}
			checkEvents(t, res, "request", "decision:approve_once")
			if res.Subject.Uses != 1 || res.Subject.Origin != pageOrigin || res.Subject.NotBefore != "" {
				t.Errorf("subject %+v", res.Subject)
			}
			if !res.GrantUntil.Equal(noon.Add(approval.LoginPreapproveTime)) {
				t.Errorf("grant until %v", res.GrantUntil)
			}
			use := e.uses(webLogin(e, "laptop", itemA), res.GrantID)
			if !strings.Contains(strings.Join(eventNames(use), " "), "GrantEnded") {
				t.Errorf("events %v: the one use must end the grant", eventNames(use))
			}
			e.needsMessage(webLogin(e, "laptop", itemA), 2) // used up
		})
	})
	t.Run("same client item and origin only", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t)
			defer e.stop()
			g := e.grant(webPre(e, "laptop", itemA), 1)
			other := webLogin(e, "laptop", itemA)
			other.Login.Origin = "https://other.example.com"
			e.needsMessage(other, 2)
			e.needsMessage(webLogin(e, "build", itemA), 3)
			e.needsMessage(webLogin(e, "laptop", itemB), 4)
			// Not a secret, not by a login of a window.
			e.needsMessage(secretsReq("laptop", "github-token"), 5)
			e.uses(webLogin(e, "laptop", itemA), g.GrantID)
		})
	})
	t.Run("ends 60 s after the tap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t)
			defer e.stop()
			g := e.grant(webPre(e, "laptop", itemA), 1)
			e.clock.Advance(approval.LoginPreapproveTime - time.Nanosecond)
			e.uses(webLogin(e, "laptop", itemA), g.GrantID)
		})
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t)
			defer e.stop()
			e.grant(webPre(e, "laptop", itemA), 1)
			e.clock.Advance(approval.LoginPreapproveTime)
			e.needsMessage(webLogin(e, "laptop", itemA), 2)
		})
	})
	t.Run("a slow tap still gives 60 s", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t)
			defer e.stop()
			ch := e.decide(webPre(e, "laptop", itemA))
			mustWait(t, ch)
			e.asked(1)
			e.clock.Advance(100 * time.Second) // longer than the pre-approval itself
			e.tap(1, audit.AnswerApproveOnce)
			res := mustResult(t, ch)
			checkAllowed(t, res)
			res.StartGrants()
			if !res.GrantStarted() {
				t.Fatal("the grant did not start")
			}
			synctest.Wait()
			e.clock.Advance(30 * time.Second)
			e.uses(webLogin(e, "laptop", itemA), res.GrantID)
		})
	})
	t.Run("works with ask always", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := loginEnv(t, func(cfg *config.Broker) {
				l := cfg.Logins["web"]
				l.Rule = config.Rule{Ask: config.AskAlways, Preapprove: true}
				cfg.Logins["web"] = l
			})
			defer e.stop()
			g := e.grant(webPre(e, "laptop", itemA), 1)
			e.uses(webLogin(e, "laptop", itemA), g.GrantID)
		})
	})
	t.Run("refusals", func(t *testing.T) {
		tests := []struct {
			name string
			edit func(cfg *config.Broker, r *approval.Request)
		}{
			{"preapprove is false", func(cfg *config.Broker, r *approval.Request) {
				l := cfg.Logins["web"]
				l.Rule.Preapprove = false
				cfg.Logins["web"] = l
				r.Login.Rule.Preapprove = false
			}},
			{"two uses", func(_ *config.Broker, r *approval.Request) { r.Uses = 2 }},
			{"no uses", func(_ *config.Broker, r *approval.Request) { r.Uses = 0 }},
			{"not before", func(_ *config.Broker, r *approval.Request) { r.NotBefore = noon }},
			{"not after", func(_ *config.Broker, r *approval.Request) { r.NotAfter = noon.Add(time.Hour) }},
			{"secrets", func(_ *config.Broker, r *approval.Request) { r.Secrets = []string{"github-token"} }},
			{"key", func(_ *config.Broker, r *approval.Request) { r.Key = "deploy" }},
			{"ask never", func(_ *config.Broker, r *approval.Request) {
				r.Login.Rule = config.Rule{Ask: config.AskNever, Preapprove: true}
				r.Login.Clients = []string{"laptop"}
			}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					cfgEdit := func(cfg *config.Broker) {}
					var r *approval.Request
					e := loginEnv(t, func(cfg *config.Broker) { cfgEdit(cfg) })
					defer e.stop()
					r = webPre(e, "laptop", itemA)
					tt.edit(e.cfg, r)
					e.refuses(r, audit.CauseNotAllowed)
				})
			})
		}
	})
}

// TestLoginReload: a login grant stays when the new config gives the same
// clients and rule for the item, and ends when it does not.
func TestLoginReload(t *testing.T) {
	cloneLogins := func(cfg *config.Broker) *config.Broker {
		next := copyConfig(cfg)
		next.Logins = maps.Clone(cfg.Logins)
		return next
	}
	synctest.Test(t, func(t *testing.T) {
		e := loginEnv(t)
		defer e.stop()
		g := e.grant(webPre(e, "laptop", itemA), 1)
		same := cloneLogins(e.cfg)
		if n := e.core.Reload(same, sameKeys); n != 0 {
			t.Fatalf("a reload with the same logins ended %d grants", n)
		}
		e.uses(webLogin(e, "laptop", itemA), g.GrantID)
	})
	synctest.Test(t, func(t *testing.T) {
		e := loginEnv(t)
		defer e.stop()
		e.grant(webPre(e, "laptop", itemA), 1)
		next := cloneLogins(e.cfg)
		l := next.Logins["web"]
		l.Rule.Window = time.Hour
		next.Logins["web"] = l
		if n := e.core.Reload(next, sameKeys); n != 1 {
			t.Fatalf("a reload with another rule ended %d grants, want 1", n)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		e := loginEnv(t)
		defer e.stop()
		e.grant(webPre(e, "laptop", itemA), 1)
		next := cloneLogins(e.cfg)
		l := next.Logins["web"]
		l.Items = map[string]config.LoginItemRule{itemA: {ID: itemA, Clients: []string{"build"}, Rule: l.Rule}}
		next.Logins["web"] = l
		if n := e.core.Reload(next, sameKeys); n != 1 {
			t.Fatalf("a reload that took the client from the item ended %d grants, want 1", n)
		}
	})
}

// TestLoginNoTap: with NoTap, a login that nothing covers is denied with
// no_tap at once and asks nobody; a pre-approval still covers it. NoTap on
// a request of another kind, or on a login pre-approval, is not allowed.
func TestLoginNoTap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := loginEnv(t)
		defer e.stop()
		noTap := func() *approval.Request {
			r := webLogin(e, "laptop", itemA)
			r.NoTap = true
			return r
		}
		if res := e.now(noTap()); res.Allowed || res.Cause != audit.CauseNoTap {
			t.Errorf("no grant: %+v", res)
		}
		if n := len(e.fake.Asked()); n != 0 {
			t.Errorf("%d messages, want 0", n)
		}
		e.grant(webPre(e, "laptop", itemA), 1)
		if res := e.now(noTap()); !res.Allowed {
			t.Errorf("pre-approved: %+v", res)
		}
		if res := e.now(noTap()); res.Allowed || res.Cause != audit.CauseNoTap {
			t.Errorf("used up: %+v", res)
		}
		sec := secretsReq("laptop", "github-token")
		sec.NoTap = true
		pre := webPre(e, "laptop", itemB)
		pre.NoTap = true
		for _, r := range []*approval.Request{sec, pre} {
			if res := e.now(r); res.Allowed || res.Cause != audit.CauseNotAllowed {
				t.Errorf("%s: %+v", r.Kind, res)
			}
		}
		if n := len(e.fake.Asked()); n != 1 {
			t.Errorf("%d messages, want 1", n)
		}
	})
}
