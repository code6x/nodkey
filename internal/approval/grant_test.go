package approval_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// approveWindow asks for r, taps "Approve N min" on its message (the
// message number n) and starts the grants.
func (e *env) approveWindow(r *approval.Request, n int) *approval.Result {
	e.t.Helper()
	ch := e.decide(r)
	mustWait(e.t, ch)
	e.asked(n)
	e.tap(n, audit.AnswerApproveWindow)
	res := mustResult(e.t, ch)
	checkAllowed(e.t, res)
	res.StartGrants()
	return res
}

// needsTap checks that r needs a message: it waits, and the core asked
// for message n. Then it approves it once, which makes no grant and ends
// none.
func (e *env) needsTap(r *approval.Request, n int) {
	e.t.Helper()
	ch := e.decide(r)
	mustWait(e.t, ch)
	e.asked(n)
	e.tap(n, audit.AnswerApproveOnce)
	checkAllowed(e.t, mustResult(e.t, ch))
}

// asks checks that r needs a message: it waits, and the core asked for
// message n. Then it denies it, and waits out the pause after the Deny.
// The Deny ends the client's grants for the secrets or the key of r.
func (e *env) asks(r *approval.Request, n int) {
	e.t.Helper()
	ch := e.decide(r)
	mustWait(e.t, ch)
	e.asked(n)
	e.tap(n, audit.AnswerDeny)
	checkDenied(e.t, mustResult(e.t, ch), audit.CauseApprover)
	e.clock.Advance(approval.DenyPause)
}

// TestGrantScopeSecret checks that a grant covers (client, secret) only.
func TestGrantScopeSecret(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1)

		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		// Another secret, another client, and a request that holds a
		// secret without a grant: each needs a message.
		e.needsTap(secretsReq("laptop", "npm-token"), 2)
		e.needsTap(secretsReq("build", "github-token"), 3)
		e.needsTap(secretsReq("laptop", "github-token", "npm-token"), 4)
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
	})
}

// TestGrantScopeSSH checks that a grant from a login covers (client, key,
// host key, remote user) only: not another remote user, not another host
// key of the same host, not another host, key or client (DESIGN.md
// section 8).
func TestGrantScopeSSH(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		h := e.hosts
		e.approveWindow(loginReq("laptop", "deploy", h.web1, "deploy"), 1)

		r := e.now(loginReq("laptop", "deploy", h.web1, "deploy"))
		checkAllowed(t, r)
		checkEvents(t, r, "request", "grant_used:grant")

		n := 1
		for _, req := range []*approval.Request{
			loginReq("laptop", "deploy", h.web1, "root"),        // another remote user
			loginReq("laptop", "deploy", h.web1ecdsa, "deploy"), // another host key of web-1
			loginReq("laptop", "deploy", h.web2, "deploy"),      // another host
			loginReq("laptop", "web", h.web1, "deploy"),         // another key
			loginReq("build", "deploy", h.web1, "deploy"),       // another client
		} {
			n++
			e.needsTap(req, n)
		}
		// The grant still covers its own scope.
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web1, "deploy")))
	})
}

// TestGrantEnds checks that a grant ends N minutes after the tap, and that
// using it does not make it longer.
func TestGrantEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.clock.Advance(10 * time.Second) // the time the person needs to tap
		e.approveWindow(secretsReq("laptop", "npm-token"), 1)
		for range 4 {
			e.clock.Advance(time.Minute)
			checkAllowed(t, e.now(secretsReq("laptop", "npm-token")))
		}
		e.clock.Advance(time.Minute - time.Nanosecond)
		checkAllowed(t, e.now(secretsReq("laptop", "npm-token")))
		e.clock.Advance(time.Nanosecond)
		e.asks(secretsReq("laptop", "npm-token"), 2)
	})
}

// TestGrantStartsLate checks that a late StartGrants does not move the end
// of the grants, and that a second call does nothing.
func TestGrantStartsLate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		ch := e.decide(secretsReq("laptop", "npm-token"))
		mustWait(t, ch)
		e.asked(1)
		e.tap(1, audit.AnswerApproveWindow)
		r := mustResult(t, ch)
		e.clock.Advance(4 * time.Minute)
		r.StartGrants()
		r.StartGrants()
		e.clock.Advance(time.Minute - time.Nanosecond)
		checkAllowed(t, e.now(secretsReq("laptop", "npm-token")))
		e.clock.Advance(time.Nanosecond)
		e.asks(secretsReq("laptop", "npm-token"), 2)

		// A grant that has already ended does not start.
		ch = e.decide(secretsReq("laptop", "npm-token"))
		mustWait(t, ch)
		e.asked(3)
		e.tap(3, audit.AnswerApproveWindow)
		r = mustResult(t, ch)
		e.clock.Advance(5 * time.Minute)
		r.StartGrants()
		e.asks(secretsReq("laptop", "npm-token"), 4)
	})
}

// TestStartGrantsOnlyForWindow checks that StartGrants makes no grant for
// an approve_once answer, a deny, or a result from outside the core.
func TestStartGrantsOnlyForWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		for i, action := range []audit.Answer{audit.AnswerApproveOnce, audit.AnswerDeny} {
			ch := e.decide(secretsReq("laptop", "github-token"))
			mustWait(t, ch)
			e.asked(i + 1)
			e.tap(i+1, action)
			mustResult(t, ch).StartGrants()
		}
		e.clock.Advance(approval.DenyPause)
		(&approval.Result{Allowed: true, WindowMinutes: 15, Answer: audit.AnswerApproveWindow}).StartGrants()
		var none *approval.Result
		none.StartGrants()
		e.asks(secretsReq("laptop", "github-token"), 3)
	})
}

// TestGrantNewApprovalKeepsTheLaterEnd checks that a second "Approve N
// min" for one scope keeps the end that is later.
func TestGrantNewApprovalKeepsTheLaterEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		// github-token has 15 minutes, npm-token 5. A request for both
		// gives 5 minutes to each; github-token keeps its 15.
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		r := e.approveWindow(secretsReq("laptop", "github-token", "npm-token"), 2)
		if r.WindowMinutes != 5 {
			t.Errorf("window %d minutes, want 5, the shorter one", r.WindowMinutes)
		}
		e.clock.Advance(5 * time.Minute)
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		e.asks(secretsReq("laptop", "npm-token"), 3)
		e.clock.Advance(9 * time.Minute) // 15 minutes after the first tap, with the pause
		e.asks(secretsReq("laptop", "github-token"), 4)
	})
}

// TestWindowChoice checks the "Approve N min" button: only if every item
// has the "window" rule, and N is the shortest window in whole minutes,
// rounded down.
func TestWindowChoice(t *testing.T) {
	for _, tt := range []struct {
		name    string
		windows map[string]time.Duration // secret → window; 0 is an "always" rule
		secrets []string
		want    int
	}{
		{"one secret", map[string]time.Duration{"github-token": 15 * time.Minute}, []string{"github-token"}, 15},
		{"the shortest window", map[string]time.Duration{"github-token": 15 * time.Minute, "npm-token": 5 * time.Minute},
			[]string{"github-token", "npm-token"}, 5},
		{"one without a window", map[string]time.Duration{"github-token": 15 * time.Minute, "npm-token": 0},
			[]string{"github-token", "npm-token"}, 0},
		{"rounded down", map[string]time.Duration{"github-token": 90 * time.Second}, []string{"github-token"}, 1},
		{"8 hours", map[string]time.Duration{"github-token": config.MaxWindow}, []string{"github-token"}, 480},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, func(cfg *config.Broker) {
					for name, w := range tt.windows {
						if w == 0 {
							setSecretRule(cfg, name, config.Rule{Ask: config.AskAlways})
						} else {
							setSecretRule(cfg, name, config.Rule{Ask: config.AskWindow, Window: w})
						}
					}
				})
				defer e.stop()
				ch := e.decide(secretsReq("laptop", tt.secrets...))
				mustWait(t, ch)
				p := e.asked(1)[0].Prompt
				if p.WindowMinutes != tt.want || !p.Once {
					t.Errorf("window %d, once %v; want window %d and once", p.WindowMinutes, p.Once, tt.want)
				}
				if tt.want == 0 {
					// The deny path: no button, so the tap does not count.
					err := e.answer(1, func(a *approval.Answer) { a.Action = audit.AnswerApproveWindow })
					if !errors.Is(err, approval.ErrNotAllowed) {
						t.Errorf("Approve N min without the button: %v, want ErrNotAllowed", err)
					}
					mustWait(t, ch)
					e.tap(1, audit.AnswerDeny)
					checkDenied(t, mustResult(t, ch), audit.CauseApprover)
					return
				}
				e.tap(1, audit.AnswerApproveWindow)
				r := mustResult(t, ch)
				checkAllowed(t, r)
				if r.WindowMinutes != tt.want {
					t.Errorf("result window %d, want %d", r.WindowMinutes, tt.want)
				}
				r.StartGrants()
				// The grant lasts exactly N whole minutes.
				e.clock.Advance(time.Duration(tt.want)*time.Minute - time.Nanosecond)
				checkAllowed(t, e.now(secretsReq("laptop", tt.secrets...)))
				e.clock.Advance(time.Nanosecond)
				e.asks(secretsReq("laptop", tt.secrets...), 2)
			})
		})
	}
}

// TestSSHGrant checks the pre-approval of nodkey ssh-grant (DESIGN.md
// section 13): one tap makes a grant for each host key of each listed
// host, for that remote user, until the end shown in the message.
func TestSSHGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		h := e.hosts

		ch := e.decide(grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1", "web-2", "web-1"))
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		ends := noon.Add(15 * time.Minute)
		if p.Kind != audit.KindSSHGrant || !reflect.DeepEqual(p.Hosts, []string{"web-1", "web-2"}) ||
			p.Key != "deploy" || p.RemoteUser != "deploy" || p.HostKey != "" || !p.GrantEnds.Equal(ends) {
			t.Errorf("prompt %+v; want deploy@web-1 and web-2 until %v", p, ends)
		}
		if p.Once || p.WindowMinutes != 15 {
			t.Errorf("buttons: once %v, window %d; want only Approve 15 min and Deny", p.Once, p.WindowMinutes)
		}
		if p.TimeLeft != secretsTimeout {
			t.Errorf("an SSH grant has %v to be answered, want %v (it is not a login)", p.TimeLeft, secretsTimeout)
		}
		if err := e.answer(1, func(a *approval.Answer) { a.Action = audit.AnswerApproveOnce }); !errors.Is(err, approval.ErrNotAllowed) {
			t.Errorf("Approve once on an SSH grant: %v, want ErrNotAllowed", err)
		}

		// The person taps after one minute; the grants still end at the
		// time the message showed.
		e.clock.Advance(time.Minute)
		e.tap(1, audit.AnswerApproveWindow)
		r := mustResult(t, ch)
		checkAllowed(t, r)
		checkEvents(t, r, "request", "decision:approve_window")
		if r.WindowMinutes != 15 || !reflect.DeepEqual(r.Subject.Hosts, []string{"web-1", "web-2"}) {
			t.Errorf("window %d, hosts %v; want 15 and web-1, web-2", r.WindowMinutes, r.Subject.Hosts)
		}

		// Before StartGrants, nothing is granted.
		n := 2
		e.needsTap(loginReq("laptop", "deploy", h.web1, "deploy"), n)
		r.StartGrants()
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web1, "deploy")))
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web1ecdsa, "deploy")))
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web2, "deploy")))
		// Not another host, user, key or client.
		for _, req := range []*approval.Request{
			loginReq("laptop", "deploy", h.web3, "deploy"),
			loginReq("laptop", "deploy", h.web1, "root"),
			loginReq("laptop", "web", h.web1, "deploy"),
			loginReq("build", "deploy", h.web1, "deploy"),
		} {
			n++
			e.needsTap(req, n)
		}
		e.clock.Advance(ends.Sub(e.clock.Now()) - time.Nanosecond)
		checkAllowed(t, e.now(loginReq("laptop", "deploy", h.web2, "deploy")))
		e.clock.Advance(time.Nanosecond)
		n++
		e.asks(loginReq("laptop", "deploy", h.web2, "deploy"), n)
	})
}

// TestSSHGrantDeny checks the deny path of an SSH grant: no grants, and a
// pause for the key.
func TestSSHGrantDeny(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		ch := e.decide(grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1"))
		mustWait(t, ch)
		e.asked(1)
		e.tap(1, audit.AnswerDeny)
		r := mustResult(t, ch)
		checkDenied(t, r, audit.CauseApprover)
		r.StartGrants()
		checkDenied(t, e.now(loginReq("laptop", "deploy", e.hosts.web1, "deploy")), audit.CauseLimit)
		e.clock.Advance(approval.DenyPause)
		e.asks(loginReq("laptop", "deploy", e.hosts.web1, "deploy"), 2)
	})
}

// TestSSHGrantRefused checks each refusal of DESIGN.md section 13. The
// broker refuses these without a message.
func TestSSHGrantRefused(t *testing.T) {
	var many []string
	for i := 1; i <= approval.MaxGrantHosts+1; i++ {
		many = append(many, fmt.Sprintf("more-%d", i))
	}
	for _, tt := range []struct {
		name string
		req  *approval.Request
	}{
		{"bad remote user", grantReq("laptop", "deploy", "root;", 15*time.Minute, "web-1")},
		{"no remote user", grantReq("laptop", "deploy", "", 15*time.Minute, "web-1")},
		{"key rule always", grantReq("laptop", "admin", "deploy", 15*time.Minute, "web-1")},
		{"key rule never", grantReq("ci", "backup", "backup", 15*time.Minute, "db-1")},
		{"longer than the window", grantReq("laptop", "deploy", "deploy", 15*time.Minute+time.Second, "web-1")},
		{"under a minute", grantReq("laptop", "deploy", "deploy", 59*time.Second, "web-1")},
		{"no time", grantReq("laptop", "deploy", "deploy", 0, "web-1")},
		{"a time below 0", grantReq("laptop", "deploy", "deploy", -time.Minute, "web-1")},
		{"unknown host", grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1", "web-9")},
		{"host not in the key's hosts", grantReq("laptop", "web", "deploy", 15*time.Minute, "web-1", "web-3")},
		{"no host", grantReq("laptop", "deploy", "deploy", 15*time.Minute)},
		{"more than 20 hosts", grantReq("laptop", "deploy", "deploy", 15*time.Minute, many...)},
		{"unknown key", grantReq("laptop", "nope", "deploy", 15*time.Minute, "web-1")},
		{"key of another client", grantReq("build", "web", "deploy", 15*time.Minute, "web-1")},
		{"with a host key", func() *approval.Request {
			r := grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1")
			r.HostKey = newEd25519Key(t)
			return r
		}()},
		{"with secrets", func() *approval.Request {
			r := grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1")
			r.Secrets = []string{"github-token"}
			return r
		}()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, nil)
				defer e.stop()
				r := e.now(tt.req)
				checkDenied(t, r, audit.CauseNotAllowed)
				e.asked(0)
				if len(r.Subject.Hosts) > approval.MaxGrantHosts {
					t.Errorf("the subject lists %d hosts", len(r.Subject.Hosts))
				}
			})
		})
	}
}

// TestSSHGrantLimits checks the good edges: 20 hosts, and a time of the
// whole window, and that the time counts in whole minutes.
func TestSSHGrantLimits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		var hosts []string
		for i := 1; i <= approval.MaxGrantHosts; i++ {
			hosts = append(hosts, fmt.Sprintf("more-%d", i))
		}
		ch := e.decide(grantReq("laptop", "deploy", "deploy", 14*time.Minute+59*time.Second, hosts...))
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		if len(p.Hosts) != approval.MaxGrantHosts || p.WindowMinutes != 14 || !p.GrantEnds.Equal(noon.Add(14*time.Minute)) {
			t.Errorf("%d hosts, window %d, ends %v; want 20 hosts, 14 minutes", len(p.Hosts), p.WindowMinutes, p.GrantEnds)
		}
		e.tap(1, audit.AnswerApproveWindow)
		r := mustResult(t, ch)
		checkAllowed(t, r)
		r.StartGrants()
		checkAllowed(t, e.now(loginReq("laptop", "deploy", e.hosts.more[19], "deploy")))
		e.asks(loginReq("laptop", "deploy", e.hosts.more[20], "deploy"), 2) // more-21 is not in the list
	})
}

// TestDenyEndsGrants checks that the person's Deny ends the client's
// grants for each secret of the denied request, at once. Before, the agent
// still got the secret by its grant right after the Deny. Grants of other
// secrets and of other clients stay. (From the security review of issue
// #6.)
func TestDenyEndsGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		e.approveWindow(secretsReq("laptop", "npm-token"), 2)
		e.approveWindow(secretsReq("build", "github-token"), 3)

		ch := e.decide(secretsReq("laptop", "github-token", "db-password"))
		mustWait(t, ch)
		e.asked(4)
		e.tap(4, audit.AnswerDeny)
		checkDenied(t, mustResult(t, ch), audit.CauseApprover)

		// The grant has ended, and the pause holds a new request.
		r := e.now(secretsReq("laptop", "github-token"))
		checkDenied(t, r, audit.CauseLimit)
		checkEvents(t, r, "request", "denied:limit")
		checkAllowed(t, e.now(secretsReq("laptop", "npm-token")))
		checkAllowed(t, e.now(secretsReq("build", "github-token")))
		e.clock.Advance(approval.DenyPause)
		e.needsTap(secretsReq("laptop", "github-token"), 5)
	})
}

// TestDenyEndsSSHGrants checks the scope that a Deny ends for a key: all
// of the client's grants for that key, at every host key and for every
// remote user, as wide as the pause. Grants of other keys and of other
// clients stay.
func TestDenyEndsSSHGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		h := e.hosts
		e.approveWindow(grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1", "web-2"), 1)
		e.approveWindow(loginReq("laptop", "deploy", h.web3, "root"), 2)
		e.approveWindow(loginReq("laptop", "web", h.web1, "deploy"), 3)
		e.approveWindow(loginReq("build", "deploy", h.web1, "deploy"), 4)

		// A Deny for a login with deploy to db-1.
		ch := e.decide(loginReq("laptop", "deploy", h.db1, "deploy"))
		mustWait(t, ch)
		e.asked(5)
		e.tap(5, audit.AnswerDeny)
		mustResult(t, ch)
		e.clock.Advance(approval.DenyPause)

		n := 5
		for _, req := range []*approval.Request{
			loginReq("laptop", "deploy", h.web1, "deploy"),
			loginReq("laptop", "deploy", h.web1ecdsa, "deploy"),
			loginReq("laptop", "deploy", h.web2, "deploy"),
			loginReq("laptop", "deploy", h.web3, "root"),
		} {
			n++
			e.needsTap(req, n)
		}
		checkAllowed(t, e.now(loginReq("laptop", "web", h.web1, "deploy")))
		checkAllowed(t, e.now(loginReq("build", "deploy", h.web1, "deploy")))
	})
}

// TestDenyStopsAGrantNotStarted checks a Deny that comes after an "Approve
// N min" tap, but before the broker called StartGrants for it: that grant
// does not start. A tap after the Deny makes a grant again.
func TestDenyStopsAGrantNotStarted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chA := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, chA)
		chB := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, chB)
		e.asked(2)
		e.tap(1, audit.AnswerApproveWindow)
		rA := mustResult(t, chA)
		checkAllowed(t, rA)
		e.tap(2, audit.AnswerDeny)
		mustResult(t, chB)
		rA.StartGrants() // the decision of A is on disk only now
		e.clock.Advance(approval.DenyPause)
		e.needsTap(secretsReq("laptop", "github-token"), 3)

		e.approveWindow(secretsReq("laptop", "github-token"), 4)
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
	})
}

// TestSSHGrantEndsWithItsGrants checks that a request for an SSH grant
// waits only until its grants would end, when that comes before its
// timeout. Before, a tap after that end gave an approval that granted
// nothing. (From the security review of issue #6.)
func TestSSHGrantEndsWithItsGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) { cfg.Telegram.Timeout = 10 * time.Minute })
		defer e.stop()
		ch := e.decide(grantReq("laptop", "deploy", "deploy", time.Minute, "web-1"))
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		if p.TimeLeft != time.Minute || !p.Expires.Equal(p.GrantEnds) {
			t.Errorf("time left %v, expires %v, grant ends %v; want 1m, and the same end", p.TimeLeft, p.Expires, p.GrantEnds)
		}
		e.clock.Advance(time.Minute - time.Nanosecond)
		mustWait(t, ch)
		e.clock.Advance(time.Nanosecond)
		r := mustResult(t, ch)
		checkDenied(t, r, audit.CauseExpired)
		if err := e.fake.Tap(p.RequestID, audit.AnswerApproveWindow); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("a tap after the end: %v, want ErrUnknownRequest", err)
		}
	})
}

// TestGrantEndsOnTheWallClock checks a grant across a host that slept, and
// across a wall clock that was set back: it ends when either clock reaches
// its end.
func TestGrantEndsOnTheWallClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		e.clock.Advance(5 * time.Minute)
		e.clock.JumpWall(8 * time.Hour) // the host slept: the monotonic clock stopped
		e.needsTap(secretsReq("laptop", "github-token"), 2)

		e.approveWindow(secretsReq("laptop", "npm-token"), 3)
		e.clock.JumpWall(-time.Hour) // the wall clock is set back
		e.clock.Advance(5*time.Minute - time.Nanosecond)
		checkAllowed(t, e.now(secretsReq("laptop", "npm-token")))
		e.clock.Advance(time.Nanosecond)
		e.needsTap(secretsReq("laptop", "npm-token"), 4)
	})
}

// TestWallClockBackDoesNotExtend checks that a wall clock set back makes
// neither a grant nor a waiting request last longer: the monotonic clock
// still ends them. (From the second security review of issue #6.)
func TestWallClockBackDoesNotExtend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "npm-token"), 1) // 5 minutes
		ch := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, ch)
		e.asked(2)
		e.clock.JumpWall(-time.Hour)
		e.clock.Advance(secretsTimeout) // the time of the request is up on the monotonic clock
		checkDenied(t, mustResult(t, ch), audit.CauseExpired)
		e.clock.Advance(5*time.Minute - secretsTimeout)
		e.asks(secretsReq("laptop", "npm-token"), 3) // the grant has ended
	})
}

// TestWallClockForwardEndsWhatExists checks that a wall clock set forward
// ends the grants and the waiting requests at once (fail closed), and that
// new requests after it work as usual. (From the second security review
// of issue #6.)
func TestWallClockForwardEndsWhatExists(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1) // 15 minutes
		ch := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, ch)
		e.asked(2)
		e.clock.JumpWall(time.Hour)
		if err := e.answer(2, nil); !errors.Is(err, approval.ErrExpired) {
			t.Fatalf("a tap after the jump: %v, want ErrExpired", err)
		}
		e.clock.Advance(secretsTimeout)
		checkDenied(t, mustResult(t, ch), audit.CauseExpired)
		// The grant has ended; a new request asks, and a tap counts.
		e.needsTap(secretsReq("laptop", "github-token"), 3)
	})
}

// TestDenyIsPerClientAndOrdered checks that a Deny for one client leaves
// the grants, pauses and requests of another client alone, and that a grant
// from a tap after the Deny starts. (From the second security review of
// issue #6.)
func TestDenyIsPerClientAndOrdered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		// build waits for github-token; the request of laptop for it is
		// denied.
		chB := e.decide(secretsReq("build", "github-token"))
		mustWait(t, chB)
		chL := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, chL)
		e.asked(2)
		e.tap(2, audit.AnswerDeny)
		checkDenied(t, mustResult(t, chL), audit.CauseApprover)
		mustWait(t, chB)
		e.tap(1, audit.AnswerApproveWindow)
		rB := mustResult(t, chB)
		checkAllowed(t, rB)
		rB.StartGrants()
		checkAllowed(t, e.now(secretsReq("build", "github-token"))) // the grant of build started
		checkDenied(t, e.now(secretsReq("laptop", "github-token")), audit.CauseLimit)
		// After the pause, laptop asks; a tap after the Deny makes a grant.
		e.clock.Advance(approval.DenyPause)
		e.approveWindow(secretsReq("laptop", "github-token"), 3)
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
	})
}
