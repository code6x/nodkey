package approval_test

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"
	_ "time/tzdata" // for TestRuleNeverHoursDST on hosts without time zone files

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// TestRuleAlways checks ask = "always": every request gets a message with
// "Approve once" and "Deny", and no "Approve N min".
func TestRuleAlways(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()

		ch := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		if !p.Once || p.WindowMinutes != 0 {
			t.Errorf("buttons: once %v, window %d; want only Approve once and Deny", p.Once, p.WindowMinutes)
		}
		// "Approve N min" is not on the message, so it does not count.
		if err := e.answer(1, func(a *approval.Answer) { a.Action = audit.AnswerApproveWindow }); !errors.Is(err, approval.ErrNotAllowed) {
			t.Errorf("Approve N min on an always rule: %v, want ErrNotAllowed", err)
		}
		mustWait(t, ch)
		e.tap(1, audit.AnswerApproveOnce)
		r := mustResult(t, ch)
		checkAllowed(t, r)
		checkEvents(t, r, "request", "decision:approve_once")
		if r.Message == "" || r.Message != e.fake.Asked()[0].Text || r.UserID != approverID {
			t.Errorf("message %q, user %d; want the text that was shown and the approver", r.Message, r.UserID)
		}

		// The next request asks again: "Approve once" makes no grant.
		r.StartGrants()
		ch = e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, ch)
		e.asked(2)

		// The deny path.
		e.tap(2, audit.AnswerDeny)
		r = mustResult(t, ch)
		checkDenied(t, r, audit.CauseApprover)
		checkEvents(t, r, "request", "decision:deny", "denied:approver")
	})
}

// TestRuleWindow checks ask = "window": the message has "Approve N min",
// and that tap makes a grant for the next N minutes, once its decision is
// on disk.
func TestRuleWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()

		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		if !p.Once || p.WindowMinutes != 15 {
			t.Errorf("buttons: once %v, window %d; want Approve once and Approve 15 min", p.Once, p.WindowMinutes)
		}
		e.tap(1, audit.AnswerApproveWindow)
		r := mustResult(t, ch)
		checkAllowed(t, r)
		if r.WindowMinutes != 15 {
			t.Errorf("window %d minutes, want 15", r.WindowMinutes)
		}
		checkEvents(t, r, "request", "decision:approve_window")

		// Until StartGrants, there is no grant: the decision may not be on
		// disk yet.
		ch = e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.asked(2)
		e.tap(2, audit.AnswerApproveOnce)
		checkAllowed(t, mustResult(t, ch))

		r.StartGrants()
		r2 := e.now(secretsReq("laptop", "github-token"))
		checkAllowed(t, r2)
		checkEvents(t, r2, "request", "grant_used:grant")
		if r2.Message != "" {
			t.Errorf("a request that a grant allows has the message %q, want none", r2.Message)
		}
		e.asked(2) // no new message

		// The grant started at the tap, so it ends 15 minutes after it.
		e.clock.Advance(15*time.Minute - time.Nanosecond)
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		e.clock.Advance(time.Nanosecond)
		ch = e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.asked(3)
	})
}

// TestRuleNever checks ask = "never": the request is allowed without a
// message, and a silent notice goes out unless notify = false.
func TestRuleNever(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()

		r := e.now(secretsReq("ci", "backup-token"))
		checkAllowed(t, r)
		checkEvents(t, r, "request", "grant_used:never_rule")
		e.asked(0)
		notices := e.fake.Notices()
		if len(notices) != 1 {
			t.Fatalf("%d notices, want 1", len(notices))
		}
		if n := notices[0]; n.Once || n.WindowMinutes != 0 || n.RequestID != r.RequestID ||
			n.Client != "ci" || len(n.Secrets) != 1 || n.Secrets[0] != "backup-token" {
			t.Errorf("notice %+v; want the request without buttons", n)
		}

		// The deny path: no notice, so the use is denied.
		e.fake.FailNotify(errors.New("telegram is down"))
		r = e.now(secretsReq("ci", "backup-token"))
		checkDenied(t, r, audit.CauseError)
		if r.ErrorCode != audit.CodeApproverFailed || r.Err == nil {
			t.Errorf("code %q, err %v; want approver_failed and the error", r.ErrorCode, r.Err)
		}
		checkEvents(t, r, "request", "error:approver_failed", "denied:error")
	})
}

// TestRuleNeverNoticeFails checks a "never ask" use whose notice fails for
// another reason than a limit of the approver: it is still denied with
// cause error, and it still counts for max_per_day, because the notice may
// have gone out. So with max_per_day = 1, the next use asks the person.
// Only a limit of the approver does not count (issue #47).
func TestRuleNeverNoticeFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 1})
		})
		defer e.stop()
		down := errors.New("telegram cannot be reached")
		e.fake.FailNotify(down)
		r := e.now(secretsReq("ci", "backup-token"))
		checkDenied(t, r, audit.CauseError)
		if r.ErrorCode != audit.CodeApproverFailed || !errors.Is(r.Err, down) || errors.Is(r.Err, approval.ErrLimit) {
			t.Errorf("code %q, err %v; want approver_failed and the error", r.ErrorCode, r.Err)
		}
		checkEvents(t, r, "request", "error:approver_failed", "denied:error")

		// The use counted: the next one asks, also when notices work again.
		e.fake.FailNotify(nil)
		ch := e.decide(secretsReq("ci", "backup-token"))
		mustWait(t, ch)
		e.asked(1)
		if n := len(e.fake.Notices()); n != 0 {
			t.Errorf("%d notices, want 0", n)
		}
	})
}

// TestRuleNeverWithoutNotify checks that notify = false sends no notice.
func TestRuleNeverWithoutNotify(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: false})
		})
		defer e.stop()
		e.fake.FailNotify(errors.New("a notice must not be sent"))
		checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		if n := len(e.fake.Notices()); n != 0 {
			t.Errorf("%d notices, want 0", n)
		}
	})
}

// TestRuleNeverKey checks a "never" rule of a key: logins to its hosts go
// without a message, logins to other hosts are denied.
func TestRuleNeverKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		r := e.now(loginReq("ci", "backup", e.hosts.db1, "backup"))
		checkAllowed(t, r)
		checkEvents(t, r, "request", "grant_used:never_rule")
		if len(e.fake.Notices()) != 1 {
			t.Errorf("%d notices, want 1", len(e.fake.Notices()))
		}
		// web-1 is not in the key's hosts.
		r = e.now(loginReq("ci", "backup", e.hosts.web1, "backup"))
		checkDenied(t, r, audit.CauseNotAllowed)
		e.asked(0)
	})
}

// TestRuleNeverHours checks hours: inside them the rule allows the request
// without a tap; outside them the broker asks as for "always", in the
// local time of the clock.
func TestRuleNeverHours(t *testing.T) {
	east := time.FixedZone("UTC+3", 3*60*60)
	for _, tt := range []struct {
		name  string
		hours string
		at    time.Time
		asks  bool
	}{
		{"inside", "03:00-03:20", time.Date(2026, 10, 14, 3, 10, 0, 0, time.UTC), false},
		{"at the start", "03:00-03:20", time.Date(2026, 10, 14, 3, 0, 0, 0, time.UTC), false},
		{"at the end", "03:00-03:20", time.Date(2026, 10, 14, 3, 20, 0, 0, time.UTC), true},
		{"before", "03:00-03:20", time.Date(2026, 10, 14, 2, 59, 59, 0, time.UTC), true},
		{"at noon", "03:00-03:20", noon, true},
		{"past midnight", "23:30-00:30", time.Date(2026, 10, 15, 0, 10, 0, 0, time.UTC), false},
		// 00:10 UTC is 03:10 three hours east.
		{"in the clock's location", "03:00-03:20", time.Date(2026, 10, 14, 0, 10, 0, 0, time.UTC).In(east), false},
		{"not in UTC", "03:00-03:20", time.Date(2026, 10, 14, 3, 10, 0, 0, time.UTC).In(east), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, h := testConfig(t)
				hours := parseHours(t, tt.hours)
				setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, Hours: &hours})
				e := newEnvWith(t, cfg, h, approvaltest.NewClock(tt.at))
				defer e.stop()

				ch := e.decide(secretsReq("ci", "backup-token"))
				if !tt.asks {
					r := mustResult(t, ch)
					checkAllowed(t, r)
					checkEvents(t, r, "request", "grant_used:never_rule")
					return
				}
				mustWait(t, ch)
				p := e.asked(1)[0].Prompt
				if !p.Once || p.WindowMinutes != 0 {
					t.Errorf("buttons: once %v, window %d; want only Approve once and Deny", p.Once, p.WindowMinutes)
				}
				if len(e.fake.Notices()) != 0 {
					t.Error("a notice for a request that asks the person")
				}
				e.tap(1, audit.AnswerDeny)
				checkDenied(t, mustResult(t, ch), audit.CauseApprover)
			})
		})
	}
}

// TestRuleNeverMaxPerDay checks max_per_day: over the limit the broker
// asks, and the next day the count starts again.
func TestRuleNeverMaxPerDay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 2})
		})
		defer e.stop()

		for range 2 {
			checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		}
		// The third use asks; the person's answer is not a use of the rule.
		ch := e.decide(secretsReq("ci", "backup-token"))
		mustWait(t, ch)
		e.asked(1)
		e.tap(1, audit.AnswerApproveOnce)
		r := mustResult(t, ch)
		checkAllowed(t, r)
		checkEvents(t, r, "request", "decision:approve_once")

		// The deny path.
		ch = e.decide(secretsReq("ci", "backup-token"))
		mustWait(t, ch)
		e.asked(2)
		e.tap(2, audit.AnswerDeny)
		checkDenied(t, mustResult(t, ch), audit.CauseApprover)

		// A new day starts at midnight, in the clock's location.
		e.clock.Advance(12*time.Hour - time.Second)
		ch = e.decide(secretsReq("ci", "backup-token"))
		mustWait(t, ch)
		e.asked(3)
		e.tap(3, audit.AnswerApproveOnce)
		mustResult(t, ch)
		e.clock.Advance(time.Second)
		for range 2 {
			checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		}
		ch = e.decide(secretsReq("ci", "backup-token"))
		mustWait(t, ch)
		e.asked(4)
	})
}

// TestRuleNeverMaxPerDayAtOnce checks that requests at the same time
// cannot use more than max_per_day: counting is under the lock.
func TestRuleNeverMaxPerDayAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 3})
		})
		defer e.stop()
		var chs []<-chan *approval.Result
		for range approval.MaxOpenMessages + 3 {
			chs = append(chs, e.decide(secretsReq("ci", "backup-token")))
		}
		synctest.Wait()
		allowed := 0
		for _, ch := range chs {
			select {
			case r := <-ch:
				checkAllowed(t, r)
				allowed++
			default: // waits for the person
			}
		}
		if allowed != 3 || len(e.fake.Asked()) != approval.MaxOpenMessages {
			t.Errorf("%d allowed without a tap and %d messages, want 3 and %d",
				allowed, len(e.fake.Asked()), approval.MaxOpenMessages)
		}
	})
}

// TestRuleNotKnownDenies checks that an ask value other than "always",
// "window" or "never", also the empty one, denies the request without a
// message: for a secret, and for a key. This is the zero Rule, and any
// rule that LoadBroker did not make.
func TestRuleNotKnownDenies(t *testing.T) {
	for _, ask := range []config.Ask{"", "sometimes", "ALWAYS", "Never", "window "} {
		t.Run(string(ask), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, func(cfg *config.Broker) {
					setSecretRule(cfg, "npm-token", config.Rule{Ask: ask, Window: 5 * time.Minute})
					setKeyRule(cfg, "deploy", config.Rule{Ask: ask, Window: 15 * time.Minute})
				})
				defer e.stop()
				for _, req := range []*approval.Request{
					secretsReq("laptop", "npm-token"),
					// One bad rule denies the whole request.
					secretsReq("laptop", "github-token", "npm-token"),
					loginReq("laptop", "deploy", e.hosts.web1, "deploy"),
					grantReq("laptop", "deploy", "deploy", 15*time.Minute, "web-1"),
				} {
					r := e.now(req)
					checkDenied(t, r, audit.CauseNotAllowed)
					checkEvents(t, r, "request", "denied:not_allowed")
				}
				e.asked(0)
				if len(e.fake.Notices()) != 0 {
					t.Error("a notice for a rule that is not known")
				}
			})
		})
	}
}

// TestRuleNeverKeyWithoutHostsDenies checks that a "never" rule for a key
// with no hosts denies, also for a host that is known. An empty hosts
// list means any host only for the other rules.
func TestRuleNeverKeyWithoutHostsDenies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			k := cfg.Keys["backup"]
			k.Hosts = nil
			cfg.Keys["backup"] = k
		})
		defer e.stop()
		for _, r := range []*approval.Result{
			e.now(loginReq("ci", "backup", e.hosts.db1, "backup")),
			e.now(loginReq("ci", "backup", e.hosts.web1, "backup")),
		} {
			checkDenied(t, r, audit.CauseNotAllowed)
		}
		e.asked(0)
		if len(e.fake.Notices()) != 0 {
			t.Error("a notice for a denied request")
		}
	})
}

// TestRuleNotValidDenies checks rules that LoadBroker refuses: the core
// denies them too.
func TestRuleNotValidDenies(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*config.Broker)
	}{
		{"window 0", func(cfg *config.Broker) {
			setSecretRule(cfg, "npm-token", config.Rule{Ask: config.AskWindow})
		}},
		{"window below 0", func(cfg *config.Broker) {
			setSecretRule(cfg, "npm-token", config.Rule{Ask: config.AskWindow, Window: -time.Minute})
		}},
		{"window under a minute", func(cfg *config.Broker) {
			setSecretRule(cfg, "npm-token", config.Rule{Ask: config.AskWindow, Window: config.MinWindow - time.Nanosecond})
		}},
		{"window over 8 hours", func(cfg *config.Broker) {
			setSecretRule(cfg, "npm-token", config.Rule{Ask: config.AskWindow, Window: config.MaxWindow + time.Second})
		}},
		{"never for two clients", func(cfg *config.Broker) {
			s := cfg.Secrets["npm-token"]
			s.Clients = []string{"laptop", "build"}
			s.Rule = config.Rule{Ask: config.AskNever, Notify: true}
			cfg.Secrets["npm-token"] = s
		}},
		{"max_per_day below 0", func(cfg *config.Broker) {
			setSecretRule(cfg, "npm-token", config.Rule{Ask: config.AskNever, MaxPerDay: -1})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, tt.edit)
				defer e.stop()
				checkDenied(t, e.now(secretsReq("laptop", "npm-token")), audit.CauseNotAllowed)
				e.asked(0)
			})
		})
	}
}

// TestRuleNeverMaxPerDayCountsPerNight checks max_per_day with hours that
// go past midnight: the uses after midnight count for the day the hours
// began, so max_per_day = 1 gives one use a night, not two. (From the
// security review of issue #6.)
func TestRuleNeverMaxPerDayCountsPerNight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, h := testConfig(t)
		hours := parseHours(t, "23:30-00:30")
		setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 1, Hours: &hours})
		e := newEnvWith(t, cfg, h, approvaltest.NewClock(time.Date(2026, 10, 14, 23, 45, 0, 0, time.UTC)))
		defer e.stop()
		checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		e.clock.Advance(30 * time.Minute) // 00:15, the same night
		e.asks(secretsReq("ci", "backup-token"), 1)
		e.clock.Advance(23 * time.Hour) // 23:16 the next evening: outside the hours
		e.asks(secretsReq("ci", "backup-token"), 2)
		e.clock.Advance(30 * time.Minute) // 23:47, the next night
		checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
	})
}

// TestRuleNeverHoursDST checks hours in a time zone with summer time
// (DESIGN.md section 12). On the day the clocks go back, 03:00-03:20 comes
// twice, so the hours open twice; max_per_day = 1 still allows one use
// that day. On the day the clocks go forward, 03:00-03:59 does not exist,
// so the hours do not open. (From the security review of issue #6.)
func TestRuleNeverHoursDST(t *testing.T) {
	sofia, err := time.LoadLocation("Europe/Sofia")
	if err != nil {
		t.Fatal(err) // time/tzdata is in the test binary
	}
	hours := parseHours(t, "03:00-03:20")
	for _, tt := range []struct {
		name  string
		max   int
		start time.Time // in UTC
		uses  []bool    // the first use, and one an hour later: allowed without a tap?
	}{
		// 2026-10-25: at 04:00 summer time (01:00 UTC) the clocks go back
		// to 03:00 winter time. 00:05 UTC is 03:05 EEST, 01:05 UTC is 03:05
		// EET.
		{"autumn, no limit", 0, time.Date(2026, 10, 25, 0, 5, 0, 0, time.UTC), []bool{true, true}},
		{"autumn, max_per_day 1", 1, time.Date(2026, 10, 25, 0, 5, 0, 0, time.UTC), []bool{true, false}},
		// 2026-03-29: at 03:00 winter time (01:00 UTC) the clocks go forward
		// to 04:00 summer time. 00:59 UTC is 02:59 EET, 01:59 UTC is 04:59
		// EEST.
		{"spring", 0, time.Date(2026, 3, 29, 0, 59, 0, 0, time.UTC), []bool{false, false}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg, h := testConfig(t)
				setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: tt.max, Hours: &hours})
				e := newEnvWith(t, cfg, h, approvaltest.NewClock(tt.start.In(sofia)))
				defer e.stop()
				n := 0
				for i, free := range tt.uses {
					if i > 0 {
						e.clock.Advance(time.Hour)
					}
					if free {
						checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
						continue
					}
					n++
					e.asks(secretsReq("ci", "backup-token"), n)
				}
			})
		})
	}
	// The spring day has no 03:00-03:20 at all.
	for m := 0; m < 24*60; m++ {
		at := time.Date(2026, 3, 29, 0, 0, 0, 0, sofia).Add(time.Duration(m) * time.Minute)
		if hours.Contains(at) {
			t.Fatalf("the hours contain %s on the spring day", at.Format("15:04 MST"))
		}
	}
}
