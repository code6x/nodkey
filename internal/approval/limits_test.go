package approval_test

import (
	"context"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// fill starts n requests for db-password ("always") by laptop, one after
// the other, and returns their result channels. So the request i gets
// message i, if it gets one.
func (e *env) fill(n int) []<-chan *approval.Result {
	var chs []<-chan *approval.Result
	for range n {
		chs = append(chs, e.decide(secretsReq("laptop", "db-password")))
		synctest.Wait()
	}
	return chs
}

// TestLimitOpenMessages checks that a client has at most 5 messages that
// wait for an answer. The next request waits in the queue, without a
// message, and gets one when a place is free.
func TestLimitOpenMessages(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chs := e.fill(approval.MaxOpenMessages)
		e.asked(approval.MaxOpenMessages)

		var code string
		req := secretsReq("laptop", "db-password")
		req.OnWait = func(c string) { code = c }
		queued := e.decide(req)
		mustWait(t, queued)
		e.asked(approval.MaxOpenMessages) // no new message
		if code == "" {
			t.Error("OnWait was not called for a request in the queue")
		}

		e.tap(1, audit.AnswerApproveOnce)
		checkAllowed(t, mustResult(t, chs[0]))
		asked := e.asked(approval.MaxOpenMessages + 1)
		if p := asked[approval.MaxOpenMessages].Prompt; p.ShortCode != code {
			t.Errorf("the message of the queued request has code %q, OnWait got %q", p.ShortCode, code)
		}
		mustWait(t, queued)
		e.tap(approval.MaxOpenMessages+1, audit.AnswerApproveOnce)
		checkAllowed(t, mustResult(t, queued))
	})
}

// TestLimitNewMessagesPerMinute checks that a client gets at most 6 new
// messages in any 60 seconds, even when the person answers each at once.
func TestLimitNewMessagesPerMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		for i := 1; i <= approval.MaxNewMessagesPerMinute; i++ {
			ch := e.decide(secretsReq("laptop", "db-password"))
			mustWait(t, ch)
			e.asked(i)
			e.tap(i, audit.AnswerApproveOnce)
			mustResult(t, ch)
			e.clock.Advance(time.Second)
		}
		// 6 seconds after the first message. The seventh waits until the
		// first is a minute old.
		ch := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, ch)
		e.asked(approval.MaxNewMessagesPerMinute)
		e.clock.Advance(54*time.Second - time.Nanosecond)
		mustWait(t, ch)
		e.asked(approval.MaxNewMessagesPerMinute)
		e.clock.Advance(time.Nanosecond)
		mustWait(t, ch)
		p := e.asked(approval.MaxNewMessagesPerMinute + 1)[approval.MaxNewMessagesPerMinute].Prompt
		if p.TimeLeft != secretsTimeout-54*time.Second {
			t.Errorf("the message has %v left, want %v: the time in the queue counts", p.TimeLeft, secretsTimeout-54*time.Second)
		}
		// The next one waits for the second message to be a minute old.
		ch2 := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, ch2)
		e.asked(approval.MaxNewMessagesPerMinute + 1)
		e.clock.Advance(time.Second)
		mustWait(t, ch2)
		e.asked(approval.MaxNewMessagesPerMinute + 2)
	})
}

// TestLimitQueue checks that at most 10 requests wait in the queue. The
// next one is denied at once, without a message.
func TestLimitQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chs := e.fill(approval.MaxOpenMessages + approval.MaxQueued)
		for _, ch := range chs {
			mustWait(t, ch)
		}
		e.asked(approval.MaxOpenMessages)
		onWait := false
		req := secretsReq("laptop", "db-password")
		req.OnWait = func(string) { onWait = true }
		r := e.now(req)
		checkDenied(t, r, audit.CauseLimit)
		checkEvents(t, r, "request", "denied:limit")
		if r.Message != "" || onWait {
			t.Errorf("message %q, OnWait %v; want no message", r.Message, onWait)
		}
		e.asked(approval.MaxOpenMessages)
	})
}

// TestLimitQueueOrder checks that the queue lets requests out oldest
// first.
func TestLimitQueueOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.fill(approval.MaxOpenMessages)
		var codes []string
		for range 3 {
			req := secretsReq("laptop", "db-password")
			req.OnWait = func(c string) { codes = append(codes, c) }
			e.decide(req)
			synctest.Wait() // one after the other
		}
		for i := 1; i <= 3; i++ {
			e.tap(i, audit.AnswerApproveOnce)
			asked := e.asked(approval.MaxOpenMessages + i)
			if got := asked[approval.MaxOpenMessages+i-1].Prompt.ShortCode; got != codes[i-1] {
				t.Errorf("message %d is for %q, want %q, the queued request %d", approval.MaxOpenMessages+i, got, codes[i-1], i)
			}
			if i == 1 {
				// 6 messages in this minute: the next waits for the next.
				e.clock.Advance(time.Minute)
			}
		}
	})
}

// TestLimitDenyEndsQueued checks that a Deny also ends the requests for
// the same secret or key that wait in the queue of that client: their
// messages would come during the pause.
func TestLimitDenyEndsQueued(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.fill(approval.MaxOpenMessages)
		same := []<-chan *approval.Result{
			e.decide(secretsReq("laptop", "db-password")),
			e.decide(secretsReq("laptop", "npm-token", "db-password")),
		}
		other := e.decide(secretsReq("laptop", "npm-token"))
		synctest.Wait()
		e.tap(1, audit.AnswerDeny)
		for _, ch := range same {
			r := mustResult(t, ch)
			checkDenied(t, r, audit.CauseLimit)
			if r.Message != "" {
				t.Errorf("message %q, want none", r.Message)
			}
		}
		mustWait(t, other)
		asked := e.asked(approval.MaxOpenMessages + 1)
		if p := asked[approval.MaxOpenMessages].Prompt; len(p.Secrets) != 1 || p.Secrets[0] != "npm-token" {
			t.Errorf("the free place went to %v, want the request for npm-token", p.Secrets)
		}
		// The other open messages for db-password stay: the person answers
		// each.
		mustWait(t, e.decide(secretsReq("build", "github-token")))
		if n := len(e.fake.Ended()); n != 1 {
			t.Errorf("%d messages ended, want 1", n)
		}
	})
}

// TestLimitQueueTimeLeft checks that a request leaves the queue only with
// at least 30 seconds left. Otherwise it is denied without a message, so
// the person never gets a message they cannot answer in time.
func TestLimitQueueTimeLeft(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chs := e.fill(approval.MaxOpenMessages)

		// The request waits in the queue while 30 seconds or more are
		// left.
		e.clock.Advance(10 * time.Second)
		queued := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, queued)
		e.clock.Advance(secretsTimeout - approval.MinTimeLeft)
		mustWait(t, queued)
		e.clock.Advance(time.Nanosecond)
		r := mustResult(t, queued)
		checkDenied(t, r, audit.CauseLimit)
		checkEvents(t, r, "request", "denied:limit")
		if r.Message != "" {
			t.Errorf("message %q, want none", r.Message)
		}
		e.asked(approval.MaxOpenMessages)

		// The open messages expire at 12:02. Then the places are free.
		e.clock.Advance(20 * time.Second)
		for _, ch := range chs {
			checkDenied(t, mustResult(t, ch), audit.CauseExpired)
		}
		e.fill(approval.MaxOpenMessages)
		e.asked(2 * approval.MaxOpenMessages)
	})
}

// TestLimitQueueTimeLeftAtTheFreePlace checks the time left when a place
// becomes free: with exactly 30 seconds left a request gets the place;
// with less it is denied, and the next one in the queue gets the place.
func TestLimitQueueTimeLeftAtTheFreePlace(t *testing.T) {
	for _, tt := range []struct {
		name  string
		after time.Duration // from the first queued request to the free place
		first bool          // the first queued request gets the place
	}{
		{"exactly 30 s left", secretsTimeout - approval.MinTimeLeft, true},
		{"less than 30 s left", secretsTimeout - approval.MinTimeLeft + time.Nanosecond, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, nil)
				defer e.stop()
				e.fill(approval.MaxOpenMessages)
				first := e.decide(secretsReq("laptop", "db-password"))
				synctest.Wait()
				e.clock.Advance(20 * time.Second)
				second := e.decide(secretsReq("laptop", "db-password"))
				mustWait(t, second)

				e.clock.Advance(tt.after - 20*time.Second)
				e.tap(1, audit.AnswerApproveOnce)
				asked := e.asked(approval.MaxOpenMessages + 1)
				p := asked[approval.MaxOpenMessages].Prompt
				if tt.first {
					mustWait(t, first)
					if p.TimeLeft != approval.MinTimeLeft {
						t.Errorf("the message has %v left, want %v", p.TimeLeft, approval.MinTimeLeft)
					}
					return
				}
				checkDenied(t, mustResult(t, first), audit.CauseLimit)
				mustWait(t, second)
				if want := approval.MinTimeLeft + 20*time.Second - time.Nanosecond; p.TimeLeft != want {
					t.Errorf("the message has %v left, want %v: it is for the second request", p.TimeLeft, want)
				}
			})
		})
	}
}

// TestLimitShortTimeout checks that a request whose whole time is under 30
// seconds is denied at once when it would have to wait in the queue: it
// could never leave it.
func TestLimitShortTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) { cfg.Telegram.Timeout = 20 * time.Second })
		defer e.stop()
		e.fill(approval.MaxOpenMessages)
		checkDenied(t, e.now(secretsReq("laptop", "db-password")), audit.CauseLimit)
		e.asked(approval.MaxOpenMessages)
	})
}

// TestLimitDenyPause checks the pause after a Deny: for 60 seconds, new
// requests from that client for that secret are denied without a
// message. Other secrets and other clients still ask.
func TestLimitDenyPause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		ch := e.decide(secretsReq("laptop", "github-token", "npm-token"))
		mustWait(t, ch)
		e.asked(1)
		e.clock.Advance(5 * time.Second)
		e.tap(1, audit.AnswerDeny)
		mustResult(t, ch)

		for _, req := range []*approval.Request{
			secretsReq("laptop", "github-token"),
			secretsReq("laptop", "npm-token"),
			secretsReq("laptop", "db-password", "npm-token"),
		} {
			r := e.now(req)
			checkDenied(t, r, audit.CauseLimit)
			checkEvents(t, r, "request", "denied:limit")
		}
		e.asked(1)
		e.asks(secretsReq("laptop", "db-password"), 2) // another secret; this pauses it too
		e.asks(secretsReq("build", "github-token"), 3) // another client

		// The pause of github-token ends 60 seconds after the Deny. The
		// two asks above took 120 seconds, so it has ended.
		e.asks(secretsReq("laptop", "github-token"), 4)
	})
}

// TestLimitDenyPauseEnds checks the exact end of the pause.
func TestLimitDenyPauseEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		ch := e.decide(loginReq("laptop", "deploy", e.hosts.web1, "deploy"))
		mustWait(t, ch)
		e.asked(1)
		e.tap(1, audit.AnswerDeny)
		mustResult(t, ch)
		// The pause is for the key, at any host, and for an SSH grant too.
		e.clock.Advance(approval.DenyPause - time.Nanosecond)
		checkDenied(t, e.now(loginReq("laptop", "deploy", e.hosts.web2, "deploy")), audit.CauseLimit)
		checkDenied(t, e.now(grantReq("laptop", "deploy", "deploy", time.Minute, "web-3")), audit.CauseLimit)
		e.clock.Advance(time.Nanosecond)
		e.asks(loginReq("laptop", "deploy", e.hosts.web2, "deploy"), 2)
	})
}

// TestLimitNoPauseAfterExpiry checks that only the person's Deny starts a
// pause, not a request that expired.
func TestLimitNoPauseAfterExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.clock.Advance(secretsTimeout)
		checkDenied(t, mustResult(t, ch), audit.CauseExpired)
		e.asks(secretsReq("laptop", "github-token"), 2)
	})
}

// TestLimitCoveredDoNotCount checks that requests that a grant or a "never
// ask" rule allows do not count for the limits of messages and are not
// limited by them. A "never ask" rule without notices is not limited at
// all; one with notices has its own limit (TestLimitNotices).
func TestLimitCoveredDoNotCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: false})
		})
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		// A Deny for npm-token pauses npm-token only.
		ch := e.decide(secretsReq("laptop", "npm-token"))
		mustWait(t, ch)
		e.asked(2)
		e.tap(2, audit.AnswerDeny)
		mustResult(t, ch)
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		e.clock.Advance(time.Minute) // a new minute for the limit per minute

		// Fill the places and the queue of laptop and ci.
		e.fill(approval.MaxOpenMessages + approval.MaxQueued)
		for range approval.MaxOpenMessages + approval.MaxQueued {
			e.decide(loginReq("ci", "backup", e.hosts.web1, "backup")) // denied: web-1 is not its host
		}
		for range 50 {
			checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
			checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		}
		e.asked(2 + approval.MaxOpenMessages)
	})
}

// TestLimitsPerClient checks that the limits of one client do not stop
// another.
func TestLimitsPerClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.fill(approval.MaxOpenMessages + approval.MaxQueued)
		checkDenied(t, e.now(secretsReq("laptop", "db-password")), audit.CauseLimit)
		ch := e.decide(secretsReq("build", "github-token"))
		mustWait(t, ch)
		asked := e.asked(approval.MaxOpenMessages + 1)
		if asked[approval.MaxOpenMessages].Prompt.Client != "build" {
			t.Error("the message is not for build")
		}
	})
}

// TestLimitQueueWakesForTheMinute checks a request in the queue that
// first waits for a free place, and then, when a place is free, for the
// limit per minute: it gets its message when the minute has passed.
func TestLimitQueueWakesForTheMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.fill(approval.MaxOpenMessages) // 5 messages at 12:00
		first := e.decide(secretsReq("laptop", "db-password"))
		synctest.Wait()
		second := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, second)

		// A place is free: the first queued request gets the sixth message
		// of this minute.
		e.tap(1, audit.AnswerApproveOnce)
		mustWait(t, first)
		e.asked(approval.MaxOpenMessages + 1)
		// Another place is free, but the minute is full.
		e.clock.Advance(10 * time.Second)
		e.tap(2, audit.AnswerApproveOnce)
		mustWait(t, second)
		e.asked(approval.MaxOpenMessages + 1)
		// At 12:01 the first message is a minute old.
		e.clock.Advance(50 * time.Second)
		mustWait(t, second)
		e.asked(approval.MaxOpenMessages + 2)
	})
}

// TestLimitNotices checks the limit of notices of "never ask" uses: at
// most 6 in any 60 seconds per client, for its secrets and keys together.
// A use over the limit is denied, sends no notice, and does not count for
// max_per_day. Before this limit, one client could send any number of
// notices. (From the security review of issue #6.)
func TestLimitNotices(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 8})
		})
		defer e.stop()
		for range approval.MaxNoticesPerMinute - 1 {
			checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
			e.clock.Advance(time.Second)
		}
		// The notices of the key count with those of the secret.
		checkAllowed(t, e.now(loginReq("ci", "backup", e.hosts.db1, "backup")))
		for _, req := range []*approval.Request{secretsReq("ci", "backup-token"), loginReq("ci", "backup", e.hosts.db1, "backup")} {
			r := e.now(req)
			checkDenied(t, r, audit.CauseLimit)
			checkEvents(t, r, "request", "denied:limit")
		}
		if n := len(e.fake.Notices()); n != approval.MaxNoticesPerMinute {
			t.Errorf("%d notices, want %d", n, approval.MaxNoticesPerMinute)
		}
		e.asked(0)

		// A minute after the first notice, one more may go.
		e.clock.Advance(time.Minute - 5*time.Second - time.Nanosecond)
		checkDenied(t, e.now(secretsReq("ci", "backup-token")), audit.CauseLimit)
		e.clock.Advance(time.Nanosecond)
		checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		checkDenied(t, e.now(secretsReq("ci", "backup-token")), audit.CauseLimit)

		// The denied uses did not count: backup-token has 6 of its 8.
		e.clock.Advance(time.Minute)
		checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		checkAllowed(t, e.now(secretsReq("ci", "backup-token")))
		ch := e.decide(secretsReq("ci", "backup-token")) // over max_per_day: it asks
		mustWait(t, ch)
		e.asked(1)
	})
}

// TestLimitApproverRefusesNotice checks a "never ask" use whose notice a
// limit of the approver itself stops, such as the limit of the Telegram
// code for all clients together. The use is denied with cause limit, as
// for the limit per client, without an error entry, and it does not count
// for max_per_day: with max_per_day = 1, the next use in the same night
// still works. The refused notices still count for the limit per client.
// Before, such a use was an approver failure, and it used up the one use
// of the night. (Issue #47.)
func TestLimitApproverRefusesNotice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, h := testConfig(t)
		night := parseHours(t, "23:30-00:30")
		setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, Hours: &night, MaxPerDay: 1})
		e := newEnvWith(t, cfg, h, approvaltest.NewClock(time.Date(2026, 10, 14, 23, 50, 0, 0, time.UTC)))
		defer e.stop()

		e.fake.FailNotify(fmt.Errorf("the notice chat is full: %w", approval.ErrLimit))
		for range approval.MaxNoticesPerMinute {
			r := e.now(secretsReq("ci", "backup-token"))
			checkDenied(t, r, audit.CauseLimit)
			if r.ErrorCode != "" || r.Err != nil {
				t.Errorf("code %q, err %v; want no error", r.ErrorCode, r.Err)
			}
			checkEvents(t, r, "request", "denied:limit")
		}
		// The refused notices count for the limit per client: in this
		// minute no notice goes out, also when the approver has room again.
		e.fake.FailNotify(nil)
		checkDenied(t, e.now(secretsReq("ci", "backup-token")), audit.CauseLimit)
		if n := len(e.fake.Notices()); n != 0 {
			t.Errorf("%d notices, want 0", n)
		}
		e.asked(0)

		// 00:10 is the next day, but the same night: its uses count for
		// October 14, and none of the refused uses counted.
		e.clock.Advance(20 * time.Minute)
		r := e.now(secretsReq("ci", "backup-token"))
		checkAllowed(t, r)
		checkEvents(t, r, "request", "grant_used:never_rule")
		if n := len(e.fake.Notices()); n != 1 {
			t.Errorf("%d notices, want 1", n)
		}
		// That was the one use of the night: the next one asks the person.
		ch := e.decide(secretsReq("ci", "backup-token"))
		mustWait(t, ch)
		e.asked(1)
	})
}

// slowNotify is an approver whose Notify waits until release is closed,
// as Telegram does when it is slow or limits the bot.
type slowNotify struct {
	*approvaltest.Approver
	release chan struct{}
}

func (a *slowNotify) Notify(ctx context.Context, p approval.Prompt) error {
	select {
	case <-a.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return a.Approver.Notify(ctx, p)
}

// TestLimitNoticesBoundTheRequests checks that while Notify is slow, one
// client cannot keep more than 6 "never ask" uses in progress at once:
// the others are denied at once. Before the limit, one client held 2000
// request IDs. (From the security review of issue #6.)
func TestLimitNoticesBoundTheRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		a := &slowNotify{Approver: approvaltest.NewApprover(approverID), release: make(chan struct{})}
		core, err := approval.New(cfg, a, approval.Options{Clock: approvaltest.NewClock(noon)})
		if err != nil {
			t.Fatal(err)
		}
		const n = 2000
		results := make(chan *approval.Result, n)
		for range n {
			go func() { results <- core.Decide(context.Background(), secretsReq("ci", "backup-token")) }()
		}
		synctest.Wait()
		if ids, codes, _ := core.Live(); ids != approval.MaxNoticesPerMinute || codes != ids {
			t.Errorf("%d request IDs and %d short codes in use, want %d", ids, codes, approval.MaxNoticesPerMinute)
		}
		close(a.release)
		allowed := 0
		for range n {
			if r := <-results; r.Allowed {
				allowed++
			} else if r.Cause != audit.CauseLimit {
				t.Fatalf("denied with cause %q, want limit", r.Cause)
			}
		}
		if allowed != approval.MaxNoticesPerMinute {
			t.Errorf("%d allowed, want %d", allowed, approval.MaxNoticesPerMinute)
		}
	})
}
