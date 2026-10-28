package approval_test

// Tests of the Revoke button, of the update of the message of a scheduled
// grant, and of the notice of a grant that was not used (DESIGN.md
// sections 7 and 8).

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// updates returns the updates of the message n (counted from 1) after the
// core made them all.
func (e *env) updates(n int) []approvaltest.Ended {
	e.t.Helper()
	synctest.Wait()
	msg := e.fake.Asked()[n-1].Message
	var out []approvaltest.Ended
	for _, u := range e.fake.Ended() {
		if u.Message == msg {
			out = append(out, u)
		}
	}
	return out
}

// lastUpdate checks that the message n has had count updates, and returns
// the last.
func (e *env) lastUpdate(n, count int) approval.Ending {
	e.t.Helper()
	ups := e.updates(n)
	if len(ups) != count {
		e.t.Fatalf("message %d had %d updates, want %d", n, len(ups), count)
	}
	return ups[len(ups)-1].Ending
}

// TestRevokeEndsGrant: after Approve the message keeps a Revoke button. A
// Revoke tap ends the grant at once with cause revoked, writes its entry,
// updates the message, and a later use needs a tap. It sends no notice.
func TestRevokeEndsGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		g := e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token"), 1)
		// The approval shows first; then the message keeps one Revoke button.
		if hold := e.lastUpdate(1, 2); !hold.Revoke || hold.GrantEnd != "" {
			t.Fatalf("second update %+v; want Revoke", hold)
		}
		e.uses(secretsReq("laptop", "github-token"), g.GrantID)
		e.tap(1, audit.AnswerRevoke)
		synctest.Wait()
		got := rec.all()
		if len(got) != 1 || got[0].Cause != audit.EndRevoked || got[0].UsesLeft != 2 || got[0].GrantID != g.GrantID ||
			got[0].RequestID != g.RequestID {
			t.Fatalf("ended entries %+v", got)
		}
		end := e.lastUpdate(1, 3)
		if !end.Approved.Equal(noon) {
			t.Errorf("approved at %v, want %v", end.Approved, noon)
		}
		if end.Revoke || end.GrantEnd != audit.EndRevoked || end.UsesLeft != 2 {
			t.Errorf("last update %+v; want the end by revoke, no button", end)
		}
		e.needsMessage(secretsReq("laptop", "github-token"), 2)
		for _, n := range e.fake.Notices() {
			if n.GrantID != "" {
				t.Errorf("a revoke sent a not used notice: %+v", n)
			}
		}
	})
}

// TestRevokeBeforeStart: a grant that has not started yet can be revoked.
func TestRevokeBeforeStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		e.grant(preSecrets("laptop", 1, time.Hour, 2*time.Hour, "github-token"), 1)
		e.tap(1, audit.AnswerRevoke)
		e.clock.Advance(time.Hour)
		e.needsMessage(secretsReq("laptop", "github-token"), 2)
	})
}

// TestRevokeRefused: a Revoke that is not the approver's, not on the
// message of the grant, for a request that made no grant, or after the
// grant ended, changes nothing.
func TestRevokeRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		g := e.grant(preSecrets("laptop", 2, 0, time.Hour, "github-token"), 1)
		for _, tc := range []struct {
			name   string
			change func(*approval.Answer)
			want   error
		}{
			{"other user", func(a *approval.Answer) { a.Action = audit.AnswerRevoke; a.UserID = approverID + 1 }, approval.ErrNotApprover},
			{"no user", func(a *approval.Answer) { a.Action = audit.AnswerRevoke; a.UserID = 0 }, approval.ErrNotApprover},
			{"other message", func(a *approval.Answer) { a.Action = audit.AnswerRevoke; a.Message = "message-99" }, approval.ErrWrongMessage},
			{"no message", func(a *approval.Answer) { a.Action = audit.AnswerRevoke; a.Message = "" }, approval.ErrWrongMessage},
			{"unknown request", func(a *approval.Answer) { a.Action = audit.AnswerRevoke; a.RequestID = "AAAAAAAAAAAAAAAAAAAAAA" }, approval.ErrUnknownRequest},
			{"the grant ID is not the request ID", func(a *approval.Answer) { a.Action = audit.AnswerRevoke; a.RequestID = g.GrantID }, approval.ErrUnknownRequest},
		} {
			if err := e.answer(1, tc.change); !errors.Is(err, tc.want) {
				t.Errorf("%s: error %v, want %v", tc.name, err, tc.want)
			}
		}
		e.uses(secretsReq("laptop", "github-token"), g.GrantID)
		e.uses(secretsReq("laptop", "github-token"), g.GrantID) // both uses: the grant stayed

		// A Revoke after the grant is used up, ended or revoked is late.
		revoke := func(a *approval.Answer) { a.Action = audit.AnswerRevoke }
		if err := e.answer(1, revoke); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("revoke after used up: %v", err)
		}
		e.grant(preSecrets("laptop", 2, 0, time.Hour, "npm-token"), 2)
		e.grant(preSecrets("laptop", 2, 0, 2*time.Hour, "db-password"), 3)
		e.clock.Advance(time.Hour)
		if err := e.answer(2, revoke); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("revoke after the end: %v", err)
		}
		e.tap(3, audit.AnswerRevoke)
		if err := e.answer(3, revoke); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("second revoke: %v", err)
		}
		if got := len(e.updates(3)); got != 3 {
			t.Errorf("%d updates of message 3, want 3: a refused revoke changes nothing", got)
		}
	})
}

// TestRevokeNeedsTheMessageOfTheGrant: the tap of a request that still
// waits for its first answer is not a Revoke.
func TestRevokeWaitingRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		ch := e.decide(preSecrets("laptop", 1, 0, time.Hour, "github-token"))
		mustWait(t, ch)
		e.asked(1)
		err := e.answer(1, func(a *approval.Answer) { a.Action = audit.AnswerRevoke })
		if !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("revoke of a waiting request: %v", err)
		}
		e.tap(1, audit.AnswerApproveOnce) // it still waits
		checkAllowed(t, mustResult(t, ch))
	})
}

// TestGrantEndChangesMessage: every cause of the end removes the button
// and says how and when the grant ended, in the last update of the message.
func TestGrantEndChangesMessage(t *testing.T) {
	use := func(e *env, g *approval.Result) { e.uses(secretsReq("laptop", "github-token"), g.GrantID) }
	for _, tc := range []struct {
		cause audit.EndCause
		left  int
		do    func(e *env, g *approval.Result)
	}{
		{audit.EndUsedUp, 0, func(e *env, g *approval.Result) { use(e, g) }},
		{audit.EndEnded, 1, func(e *env, g *approval.Result) { e.clock.Advance(time.Hour) }},
		{audit.EndCancelled, 1, func(e *env, g *approval.Result) { e.core.CancelGrant("laptop", g.GrantID) }},
		{audit.EndRevoked, 1, func(e *env, g *approval.Result) { e.tap(1, audit.AnswerRevoke) }},
		{audit.EndDenied, 1, func(e *env, g *approval.Result) {
			ch := e.decide(secretsReq("laptop", "github-token", "npm-token"))
			mustWait(e.t, ch)
			e.tap(2, audit.AnswerDeny)
			mustResult(e.t, ch)
		}},
		{audit.EndStopped, 1, func(e *env, g *approval.Result) { e.stop(); e.core.FlushMessages() }},
	} {
		t.Run(string(tc.cause), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := preEnv(t)
				defer e.stop()
				g := e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 1)
				tc.do(e, g)
				end := e.lastUpdate(1, 3)
				if end.Revoke || end.GrantEnd != tc.cause || end.UsesLeft != tc.left || end.At.IsZero() {
					t.Errorf("last update %+v; want the end by %s, %d left, no button", end, tc.cause, tc.left)
				}
			})
		})
	}
}

// TestNotUsedNotice: a grant that reaches its end with uses left sends one
// silent notice. It is not sent when the uses ran out, or on cancel,
// revoke, a later Deny or a stop. The notice does not count for the limit
// per client.
func TestNotUsedNotice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		notUsed := func() []approval.Prompt {
			synctest.Wait()
			var out []approval.Prompt
			for _, n := range e.fake.Notices() {
				if n.GrantID != "" {
					out = append(out, n)
				}
			}
			return out
		}
		// Used up, cancelled, revoked, denied: no notice.
		a := e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 1)
		e.uses(secretsReq("laptop", "github-token"), a.GrantID)
		b := e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 2)
		e.core.CancelGrant("laptop", b.GrantID)
		e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 3)
		e.tap(3, audit.AnswerRevoke)
		e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 4)
		ch := e.decide(secretsReq("laptop", "github-token", "npm-token"))
		mustWait(t, ch)
		e.tap(5, audit.AnswerDeny)
		mustResult(t, ch)
		e.clock.Advance(approval.DenyPause)
		if got := notUsed(); len(got) != 0 {
			t.Fatalf("%d not used notices without a reason: %+v", len(got), got)
		}
		// The end with 2 of 3 uses left.
		c := e.grant(preSecrets("laptop", 3, 0, time.Hour, "github-token", "npm-token"), 6)
		e.uses(secretsReq("laptop", "github-token", "npm-token"), c.GrantID)
		e.clock.Advance(time.Hour)
		got := notUsed()
		if len(got) != 1 {
			t.Fatalf("%d not used notices, want 1", len(got))
		}
		n := got[0]
		if n.GrantID != c.GrantID || n.UsesLeft != 2 || n.Uses != 3 || n.Client != "laptop" || n.Once || n.WindowMinutes != 0 ||
			!n.Expires.IsZero() || n.Kind != audit.KindPreapprove || len(n.Secrets) != 2 || n.Via != "" {
			t.Errorf("notice %+v", n)
		}
		e.clock.Advance(time.Hour)
		if got := notUsed(); len(got) != 1 {
			t.Errorf("%d notices after more time, want 1", len(got))
		}
	})
}

// TestNotUsedNoticeLimits: the notice does not count toward the limit of 6
// per client, and one that the approver cannot send is only logged: the
// message is updated anyway.
func TestNotUsedNoticeLimits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		var off time.Duration
		for i := range 8 {
			e.grant(preSecrets("laptop", 1, off, off+time.Hour, "github-token"), i+1)
			off += time.Hour
			e.clock.Advance(time.Hour)
		}
		// A client with many not used notices still has all its uses.
		g := e.grant(preSecrets("laptop", 1, off, off+time.Hour, "github-token"), 9)
		e.uses(secretsReq("laptop", "github-token"), g.GrantID)

		e.fake.FailNotify(errors.New("telegram is down"))
		e.grant(preSecrets("laptop", 2, off, off+time.Hour, "npm-token"), 10)
		e.clock.Advance(time.Hour)
		synctest.Wait()
		end := e.lastUpdate(10, 3)
		if end.GrantEnd != audit.EndEnded || end.UsesLeft != 2 {
			t.Errorf("last update %+v", end)
		}
	})
}

// blockingApprover is a fake whose End waits until its context ends, as a
// Telegram that does not answer.
type blockingApprover struct {
	*approvaltest.Approver
	block       chan struct{} // closed: End blocks
	revokeBlock bool          // only an End that adds a Revoke button blocks
}

func (b *blockingApprover) End(ctx context.Context, m approval.MessageID, p approval.Prompt, e approval.Ending) error {
	select {
	case <-b.block:
		if b.revokeBlock && !e.Revoke {
			return b.Approver.End(ctx, m, p, e)
		}
		<-ctx.Done()
		return ctx.Err()
	default:
		return b.Approver.End(ctx, m, p, e)
	}
}

// TestStopDoesNotHangOnMessages: when Telegram does not answer, the stop
// of the core waits at most a few seconds for the updates of the messages.
func TestStopDoesNotHangOnMessages(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		cfg.Preapprove = config.DefaultPreapprove()
		s := cfg.Secrets["github-token"]
		s.Rule.Preapprove = true
		cfg.Secrets["github-token"] = s
		clock := approvaltest.NewClock(noon)
		b := &blockingApprover{Approver: approvaltest.NewApprover(approverID), block: make(chan struct{})}
		core, err := approval.New(cfg, b, approval.Options{Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- core.Run(ctx) }()
		synctest.Wait()
		var rec endedRecorder
		core.OnGrantEnded(rec.add)
		ch := make(chan *approval.Result, 1)
		go func() { ch <- core.Decide(context.Background(), preSecrets("laptop", 1, 0, time.Hour, "github-token")) }()
		synctest.Wait()
		asked := b.Asked()
		if len(asked) != 1 {
			t.Fatalf("asked %d messages", len(asked))
		}
		if err := b.Tap(asked[0].Prompt.RequestID, audit.AnswerApproveOnce); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		res := <-ch
		res.StartGrants()
		synctest.Wait()
		close(b.block) // Telegram stops answering
		start := time.Now()
		cancel()
		<-done
		// Run itself does not wait for Telegram: the broker denies every
		// request before it flushes the messages.
		if d := time.Since(start); d != 0 {
			t.Errorf("Run took %v after the stop", d)
		}
		core.FlushMessages()
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("the stop took %v", d)
		}
		if got := rec.all(); len(got) != 1 || got[0].Cause != audit.EndStopped {
			t.Errorf("ended entries %+v", got)
		}
	})
}

// TestStopSkipsRevokeEdit: at a stop, the edit that adds a Revoke button
// is cut short, but it does not take the time of the flush: its grant is
// gone, so the edit of the end goes out.
func TestStopSkipsRevokeEdit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		cfg.Preapprove = config.DefaultPreapprove()
		s := cfg.Secrets["github-token"]
		s.Rule.Preapprove = true
		cfg.Secrets["github-token"] = s
		b := &blockingApprover{Approver: approvaltest.NewApprover(approverID), block: make(chan struct{}), revokeBlock: true}
		core, err := approval.New(cfg, b, approval.Options{Clock: approvaltest.NewClock(noon)})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- core.Run(ctx) }()
		synctest.Wait()
		ch := make(chan *approval.Result, 1)
		go func() { ch <- core.Decide(context.Background(), preSecrets("laptop", 1, 0, time.Hour, "github-token")) }()
		synctest.Wait()
		if err := b.Tap(b.Asked()[0].Prompt.RequestID, audit.AnswerApproveOnce); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		close(b.block) // the edit that adds the button now hangs
		(<-ch).StartGrants()
		synctest.Wait()
		cancel()
		<-done
		start := time.Now()
		core.FlushMessages()
		if d := time.Since(start); d != 0 {
			t.Errorf("the flush took %v", d)
		}
		var last approval.Ending
		for _, u := range b.Ended() {
			last = u.Ending
		}
		if last.GrantEnd != audit.EndStopped || last.Revoke {
			t.Errorf("last update %+v; want the end by a stop", last)
		}
	})
}

// holdUpdates counts the updates of the message n that add a Revoke button.
func (e *env) holdUpdates(n int) int {
	count := 0
	for _, u := range e.updates(n) {
		if u.Ending.Revoke {
			count++
		}
	}
	return count
}

// TestRevokeEditRetried: an edit that adds the Revoke button and fails is
// tried again after a wait, while the grant lives.
func TestRevokeEditRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		e.fake.FailEnd(errors.New("timeout"))
		e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 1)
		if got := e.holdUpdates(1); got != 1 {
			t.Fatalf("%d tries, want 1", got)
		}
		e.fake.FailEnd(nil)
		e.clock.Advance(10 * time.Second)
		synctest.Wait()
		if got := e.holdUpdates(1); got != 2 {
			t.Errorf("%d tries after the wait, want 2", got)
		}
		e.clock.Advance(time.Minute)
		synctest.Wait()
		if got := e.holdUpdates(1); got != 2 {
			t.Errorf("%d tries; a good edit must not be repeated", got)
		}
	})
}

// TestRevokeEditRetriesAreBounded: a failing edit is tried at most
// holdTries times, and no more once the grant has ended.
func TestRevokeEditRetriesAreBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		e.fake.FailEnd(errors.New("timeout"))
		e.grant(preSecrets("laptop", 1, 0, time.Hour, "github-token"), 1)
		for range 10 {
			e.clock.Advance(time.Minute)
			synctest.Wait()
		}
		if got := e.holdUpdates(1); got != 3 {
			t.Errorf("%d tries, want 3", got)
		}
		// A grant that ended is not given a button.
		g := e.grant(preSecrets("laptop", 1, 10*time.Minute, time.Hour, "npm-token"), 2)
		if got := e.holdUpdates(2); got != 1 {
			t.Fatalf("%d tries, want 1", got)
		}
		e.core.CancelGrant("laptop", g.GrantID)
		e.clock.Advance(time.Minute)
		synctest.Wait()
		if got := e.holdUpdates(2); got != 1 {
			t.Errorf("%d tries after the grant ended, want 1", got)
		}
	})
}
