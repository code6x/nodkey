package approval_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
)

// TestAnswerRefused checks each answer that must not count (DESIGN.md
// section 7). Each one changes nothing: the request still waits, and a
// valid tap then counts.
func TestAnswerRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chA := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, chA)
		chB := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, chB)
		asked := e.asked(2)
		a, b := asked[0], asked[1]

		for _, tt := range []struct {
			name   string
			change func(*approval.Answer)
			want   error
		}{
			{"another user", func(x *approval.Answer) { x.UserID = 987654321 }, approval.ErrNotApprover},
			{"no user", func(x *approval.Answer) { x.UserID = 0 }, approval.ErrNotApprover},
			{"a user ID below 0", func(x *approval.Answer) { x.UserID = -approverID }, approval.ErrNotApprover},
			{"an unknown request ID", func(x *approval.Answer) { x.RequestID = "AAAAAAAAAAAAAAAAAAAAAA" }, approval.ErrUnknownRequest},
			{"no request ID", func(x *approval.Answer) { x.RequestID = "" }, approval.ErrUnknownRequest},
			{"the short code as the ID", func(x *approval.Answer) { x.RequestID = a.Prompt.ShortCode }, approval.ErrUnknownRequest},
			{"another message", func(x *approval.Answer) { x.Message = "message-999" }, approval.ErrWrongMessage},
			{"no message", func(x *approval.Answer) { x.Message = "" }, approval.ErrWrongMessage},
			{"the message of another request", func(x *approval.Answer) { x.Message = b.Message }, approval.ErrWrongMessage},
			{"Approve N min without the button", func(x *approval.Answer) { x.Action = audit.AnswerApproveWindow }, approval.ErrNotAllowed},
			{"no action", func(x *approval.Answer) { x.Action = "" }, approval.ErrNotAllowed},
			{"an unknown action", func(x *approval.Answer) { x.Action = "approve" }, approval.ErrNotAllowed},
			{"the button data as the action", func(x *approval.Answer) { x.Action = "o" }, approval.ErrNotAllowed},
		} {
			if err := e.answer(1, tt.change); !errors.Is(err, tt.want) {
				t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
			}
		}
		mustWait(t, chA)
		mustWait(t, chB)
		if len(e.fake.Ended()) != 0 {
			t.Error("a refused answer ended a message")
		}

		// A valid tap counts once. The second tap finds no waiting request.
		e.tap(1, audit.AnswerApproveOnce)
		r := mustResult(t, chA)
		checkAllowed(t, r)
		for _, action := range []audit.Answer{audit.AnswerDeny, audit.AnswerApproveOnce} {
			if err := e.answer(1, func(x *approval.Answer) { x.Action = action }); !errors.Is(err, approval.ErrUnknownRequest) {
				t.Errorf("a second tap (%s): %v, want ErrUnknownRequest", action, err)
			}
		}
		if r.Answer != audit.AnswerApproveOnce {
			t.Errorf("the result changed to %q", r.Answer)
		}
		mustWait(t, chB)
	})
}

// TestOneAnswerCounts checks that of many answers to one request at the
// same time, exactly one counts, and the result is that answer. Run it
// with -race.
func TestOneAnswerCounts(t *testing.T) {
	actions := []audit.Answer{audit.AnswerApproveOnce, audit.AnswerApproveWindow, audit.AnswerDeny}
	for round := range 50 {
		synctest.Test(t, func(t *testing.T) {
			e := newEnv(t, nil)
			defer e.stop()
			ch := e.decide(secretsReq("laptop", "github-token"))
			mustWait(t, ch)
			asked := e.asked(1)[0]

			const taps = 32
			errs := make([]error, taps)
			var wg sync.WaitGroup
			for i := range taps {
				wg.Go(func() {
					errs[i] = e.fake.Answer(approval.Answer{
						RequestID: asked.Prompt.RequestID, Action: actions[(i+round)%len(actions)],
						Message: asked.Message, UserID: approverID,
					})
				})
			}
			wg.Wait()
			r := mustResult(t, ch)
			won := -1
			for i, err := range errs {
				switch {
				case err == nil && won >= 0:
					t.Fatalf("taps %d and %d both counted", won, i)
				case err == nil:
					won = i
				case !errors.Is(err, approval.ErrUnknownRequest):
					t.Errorf("tap %d: %v, want nil or ErrUnknownRequest", i, err)
				}
			}
			if won < 0 {
				t.Fatal("no tap counted")
			}
			if want := actions[(won+round)%len(actions)]; r.Answer != want || r.Allowed != (want != audit.AnswerDeny) {
				t.Errorf("result %q (allowed %v); the tap that counted was %q", r.Answer, r.Allowed, want)
			}
			if n := len(e.fake.Ended()); n != 1 {
				t.Errorf("%d updates of the message, want 1", n)
			}
		})
	}
}

// TestAnswerRacesTheEnd checks a tap at the same time as the expiry and
// the client's cancel: the request ends once, and a tap counts only if it
// came first.
func TestAnswerRacesTheEnd(t *testing.T) {
	for round := range 50 {
		synctest.Test(t, func(t *testing.T) {
			e := newEnv(t, nil)
			defer e.stop()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ch := e.decideCtx(ctx, secretsReq("laptop", "github-token"))
			mustWait(t, ch)
			asked := e.asked(1)[0]

			var tapErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				tapErr = e.fake.Answer(approval.Answer{
					RequestID: asked.Prompt.RequestID, Action: audit.AnswerApproveOnce,
					Message: asked.Message, UserID: approverID,
				})
			})
			if round%2 == 0 {
				wg.Go(func() { e.clock.Advance(secretsTimeout) })
			} else {
				wg.Go(cancel)
			}
			wg.Wait()
			r := mustResult(t, ch)
			if tapErr == nil {
				checkAllowed(t, r)
			} else {
				if !errors.Is(tapErr, approval.ErrUnknownRequest) && !errors.Is(tapErr, approval.ErrExpired) {
					t.Errorf("tap: %v, want nil, ErrUnknownRequest or ErrExpired", tapErr)
				}
				if r.Allowed || (r.Cause != audit.CauseExpired && r.Cause != audit.CauseCancelled) {
					t.Errorf("allowed %v, cause %q; want expired or cancelled", r.Allowed, r.Cause)
				}
			}
			if n := len(e.fake.Ended()); n != 1 {
				t.Errorf("%d updates of the message, want 1", n)
			}
		})
	}
}

// TestManyRequestsAndAnswers runs many clients' requests and many taps at
// once, to find data races with -race. Each request ends exactly once.
func TestManyRequestsAndAnswers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		var wg sync.WaitGroup
		var mu sync.Mutex
		results := map[string]int{}
		for i := range 40 {
			client := []string{"laptop", "build"}[i%2]
			wg.Go(func() {
				r := e.core.Decide(context.Background(), secretsReq(client, "github-token"))
				mu.Lock()
				results[r.RequestID]++
				mu.Unlock()
			})
		}
		synctest.Wait()
		for range 3 {
			for _, x := range e.fake.Asked() {
				wg.Go(func() {
					_ = e.fake.Answer(approval.Answer{
						RequestID: x.Prompt.RequestID, Action: audit.AnswerDeny, Message: x.Message, UserID: approverID,
					})
				})
				wg.Go(func() { e.clock.Advance(time.Second) })
			}
			synctest.Wait()
		}
		e.clock.Advance(secretsTimeout)
		wg.Wait()
		if len(results) != 40 {
			t.Errorf("%d different request IDs, want 40", len(results))
		}
		for id, n := range results {
			if n != 1 {
				t.Errorf("request %s ended %d times", id, n)
			}
		}
		ended := map[approval.MessageID]int{}
		for _, x := range e.fake.Ended() {
			ended[x.Message]++
		}
		for _, x := range e.fake.Asked() {
			if ended[x.Message] != 1 {
				t.Errorf("message %s was updated %d times, want 1", x.Message, ended[x.Message])
			}
		}
	})
}

// TestForgedAnswers checks answers that an attacker with the bot token, or
// a bug in the Telegram code, could pass. None counts, and the requests
// still wait for the person. (From the security review of issue #6.)
func TestForgedAnswers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chA := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, chA)
		chB := e.decide(secretsReq("build", "github-token"))
		mustWait(t, chB)
		asked := e.asked(2)
		a, b := asked[0], asked[1]
		for _, ans := range []approval.Answer{
			// A's ID on B's message: a forged button on another message.
			{RequestID: a.Prompt.RequestID, Action: audit.AnswerApproveWindow, Message: b.Message, UserID: approverID},
			// The short code instead of the ID.
			{RequestID: a.Prompt.ShortCode, Action: audit.AnswerApproveOnce, Message: a.Message, UserID: approverID},
			// The ID with the button data around it.
			{RequestID: "o:" + a.Prompt.RequestID, Action: audit.AnswerApproveOnce, Message: a.Message, UserID: approverID},
			// The action in upper case.
			{RequestID: a.Prompt.RequestID, Action: "APPROVE_ONCE", Message: a.Message, UserID: approverID},
			// Another user, on the right message.
			{RequestID: a.Prompt.RequestID, Action: audit.AnswerApproveOnce, Message: a.Message, UserID: approverID + 1},
		} {
			if err := e.core.Answer(ans); err == nil {
				t.Fatalf("the forged answer %+v counted", ans)
			}
		}
		mustWait(t, chA)
		mustWait(t, chB)
		e.clock.Advance(secretsTimeout)
		checkDenied(t, mustResult(t, chA), audit.CauseExpired)
		checkDenied(t, mustResult(t, chB), audit.CauseExpired)
	})
}

// TestAnswerRacesStop checks a tap at the same time as Run returns: either
// it counts and the request is allowed, or it gets an error and the
// request is denied. Never both, never neither. (From the security review
// of issue #6.)
func TestAnswerRacesStop(t *testing.T) {
	for round := range 50 {
		synctest.Test(t, func(t *testing.T) {
			e := newEnv(t, nil)
			defer e.stop()
			ch := e.decide(secretsReq("laptop", "github-token"))
			mustWait(t, ch)
			x := e.asked(1)[0]
			var tapErr error
			var wg sync.WaitGroup
			wg.Go(func() {
				tapErr = e.core.Answer(approval.Answer{
					RequestID: x.Prompt.RequestID, Action: audit.AnswerApproveOnce, Message: x.Message, UserID: approverID,
				})
			})
			if round%2 == 0 {
				wg.Go(func() { e.fake.Stop(errors.New("down")) })
			} else {
				wg.Go(e.cancel)
			}
			wg.Wait()
			r := mustResult(t, ch)
			switch {
			case tapErr == nil && !r.Allowed:
				t.Fatal("the tap counted, but the request was denied")
			case tapErr != nil && r.Allowed:
				t.Fatal("the tap did not count, but the request was allowed")
			case tapErr != nil && !errors.Is(tapErr, approval.ErrStopped) && !errors.Is(tapErr, approval.ErrUnknownRequest):
				t.Fatalf("tap: %v", tapErr)
			}
		})
	}
}

// slowAsk sends the message, so the person can see it and tap, and then
// waits for release before Ask returns, as when Telegram's answer to
// sendMessage is slow.
type slowAsk struct {
	*approvaltest.Approver
	sent    chan approval.Shown
	release chan struct{}
}

func (a *slowAsk) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	shown, err := a.Approver.Ask(ctx, p)
	a.sent <- shown
	<-a.release
	return shown, err
}

// TestEarlyTap checks a tap that comes before Ask has returned: it gets
// ErrTooEarly, not the ErrUnknownRequest of a late or repeated tap, so the
// approver does not mark the message as expired. It changes nothing, and
// a tap after Ask returned counts.
func TestEarlyTap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		a := &slowAsk{Approver: approvaltest.NewApprover(approverID), sent: make(chan approval.Shown, 1), release: make(chan struct{})}
		core, err := approval.New(cfg, a, approval.Options{Clock: approvaltest.NewClock(noon)})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = core.Run(ctx) }()
		ch := make(chan *approval.Result, 1)
		go func() { ch <- core.Decide(context.Background(), secretsReq("laptop", "db-password")) }()
		shown := <-a.sent
		id := a.Asked()[0].Prompt.RequestID
		ans := approval.Answer{RequestID: id, Action: audit.AnswerApproveOnce, Message: shown.ID, UserID: approverID}
		for _, action := range []audit.Answer{audit.AnswerApproveOnce, audit.AnswerDeny} {
			early := ans
			early.Action = action
			if err := core.Answer(early); !errors.Is(err, approval.ErrTooEarly) {
				t.Fatalf("early tap (%s): %v, want ErrTooEarly", action, err)
			}
		}
		// A tap from another user is refused for that first.
		if err := core.Answer(approval.Answer{RequestID: id, UserID: approverID + 1}); !errors.Is(err, approval.ErrNotApprover) {
			t.Errorf("early tap of another user: %v, want ErrNotApprover", err)
		}
		close(a.release)
		synctest.Wait()
		if err := core.Answer(ans); err != nil {
			t.Fatalf("the tap after Ask returned: %v", err)
		}
		checkAllowed(t, <-ch)
		if err := core.Answer(ans); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("late tap: %v, want ErrUnknownRequest", err)
		}
	})
}

// TestTooEarlyNeedsTheApprover checks that only the approver gets
// ErrTooEarly; another user gets ErrNotApprover, so a stranger learns
// nothing about the requests in progress. (From the second security review
// of issue #6.)
func TestTooEarlyNeedsTheApprover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		a := &slowAsk{Approver: approvaltest.NewApprover(approverID), sent: make(chan approval.Shown, 1), release: make(chan struct{})}
		core, err := approval.New(cfg, a, approval.Options{Clock: approvaltest.NewClock(noon)})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = core.Run(ctx) }()
		ch := make(chan *approval.Result, 1)
		go func() { ch <- core.Decide(context.Background(), secretsReq("laptop", "db-password")) }()
		shown := <-a.sent
		ans := approval.Answer{RequestID: a.Asked()[0].Prompt.RequestID, Action: audit.AnswerApproveOnce, Message: shown.ID, UserID: approverID + 1}
		if err := core.Answer(ans); !errors.Is(err, approval.ErrNotApprover) {
			t.Fatalf("an early tap of a stranger: %v, want ErrNotApprover", err)
		}
		ans.UserID = approverID
		if err := core.Answer(ans); !errors.Is(err, approval.ErrTooEarly) {
			t.Fatalf("an early tap of the approver: %v, want ErrTooEarly", err)
		}
		close(a.release)
		synctest.Wait()
		if err := core.Answer(ans); err != nil {
			t.Fatal(err)
		}
		checkAllowed(t, <-ch)
	})
}
