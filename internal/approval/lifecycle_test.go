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
	"github.com/code6x/nodkey/internal/config"
)

// TestExpiry checks that a request with no answer is denied when its time
// is up, that its message is updated, and that a late tap does not count.
func TestExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.asked(1)
		e.clock.Advance(secretsTimeout - time.Nanosecond)
		mustWait(t, ch)
		e.clock.Advance(time.Nanosecond)
		r := mustResult(t, ch)
		checkDenied(t, r, audit.CauseExpired)
		checkEvents(t, r, "request", "denied:expired")
		if r.Message == "" {
			t.Error("the result has no message text; the person saw one")
		}
		ended := e.fake.Ended()
		if len(ended) != 1 || ended[0].Message != e.fake.Asked()[0].Message ||
			ended[0].Ending.Cause != audit.CauseExpired || ended[0].Ending.Answer != "" ||
			!ended[0].Ending.At.Equal(noon.Add(secretsTimeout)) {
			t.Errorf("updates %+v; want one for the message: expired at %v", ended, noon.Add(secretsTimeout))
		}

		// The deny path of a late tap: it does not count.
		if err := e.answer(1, nil); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("late tap: %v, want ErrUnknownRequest", err)
		}
		if err := e.fake.Tap(e.fake.Asked()[0].Prompt.RequestID, audit.AnswerApproveOnce); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("late tap: %v, want ErrUnknownRequest", err)
		}
		// The place of the message is free again.
		ch = e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.asked(2)
	})
}

// TestTimeoutsByKind checks how long each kind of request waits: an SSH
// login has ssh_timeout; secrets and an SSH grant have timeout.
func TestTimeoutsByKind(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		h := e.hosts
		for _, tt := range []struct {
			req  *approval.Request
			wait time.Duration
		}{
			{loginReq("laptop", "deploy", h.web1, "deploy"), sshTimeout},
			{secretsReq("laptop", "github-token"), secretsTimeout},
			{grantReq("laptop", "web", "deploy", 15*time.Minute, "web-1"), secretsTimeout},
		} {
			ch := e.decide(tt.req)
			mustWait(t, ch)
			e.clock.Advance(tt.wait - time.Nanosecond)
			mustWait(t, ch)
			e.clock.Advance(time.Nanosecond)
			checkDenied(t, mustResult(t, ch), audit.CauseExpired)
		}
	})
}

// TestCancelWhileWaiting checks that a client that hangs up cancels its
// request: it is denied, the message says so, and its place is free.
func TestCancelWhileWaiting(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chs := e.fill(approval.MaxOpenMessages - 1)
		ctx, cancel := context.WithCancel(context.Background())
		ch := e.decideCtx(ctx, secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		queued := e.decide(secretsReq("laptop", "npm-token"))
		mustWait(t, queued)
		e.asked(approval.MaxOpenMessages)

		cancel()
		r := mustResult(t, ch)
		checkDenied(t, r, audit.CauseCancelled)
		checkEvents(t, r, "request", "denied:cancelled")
		ended := e.fake.Ended()
		if len(ended) != 1 || ended[0].Ending.Cause != audit.CauseCancelled {
			t.Errorf("updates %+v; want one: cancelled", ended)
		}
		// A tap after the cancel does not count.
		if err := e.answer(approval.MaxOpenMessages, nil); !errors.Is(err, approval.ErrUnknownRequest) {
			t.Errorf("tap after the cancel: %v, want ErrUnknownRequest", err)
		}
		// The queued request got the place.
		mustWait(t, queued)
		e.asked(approval.MaxOpenMessages + 1)
		for _, ch := range chs {
			mustWait(t, ch)
		}
	})
}

// TestCancelInQueue checks that a request in the queue is cancelled
// without a message, and that it leaves the queue.
func TestCancelInQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.fill(approval.MaxOpenMessages + approval.MaxQueued - 1)
		ctx, cancel := context.WithCancel(context.Background())
		ch := e.decideCtx(ctx, secretsReq("laptop", "db-password"))
		mustWait(t, ch)
		checkDenied(t, e.now(secretsReq("laptop", "db-password")), audit.CauseLimit) // the queue is full

		cancel()
		r := mustResult(t, ch)
		checkDenied(t, r, audit.CauseCancelled)
		if r.Message != "" {
			t.Errorf("message %q, want none", r.Message)
		}
		e.asked(approval.MaxOpenMessages)
		// It left the queue: there is room for one more.
		mustWait(t, e.decide(secretsReq("laptop", "db-password")))
		checkDenied(t, e.now(secretsReq("laptop", "db-password")), audit.CauseLimit)
	})
}

// TestCancelBeforeStart checks that a request whose client has already
// hung up is denied, without a message and without using a "never ask"
// rule.
func TestCancelBeforeStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 1})
		})
		defer e.stop()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for _, req := range []*approval.Request{secretsReq("laptop", "github-token"), secretsReq("ci", "backup-token")} {
			checkDenied(t, mustResult(t, e.decideCtx(ctx, req)), audit.CauseCancelled)
		}
		e.asked(0)
		if len(e.fake.Notices()) != 0 {
			t.Error("a notice for a cancelled request")
		}
		checkAllowed(t, e.now(secretsReq("ci", "backup-token"))) // the one use of the day is still there
	})
}

// TestCancelDuringNotice checks that a "never ask" use whose client hangs
// up while the notice goes out is denied.
func TestCancelDuringNotice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		clock := approvaltest.NewClock(noon)
		ctx, cancel := context.WithCancel(context.Background())
		a := &cancelOnNotify{Approver: approvaltest.NewApprover(approverID), cancel: cancel}
		core, err := approval.New(cfg, a, approval.Options{Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		r := core.Decide(ctx, secretsReq("ci", "backup-token"))
		checkDenied(t, r, audit.CauseCancelled)
	})
}

// cancelOnNotify cancels the request's context when the notice goes out.
type cancelOnNotify struct {
	*approvaltest.Approver
	cancel context.CancelFunc
}

func (a *cancelOnNotify) Notify(ctx context.Context, p approval.Prompt) error {
	a.cancel()
	return a.Approver.Notify(ctx, p)
}

// TestAskFails checks that a request is denied when its message cannot be
// sent, and that its place is free again.
func TestAskFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		down := errors.New("telegram cannot be reached")
		e.fake.FailAsk(down)
		for range approval.MaxOpenMessages + 1 {
			r := e.now(secretsReq("laptop", "github-token"))
			checkDenied(t, r, audit.CauseError)
			if r.ErrorCode != audit.CodeApproverFailed || !errors.Is(r.Err, down) || r.Message != "" {
				t.Errorf("code %q, err %v, message %q; want approver_failed, the error, no message", r.ErrorCode, r.Err, r.Message)
			}
			checkEvents(t, r, "request", "error:approver_failed", "denied:error")
		}
		if len(e.fake.Ended()) != 0 {
			t.Error("End was called for a message that was not sent")
		}
		e.fake.FailAsk(nil)
		e.clock.Advance(time.Minute) // the failed sends count for the limit per minute
		e.fill(approval.MaxOpenMessages)
		e.asked(approval.MaxOpenMessages)
	})
}

// noIDApprover sends a message, but does not say which one.
type noIDApprover struct{ *approvaltest.Approver }

func (a noIDApprover) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	shown, err := a.Approver.Ask(ctx, p)
	shown.ID = ""
	return shown, err
}

// TestAskWithoutMessageID checks that a message without an ID is a
// failure: no answer could ever name it.
func TestAskWithoutMessageID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		core, err := approval.New(cfg, noIDApprover{approvaltest.NewApprover(approverID)}, approval.Options{Clock: approvaltest.NewClock(noon)})
		if err != nil {
			t.Fatal(err)
		}
		r := core.Decide(context.Background(), secretsReq("laptop", "github-token"))
		checkDenied(t, r, audit.CauseError)
	})
}

// TestApproverStops checks that when Run returns, no answer can come: the
// requests that wait for the person are denied, and so is each new one
// that needs a message. No notice goes out any more either, so a "never
// ask" use that needs one is denied too. Grants still work, and so do
// "never ask" rules with notify = false. The fake approver honours its
// context, as a real one does.
func TestApproverStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			setSecretRule(cfg, "npm-token", config.Rule{Ask: config.AskNever, Notify: false})
		})
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		e.clock.Advance(time.Minute)
		chs := e.fill(approval.MaxOpenMessages + 2)

		down := errors.New("the bot token was revoked")
		e.fake.Stop(down)
		if err := e.runResult(); !errors.Is(err, down) {
			t.Errorf("Run returned %v, want %v", err, down)
		}
		for i, ch := range chs {
			r := mustResult(t, ch)
			checkDenied(t, r, audit.CauseError)
			if r.ErrorCode != audit.CodeApproverFailed || !errors.Is(r.Err, approval.ErrStopped) {
				t.Errorf("request %d: code %q, err %v; want approver_failed and ErrStopped", i, r.ErrorCode, r.Err)
			}
		}
		if n := len(e.fake.Ended()); n != approval.MaxOpenMessages+1 {
			t.Errorf("%d messages updated, want %d", n, approval.MaxOpenMessages+1)
		}
		r := e.now(secretsReq("laptop", "db-password"))
		checkDenied(t, r, audit.CauseError)
		e.asked(1 + approval.MaxOpenMessages)
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		checkAllowed(t, e.now(secretsReq("laptop", "npm-token"))) // notify = false
		r = e.now(secretsReq("ci", "backup-token"))               // notify = true
		checkDenied(t, r, audit.CauseError)
		if r.ErrorCode != audit.CodeApproverFailed || !errors.Is(r.Err, context.Canceled) {
			t.Errorf("a never-ask use with a notice: code %q, err %v; want approver_failed, context.Canceled", r.ErrorCode, r.Err)
		}
		checkEvents(t, r, "request", "error:approver_failed", "denied:error")
		if n := len(e.fake.Notices()); n != 0 {
			t.Errorf("%d notices after the stop, want 0", n)
		}
		if err := e.core.Answer(approval.Answer{UserID: approverID}); !errors.Is(err, approval.ErrStopped) {
			t.Errorf("an answer after Run returned: %v, want ErrStopped", err)
		}
		if err := e.core.Run(context.Background()); err == nil {
			t.Error("a second Run worked")
		}
	})
}

// TestRunStopsWithTheContext checks that Run returns when its context
// ends, and that the core then denies what waits.
func TestRunStopsWithTheContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.stop()
		if err := e.runResult(); !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
		checkDenied(t, mustResult(t, ch), audit.CauseError)
	})
}

// TestEndFails checks that a message that cannot be updated does not
// change the decision.
func TestEndFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.fake.FailEnd(errors.New("telegram cannot be reached"))
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.tap(1, audit.AnswerApproveOnce)
		checkAllowed(t, mustResult(t, ch))
	})
}

// TestEndShowsTheAnswer checks the update of a message after an answer.
func TestEndShowsTheAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		for i, action := range []audit.Answer{audit.AnswerApproveOnce, audit.AnswerApproveWindow, audit.AnswerDeny} {
			ch := e.decide(secretsReq("laptop", "npm-token"))
			mustWait(t, ch)
			e.clock.Advance(7 * time.Second)
			e.tap(i+1, action)
			mustResult(t, ch)
			at := e.clock.Now()
			ended := e.fake.Ended()
			if len(ended) != i+1 {
				t.Fatalf("%d updates, want %d", len(ended), i+1)
			}
			end := ended[i]
			want := approval.Ending{Answer: action, At: at}
			switch action {
			case audit.AnswerApproveWindow:
				want.WindowMinutes = 5
			case audit.AnswerDeny:
				want.Cause = audit.CauseApprover
			}
			if end.Ending != want || end.Message != e.fake.Asked()[i].Message || end.Prompt.RequestID != e.fake.Asked()[i].Prompt.RequestID {
				t.Errorf("update %+v, want %+v on message %s", end, want, e.fake.Asked()[i].Message)
			}
		}
	})
}

// TestNewChecksItsInput checks that New refuses what it cannot work with.
func TestNewChecksItsInput(t *testing.T) {
	cfg, _ := testConfig(t)
	fake := approvaltest.NewApprover(approverID)
	if _, err := approval.New(nil, fake, approval.Options{}); err == nil {
		t.Error("New without a config worked")
	}
	if _, err := approval.New(cfg, nil, approval.Options{}); err == nil {
		t.Error("New without an approver worked")
	}
	for _, edit := range []func(*config.Broker){
		func(c *config.Broker) { c.Telegram.UserID = 0 },
		func(c *config.Broker) { c.Telegram.UserID = -1 },
		func(c *config.Broker) { c.Telegram.Timeout = 0 },
		func(c *config.Broker) { c.Telegram.SSHTimeout = 0 },
	} {
		c := *cfg
		edit(&c)
		if _, err := approval.New(&c, fake, approval.Options{}); err == nil {
			t.Errorf("New worked with %+v", c.Telegram)
		}
	}
	if _, err := approval.New(cfg, fake, approval.Options{}); err != nil {
		t.Errorf("New with the defaults: %v", err)
	}
}

// TestRealClock checks the core with the real clock: a request expires
// on time. synctest makes the time of the time package fake, so the test
// does not wait.
func TestRealClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		fake := approvaltest.NewApprover(approverID)
		core, err := approval.New(cfg, fake, approval.Options{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = core.Run(ctx) }()
		start := time.Now()
		r := core.Decide(context.Background(), secretsReq("laptop", "github-token"))
		checkDenied(t, r, audit.CauseExpired)
		if took := time.Since(start); took != secretsTimeout {
			t.Errorf("the request expired after %v, want %v", took, secretsTimeout)
		}
	})
}

// decideRecover runs Decide as a broker that recovers a panic for each
// connection would. It returns nil when Decide panicked.
func decideRecover(core *approval.Core, r *approval.Request) (res *approval.Result) {
	defer func() {
		if v := recover(); v != nil {
			res = nil
		}
	}()
	return core.Decide(context.Background(), r)
}

// panicAsk panics in Ask the first left times, as a bug in the approver
// would.
type panicAsk struct {
	*approvaltest.Approver
	mu   sync.Mutex
	left int
}

func (a *panicAsk) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	a.mu.Lock()
	if a.left > 0 {
		a.left--
		a.mu.Unlock()
		panic("a bug in the approver")
	}
	a.mu.Unlock()
	return a.Approver.Ask(ctx, p)
}

// TestAskPanicFreesThePlace checks that a panic in Ask goes on to the
// caller, and that the request gives its place back. Before, 5 panics
// locked the client out until a restart. (From the security review of
// issue #6.)
func TestAskPanicFreesThePlace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		a := &panicAsk{Approver: approvaltest.NewApprover(approverID), left: approval.MaxOpenMessages}
		clock := approvaltest.NewClock(noon)
		core, err := approval.New(cfg, a, approval.Options{Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		for range approval.MaxOpenMessages {
			if r := decideRecover(core, secretsReq("laptop", "db-password")); r != nil {
				t.Fatalf("Decide did not panic: %+v", r)
			}
		}
		if open, queued := core.Counts("laptop"); open != 0 || queued != 0 {
			t.Fatalf("%d open and %d queued after the panics, want 0", open, queued)
		}
		if ids, _, waiting := core.Live(); ids != 0 || waiting != 0 {
			t.Fatalf("%d IDs and %d waiting after the panics, want 0", ids, waiting)
		}
		ch := make(chan *approval.Result, 1)
		go func() { ch <- core.Decide(context.Background(), secretsReq("laptop", "db-password")) }()
		synctest.Wait()
		if n := len(a.Asked()); n != 1 {
			t.Fatalf("%d messages, want 1: the client gets messages again", n)
		}
		if open, _ := core.Counts("laptop"); open != 1 {
			t.Errorf("%d open, want 1", open)
		}
		clock.Advance(secretsTimeout)
		checkDenied(t, <-ch, audit.CauseExpired)
	})
}

// TestOnWaitPanicFreesThePlace checks a panic in OnWait, for a request with
// a place and for one in the queue.
func TestOnWaitPanicFreesThePlace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		boom := func(string) { panic("a bug in the broker") }
		for range approval.MaxOpenMessages + 2 {
			req := secretsReq("laptop", "db-password")
			req.OnWait = boom
			if r := decideRecover(e.core, req); r != nil {
				t.Fatalf("Decide did not panic: %+v", r)
			}
		}
		if open, queued := e.core.Counts("laptop"); open != 0 || queued != 0 {
			t.Fatalf("%d open and %d queued after the panics, want 0", open, queued)
		}
		e.asked(0)
		e.clock.Advance(time.Minute) // each place that was taken counts for the limit per minute
		e.fill(approval.MaxOpenMessages + approval.MaxQueued)
		e.asked(approval.MaxOpenMessages)
		if _, queued := e.core.Counts("laptop"); queued != approval.MaxQueued {
			t.Errorf("%d queued, want %d: the queue has all its room", queued, approval.MaxQueued)
		}
	})
}

// panicRun panics in Run when boom is closed.
type panicRun struct {
	*approvaltest.Approver
	boom chan struct{}
}

func (a *panicRun) Run(context.Context, func(approval.Answer) error) error {
	<-a.boom
	panic("a bug in the poll loop")
}

// TestRunPanicStopsTheCore checks that a panic in the approver's Run goes
// on, and stops the core as a return would: the requests that wait for
// the person are denied at once, and new ones get no message. (From the
// security review of issue #6.)
func TestRunPanicStopsTheCore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		a := &panicRun{Approver: approvaltest.NewApprover(approverID), boom: make(chan struct{})}
		core, err := approval.New(cfg, a, approval.Options{Clock: approvaltest.NewClock(noon)})
		if err != nil {
			t.Fatal(err)
		}
		panicked := make(chan bool, 1)
		go func() {
			defer func() { panicked <- recover() != nil }()
			_ = core.Run(context.Background())
		}()
		ch := make(chan *approval.Result, 1)
		go func() { ch <- core.Decide(context.Background(), secretsReq("laptop", "db-password")) }()
		synctest.Wait()
		close(a.boom)
		if !<-panicked {
			t.Fatal("Run did not panic")
		}
		synctest.Wait()
		select {
		case r := <-ch:
			checkDenied(t, r, audit.CauseError)
			if !errors.Is(r.Err, approval.ErrStopped) {
				t.Errorf("err %v, want ErrStopped", r.Err)
			}
		default:
			t.Fatal("the waiting request did not end")
		}
		r := core.Decide(context.Background(), secretsReq("laptop", "github-token"))
		checkDenied(t, r, audit.CauseError)
		if n := len(a.Asked()); n != 1 {
			t.Errorf("%d messages, want 1: none after the panic", n)
		}
	})
}

// TestNoMessageWithoutTime checks that no message goes out when the
// request's time is up before Ask, for example while OnWait blocked.
// Before, Ask ran with no time left. (From the security review of issue
// #6.)
func TestNoMessageWithoutTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		release := make(chan struct{})
		req := secretsReq("laptop", "db-password")
		req.OnWait = func(string) { <-release }
		ch := e.decide(req)
		synctest.Wait()
		if open, _ := e.core.Counts("laptop"); open != 1 {
			t.Fatalf("%d open, want 1: the place is held while OnWait blocks", open)
		}
		e.clock.Advance(secretsTimeout)
		close(release)
		r := mustResult(t, ch)
		checkDenied(t, r, audit.CauseExpired)
		checkEvents(t, r, "request", "denied:expired")
		e.asked(0)
		if open, _ := e.core.Counts("laptop"); open != 0 {
			t.Errorf("%d open, want 0", open)
		}
	})
}

// blockingAsk is an approver whose Ask waits until its context ends, as
// when Telegram cannot be reached and the approver tries again.
type blockingAsk struct{ *approvaltest.Approver }

func (blockingAsk) Ask(ctx context.Context, _ approval.Prompt) (approval.Shown, error) {
	<-ctx.Done()
	return approval.Shown{}, ctx.Err()
}

// TestAskEndsWhenRunReturns checks that the context of Ask ends when Run
// returns: no answer could come then.
func TestAskEndsWhenRunReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, _ := testConfig(t)
		a := blockingAsk{approvaltest.NewApprover(approverID)}
		core, err := approval.New(cfg, a, approval.Options{Clock: approvaltest.NewClock(noon)})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		runErr := make(chan error, 1)
		go func() { runErr <- core.Run(ctx) }()
		ch := make(chan *approval.Result, 1)
		go func() { ch <- core.Decide(context.Background(), secretsReq("laptop", "db-password")) }()
		synctest.Wait()
		select {
		case <-ch:
			t.Fatal("the request ended while Ask waits")
		default:
		}
		cancel()
		<-runErr
		synctest.Wait()
		select {
		case r := <-ch:
			checkDenied(t, r, audit.CauseError)
		default:
			t.Fatal("Ask did not end when Run returned")
		}
	})
}

// TestRequestEndsOnTheWallClock checks a host that slept: the monotonic
// clock stopped, but the wall clock went on past the end of the request.
// No answer counts then, and the queue lets no such request out.
func TestRequestEndsOnTheWallClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		chs := e.fill(approval.MaxOpenMessages)
		queued := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, queued)
		e.clock.Advance(10 * time.Second)
		e.clock.JumpWall(8 * time.Hour) // the host slept 8 hours
		if err := e.answer(1, nil); !errors.Is(err, approval.ErrExpired) {
			t.Errorf("a tap after the wall clock passed the end: %v, want ErrExpired", err)
		}
		// A place is free; the queued request does not get it.
		e.clock.Advance(sshTimeout)
		checkDenied(t, mustResult(t, queued), audit.CauseLimit)
		for _, ch := range chs {
			mustWait(t, ch) // they end on the monotonic clock: 120 s after their start
		}
		e.clock.Advance(secretsTimeout)
		for _, ch := range chs {
			checkDenied(t, mustResult(t, ch), audit.CauseExpired)
		}
		e.asked(approval.MaxOpenMessages)
	})
}
