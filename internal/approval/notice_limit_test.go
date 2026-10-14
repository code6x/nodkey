package approval_test

// Attack tests from the security review of issue #47: can taking back a
// use after an approver limit (uncount) give more than max_per_day uses
// without a tap?

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// holdFirstNotice holds the first Notify until release is closed, then
// refuses it with the approver's limit. Later calls go to the fake.
type holdFirstNotice struct {
	*approvaltest.Approver
	mu      sync.Mutex
	calls   int
	held    chan struct{} // closed when the first call waits
	release chan struct{}
}

func (a *holdFirstNotice) Notify(ctx context.Context, p approval.Prompt) error {
	a.mu.Lock()
	a.calls++
	first := a.calls == 1
	a.mu.Unlock()
	if first {
		close(a.held)
		<-a.release
		return fmt.Errorf("refused: %w", approval.ErrLimit)
	}
	return a.Approver.Notify(ctx, p)
}

// nlEnv starts a core with backup-token as never, notify, max_per_day = 1
// and the approver a, at start.
func nlEnv(t *testing.T, start time.Time, hours *config.Hours) (*approval.Core, *holdFirstNotice, *approvaltest.Clock, context.CancelFunc) {
	t.Helper()
	cfg, _ := testConfig(t)
	setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 1, Hours: hours})
	a := &holdFirstNotice{Approver: approvaltest.NewApprover(approverID), held: make(chan struct{}), release: make(chan struct{})}
	clock := approvaltest.NewClock(start)
	core, err := approval.New(cfg, a, approval.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = core.Run(ctx) }()
	synctest.Wait()
	return core, a, clock, cancel
}

// decideAsync runs Decide with a context that the test can end, so a
// request that asks the person does not wait for its timeout.
func decideAsync(core *approval.Core) (<-chan *approval.Result, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *approval.Result, 1)
	go func() { ch <- core.Decide(ctx, secretsReq("ci", "backup-token")) }()
	return ch, cancel
}

// TestNLConcurrentRefusalGivesNoExtraUse: A holds the one use while its
// notice waits; B, at the same time, must ask. A is refused by the limit
// and its use comes back; C then goes without a tap, and D asks. One use
// without a tap in all.
func TestLimitRefusalAtTheSameTimeGivesNoExtraUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		core, a, _, cancel := nlEnv(t, noon, nil)
		defer cancel()
		chA, cA := decideAsync(core)
		defer cA()
		<-a.held
		chB, cB := decideAsync(core)
		synctest.Wait()
		if n := len(a.Asked()); n != 1 {
			t.Fatalf("B: %d messages, want 1 (B must ask while A holds the use)", n)
		}
		cB()
		synctest.Wait()
		checkDenied(t, <-chB, audit.CauseCancelled)
		close(a.release)
		synctest.Wait()
		checkDenied(t, <-chA, audit.CauseLimit)
		if n := core.Uses("ci", false, "backup-token", noon); n != 0 {
			t.Fatalf("uses %d after the refusal, want 0", n)
		}
		chC, cC := decideAsync(core)
		defer cC()
		synctest.Wait()
		checkAllowed(t, <-chC)
		chD, cD := decideAsync(core)
		synctest.Wait()
		if n := len(a.Asked()); n != 2 {
			t.Fatalf("D: %d messages, want 2 (the one use is gone)", n)
		}
		cD()
		synctest.Wait()
		<-chD
	})
}

// TestNLRefusalAfterMidnightKeepsTheNewDay: A counts at 23:59:59 and is
// refused after midnight, when B has already counted for the new day. The
// take-back of A must not touch the count of the new day.
func TestLimitRefusalAfterMidnightKeepsTheNewDay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Date(2026, 10, 14, 23, 59, 59, 0, time.UTC)
		core, a, clock, cancel := nlEnv(t, start, nil)
		defer cancel()
		chA, cA := decideAsync(core)
		defer cA()
		<-a.held
		clock.Advance(2 * time.Second) // 00:00:01 on October 15
		chB, cB := decideAsync(core)
		defer cB()
		synctest.Wait()
		checkAllowed(t, <-chB) // a new day
		close(a.release)
		synctest.Wait()
		checkDenied(t, <-chA, audit.CauseLimit)
		if n := core.Uses("ci", false, "backup-token", clock.Wall()); n != 1 {
			t.Fatalf("uses of the new day %d, want 1 (A's take-back changed it)", n)
		}
		chC, cC := decideAsync(core)
		synctest.Wait()
		if n := len(a.Asked()); n != 1 {
			t.Fatalf("C: %d messages, want 1 (C must ask)", n)
		}
		cC()
		synctest.Wait()
		<-chC
	})
}

// TestNLRefusalWithTheClockSetBack: A counts on the 15th, the wall clock
// goes back to the 14th, and B must ask (the later day still counts). A's
// refusal takes its use back from the count of the 15th, so C may go; D
// asks. One use without a tap.
func TestLimitRefusalWithTheClockSetBack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		core, a, clock, cancel := nlEnv(t, noon, nil)
		defer cancel()
		clock.JumpWall(24 * time.Hour) // the 15th
		chA, cA := decideAsync(core)
		defer cA()
		<-a.held
		clock.JumpWall(-24 * time.Hour) // back to the 14th
		chB, cB := decideAsync(core)
		synctest.Wait()
		if n := len(a.Asked()); n != 1 {
			t.Fatalf("B: %d messages, want 1", n)
		}
		cB()
		synctest.Wait()
		<-chB
		close(a.release)
		synctest.Wait()
		checkDenied(t, <-chA, audit.CauseLimit)
		chC, cC := decideAsync(core)
		defer cC()
		synctest.Wait()
		checkAllowed(t, <-chC)
		chD, cD := decideAsync(core)
		synctest.Wait()
		if n := len(a.Asked()); n != 2 {
			t.Fatalf("D: %d messages, want 2", n)
		}
		cD()
		synctest.Wait()
		<-chD
	})
}

// TestNLOnlyErrLimitIsALimit: errors that only look like a limit by their
// text, or that wrap another error, are failures, and the use counts.
func TestOnlyErrLimitIsALimit(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("approval: over a limit of the approver"), // same text, not the value
		fmt.Errorf("429 too many requests: %w", context.DeadlineExceeded),
	} {
		synctest.Test(t, func(t *testing.T) {
			e := newEnv(t, func(cfg *config.Broker) {
				setSecretRule(cfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 1})
			})
			defer e.stop()
			e.fake.FailNotify(err)
			r := e.now(secretsReq("ci", "backup-token"))
			checkDenied(t, r, audit.CauseError)
			if n := e.core.Uses("ci", false, "backup-token", noon); n != 1 {
				t.Fatalf("%v: uses %d, want 1 (the notice may have gone out)", err, n)
			}
		})
	}
}
