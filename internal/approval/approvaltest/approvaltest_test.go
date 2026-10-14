package approvaltest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
)

var start = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func fired(tm approval.Timer) bool {
	select {
	case <-tm.C():
		return true
	default:
		return false
	}
}

func TestClock(t *testing.T) {
	c := approvaltest.NewClock(start)
	if !c.Now().Equal(start) {
		t.Fatalf("Now = %v, want %v", c.Now(), start)
	}
	past := c.TimerAt(start)
	if !fired(past) {
		t.Error("a timer for now did not fire at once")
	}
	late := c.TimerAt(start.Add(2 * time.Second))
	early := c.TimerAt(start.Add(time.Second))
	stopped := c.TimerAt(start.Add(time.Second))
	stopped.Stop()
	if c.Timers() != 2 {
		t.Errorf("%d timers wait, want 2", c.Timers())
	}
	c.Advance(time.Second - 1)
	if fired(early) || fired(late) {
		t.Error("a timer fired before its time")
	}
	c.Advance(1)
	if !fired(early) || fired(late) || fired(stopped) {
		t.Error("after 1 s: want only the 1 s timer to fire")
	}
	c.Advance(-time.Hour)
	c.Advance(0)
	if !c.Now().Equal(start.Add(time.Second)) {
		t.Errorf("the clock moved back to %v", c.Now())
	}
	c.Advance(time.Hour)
	if !fired(late) || c.Timers() != 0 {
		t.Errorf("after an hour: the 2 s timer fired %v, %d timers wait", fired(late), c.Timers())
	}
	late.Stop() // a fired timer can be stopped
}

// TestClockFiresAllDue checks that one Advance fires every timer that is
// due, and only those.
func TestClockFiresAllDue(t *testing.T) {
	c := approvaltest.NewClock(start)
	var due []approval.Timer
	for i := 1; i <= 5; i++ {
		due = append(due, c.TimerAt(start.Add(time.Duration(i)*time.Second)))
	}
	later := c.TimerAt(start.Add(time.Hour))
	c.Advance(5 * time.Second)
	for i, tm := range due {
		if !fired(tm) {
			t.Errorf("timer %d did not fire", i+1)
		}
	}
	if fired(later) || c.Timers() != 1 {
		t.Errorf("the later timer fired %v; %d timers wait, want 1", fired(later), c.Timers())
	}
}

func TestApproverRecords(t *testing.T) {
	a := approvaltest.NewApprover(42)
	ctx := context.Background()
	p := approval.Prompt{RequestID: "id-1", ShortCode: "k3f9", Kind: audit.KindSecrets, Client: "laptop",
		Secrets: []string{"github-token"}, Claim: approval.Claim{Command: "gh release create v1.2.0"}, Once: true, WindowMinutes: 15}
	shown, err := a.Ask(ctx, p)
	if err != nil || shown.ID != "message-1" || shown.Text != approvaltest.Text(p) {
		t.Fatalf("Ask = %+v, %v", shown, err)
	}
	for _, want := range []string{"request k3f9", "machine: laptop", "secrets: github-token", "command: gh release create v1.2.0",
		"[Approve once] [Approve 15 min] [Deny]"} {
		if !strings.Contains(shown.Text, want) {
			t.Errorf("the text has no %q:\n%s", want, shown.Text)
		}
	}
	if err := a.End(ctx, shown.ID, p, approval.Ending{Cause: audit.CauseExpired}); err != nil {
		t.Fatal(err)
	}
	if err := a.Notify(ctx, p); err != nil {
		t.Fatal(err)
	}
	if len(a.Asked()) != 1 || len(a.Ended()) != 1 || len(a.Notices()) != 1 {
		t.Errorf("kept %d asks, %d ends, %d notices; want 1 of each", len(a.Asked()), len(a.Ended()), len(a.Notices()))
	}

	down := errors.New("down")
	a.FailAsk(down)
	a.FailNotify(down)
	a.FailEnd(down)
	if _, err := a.Ask(ctx, p); !errors.Is(err, down) {
		t.Errorf("Ask: %v, want %v", err, down)
	}
	if err := a.Notify(ctx, p); !errors.Is(err, down) {
		t.Errorf("Notify: %v, want %v", err, down)
	}
	if err := a.End(ctx, shown.ID, p, approval.Ending{}); !errors.Is(err, down) {
		t.Errorf("End: %v, want %v", err, down)
	}
	if len(a.Asked()) != 1 || len(a.Notices()) != 1 {
		t.Error("a failed Ask or Notify was kept")
	}
	if _, err := a.WaitAsked(2, time.Millisecond); err == nil {
		t.Error("WaitAsked did not time out")
	}
}

func TestApproverRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := approvaltest.NewApprover(42)
		if err := a.Answer(approval.Answer{}); err == nil {
			t.Error("an answer reached the core before Run")
		}
		var got []approval.Answer
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- a.Run(ctx, func(ans approval.Answer) error {
				got = append(got, ans)
				return nil
			})
		}()
		if err := a.WaitRunning(time.Second); err != nil || !a.Running() {
			t.Fatalf("Run is not running: %v", err)
		}
		if err := a.Run(ctx, nil); err == nil {
			t.Error("a second Run worked")
		}
		if err := a.Tap("id-1", audit.AnswerApproveOnce); err == nil {
			t.Error("a tap on a request without a message worked")
		}
		shown, _ := a.Ask(ctx, approval.Prompt{RequestID: "id-1"})
		if err := a.Tap("id-1", audit.AnswerDeny); err != nil {
			t.Fatal(err)
		}
		want := approval.Answer{RequestID: "id-1", Action: audit.AnswerDeny, Message: shown.ID, UserID: 42}
		if len(got) != 1 || got[0] != want {
			t.Errorf("the core got %+v, want %+v", got, want)
		}

		stop := errors.New("stopped")
		a.Stop(stop)
		a.Stop(stop) // a second Stop does not block
		if err := <-done; !errors.Is(err, stop) {
			t.Errorf("Run returned %v, want %v", err, stop)
		}
		if a.Running() {
			t.Error("Run still runs")
		}
		cancel()
	})
}

// TestApproverAuto checks Auto with a real core: each message gets the
// tap at once.
func TestApproverAuto(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := approvaltest.NewApprover(42)
		answers := make(chan approval.Answer, 4)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready := false
		go func() {
			_ = a.Run(ctx, func(ans approval.Answer) error {
				// The first try comes before the core knows the message.
				if !ready {
					ready = true
					return approval.ErrTooEarly
				}
				answers <- ans
				return nil
			})
		}()
		synctest.Wait()
		a.Auto(audit.AnswerApproveWindow)
		if _, err := a.Ask(ctx, approval.Prompt{RequestID: "id-1"}); err != nil {
			t.Fatal(err)
		}
		if ans := <-answers; ans.RequestID != "id-1" || ans.Action != audit.AnswerApproveWindow {
			t.Errorf("auto answer %+v", ans)
		}
		a.Auto("")
		if _, err := a.Ask(ctx, approval.Prompt{RequestID: "id-2"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if len(answers) != 0 {
			t.Error("an answer came after Auto was turned off")
		}
		if _, err := a.WaitEnded(1, time.Second); err == nil {
			t.Error("WaitEnded did not time out")
		}
	})
}
