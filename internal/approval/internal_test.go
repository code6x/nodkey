package approval

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// The tests in this file look inside the core. They cannot use package
// approvaltest, which imports this package, so they have their own small
// clock.

type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time  { return c.now }
func (c *manualClock) Wall() time.Time { return c.now }

func (c *manualClock) TimerAt(time.Time) Timer { return nilTimer{} }

type nilTimer struct{}

func (nilTimer) C() <-chan time.Time { return nil }
func (nilTimer) Stop()               {}

// TestDayUses checks the count of max_per_day: a later day starts again,
// and a clock that goes back does not.
func TestDayUses(t *testing.T) {
	d1 := dayOf(time.Date(2026, 10, 14, 23, 59, 59, 0, time.UTC))
	d2 := dayOf(time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	d0 := dayOf(time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))
	newYear := dayOf(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))

	var u dayUses
	if u.on(d1) != 0 {
		t.Fatal("a new count is not 0")
	}
	u = u.add(d1).add(d1)
	if u.on(d1) != 2 {
		t.Errorf("2 uses on one day count %d", u.on(d1))
	}
	if u.on(d2) != 0 || u.on(newYear) != 0 {
		t.Error("the uses of yesterday count today")
	}
	// The clock goes back a day: the uses of the later day still count.
	if u.on(d0) != 2 {
		t.Errorf("after the clock went back, the count is %d, want 2", u.on(d0))
	}
	u = u.add(d0)
	if u.on(d1) != 3 || u.on(d0) != 3 {
		t.Errorf("a use while the clock is back counts %d, want 3 for the later day", u.on(d1))
	}
	u = u.add(d2)
	if u.on(d2) != 1 {
		t.Errorf("a new day counts %d, want 1", u.on(d2))
	}
}

// TestDayUsesRemove checks that a use taken back comes off the count of
// its own day only: not off a count that a later day started again, and
// never below 0. (Issue #47: a notice that the approver's limit stopped.)
func TestDayUsesRemove(t *testing.T) {
	d1 := dayOf(time.Date(2026, 10, 14, 23, 59, 59, 0, time.UTC))
	d2 := dayOf(time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	d0 := dayOf(time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))

	u := dayUses{}.add(d1).add(d1)
	if u = u.remove(d1); u.on(d1) != 1 {
		t.Errorf("after one use was taken back, the count is %d, want 1", u.on(d1))
	}
	if u = u.remove(d1).remove(d1); u.on(d1) != 0 {
		t.Errorf("the count is %d, want 0", u.on(d1))
	}
	// A later day started again: a use of the day before is not in it.
	u = u.add(d1).add(d2)
	if u = u.remove(d1); u.on(d2) != 1 {
		t.Errorf("a use of the day before came off the new count: %d, want 1", u.on(d2))
	}
	// While the clock is back, a use counts on the later day. add returns
	// that day, and the use comes off its count.
	u = u.add(d0)
	if u.day != d2 || u.on(d2) != 2 {
		t.Fatalf("a use while the clock is back: day %v, count %d; want %v and 2", u.day, u.on(d2), d2)
	}
	if u = u.remove(u.day); u.on(d2) != 1 {
		t.Errorf("the count is %d, want 1", u.on(d2))
	}
	if u = u.remove(d0); u.on(d2) != 1 {
		t.Errorf("a remove for an earlier day changed the count to %d", u.on(d2))
	}
}

// TestWindowMinutes checks the N of "Approve N min".
func TestWindowMinutes(t *testing.T) {
	w := func(d time.Duration) item { return item{rule: config.Rule{Ask: config.AskWindow, Window: d}} }
	always := item{rule: config.Rule{Ask: config.AskAlways}}
	never := item{rule: config.Rule{Ask: config.AskNever}}
	for _, tt := range []struct {
		items []item
		want  int
	}{
		{nil, 0},
		{[]item{w(15 * time.Minute)}, 15},
		{[]item{w(15 * time.Minute), w(5 * time.Minute)}, 5},
		{[]item{w(5 * time.Minute), w(15 * time.Minute)}, 5},
		{[]item{w(15 * time.Minute), always}, 0},
		{[]item{never, w(15 * time.Minute)}, 0},
		{[]item{w(119 * time.Second)}, 1},
		{[]item{w(time.Minute - 1)}, 0},
		{[]item{w(15 * time.Minute), w(30 * time.Second)}, 0},
	} {
		if got := windowMinutes(tt.items); got != tt.want {
			t.Errorf("windowMinutes(%v) = %d, want %d", tt.items, got, tt.want)
		}
	}
}

// TestAnswerAfterTheDeadline checks that an answer that comes after the
// deadline, before the waiting goroutine has noticed it, does not count
// and changes nothing.
func TestAnswerAfterTheDeadline(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	cfg := &config.Broker{Telegram: config.Telegram{UserID: 1, Timeout: time.Minute, SSHTimeout: time.Minute}}
	c, err := New(cfg, stubApprover{}, Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	p := &pending{
		id: "AAAAAAAAAAAAAAAAAAAAAA", client: "laptop", once: true, msg: "m",
		deadline: c.now().add(time.Minute), state: stateWaiting,
		ready: make(chan struct{}), poke: make(chan struct{}, 1), done: make(chan struct{}),
	}
	c.waiting[p.id] = p
	c.client("laptop").open = 1
	clock.now = p.deadline.mono
	err = c.Answer(Answer{RequestID: p.id, Action: audit.AnswerApproveOnce, Message: "m", UserID: 1})
	if !errors.Is(err, ErrExpired) {
		t.Errorf("answer at the deadline: %v, want ErrExpired", err)
	}
	if c.waiting[p.id] != p || p.state != stateWaiting || p.result != nil || c.clients["laptop"].open != 1 {
		t.Error("the refused answer changed the request")
	}
	select {
	case <-p.done:
		t.Error("the refused answer ended the request")
	default:
	}
}

// stubApprover is an approver that does nothing.
type stubApprover struct{}

func (stubApprover) Ask(context.Context, Prompt) (Shown, error)           { return Shown{}, errors.New("stub") }
func (stubApprover) End(context.Context, MessageID, Prompt, Ending) error { return nil }
func (stubApprover) Notify(context.Context, Prompt) error                 { return nil }
func (stubApprover) Run(ctx context.Context, _ func(Answer) error) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestShortCodes checks that short codes use only the alphabet and every
// character of it.
func TestShortCodes(t *testing.T) {
	var b bytes.Buffer
	for i := range 248 {
		b.WriteByte(byte(i))
	}
	seen := map[rune]bool{}
	r := bytes.NewReader(bytes.Repeat(b.Bytes(), 4))
	for range 62 {
		code, err := newCode(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != codeSize || strings.Trim(code, codeAlphabet) != "" {
			t.Fatalf("code %q", code)
		}
		for _, c := range code {
			seen[c] = true
		}
	}
	if len(seen) != len(codeAlphabet) {
		t.Errorf("the codes use %d characters, want all %d", len(seen), len(codeAlphabet))
	}
	for _, c := range "01ilo" {
		if strings.ContainsRune(codeAlphabet, c) {
			t.Errorf("the alphabet has %q, which people mix up", c)
		}
	}
}

// TestRateFree checks when the limit per minute lets the next message go.
func TestRateFree(t *testing.T) {
	t0 := moment{mono: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	t0.wall = t0.mono
	var cs clientState
	for i := range MaxNewMessagesPerMinute {
		cs.reserve(t0.add(time.Duration(i) * time.Second))
		cs.release()
	}
	if len(cs.sent) != MaxNewMessagesPerMinute {
		t.Fatalf("it keeps %d send times, want %d", len(cs.sent), MaxNewMessagesPerMinute)
	}
	now := t0.add(10 * time.Second)
	at, limited := cs.rateFree(now)
	if !limited || !at.Equal(t0.mono.Add(time.Minute)) || cs.canSend(now) {
		t.Errorf("rateFree = %v, %v; want limited until %v", at, limited, t0.mono.Add(time.Minute))
	}
	if !cs.canSend(t0.add(time.Minute)) {
		t.Error("the limit holds a minute after the first message")
	}
	cs.reserve(t0.add(time.Minute))
	if len(cs.sent) != MaxNewMessagesPerMinute || !cs.sent[0].Equal(t0.mono.Add(time.Second)) {
		t.Errorf("send times %v; want the newest %d", cs.sent, MaxNewMessagesPerMinute)
	}
}

// TestMoment checks that an end comes when either clock reaches it.
func TestMoment(t *testing.T) {
	t0 := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	start := moment{mono: t0, wall: t0}
	end := start.add(15 * time.Minute)
	for _, tt := range []struct {
		name   string
		now    moment
		before bool
		left   time.Duration
	}{
		{"both before", start.add(5 * time.Minute), true, 10 * time.Minute},
		{"both at the end", end, false, 0},
		// The host slept 8 hours: the monotonic clock stopped.
		{"the wall clock is past", moment{mono: t0.Add(5 * time.Minute), wall: t0.Add(8 * time.Hour)}, false, -7*time.Hour - 45*time.Minute},
		// Someone set the wall clock back an hour.
		{"the monotonic clock is past", moment{mono: t0.Add(16 * time.Minute), wall: t0.Add(-44 * time.Minute)}, false, -time.Minute},
		{"the wall clock is behind", moment{mono: t0.Add(5 * time.Minute), wall: t0.Add(-55 * time.Minute)}, true, 10 * time.Minute},
	} {
		if got := tt.now.before(end); got != tt.before {
			t.Errorf("%s: before = %v, want %v", tt.name, got, tt.before)
		}
		if got := tt.now.until(end); got != tt.left {
			t.Errorf("%s: until = %v, want %v", tt.name, got, tt.left)
		}
	}
	a := moment{mono: t0.Add(time.Minute), wall: t0.Add(3 * time.Minute)}
	b := moment{mono: t0.Add(2 * time.Minute), wall: t0.Add(2 * time.Minute)}
	if got := earlier(a, b); !got.mono.Equal(a.mono) || !got.wall.Equal(b.wall) {
		t.Errorf("earlier = %+v, want the earlier time on each clock", got)
	}
}

// TestUseDay checks the day that a use of a "never ask" rule counts for:
// for hours that go past midnight, the day the hours began.
func TestUseDay(t *testing.T) {
	night := config.Hours{From: 23*time.Hour + 30*time.Minute, To: 30 * time.Minute}
	early := config.Hours{From: 3 * time.Hour, To: 3*time.Hour + 20*time.Minute}
	at := func(d, hh, mm int) time.Time { return time.Date(2026, 10, d, hh, mm, 0, 0, time.UTC) }
	for _, tt := range []struct {
		hours *config.Hours
		t     time.Time
		want  int // day of October
	}{
		{nil, at(15, 0, 15), 15},
		{&early, at(15, 3, 10), 15},
		{&night, at(14, 23, 45), 14},
		{&night, at(15, 0, 15), 14},
		{&night, at(15, 0, 30), 15}, // the end is not part of the hours
		{&night, at(15, 12, 0), 15},
	} {
		got := useDay(config.Rule{Ask: config.AskNever, Hours: tt.hours}, tt.t)
		if got != (day{2026, time.October, tt.want}) {
			t.Errorf("useDay(%v, %s) = %v, want October %d", tt.hours, tt.t.Format("Jan 2 15:04"), got, tt.want)
		}
	}
	// Across the end of a month.
	if got := useDay(config.Rule{Ask: config.AskNever, Hours: &night}, time.Date(2026, 11, 1, 0, 10, 0, 0, time.UTC)); got != (day{2026, time.October, 31}) {
		t.Errorf("useDay at November 1 00:10 = %v, want October 31", got)
	}
}
