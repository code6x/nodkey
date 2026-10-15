package broker

import (
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// maxLogValue is the most bytes of one value in a log line of the broker.
const maxLogValue = 1 << 10

// NewLogger returns a logger for the broker's log, on w: slog's text
// handler. Each record is one line that starts with "time=". The handler
// quotes a value with a line break or another control character, and
// escapes it, so no value can start a new line, such as a line that starts
// with "audit anchor " (DESIGN.md section 9). NewLogger also cuts each
// value to maxLogValue bytes, so no line comes near the 48 KiB at which
// journald splits a line.
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{ReplaceAttr: cutAttr}))
}

// cutAttr cuts the value of a to maxLogValue bytes. An error becomes its
// text, cut.
func cutAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		if s := a.Value.String(); len(s) > maxLogValue {
			a.Value = slog.StringValue(cutText(s))
		}
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok {
			a.Value = slog.StringValue(errorText(err))
		} else {
			a.Value = slog.StringValue(cutText(fmt.Sprint(a.Value.Any())))
		}
	default:
	}
	return a
}

// errorText returns the text of err for the log, cut to maxLogValue
// bytes. The broker logs only errors whose text is fixed, such as those of
// the stores, the approver and package sshauth; the cut is one more guard.
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return cutText(err.Error())
}

// cutText cuts s to at most maxLogValue bytes, at the start of a
// character, with "..." at the end.
func cutText(s string) string {
	if len(s) <= maxLogValue {
		return s
	}
	n := maxLogValue - len("...")
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// panicPlace returns where a panic happened: the function, file and line
// of the frames below the panic, without any values. Call it in the
// deferred function that recovered the panic.
func panicPlace() string {
	pcs := make([]uintptr, 64)
	n := runtime.Callers(1, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	var places []string
	below := false // past runtime.gopanic: in the frames that panicked
	for {
		f, more := frames.Next()
		switch {
		case f.Function == "runtime.gopanic":
			below = true
		case below && !strings.HasPrefix(f.Function, "runtime."):
			places = append(places, f.Function+" "+f.File+":"+strconv.Itoa(f.Line))
		}
		if !more || len(places) == 8 {
			break
		}
	}
	if len(places) == 0 {
		return "unknown"
	}
	return strings.Join(places, " < ")
}

// rateWindow is the window of a rateLimit.
const rateWindow = time.Minute

// rateLimit lets at most n events through in each rateWindow, and counts
// the others. It reports the count of a window that dropped events with
// report: when the next window starts, or by a timer at the end of the
// window when no event comes, or at stop. It is safe for use by many
// goroutines.
type rateLimit struct {
	n      int
	report func(dropped int)

	mu      sync.Mutex
	start   time.Time // the start of the current window; zero before the first event
	count   int       // the events let through in the window
	dropped int       // the events dropped in the window
	window  uint64    // counts the windows, so a late timer changes nothing
	timer   *time.Timer
	stopped bool
}

func newRateLimit(n int, report func(dropped int)) *rateLimit {
	return &rateLimit{n: n, report: report}
}

// allow reports whether one more event may pass now.
func (l *rateLimit) allow() bool {
	l.mu.Lock()
	now := time.Now() // with a monotonic reading
	before := 0
	if l.start.IsZero() || now.Sub(l.start) >= rateWindow {
		before = l.dropped
		l.start, l.count, l.dropped = now, 0, 0
		l.window++
		if l.timer != nil {
			l.timer.Stop()
			l.timer = nil
		}
	}
	ok := l.count < l.n
	if ok {
		l.count++
	} else {
		l.dropped++
		if l.timer == nil && !l.stopped {
			window := l.window
			l.timer = time.AfterFunc(rateWindow-now.Sub(l.start), func() { l.flush(window) })
		}
	}
	l.mu.Unlock()
	if before > 0 {
		l.report(before)
	}
	return ok
}

// flush reports the count of the window, at its end, when no later event
// has reported it.
func (l *rateLimit) flush(window uint64) {
	l.mu.Lock()
	if window != l.window {
		l.mu.Unlock()
		return
	}
	dropped := l.dropped
	l.start, l.count, l.dropped, l.timer = time.Time{}, 0, 0, nil
	l.window++
	l.mu.Unlock()
	if dropped > 0 {
		l.report(dropped)
	}
}

// stop stops the timer, and reports a count that waits for it.
func (l *rateLimit) stop() {
	l.mu.Lock()
	l.stopped = true
	dropped := l.dropped
	l.dropped = 0
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	l.window++
	l.mu.Unlock()
	if dropped > 0 {
		l.report(dropped)
	}
}
