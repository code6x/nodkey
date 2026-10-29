package approval

import (
	"testing"
	"time"
)

// TestEachWindowEndSkippedHour: on 2026-03-29 the clocks in Berlin go from
// 02:00 to 03:00. A window in 02:00-03:00 never opens, but its end is
// found once, so the missed-window alarm comes (DESIGN.md section 8).
func TestEachWindowEndSkippedHour(t *testing.T) {
	berlin := mustZone(t, "Europe/Berlin")
	ws := []window{{days: anyDay, from: hm(2, 0), to: hm(3, 0)}}
	from := time.Date(2026, 3, 28, 12, 0, 0, 0, berlin)
	to := time.Date(2026, 3, 30, 12, 0, 0, 0, berlin)
	var n int
	eachWindowEnd(ws, from, to, func(k windowKey, end time.Time) { n++ })
	if n != 2 { // 03-29 and 03-30
		t.Errorf("%d window ends, want 2", n)
	}
	n = 0
	eachWindowEnd(ws, to, from, func(windowKey, time.Time) { n++ }) // time goes back: nothing
	eachWindowEnd(ws, from, from, func(windowKey, time.Time) { n++ })
	if n != 0 {
		t.Errorf("%d window ends for an empty span", n)
	}
}
