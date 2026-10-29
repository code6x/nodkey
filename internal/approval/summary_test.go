package approval

import (
	"testing"
	"time"
)

// TestNextSummary: the next time is after wall, on the day, at the minute
// of the day, in the location of wall.
func TestNextSummary(t *testing.T) {
	utc := time.UTC
	tests := []struct {
		name string
		wall time.Time
		day  time.Weekday
		min  int
		want time.Time
	}{
		{"same day, later", time.Date(2026, 10, 19, 8, 0, 0, 0, utc), time.Monday, 9 * 60, time.Date(2026, 10, 19, 9, 0, 0, 0, utc)},
		{"at the minute: next week", time.Date(2026, 10, 19, 9, 0, 0, 0, utc), time.Monday, 9 * 60, time.Date(2026, 10, 26, 9, 0, 0, 0, utc)},
		{"same day, later than the time", time.Date(2026, 10, 19, 9, 1, 0, 0, utc), time.Monday, 9 * 60, time.Date(2026, 10, 26, 9, 0, 0, 0, utc)},
		{"midweek", time.Date(2026, 10, 14, 12, 0, 0, 0, utc), time.Sunday, 23*60 + 59, time.Date(2026, 10, 18, 23, 59, 0, 0, utc)},
		{"year end", time.Date(2026, 12, 30, 12, 0, 0, 0, utc), time.Friday, 0, time.Date(2027, 1, 1, 0, 0, 0, 0, utc)},
	}
	for _, tt := range tests {
		if got := nextSummary(tt.wall, tt.day, tt.min); !got.Equal(tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
	if loc, err := time.LoadLocation("Europe/Sofia"); err == nil {
		// The clocks go back on 2026-10-25: the day is 25 hours long.
		wall := time.Date(2026, 10, 24, 12, 0, 0, 0, loc)
		got := nextSummary(wall, time.Monday, 9*60)
		if want := time.Date(2026, 10, 26, 9, 0, 0, 0, loc); !got.Equal(want) {
			t.Errorf("clock change: %v, want %v", got, want)
		}
	}
}
