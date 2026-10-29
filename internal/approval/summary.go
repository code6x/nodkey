package approval

import (
	"context"
	"log/slog"
	"time"
)

// summaryTimeout bounds the send of the weekly summary.
const summaryTimeout = 30 * time.Second

// nextSummary returns the first time after wall that is on weekday day at
// minute of the day, in the location of wall.
func nextSummary(wall time.Time, day time.Weekday, minute int) time.Time {
	y, m, d := wall.Date()
	for i := 0; i < 9; i++ { // a match comes at least every 7 days
		t := time.Date(y, m, d+i, minute/60, minute%60, 0, 0, wall.Location())
		if t.Weekday() == day && t.After(wall) {
			return t
		}
	}
	return wall.AddDate(0, 0, 7) // not reached
}

// watchSummary sends the weekly summary of the standing grants (DESIGN.md
// section 8) once a week, at the time of [standing] summary in broker local
// time, until ctx or the core ends. It does nothing without [standing] or
// with an approver that cannot send it. A send that fails is logged and
// not tried again until next week.
func (c *Core) watchSummary(ctx context.Context) {
	s, ok := c.approver.(Summarizer)
	if !ok || !c.cfg.Standing.Enabled {
		return
	}
	var sent time.Time // the target of the last summary
	for {
		now := c.now()
		target := nextSummary(now.wall, c.cfg.Standing.SummaryDay, c.cfg.Standing.SummaryMinute)
		t := c.clock.TimerAt(now.mono.Add(target.Sub(now.wall)))
		select {
		case <-t.C():
		case <-ctx.Done():
		case <-c.stopCtx.Done():
		}
		t.Stop()
		if ctx.Err() != nil || c.stopCtx.Err() != nil {
			return
		}
		if c.now().wall.Before(target) || !target.After(sent) {
			continue // the timer was early, or this time had its summary: the wall clock was set back
		}
		sent = target
		cctx, cancel := c.callContext(c.stopCtx, summaryTimeout)
		err := s.Summary(cctx, c.ListStanding())
		cancel()
		if err != nil {
			c.logger.LogAttrs(ctx, slog.LevelWarn, "approval: cannot send the weekly summary of standing grants",
				slog.Any("error", err))
		}
	}
}
