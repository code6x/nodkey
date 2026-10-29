package approval

import (
	"log/slog"
	"slices"
	"time"

	"github.com/code6x/nodkey/internal/audit"
)

// missedAlarm is the alarm of a window that ended with no use (DESIGN.md
// section 8): the entry for the audit log and the message for the approver.
type missedAlarm struct {
	ev audit.GrantAlarm
	al Alarm
}

// maxScanDays is the most days that scanMissed looks back. A grant lasts
// at most 366 days.
const maxScanDays = 400

// windowEnd returns the end of the opening of window w on the date of
// day. A window in the hour that a clock change skips has the end that
// time.Date gives; it never opened, so it counts as missed.
func windowEnd(w window, d time.Time) time.Time {
	y, m, dd := d.Date()
	mins := int(w.to / time.Minute)
	return time.Date(y, m, dd, mins/60, mins%60, 0, 0, d.Location())
}

// eachWindowEnd calls f for each opening of a window of ws whose end is
// after from and not after to, in the order of the days. f gets the
// key of the opening and its end.
func eachWindowEnd(ws []window, from, to time.Time, f func(windowKey, time.Time)) {
	if !to.After(from) {
		return
	}
	y, m, d := from.Date()
	day0 := time.Date(y, m, d, 0, 0, 0, 0, from.Location())
	for i := 0; i < maxScanDays; i++ {
		day := day0.AddDate(0, 0, i)
		if day.After(to) {
			return
		}
		for idx, w := range ws {
			if !w.valid() || !w.days.has(day.Weekday()) {
				continue
			}
			if end := windowEnd(w, day); end.After(from) && !end.After(to) {
				f(windowKey{day: dayOf(day), index: idx}, end)
			}
		}
	}
}

// nextWindowEnd returns the time from wall to the end of the next opening
// of a window of g that ends after wall and before the end of the grant.
func nextWindowEnd(g *grant, wall time.Time) (time.Duration, bool) {
	var best time.Time
	y, m, d := wall.Date()
	day0 := time.Date(y, m, d, 0, 0, 0, 0, wall.Location())
	for i := 0; i < 8 && best.IsZero(); i++ { // a window comes at least every 7 days
		day := day0.AddDate(0, 0, i)
		for _, w := range g.windows {
			if !w.valid() || !w.days.has(day.Weekday()) {
				continue
			}
			if end := windowEnd(w, day); end.After(wall) && (best.IsZero() || end.Before(best)) {
				best = end
			}
		}
	}
	if best.IsZero() || best.After(g.end.wall) {
		return 0, false
	}
	return best.Sub(wall), true
}

// scanMissed finds the windows of standing grants that ended since the
// last scan with no use in them, and queues one alarm for each. The grant
// stays. Each opening is looked at once, because scanned only moves
// forward. Core.mu must be held.
func (c *Core) scanMissed(now moment) {
	for _, g := range c.grants {
		if !g.standing() || g.pendingRenewal() || !now.wall.After(g.scanned) {
			continue
		}
		from := g.scanned
		g.scanned = now.wall
		eachWindowEnd(g.windows, from, now.wall, func(k windowKey, end time.Time) {
			if g.used[k] {
				delete(g.used, k)
				return
			}
			if !end.Before(g.end.wall) {
				return // the grant ended before this window did
			}
			sub := g.origin
			sub.Secrets = slices.Clone(g.origin.Secrets)
			sub.Hosts = slices.Clone(g.origin.Hosts)
			sub.Windows = slices.Clone(g.origin.Windows)
			c.alarmQueue = append(c.alarmQueue, missedAlarm{
				ev: audit.GrantAlarm{Subject: sub, Cause: audit.AlarmMissedWindow},
				al: Alarm{RequestID: g.reqID, ShortCode: g.code, Client: g.client, GrantID: g.id,
					Secrets: slices.Clone(sub.Secrets), Cause: audit.AlarmMissedWindow},
			})
		})
	}
}

// OnGrantAlarm sets the function that gets the audit entry of each
// missed-window alarm. The broker writes the entry. f is called from the
// core's own goroutine, not under its lock. Call it before Run.
func (c *Core) OnGrantAlarm(f func(audit.GrantAlarm)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onAlarm = f
}

// deliverAlarms writes the entries of the queued alarms, then sends the
// messages. A send that fails is logged: the entry is written, and the
// grant stays. The alarm of that window is not tried again.
func (c *Core) deliverAlarms() {
	c.mu.Lock()
	q, f := c.alarmQueue, c.onAlarm
	c.alarmQueue = nil
	c.mu.Unlock()
	for _, a := range q {
		if f != nil {
			f(a.ev)
		}
		al, ok := c.approver.(Alarmer)
		if !ok {
			continue
		}
		ctx, cancel := c.callContext(c.stopCtx, endTimeout)
		err := al.Alarm(ctx, a.al)
		cancel()
		if err != nil {
			c.logger.LogAttrs(ctx, slog.LevelWarn, "approval: cannot send the missed-window alarm of a standing grant",
				slog.String("grant_id", a.al.GrantID), slog.Any("error", err))
		}
	}
}
