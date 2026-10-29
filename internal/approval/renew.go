package approval

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/code6x/nodkey/internal/audit"
)

// Warning is what the approver shows warnDays before the end of a standing
// grant (DESIGN.md section 8): a message with a Renew button. It holds no
// token.
type Warning struct {
	// RequestID is the ID of the request that made the grant. The Renew
	// button carries it.
	RequestID, ShortCode string
	Client               string
	Secrets              []string
	// Windows are the windows as text, such as "daily 03:00-05:00", and
	// Uses the uses in each.
	Windows []string
	Uses    int
	GrantID string
	// End is when the grant ends, in the broker's local time.
	End time.Time
}

// Warner is an Approver that can send the warning before the end of a
// standing grant. It returns the message, which must be in the chat where
// the approver's taps count; a Renew counts only on it. The core sends a
// warning only to an approver that has this method.
type Warner interface {
	Warn(ctx context.Context, w Warning) (MessageID, error)
}

// warnItem is a queued warning and its grant.
type warnItem struct {
	g *grant
	w Warning
}

// OnRenewed sets the function that writes the decision entry of a Renew.
// The new grant exists only after f returned nil; with no f, or when f
// fails, a Renew does not count. f is called from the approver's goroutine,
// not under the core's lock. Call it before Run.
func (c *Core) OnRenewed(f func(audit.Decision) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onRenewed = f
}

// warnTime returns when the warning of the standing grant g comes, if g
// was approved at now: warnDays before its end. A grant that is not longer
// than that gets no warning (zero).
func (c *Core) warnTime(g *grant, now time.Time) time.Time {
	at := g.end.wall.Add(-time.Duration(c.cfg.Standing.WarnDays) * 24 * time.Hour)
	if !at.After(now) {
		return time.Time{}
	}
	return at
}

// pendingRenewal reports whether g is a renewal that waits for the next
// use of the token of the grant it renews. It has no token yet; it is not
// listed, has no alarms of its own and does not count toward max_grants.
func (g *grant) pendingRenewal() bool { return g.renewOf != nil }

// scanWarnings queues the warning of each standing grant whose warning
// time came. Each grant gets one warning, also when the send fails.
// Core.mu must be held.
func (c *Core) scanWarnings(now moment) {
	for _, g := range c.grants {
		if !g.standing() || g.warned || g.warnAt.IsZero() || g.pendingRenewal() || g.next != nil ||
			now.wall.Before(g.warnAt) || !now.before(g.end) {
			continue
		}
		g.warned = true
		loc := c.clock.Wall().Location()
		w := Warning{RequestID: g.reqID, ShortCode: g.code, Client: g.client, Uses: g.perWindow,
			GrantID: g.id, End: g.end.wall.In(loc)}
		for _, r := range g.refs {
			w.Secrets = append(w.Secrets, r.name)
		}
		for _, x := range g.windows {
			w.Windows = append(w.Windows, windowText(x))
		}
		c.warnQueue = append(c.warnQueue, warnItem{g: g, w: w})
	}
}

// deliverWarnings sends the queued warnings. A send that fails is logged;
// that grant gets no Renew button, and the person can make a new grant.
func (c *Core) deliverWarnings() {
	c.mu.Lock()
	q := c.warnQueue
	c.warnQueue = nil
	c.mu.Unlock()
	wr, ok := c.approver.(Warner)
	if !ok {
		return
	}
	for _, it := range q {
		ctx, cancel := c.callContext(c.stopCtx, endTimeout)
		m, err := wr.Warn(ctx, it.w)
		cancel()
		if err != nil || m == "" {
			c.logger.LogAttrs(ctx, slog.LevelWarn, "approval: cannot send the warning before the end of a standing grant",
				slog.String("grant_id", it.w.GrantID), slog.Any("error", err))
			continue
		}
		c.mu.Lock()
		if slices.Contains(c.grants, it.g) {
			it.g.warnMsg = m
		}
		c.mu.Unlock()
	}
}

// renew makes a new standing grant for the Renew button on the warning of
// the grant of a.RequestID (DESIGN.md section 8): a new ID, the same scope,
// and the same length counted from now, at most max_days. It passes the
// same checks as an approval: the approver, the grant and its own warning
// message. The decision entry is written first; the new grant exists only
// after that. The new grant has no token: the next use of the old grant's
// token hands it over (handOver).
func (c *Core) renew(a Answer) error {
	c.mu.Lock()
	unlock := true
	defer func() {
		if unlock {
			c.mu.Unlock()
		}
	}()
	if c.stopped {
		return ErrStopped
	}
	if a.UserID <= 0 || a.UserID != c.cfg.Telegram.UserID {
		return ErrNotApprover
	}
	now := c.now()
	c.sweepGrants(now)
	i := slices.IndexFunc(c.grants, func(g *grant) bool {
		return g.standing() && !g.pendingRenewal() && g.reqID == a.RequestID
	})
	if i < 0 {
		return ErrUnknownRequest
	}
	g := c.grants[i]
	switch {
	case g.next != nil || g.renewing:
		return ErrUnknownRequest // renewed already
	case g.warned && g.warnMsg == "":
		return ErrTooEarly
	case g.warnMsg == "" || a.Message != g.warnMsg:
		return ErrWrongMessage
	case c.onRenewed == nil:
		return ErrNotAllowed
	}
	lim := c.cfg.Standing
	// The new grant takes the place of g: g is counted, n is not.
	if c.standingCount(g.client) > lim.MaxGrants {
		return ErrNotAllowed
	}
	begin := g.start
	if begin.IsZero() || g.approved.After(begin) {
		begin = g.approved
	}
	length := min(g.end.wall.Sub(begin), time.Duration(lim.MaxDays)*24*time.Hour)
	end := now.wall.Add(length).Truncate(time.Second)
	if length <= 0 || !now.wall.Before(end) {
		return ErrNotAllowed
	}
	id, err := newID(c.random)
	if err != nil {
		return ErrNotAllowed
	}
	reqID, err := newID(c.random)
	if err != nil {
		return ErrNotAllowed
	}
	n := &grant{
		kind: kindStanding, id: id, client: g.client, refs: slices.Clone(g.refs),
		end: moment{wall: end, mono: now.mono.Add(end.Sub(now.wall))}, uses: noLimit,
		reqID: reqID, code: g.code, approved: now.wall,
		windows: slices.Clone(g.windows), perWindow: g.perWindow, scanned: now.wall,
	}
	n.warnAt = c.warnTime(n, now.wall)
	n.origin = g.origin
	n.origin.RequestID, n.origin.GrantID = reqID, id
	n.origin.Secrets = slices.Clone(g.origin.Secrets)
	n.origin.Windows = slices.Clone(g.origin.Windows)
	n.origin.Hosts = nil
	n.origin.NotBefore = now.wall.UTC().Truncate(time.Second).Format(time.RFC3339)
	n.origin.NotAfter = end.UTC().Format(time.RFC3339)
	loc := c.clock.Wall().Location()
	n.prompt = Prompt{RequestID: reqID, ShortCode: g.code, Kind: audit.KindStanding, Client: g.client,
		Secrets: slices.Clone(n.origin.Secrets), Uses: g.perWindow, From: now.wall.In(loc), Until: end.In(loc),
		Windows: slices.Clone(g.origin.Windows)}
	ev := audit.Decision{Subject: n.origin, UserID: a.UserID, Answer: audit.AnswerRenew, RenewOf: g.id}
	ev.Subject.Secrets = slices.Clone(n.origin.Secrets)
	ev.Subject.Windows = slices.Clone(n.origin.Windows)
	f := c.onRenewed
	g.renewing = true // a second tap waits for nothing: it is refused
	c.mu.Unlock()
	werr := f(ev)
	c.mu.Lock()
	g.renewing = false
	if werr != nil {
		return ErrNotAllowed
	}
	if !slices.Contains(c.grants, g) {
		// g ended while the entry was written: n ends as g did, and was
		// never usable, because only g's token could reach it.
		c.queueEnded([]audit.GrantEnded{{Subject: n.origin, Cause: g.endedAs}})
		return ErrUnknownRequest
	}
	n.renewOf, g.next = g, n
	c.grants = append(c.grants, n)
	// The warning becomes the message of the new grant, with its Revoke
	// button.
	n.msg = g.warnMsg
	g.warnMsg = ""
	c.msgQueue = append(c.msgQueue, msgUpdate{msg: n.msg, prompt: n.prompt,
		ending: Ending{Answer: audit.AnswerApproveOnce, At: now.wall, Revoke: true}})
	c.wakeGrants()
	return nil
}

// handOver ends the standing grant g, which has a renewal, with cause
// renewed, and gives the renewal g's token, its old tokens and its counts:
// the token that g's client holds is now the renewal's, and an old token
// is still an alarm. It runs on the next use of g's token, or at g's end.
// Core.mu must be held.
func (c *Core) handOver(g *grant) *grant {
	n := g.next
	n.tokenHash, n.oldHashes = g.tokenHash, g.oldHashes
	n.winKey, n.winUsed, n.marked, n.used = g.winKey, g.winUsed, g.marked, g.used
	n.lastUse, n.prevUse, n.alarmMark = g.lastUse, g.prevUse, g.alarmMark
	n.scanned = g.scanned
	g.next, n.renewOf = nil, nil
	g.oldHashes, g.used = nil, nil
	c.queueEnded(c.endWhere(func(x *grant) audit.EndCause {
		if x == g {
			return audit.EndRenewed
		}
		return ""
	}))
	return n
}
