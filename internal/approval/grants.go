package approval

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/code6x/nodkey/internal/audit"
)

// noLimit is the uses left of a grant that has no number of uses: the
// grants of "Approve N min" and of nodkey ssh-grant.
const noLimit = -1

// grant is one grant (DESIGN.md section 8). Core.mu guards it. A grant of
// an "Approve N min" tap or of nodkey ssh-grant covers one secret, or one
// key at one host key and for one remote user, until its end. A scheduled
// grant (nodkey preapprove) covers a set of secrets, or one key at a set of
// host keys and for one remote user, from its start until its end, for a
// number of uses.
type grant struct {
	// kind says what the grant is. The zero value is a window grant.
	kind grantKind
	// id is the ID of a scheduled or standing grant. It is "" for a window
	// grant, which has no entry in the audit log of its own.
	id     string
	client string
	// refs are the secrets of the grant, or the one key.
	refs []ref
	// hostKeys are the host keys in SSH wire form that a key grant covers;
	// nil for secrets.
	hostKeys []string
	// user is the remote user of a key grant; "" for secrets.
	user string

	// start is the wall time before which the grant is not used. It is
	// zero for a grant that starts at once. Only the wall clock is read for
	// it: a start that waits for the monotonic clock would be late after a
	// host slept.
	start time.Time
	// end is when the grant ends, on both clocks.
	end moment
	// uses is the number of uses left, or noLimit.
	uses int
	// origin is the subject of the request that made a scheduled grant,
	// for its audit entries.
	origin audit.Subject
	// reqID is the ID of the request that made a scheduled grant. The
	// Revoke button carries it.
	reqID string
	// msg is the message of that request and prompt is the prompt of it.
	// They are set when the grant starts, and are "" for a grant whose
	// message the core does not know.
	msg    MessageID
	prompt Prompt
	// approved is when the person approved it.
	approved time.Time

	// windows are the daily or weekly windows of a standing grant. A grant
	// without windows is live all the time before its end.
	windows []window
	// perWindow is the number of uses in each opening of a window of a
	// standing grant.
	perWindow int
	// winKey is the latest opening of a window that had a use, and winUsed
	// the uses in it. A later opening starts the count again.
	winKey  windowKey
	winUsed int
	// tokenHash is the SHA-256 hash of the current token of a standing
	// grant, and oldHashes are the hashes of the tokens that it had
	// before: one for each use. The grant never holds a token.
	tokenHash [32]byte
	oldHashes [][32]byte
	// alarmMark is the day of the last alarm outside the windows.
	alarmMark string
}

// grantKind is the kind of a grant (DESIGN.md section 8, "The grant core").
type grantKind int

const (
	// kindWindow: "Approve N min" or nodkey ssh-grant. It must be the zero
	// value.
	kindWindow grantKind = iota
	// kindScheduled: a pre-approval with one time span.
	kindScheduled
	// kindStanding: a pre-approval with daily or weekly windows.
	kindStanding
)

// msgUpdate is a call to the approver about the message of a scheduled
// grant: End, and for a grant that ended with uses left also Notify. The
// calls wait in Core.msgQueue, so they run one after the other, in the
// order of the events.
type msgUpdate struct {
	msg    MessageID
	prompt Prompt
	ending Ending
	// notice says that the approver also gets a notice that the grant
	// ended with uses left. grantID is the grant's ID for it.
	notice  bool
	grantID string
	// tries counts the failed tries of an update that adds a Revoke button.
	tries int
}

// The tries of the update that adds a Revoke button: it can fail, such as
// by a timeout, and the grant may live for days. After a failed try, the
// next one comes after holdFirstWait, then twice as long, at most
// holdTries in all, and only while the grant lives (staleHold).
const (
	holdTries     = 3
	holdFirstWait = 10 * time.Second
)

// scheduled reports whether g is a scheduled grant.
func (g *grant) scheduled() bool { return g.kind == kindScheduled }

// standing reports whether g is a standing grant.
func (g *grant) standing() bool { return g.kind == kindStanding }

// audited reports whether g comes from nodkey preapprove, of any kind: it
// has an ID, entries in the audit log and a message.
func (g *grant) audited() bool { return g.kind != kindWindow }

// live reports whether g may be used at now: not before its start on the
// wall clock, and before its end on both clocks (moment.before), so a
// grant is never usable at or after its end. A wall clock that is set back
// cannot make it last longer, because the monotonic end stays.
//
// A grant with windows is live only inside one of them, read on the wall
// clock (window.go).
func (g *grant) live(now moment) bool {
	if now.wall.Before(g.start) || !now.before(g.end) {
		return false
	}
	if len(g.windows) == 0 {
		return true
	}
	_, _, in := windowAt(g.windows, now.wall)
	return in
}

// tryUse takes one use of the standing grant g at now, if it may be used.
// It tells apart a grant that is outside its windows and one whose uses in
// this window are spent, for the alarms. A standing grant without a valid
// window cannot be used.
func (g *grant) tryUse(now moment) useResult {
	if !g.standing() || len(g.windows) == 0 || now.wall.Before(g.start) || !now.before(g.end) {
		return useNone
	}
	key, _, in := windowAt(g.windows, now.wall)
	if !in {
		return useOutsideWindow
	}
	// A later opening starts the count again. An earlier or equal one keeps
	// it, so a wall clock set back cannot give more uses.
	if key.after(g.winKey) {
		g.winKey, g.winUsed = key, 0
	}
	if g.winUsed >= g.perWindow {
		return useOverUses
	}
	g.winUsed++
	return useOK
}

// giveBackUse takes back the use that tryUse took, because the use did
// not happen.
func (g *grant) giveBackUse() {
	if g.standing() {
		g.winUsed = max(g.winUsed-1, 0)
		return
	}
	g.uses++
}

// covers reports whether g covers the item r of a request of client with
// the host key hostKey ("" for a secret) and the remote user user.
func (g *grant) covers(client string, r ref, hostKey, user string) bool {
	if g.client != client || g.user != user || !slices.Contains(g.refs, r) {
		return false
	}
	if hostKey == "" {
		return len(g.hostKeys) == 0
	}
	return slices.Contains(g.hostKeys, hostKey)
}

// touches reports whether g covers any of the items.
func (g *grant) touches(items []item) bool {
	return slices.ContainsFunc(items, func(it item) bool { return slices.Contains(g.refs, it.ref) })
}

// endWhere is the one place where grants end. It removes each grant for
// which cause returns a cause, and returns the audit entries of the
// scheduled ones among them. Core.mu must be held.
func (c *Core) endWhere(cause func(*grant) audit.EndCause) []audit.GrantEnded {
	var ended []audit.GrantEnded
	c.grants = slices.DeleteFunc(c.grants, func(g *grant) bool {
		why := cause(g)
		if why == "" {
			return false
		}
		if g.audited() {
			ended = append(ended, audit.GrantEnded{Subject: g.origin, Cause: why, UsesLeft: max(g.uses, 0)})
			c.queueMessage(g, why)
		}
		return true
	})
	return ended
}

// queueMessage queues the update of the message of g, which ended with
// cause why: no button, and how and when it ended. A grant that ended
// by time with uses left also queues a notice. Core.mu must be held.
func (c *Core) queueMessage(g *grant, why audit.EndCause) {
	if g.msg == "" {
		return
	}
	at := c.clock.Wall()
	if why == audit.EndEnded {
		at = g.end.wall
	}
	left := max(g.uses, 0)
	c.msgQueue = append(c.msgQueue, msgUpdate{
		msg:    g.msg,
		prompt: g.prompt,
		ending: Ending{Answer: audit.AnswerApproveOnce, At: at, GrantEnd: why, UsesLeft: left, Approved: g.approved},
		notice: why == audit.EndEnded && left > 0, grantID: g.id,
	})
	c.wakeGrants()
}

// sweepGrants removes the grants that have ended. The entries of the
// scheduled ones wait for the goroutine of watchGrants. Core.mu must be
// held.
func (c *Core) sweepGrants(now moment) {
	c.queueEnded(c.endWhere(func(g *grant) audit.EndCause {
		if !now.before(g.end) {
			return audit.EndEnded
		}
		return ""
	}))
}

// queueEnded queues entries for the goroutine of watchGrants to hand to
// the function of OnGrantEnded. Core.mu must be held.
func (c *Core) queueEnded(evs []audit.GrantEnded) {
	if len(evs) == 0 {
		return
	}
	c.endedQueue = append(c.endedQueue, evs...)
	c.wakeGrants()
}

// wakeGrants wakes watchGrants, so that it looks at the grants again.
func (c *Core) wakeGrants() {
	select {
	case c.grantWake <- struct{}{}:
	default: // it is awake already
	}
}

// OnGrantEnded sets the function that gets the audit entry of each
// scheduled grant that ends without a request to carry it: at its end, at
// a stop. The broker writes the entry. f is called from the core's own
// goroutines, not under its lock, and maybe from two at once. Call it
// before Run.
func (c *Core) OnGrantEnded(f func(audit.GrantEnded)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onEnded = f
}

// takeEnded returns the queued entries and the function to give them to.
func (c *Core) takeEnded() ([]audit.GrantEnded, func(audit.GrantEnded)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	evs := c.endedQueue
	c.endedQueue = nil
	return evs, c.onEnded
}

// deliverMessages makes the queued calls about the messages of scheduled
// grants, one after the other, until ctx ends. What it did not make stays
// in the queue. A call that fails is logged; the audit log has the end of
// the grant anyway.
func (c *Core) deliverMessages(ctx context.Context) {
	for ctx.Err() == nil {
		// The entries of the audit log first: a slow Telegram must not
		// delay them.
		c.deliverEnded()
		c.mu.Lock()
		if len(c.msgQueue) == 0 {
			c.mu.Unlock()
			return
		}
		u := c.msgQueue[0]
		c.msgQueue = c.msgQueue[1:]
		stale := u.ending.Revoke && c.staleHold(u)
		c.mu.Unlock()
		if stale {
			continue
		}
		if !c.updateMessage(ctx, u) {
			// The stop cut the call short: the next delivery makes it.
			c.mu.Lock()
			c.msgQueue = slices.Insert(c.msgQueue, 0, u)
			c.mu.Unlock()
		}
	}
}

// staleHold reports whether u, an update that adds a Revoke button, is
// not needed any more: its grant is gone or past its end, or the update
// of its end waits. Core.mu must be held.
func (c *Core) staleHold(u msgUpdate) bool {
	now := c.now()
	if !slices.ContainsFunc(c.grants, func(g *grant) bool { return g.msg == u.msg && now.before(g.end) }) {
		return true
	}
	return slices.ContainsFunc(c.msgQueue, func(q msgUpdate) bool { return q.msg == u.msg && q.ending.GrantEnd != "" })
}

// retryHold queues the update u, which adds a Revoke button and failed,
// again after a wait, unless it has used its tries. It does not block: the
// wait is in a goroutine of its own, which ends when the core stops.
func (c *Core) retryHold(u msgUpdate) {
	u.tries++
	if u.tries >= holdTries {
		return
	}
	wait := holdFirstWait << (u.tries - 1)
	t := c.clock.TimerAt(c.now().mono.Add(wait))
	go func() {
		defer t.Stop()
		select {
		case <-t.C():
		case <-c.stopCtx.Done():
			return
		}
		c.mu.Lock()
		c.msgQueue = append(c.msgQueue, u)
		c.mu.Unlock()
		c.wakeGrants()
	}()
}

// updateMessage makes the calls of u. It reports false when ctx ended
// before the message was updated.
func (c *Core) updateMessage(ctx context.Context, u msgUpdate) bool {
	ectx, cancel := context.WithTimeout(ctx, endTimeout)
	defer cancel()
	if err := c.approver.End(ectx, u.msg, u.prompt, u.ending); err != nil {
		if ctx.Err() != nil {
			return false
		}
		c.logger.LogAttrs(ectx, slog.LevelWarn, "approval: cannot update the message of a scheduled grant",
			slog.String("request_id", u.prompt.RequestID), slog.Any("error", err))
		if u.ending.Revoke {
			c.retryHold(u)
		}
	}
	if !u.notice {
		return true
	}
	// The grant did not run, or ran late. The approver's own limit of
	// notices applies; the limit per client does not, because the person
	// did not ask for this notice (DESIGN.md section 8).
	n := u.prompt
	n.Expires, n.TimeLeft, n.Once, n.WindowMinutes = time.Time{}, 0, false, 0
	n.GrantID, n.UsesLeft = u.grantID, u.ending.UsesLeft
	nctx, ncancel := context.WithTimeout(ctx, endTimeout)
	defer ncancel()
	if err := c.approver.Notify(nctx, n); err != nil {
		c.logger.LogAttrs(nctx, slog.LevelWarn, "approval: cannot send the notice of a scheduled grant that was not used",
			slog.String("request_id", n.RequestID), slog.Any("error", err))
	}
	return true
}

// deliverEnded gives the queued entries to the function of OnGrantEnded.
func (c *Core) deliverEnded() {
	evs, f := c.takeEnded()
	if f == nil {
		return
	}
	for _, ev := range evs {
		f(ev)
	}
}

// watchGrants ends the scheduled grants when their time is up, and hands
// their entries out, until ctx ends or the core stops. A timer follows the
// monotonic clock only; a wall clock that moves forward is found by the
// next request, which sweeps first (begin). It also wakes at the end of
// the current window of each standing grant.
func (c *Core) watchGrants(ctx context.Context) {
	for {
		c.mu.Lock()
		c.sweepGrants(c.now())
		next, ok := c.nextEnd()
		c.mu.Unlock()
		c.deliverEnded()
		c.deliverMessages(c.stopCtx)
		var timer <-chan time.Time
		var t Timer
		if ok {
			t = c.clock.TimerAt(next)
			timer = t.C()
		}
		select {
		case <-timer:
		case <-c.grantWake:
		case <-ctx.Done():
		case <-c.stopCtx.Done():
		}
		if t != nil {
			t.Stop()
		}
		if ctx.Err() != nil || c.stopCtx.Err() != nil {
			return
		}
	}
}

// nextEnd returns the earliest time that watchGrants must wake for, on
// the monotonic clock: the end of an audited grant, or the end of the
// current window of a standing grant (the missed-window alarm of part 2
// reads it). The end of a window is the wall clock time left in it, added
// to the monotonic clock; if the clocks change inside the window, the wake
// is early or late, and the one who reads it looks again. Core.mu must be
// held.
func (c *Core) nextEnd() (time.Time, bool) {
	var next time.Time
	found := false
	take := func(t time.Time) {
		if !found || t.Before(next) {
			next, found = t, true
		}
	}
	now := c.now()
	for _, g := range c.grants {
		if !g.audited() {
			continue
		}
		take(g.end.mono)
		if g.standing() && now.before(g.end) {
			if _, left, in := windowAt(g.windows, now.wall); in {
				take(now.mono.Add(left))
			}
		}
	}
	return next, found
}

// dropScheduled ends every scheduled grant with cause stopped, when the
// core stops: grants live only in memory, so a restart would lose them
// anyway (DESIGN.md section 8). It hands out the audit entries; the
// updates of the messages wait for FlushMessages.
func (c *Core) dropScheduled() {
	c.mu.Lock()
	c.queueEnded(c.endWhere(func(g *grant) audit.EndCause {
		if g.audited() {
			return audit.EndStopped
		}
		return ""
	}))
	c.mu.Unlock()
	c.deliverEnded()
}

// FlushMessages makes the updates of the messages of scheduled grants that
// are still waiting, such as those of the grants that a stop dropped. The
// broker calls it after Run returned and after it denies every request,
// because Telegram can be slow: the calls take at most
// stopMessagesTimeout together, so a stop never waits for a Telegram that
// does not answer.
func (c *Core) FlushMessages() {
	ctx, cancel := context.WithTimeout(context.Background(), stopMessagesTimeout)
	defer cancel()
	c.deliverMessages(ctx)
}

// revoke ends the scheduled grant of the request a.RequestID, for the
// Revoke button. It takes rights away only, but it passes the same checks
// as every answer: the caller checked the user; here the grant must exist
// and the message must be its own. A grant that has ended is unknown.
func (c *Core) revoke(a Answer) error {
	now := c.now()
	c.sweepGrants(now)
	i := slices.IndexFunc(c.grants, func(g *grant) bool { return g.audited() && g.reqID == a.RequestID })
	if i < 0 {
		return ErrUnknownRequest
	}
	g := c.grants[i]
	if g.msg == "" || a.Message != g.msg {
		return ErrWrongMessage
	}
	c.queueEnded(c.endWhere(func(x *grant) audit.EndCause {
		if x == g {
			return audit.EndRevoked
		}
		return ""
	}))
	return nil
}

// CancelGrant ends the scheduled grant id of client at the client's
// request, without a tap. It returns the audit entry, which the caller
// writes. It reports false for an ID that no grant of client has, and the
// answer is the same for the ID of another client: a client learns
// nothing about the grants of others.
func (c *Core) CancelGrant(client, id string) (audit.GrantEnded, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepGrants(c.now()) // a grant past its end is gone
	ended := c.endWhere(func(g *grant) audit.EndCause {
		if g.scheduled() && g.client == client && g.id == id {
			return audit.EndCancelled
		}
		return ""
	})
	if len(ended) == 0 {
		return audit.GrantEnded{}, false
	}
	return ended[0], true
}

// granted reports whether a grant of "Approve N min" or of nodkey
// ssh-grant with the scope k is valid now.
func (c *Core) granted(k grantKey, now moment) bool {
	return slices.ContainsFunc(c.grants, func(g *grant) bool {
		return g.kind == kindWindow && g.covers(k.client, k.ref, k.hostKey, k.user) && g.live(now)
	})
}

// addWindowGrant adds the grant with the scope k, or makes the end of the
// grant with the same scope later: a second tap for the same scope keeps
// the later end. Core.mu must be held.
func (c *Core) addWindowGrant(k grantKey, end moment) {
	for _, g := range c.grants {
		if g.kind == kindWindow && g.covers(k.client, k.ref, k.hostKey, k.user) && len(g.refs) == 1 {
			if g.end.mono.Before(end.mono) {
				g.end = end
			}
			return
		}
	}
	g := &grant{kind: kindWindow, client: k.client, refs: []ref{k.ref}, user: k.user, end: end, uses: noLimit}
	if k.hostKey != "" {
		g.hostKeys = []string{k.hostKey}
	}
	c.grants = append(c.grants, g)
}

// scheduledCount returns how many scheduled grants client has. Core.mu
// must be held.
func (c *Core) scheduledCount(client string) int {
	n := 0
	for _, g := range c.grants {
		if g.scheduled() && g.client == client {
			n++
		}
	}
	return n
}

// standingCount returns how many standing grants client has. Core.mu must
// be held.
func (c *Core) standingCount(client string) int {
	n := 0
	for _, g := range c.grants {
		if g.standing() && g.client == client {
			n++
		}
	}
	return n
}

// findScheduled returns the scheduled grant that p uses now: of the same
// client, live, with a use left, and covering every item of p. A request
// that has an item outside one grant is not covered by it at all; grants
// are not mixed with each other or with other rules (DESIGN.md section 8).
// Of several, the one that ends first. Core.mu must be held.
func (c *Core) findScheduled(p *pending, now moment) *grant {
	if p.kind != audit.KindSecrets && p.kind != audit.KindSSHLogin || len(p.items) == 0 {
		return nil
	}
	var best *grant
	for _, g := range c.grants {
		if !g.scheduled() || g.uses < 1 || !g.live(now) {
			continue
		}
		all := true
		for _, it := range p.items {
			if !g.covers(p.client, it.ref, p.hostKey, p.user) {
				all = false
				break
			}
		}
		if all && (best == nil || g.end.mono.Before(best.end.mono)) {
			best = g
		}
	}
	return best
}

// settle runs when the notice of a use of a scheduled grant has been
// tried, and the use counts: if it was the last use, the grant ends, with
// its entry in res, after the entries of the request. Core.mu is not held.
func (c *Core) settle(p *pending, res *Result) {
	if p.used == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	res.ended = append(res.ended, c.endWhere(func(g *grant) audit.EndCause {
		if g == p.used && g.uses < 1 {
			return audit.EndUsedUp
		}
		return ""
	})...)
}

// startScheduled starts the scheduled grant of r, at now. It does not
// start it when the end has passed, when a Deny came after the tap, or
// when the client has too many grants, or when the core has stopped (its
// grants were dropped already). Core.mu must be held.
func (c *Core) startScheduled(r *Result, now moment) {
	g := r.plan
	// The end is an absolute time. Its monotonic reading is counted from
	// now, so a wall clock that is set back later cannot make it later.
	g.end.mono = now.mono.Add(g.end.wall.Sub(now.wall))
	if c.stopped {
		r.stopped = true
		return
	}
	c.sweepGrants(now)
	if !now.before(g.end) {
		return
	}
	if g.standing() {
		// A Deny of another request does not touch a standing grant
		// (DESIGN.md section 8).
		if c.standingCount(g.client) >= c.cfg.Standing.MaxGrants {
			return
		}
	} else {
		if c.scheduledCount(g.client) >= c.cfg.Preapprove.MaxGrants {
			return
		}
		for _, ref := range g.refs {
			if c.client(g.client).denied[ref] > r.seq {
				return // a Deny came after the tap
			}
		}
	}
	c.grants = append(c.grants, g)
	r.live = true
	if r.msg != "" {
		g.msg, g.prompt, g.approved = r.msg, r.prompt, r.at
		c.msgQueue = append(c.msgQueue, msgUpdate{msg: g.msg, prompt: g.prompt,
			ending: Ending{Answer: audit.AnswerApproveOnce, At: r.at, Revoke: true}})
	}
	c.wakeGrants()
}
