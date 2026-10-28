package approval

import (
	"context"
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
	// id is the ID of a scheduled grant. It is "" for the other grants,
	// which have no entry in the audit log of their own.
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
}

// scheduled reports whether g comes from nodkey preapprove.
func (g *grant) scheduled() bool { return g.id != "" }

// live reports whether g may be used at now: not before its start on the
// wall clock, and before its end on both clocks (moment.before), so a
// grant is never usable at or after its end. A wall clock that is set back
// cannot make it last longer, because the monotonic end stays.
func (g *grant) live(now moment) bool {
	return !now.wall.Before(g.start) && now.before(g.end)
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
		if g.scheduled() {
			ended = append(ended, audit.GrantEnded{Subject: g.origin, Cause: why, UsesLeft: max(g.uses, 0)})
		}
		return true
	})
	return ended
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
// next request, which sweeps first (begin).
func (c *Core) watchGrants(ctx context.Context) {
	for {
		c.mu.Lock()
		c.sweepGrants(c.now())
		next, ok := c.nextEnd()
		c.mu.Unlock()
		c.deliverEnded()
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

// nextEnd returns the earliest end of a scheduled grant, on the monotonic
// clock. Core.mu must be held.
func (c *Core) nextEnd() (time.Time, bool) {
	var next time.Time
	found := false
	for _, g := range c.grants {
		if g.scheduled() && (!found || g.end.mono.Before(next)) {
			next, found = g.end.mono, true
		}
	}
	return next, found
}

// dropScheduled ends every scheduled grant with cause stopped, when the
// core stops: grants live only in memory, so a restart would lose them
// anyway (DESIGN.md section 8).
func (c *Core) dropScheduled() {
	c.mu.Lock()
	c.queueEnded(c.endWhere(func(g *grant) audit.EndCause {
		if g.scheduled() {
			return audit.EndStopped
		}
		return ""
	}))
	c.mu.Unlock()
	c.deliverEnded()
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
		return !g.scheduled() && g.covers(k.client, k.ref, k.hostKey, k.user) && g.live(now)
	})
}

// addWindowGrant adds the grant with the scope k, or makes the end of the
// grant with the same scope later: a second tap for the same scope keeps
// the later end. Core.mu must be held.
func (c *Core) addWindowGrant(k grantKey, end moment) {
	for _, g := range c.grants {
		if !g.scheduled() && g.covers(k.client, k.ref, k.hostKey, k.user) && len(g.refs) == 1 {
			if g.end.mono.Before(end.mono) {
				g.end = end
			}
			return
		}
	}
	g := &grant{client: k.client, refs: []ref{k.ref}, user: k.user, end: end, uses: noLimit}
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
	if !now.before(g.end) || c.scheduledCount(g.client) >= c.cfg.Preapprove.MaxGrants {
		return
	}
	for _, ref := range g.refs {
		if c.client(g.client).denied[ref] > r.seq {
			return // a Deny came after the tap
		}
	}
	c.grants = append(c.grants, g)
	r.live = true
	c.wakeGrants()
}
