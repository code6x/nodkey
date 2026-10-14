package approval

import (
	"slices"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// rateWindow is the time over which MaxNewMessagesPerMinute and
// MaxNoticesPerMinute count.
const rateWindow = time.Minute

// ref names a secret or a key of the broker config.
type ref struct {
	key  bool // a [key.*] section; else a [secret.*] section
	name string
}

// grantKey is the scope of a grant (DESIGN.md section 8): a client and a
// secret, or a client, a key, a host key and a remote user.
type grantKey struct {
	client  string
	ref     ref
	hostKey string // the host key in SSH wire form; "" for a secret
	user    string // the remote user; "" for a secret
}

// useKey names the uses of one "never ask" rule by one client.
type useKey struct {
	client string
	ref    ref
}

// day is a date in the broker's local time.
type day struct {
	year  int
	month time.Month
	day   int
}

func dayOf(t time.Time) day {
	y, m, d := t.Date()
	return day{y, m, d}
}

func (a day) after(b day) bool {
	if a.year != b.year {
		return a.year > b.year
	}
	if a.month != b.month {
		return a.month > b.month
	}
	return a.day > b.day
}

// useDay returns the day that a use of the rule r at the wall time t
// counts for: the day of t. But when the hours of r go past midnight, a
// use after midnight counts for the day before, when the hours began. So
// max_per_day counts once for each time the hours are open.
func useDay(r config.Rule, t time.Time) day {
	if h := r.Hours; h != nil && h.From > h.To {
		hh, mm, ss := t.Clock()
		since := time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute +
			time.Duration(ss)*time.Second + time.Duration(t.Nanosecond())
		if since < h.To {
			return dayOf(t.AddDate(0, 0, -1))
		}
	}
	return dayOf(t)
}

// dayUses counts the uses of a "never ask" rule on one day.
type dayUses struct {
	day day
	n   int
}

// on returns the uses counted on d. A count starts again only on a later
// day. If the clock goes back to an earlier day, the uses of the later
// day still count, so setting the clock back cannot give more uses.
func (u dayUses) on(d day) int {
	if d.after(u.day) {
		return 0
	}
	return u.n
}

// add counts one use on d.
func (u dayUses) add(d day) dayUses {
	if d.after(u.day) {
		return dayUses{day: d, n: 1}
	}
	return dayUses{day: u.day, n: u.n + 1}
}

// remove takes back one use from the count of the day d: the day that
// the count had after add counted the use. If the count has moved on to a
// later day since, the use is not in it, and nothing changes.
func (u dayUses) remove(d day) dayUses {
	if u.day == d && u.n > 0 {
		u.n--
	}
	return u
}

// countedUse is a use of a "never ask" rule that the core counted: the
// rule's client and item, and the day of the count that holds the use.
type countedUse struct {
	key useKey
	day day
}

// rateLog holds the times of the newest events of one kind, oldest first,
// on the monotonic clock: at most as many as the limit per minute allows.
type rateLog []time.Time

// recent returns how many events came in the last minute.
func (l rateLog) recent(now time.Time) int {
	n := 0
	for _, t := range l {
		if now.Sub(t) < rateWindow {
			n++
		}
	}
	return n
}

// add records an event at now, and keeps the newest limit events.
func (l rateLog) add(now time.Time, limit int) rateLog {
	l = append(l, now)
	if extra := len(l) - limit; extra > 0 {
		l = slices.Delete(l, 0, extra)
	}
	return l
}

// freeAt returns when the limit allows the next event, if it does not
// allow one now.
func (l rateLog) freeAt(now time.Time, limit int) (time.Time, bool) {
	if l.recent(now) < limit {
		return time.Time{}, false
	}
	return l[len(l)-limit].Add(rateWindow), true
}

// clientState holds the limits of one client (DESIGN.md section 8). Core.mu
// guards it.
type clientState struct {
	// open counts the messages that wait for an answer, and those that
	// are being sent.
	open int
	// sent holds when the newest messages were sent.
	sent rateLog
	// notices holds when the newest notices of "never ask" uses were sent.
	notices rateLog
	// queue holds the requests that wait for a place, oldest first.
	queue []*pending
	// paused holds when the pause after a Deny ends, for each secret or
	// key, on the monotonic clock.
	paused map[ref]time.Time
	// denied holds the number of the newest Deny for each secret or key
	// (see Core.decisions). A grant from an earlier tap does not start.
	denied map[ref]uint64
}

// client returns the state of the client name, and makes it if needed.
// Only names from the config get here, so the map stays small.
func (c *Core) client(name string) *clientState {
	cs := c.clients[name]
	if cs == nil {
		cs = &clientState{paused: make(map[ref]time.Time), denied: make(map[ref]uint64)}
		c.clients[name] = cs
	}
	return cs
}

// canSend reports whether both limits allow a new message now.
func (cs *clientState) canSend(now moment) bool {
	return cs.open < MaxOpenMessages && cs.sent.recent(now.mono) < MaxNewMessagesPerMinute
}

// rateFree returns when the limit per minute allows the next message, if
// that limit stops it now.
func (cs *clientState) rateFree(now moment) (time.Time, bool) {
	return cs.sent.freeAt(now.mono, MaxNewMessagesPerMinute)
}

// reserve takes a place for a new message, sent now.
func (cs *clientState) reserve(now moment) {
	cs.open++
	cs.sent = cs.sent.add(now.mono, MaxNewMessagesPerMinute)
}

// release gives back the place of a message whose request ended. The time
// it was sent still counts for the limit per minute.
func (cs *clientState) release() {
	cs.open--
}

// remove takes p out of the queue.
func (cs *clientState) remove(p *pending) {
	if i := slices.Index(cs.queue, p); i >= 0 {
		cs.queue = slices.Delete(cs.queue, i, i+1)
	}
}

// isPaused reports whether a Deny pauses any of the items now.
func (cs *clientState) isPaused(items []item, now moment) bool {
	paused := false
	for _, it := range items {
		end, ok := cs.paused[it.ref]
		if !ok {
			continue
		}
		if now.mono.Before(end) {
			paused = true
		} else {
			delete(cs.paused, it.ref)
		}
	}
	return paused
}

// dispatch gives free places to the requests in the queue of cs, oldest
// first. A request with less than MinTimeLeft left does not get a place:
// it is denied, because the person would not have time to answer. So is a
// request that a pause after a Deny covers. Core.mu must be held.
func (c *Core) dispatch(cs *clientState, now moment) {
	sent := false
	for len(cs.queue) > 0 && cs.canSend(now) {
		p := cs.queue[0]
		cs.queue = slices.Delete(cs.queue, 0, 1)
		if now.until(p.deadline) < MinTimeLeft || cs.isPaused(p.items, now) {
			c.finish(p, c.denied(p, audit.CauseLimit))
		} else {
			cs.reserve(now)
			p.state = stateAsking
			sent = true
		}
		close(p.ready)
	}
	if sent {
		// The new message may have used up the limit per minute. A request
		// that still waits for a free place may then have to wait for the
		// minute too, and needs a timer for it: wake it so it looks again.
		for _, p := range cs.queue {
			select {
			case p.poke <- struct{}{}:
			default: // it is awake already
			}
		}
	}
}

// deny records the person's Deny of p at now: it pauses each secret or key
// of p, ends the client's grants for them, and denies the client's queued
// requests for them. seq is the number of this decision. Core.mu must be
// held.
func (c *Core) deny(cs *clientState, p *pending, now moment, seq uint64) {
	for _, it := range p.items {
		cs.paused[it.ref] = now.mono.Add(DenyPause)
		cs.denied[it.ref] = seq
	}
	// A Deny says that something looks wrong, so it ends the grants of
	// this client for these secrets and keys: for a key, at every host key
	// and for every remote user, as wide as the pause.
	for k := range c.grants {
		if k.client == p.client && slices.ContainsFunc(p.items, func(it item) bool { return it.ref == k.ref }) {
			delete(c.grants, k)
		}
	}
	// The queued requests for them came before the Deny, but their
	// messages would come after it.
	cs.queue = slices.DeleteFunc(cs.queue, func(q *pending) bool {
		if !cs.isPaused(q.items, now) {
			return false
		}
		c.finish(q, c.denied(q, audit.CauseLimit))
		close(q.ready)
		return true
	})
}

// granted reports whether a grant with the scope k is valid now.
func (c *Core) granted(k grantKey, now moment) bool {
	end, ok := c.grants[k]
	if !ok {
		return false
	}
	if now.before(end) {
		return true
	}
	delete(c.grants, k)
	return false
}

// sweepGrants removes the grants that have ended.
func (c *Core) sweepGrants(now moment) {
	for k, end := range c.grants {
		if !now.before(end) {
			delete(c.grants, k)
		}
	}
}

// neverApplies reports whether the "never ask" rule of it allows a use
// by client now: inside its hours, and under its max_per_day.
func (c *Core) neverApplies(client string, it item, now moment) bool {
	r := it.rule
	if r.Ask != config.AskNever {
		return false
	}
	if r.Hours != nil && !r.Hours.Contains(now.wall) {
		return false
	}
	if r.MaxPerDay > 0 && c.uses[useKey{client, it.ref}].on(useDay(r, now.wall)) >= r.MaxPerDay {
		return false
	}
	return true
}

// covered reports whether grants and "never ask" rules allow every item
// of p now, and what allowed each. A request for an SSH grant is never
// covered: it asks for new grants.
func (c *Core) covered(p *pending, now moment) ([]audit.Via, bool) {
	if p.kind == audit.KindSSHGrant || len(p.items) == 0 {
		return nil, false
	}
	vias := make([]audit.Via, len(p.items))
	for i, it := range p.items {
		switch {
		case it.rule.Ask == config.AskWindow && c.granted(p.grantKey(it), now):
			vias[i] = audit.ViaGrant
		case c.neverApplies(p.client, it, now):
			vias[i] = audit.ViaNeverRule
		default:
			return nil, false
		}
	}
	return vias, true
}
