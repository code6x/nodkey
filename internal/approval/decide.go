package approval

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// state is where a request is on its way to the person.
type state int

const (
	stateNew     state = iota // checked; no place yet
	stateQueued               // in the queue of its client
	stateAsking               // has a place; its message is about to be sent, or being sent
	stateWaiting              // its message waits for an answer, in Core.waiting
	stateDone                 // decided; result is set
)

// errLeft is the error of a request that Decide left early, because the
// approver or OnWait panicked. No one gets its result.
var errLeft = errors.New("approval: the request ended in a panic")

// item is one secret or key of a request, with its rule.
type item struct {
	ref  ref
	rule config.Rule
}

// pending is one request inside Decide.
type pending struct {
	id, code string
	client   string
	kind     audit.Kind
	items    []item // the secrets, or the one key
	subject  audit.Subject
	claim    Claim

	hostKey       string   // KindSSHLogin: the host key in SSH wire form
	user          string   // KindSSHLogin, KindSSHGrant: the remote user
	grantHostKeys []string // KindSSHGrant: the host keys of the hosts, in SSH wire form
	grantEnds     moment   // KindSSHGrant: when its grants end
	plan          *grant   // KindPreapprove: the grant that an approval starts

	start, deadline moment
	once            bool // the message has "Approve once"
	windowMinutes   int  // the message has "Approve N min" with this N; 0: no
	notify          bool // a "never ask" rule with notify allowed it

	// used is the scheduled grant that allowed p, and whose use p took.
	// preCounted says that p counts in clientState.preapproving.
	used       *grant
	preCounted bool

	// counted holds the uses of "never ask" rules that begin counted for
	// p, so that notify can take them back. Under Core.mu.
	counted []countedUse

	// Under Core.mu:
	state  state
	msg    MessageID
	text   string
	result *Result
	ready  chan struct{} // closed when the request leaves the queue
	poke   chan struct{} // wakes the request in the queue to look again
	done   chan struct{} // closed when an answer has decided the request
}

// grantKey returns the scope of a grant for the item it of p.
func (p *pending) grantKey(it item) grantKey {
	return grantKey{client: p.client, ref: it.ref, hostKey: p.hostKey, user: p.user}
}

// newGrants returns the scopes of the grants that an approve_window answer
// to p makes: one for each secret, the one host key of an SSH login, or
// each host key of each host of an SSH grant.
func (p *pending) newGrants() []grantKey {
	if p.kind == audit.KindSSHGrant {
		keys := make([]grantKey, 0, len(p.grantHostKeys))
		for _, hk := range p.grantHostKeys {
			keys = append(keys, grantKey{client: p.client, ref: p.items[0].ref, hostKey: hk, user: p.user})
		}
		return keys
	}
	keys := make([]grantKey, 0, len(p.items))
	for _, it := range p.items {
		keys = append(keys, p.grantKey(it))
	}
	return keys
}

// prompt returns what the approver shows for p, made at now.
func (p *pending) prompt(now moment) Prompt {
	left := now.until(p.deadline)
	pr := Prompt{
		RequestID:     p.id,
		ShortCode:     p.code,
		Kind:          p.kind,
		Client:        p.client,
		Secrets:       slices.Clone(p.subject.Secrets),
		Key:           p.subject.Key,
		Hosts:         slices.Clone(p.subject.Hosts),
		HostKey:       p.subject.HostKey,
		RemoteUser:    p.subject.RemoteUser,
		Claim:         p.claim,
		Expires:       now.wall.Add(left),
		TimeLeft:      left,
		Once:          p.once,
		WindowMinutes: p.windowMinutes,
	}
	if p.kind == audit.KindSSHGrant {
		pr.GrantEnds = p.grantEnds.wall
	}
	if p.kind.IsPreapprove() {
		loc := now.wall.Location()
		pr.Uses, pr.From, pr.Until = p.plan.uses, p.plan.start.In(loc), p.plan.end.wall.In(loc)
		if p.kind == audit.KindStanding {
			pr.Uses, pr.Windows = p.plan.perWindow, slices.Clone(p.subject.Windows)
		}
	}
	return pr
}

// notice returns the prompt of a notice: no buttons and no expiry.
func (p *pending) notice(now moment) Prompt {
	pr := p.prompt(now)
	pr.Expires, pr.TimeLeft, pr.Once, pr.WindowMinutes = time.Time{}, 0, false, 0
	if p.used != nil {
		pr.Via = audit.ViaScheduled
	}
	return pr
}

// Decide decides the request r. It returns at once when a check fails, a
// limit denies it, or grants and "never ask" rules allow it. Otherwise it
// shows the request to the person and returns when the person answered,
// the request expired, ctx ended, or the approver stopped. ctx belongs to
// the client's connection: when the client hangs up, the request is
// cancelled.
//
// The result is never nil. If the approver or r.OnWait panics, Decide
// frees what the request holds, and the panic goes on.
func (c *Core) Decide(ctx context.Context, r *Request) *Result {
	p := &pending{start: c.now(), ready: make(chan struct{}), poke: make(chan struct{}, 1), done: make(chan struct{})}
	if err := c.register(p); err != nil {
		return &Result{Cause: audit.CauseError, Err: err, at: p.start.wall}
	}
	defer c.leave(p)
	if r == nil {
		return c.denied(p, audit.CauseNotAllowed)
	}
	p.deadline = p.start.add(c.timeout(r.Kind))
	if !c.check(r, p) {
		return c.denied(p, audit.CauseNotAllowed)
	}
	if p.kind == audit.KindSSHGrant {
		// Its grants end at a fixed time. After it, an approval would
		// grant nothing, so the request ends then too.
		p.deadline = earlier(p.deadline, p.grantEnds)
	}
	if p.kind.IsPreapprove() {
		// Its grant ends at a fixed time, as an SSH grant's do: after it,
		// an approval would grant nothing.
		end := p.plan.end.wall
		p.deadline = earlier(p.deadline, moment{mono: p.start.mono.Add(end.Sub(p.start.wall)), wall: end})
		if err := c.makeGrantID(p); err != nil {
			res := c.denied(p, audit.CauseError)
			res.Err = err
			return res
		}
	}
	if ctx.Err() != nil {
		return c.denied(p, audit.CauseCancelled)
	}
	if res := c.begin(p); res != nil {
		if res.Allowed && p.notify {
			return c.notify(ctx, p, res)
		}
		return res
	}
	if r.OnWait != nil {
		r.OnWait(p.code)
	}
	if res := c.waitQueue(ctx, p); res != nil {
		return res
	}
	return c.ask(ctx, p)
}

// leave runs when Decide returns, also when the approver or OnWait panics.
// It frees the request ID and the short code of p, and what p still holds:
// its place in the queue, its place for a message, or its place in the
// waiting list. After a normal return, p holds none of them.
func (c *Core) leave(p *pending) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ids, p.id)
	delete(c.codes, p.code)
	if p.preCounted {
		if p.kind == audit.KindStanding {
			c.client(p.client).standingPending--
		} else {
			c.client(p.client).preapproving--
		}
	}
	switch p.state {
	case stateQueued:
		c.client(p.client).remove(p)
	case stateWaiting:
		delete(c.waiting, p.id)
		fallthrough
	case stateAsking:
		cs := c.client(p.client)
		cs.release()
		c.dispatch(cs, c.now())
	default:
		return
	}
	c.finish(p, c.failed(p, errLeft))
}

// begin decides what happens to p next. It returns the result if p is
// decided at once. Otherwise p has a place for its message (stateAsking),
// or it waits in the queue (stateQueued).
func (c *Core) begin(p *pending) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweepGrants(now)
	cs := c.client(p.client)
	if p.kind.IsPreapprove() {
		// The grants that are approved and not ended, and the requests
		// that wait for a tap (StartGrants checks the first again).
		if p.kind == audit.KindStanding {
			if c.standingCount(p.client)+cs.standingPending >= c.cfg.Standing.MaxGrants {
				return c.denied(p, audit.CauseLimit)
			}
			cs.standingPending++
		} else {
			if c.scheduledCount(p.client)+cs.preapproving >= c.cfg.Preapprove.MaxGrants {
				return c.denied(p, audit.CauseLimit)
			}
			cs.preapproving++
		}
		p.preCounted = true
	}
	if vias, ok := c.covered(p, now); ok {
		notify := false
		for i, it := range p.items {
			notify = notify || (vias[i] == audit.ViaNeverRule && it.rule.Notify)
		}
		if notify {
			// Each use sends a notice. Without a limit, one client could
			// fill the phone and use up Telegram's limits for the chat.
			if cs.notices.recent(now.mono) >= MaxNoticesPerMinute {
				return c.denied(p, audit.CauseLimit)
			}
			cs.notices = cs.notices.add(now.mono, MaxNoticesPerMinute)
		}
		// The uses count now, under the lock, so requests at the same
		// time cannot pass max_per_day. If the approver's limit stops the
		// notice, notify takes them back.
		for i, it := range p.items {
			if vias[i] == audit.ViaNeverRule {
				k := useKey{p.client, it.ref}
				c.uses[k] = c.uses[k].add(useDay(it.rule, now.wall))
				p.counted = append(p.counted, countedUse{key: k, day: c.uses[k].day})
			}
		}
		p.notify = notify
		res := c.newResult(p)
		res.Allowed = true
		res.vias = vias
		return res
	}
	if g := c.findScheduled(p, now); g != nil {
		// Each use of a scheduled grant sends a notice, as a use of a
		// "never ask" rule does, and counts toward the same limit. A use
		// that the limit stops is not taken.
		if cs.notices.recent(now.mono) >= MaxNoticesPerMinute {
			return c.denied(p, audit.CauseLimit)
		}
		cs.notices = cs.notices.add(now.mono, MaxNoticesPerMinute)
		g.uses--
		p.used, p.notify = g, true
		res := c.newResult(p)
		res.Allowed = true
		res.usedID = g.id
		res.vias = make([]audit.Via, len(p.items))
		for i := range res.vias {
			res.vias[i] = audit.ViaScheduled
		}
		return res
	}
	if c.stopped {
		return c.failed(p, ErrStopped)
	}
	if cs.isPaused(p.items, now) {
		return c.denied(p, audit.CauseLimit)
	}
	c.dispatch(cs, now) // so the queue keeps its order
	switch {
	case len(cs.queue) == 0 && cs.canSend(now):
		cs.reserve(now)
		p.state = stateAsking
	case len(cs.queue) < MaxQueued && now.until(p.deadline) >= MinTimeLeft:
		cs.queue = append(cs.queue, p)
		p.state = stateQueued
	default:
		// The queue is full, or the request could never leave it in time.
		return c.denied(p, audit.CauseLimit)
	}
	return nil
}

// waitQueue waits while p is in the queue. It returns nil when p has a
// place for its message, or the result that ended p.
func (c *Core) waitQueue(ctx context.Context, p *pending) *Result {
	for {
		res, wake, queued := c.queueLook(ctx, p)
		if !queued {
			return res
		}
		t := c.clock.TimerAt(wake)
		select {
		case <-p.ready:
		case <-p.poke:
		case <-t.C():
		case <-ctx.Done():
		case <-c.stopCtx.Done():
		}
		t.Stop()
	}
}

// queueLook looks at p, which was in the queue. It returns the result that
// ended p, or nil when p has a place, or, when p still waits, the time on
// the monotonic clock to look again.
func (c *Core) queueLook(ctx context.Context, p *pending) (res *Result, wake time.Time, queued bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	cs := c.client(p.client)
	if p.state == stateQueued {
		// The minute of the rate limit may have moved on.
		c.dispatch(cs, now)
	}
	switch p.state {
	case stateDone:
		return p.result, time.Time{}, false
	case stateAsking:
		if ctx.Err() == nil && !c.stopped {
			return nil, time.Time{}, false
		}
		// It got a place, but it ends now: give the place back.
		cs.release()
		c.dispatch(cs, now)
		return c.finish(p, c.ended(ctx, p)), time.Time{}, false
	}
	switch {
	case ctx.Err() != nil || c.stopped:
		cs.remove(p)
		return c.finish(p, c.ended(ctx, p)), time.Time{}, false
	case now.until(p.deadline) < MinTimeLeft:
		cs.remove(p)
		return c.finish(p, c.denied(p, audit.CauseLimit)), time.Time{}, false
	}
	// Look again when less than MinTimeLeft is left: with exactly
	// MinTimeLeft, p may still leave the queue. A timer can only follow
	// the monotonic clock; if the wall clock ends p first, the next look
	// finds it.
	wake = p.deadline.mono.Add(-MinTimeLeft + time.Nanosecond)
	if at, limited := cs.rateFree(now); limited && at.Before(wake) {
		wake = at
	}
	return nil, wake, true
}

// ask sends the message of p, which has a place, and waits for the
// answer.
func (c *Core) ask(ctx context.Context, p *pending) *Result {
	prompt, res := c.beforeAsk(ctx, p)
	if res != nil {
		return res
	}
	actx, cancel := c.callContext(ctx, prompt.TimeLeft)
	shown, err := c.approver.Ask(actx, prompt)
	cancel()
	if err == nil && shown.ID == "" {
		err = errors.New("approval: the approver did not name the message it sent")
	}
	if res = c.afterAsk(ctx, p, shown, err); res == nil {
		res = c.wait(ctx, p)
	}
	if p.msg != "" {
		c.end(ctx, p, prompt, res)
		if res.plan != nil {
			// The grant keeps the message, with a Revoke button, once it
			// starts (startScheduled).
			res.msg, res.prompt = p.msg, prompt
		}
	}
	return res
}

// beforeAsk checks, just before the message goes out, that the person can
// still answer it: the time is not up, the client has not hung up, and
// answers can come. Then it returns the prompt. Otherwise it gives the
// place back and ends p without a message.
func (c *Core) beforeAsk(ctx context.Context, p *pending) (Prompt, *Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var res *Result
	switch {
	case ctx.Err() != nil || c.stopped:
		res = c.ended(ctx, p)
	case !now.before(p.deadline):
		res = c.denied(p, audit.CauseExpired)
	default:
		return p.prompt(now), nil
	}
	cs := c.client(p.client)
	cs.release()
	c.dispatch(cs, now)
	return Prompt{}, c.finish(p, res)
}

// afterAsk records the message that Ask sent, and puts p in the waiting
// list. It returns the result instead if Ask failed, or if p ended while
// its message was being sent.
func (c *Core) afterAsk(ctx context.Context, p *pending, shown Shown, err error) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		p.msg, p.text = shown.ID, shown.Text
	}
	now := c.now()
	var res *Result
	switch {
	case err != nil:
		// No message, or none that the core knows: nothing to update.
		res = c.failed(p, err)
	case ctx.Err() != nil || c.stopped:
		res = c.ended(ctx, p)
	case !now.before(p.deadline):
		res = c.denied(p, audit.CauseExpired)
	default:
		p.state = stateWaiting
		c.waiting[p.id] = p
		return nil
	}
	cs := c.client(p.client)
	cs.release()
	c.dispatch(cs, now)
	return c.finish(p, res)
}

// wait waits until an answer decides p, p expires, ctx ends, or the
// approver stops.
func (c *Core) wait(ctx context.Context, p *pending) *Result {
	t := c.clock.TimerAt(p.deadline.mono)
	defer func() { t.Stop() }()
	for {
		select {
		case <-p.done:
		case <-t.C():
		case <-ctx.Done():
		case <-c.stopCtx.Done():
		}
		if res := c.waitLook(ctx, p); res != nil {
			return res
		}
		// The timer fired before the deadline. Wait on.
		t.Stop()
		t = c.clock.TimerAt(p.deadline.mono)
	}
}

// waitLook ends p if it has expired, its client hung up, or the approver
// stopped. It returns the result of p, or nil if p still waits. Taking p
// out of the waiting list decides it: no answer can count after this.
func (c *Core) waitLook(ctx context.Context, p *pending) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.state != stateWaiting {
		return p.result // an answer came first
	}
	now := c.now()
	var res *Result
	switch {
	case ctx.Err() != nil || c.stopped:
		res = c.ended(ctx, p)
	case !now.before(p.deadline):
		res = c.denied(p, audit.CauseExpired)
	default:
		return nil
	}
	delete(c.waiting, p.id)
	cs := c.client(p.client)
	cs.release()
	c.dispatch(cs, now)
	return c.finish(p, res)
}

// Answer passes the person's answer to the core. The approver calls it
// for each button press. The answer counts only if all of these are true
// (DESIGN.md section 7):
//
//   - it is from the approver: a.UserID is cfg.Telegram.UserID;
//   - the request a.RequestID waits for an answer;
//   - it is on the request's own message;
//   - the request has not expired, on either clock;
//   - the request offers that button.
//
// Taking the request out of the waiting list and deciding it is one step
// under one lock, so the first valid answer wins and no second answer can
// count. Answer returns nil when the answer counted. Otherwise it returns
// why not, and the answer changed nothing:
//
//   - ErrTooEarly: the message of the request is still being sent. The
//     approver must leave the message as it is, so the person can tap
//     again.
//   - ErrUnknownRequest: no request with this ID is in progress. Only then
//     should the approver mark the message as expired.
//   - ErrNotApprover, ErrWrongMessage, ErrExpired, ErrNotAllowed or
//     ErrStopped.
func (c *Core) Answer(a Answer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return ErrStopped
	}
	if a.UserID <= 0 || a.UserID != c.cfg.Telegram.UserID {
		return ErrNotApprover
	}
	if a.Action == audit.AnswerRevoke {
		return c.revoke(a)
	}
	p := c.waiting[a.RequestID]
	if p == nil {
		if q := c.ids[a.RequestID]; q != nil && q.state == stateAsking {
			return ErrTooEarly
		}
		return ErrUnknownRequest
	}
	if a.Message != p.msg {
		return ErrWrongMessage
	}
	now := c.now()
	if !now.before(p.deadline) {
		return ErrExpired
	}
	res := c.newResult(p)
	res.Answer = a.Action
	res.UserID = a.UserID
	switch a.Action {
	case audit.AnswerApproveOnce:
		if !p.once {
			return ErrNotAllowed
		}
		res.Allowed = true
		if p.kind.IsPreapprove() {
			c.approvePlan(p, res)
		}
	case audit.AnswerApproveWindow:
		if p.windowMinutes < 1 {
			return ErrNotAllowed
		}
		res.Allowed = true
		res.WindowMinutes = p.windowMinutes
		res.grants = p.newGrants()
		// The message shows the time of the tap to the second, and the
		// minutes. The grants end at the start of the second that they
		// give, not later.
		res.grantEnd = now.add(time.Duration(p.windowMinutes) * time.Minute).wholeSecond()
		if p.kind == audit.KindSSHGrant {
			res.grantEnd = p.grantEnds // the end shown in the message
		}
	case audit.AnswerDeny:
		res.Cause = audit.CauseApprover
	default:
		return ErrNotAllowed
	}

	// The answer counts: take the request out and decide it.
	delete(c.waiting, p.id)
	c.decisions++
	res.seq = c.decisions
	cs := c.client(p.client)
	cs.release()
	c.finish(p, res)
	if a.Action == audit.AnswerDeny {
		c.deny(cs, p, res, now, res.seq)
	}
	c.dispatch(cs, now)
	close(p.done)
	return nil
}

// end updates the message of p after p ended.
func (c *Core) end(ctx context.Context, p *pending, prompt Prompt, res *Result) {
	e := Ending{Answer: res.Answer, WindowMinutes: res.WindowMinutes, Cause: res.Cause, At: res.at}
	// The client may have hung up, or the approver stopped polling; the
	// message must still show how the request ended.
	ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), endTimeout)
	defer cancel()
	if err := c.approver.End(ectx, p.msg, prompt, e); err != nil {
		c.logger.LogAttrs(ectx, slog.LevelWarn, "approval: cannot update the message of a request that ended",
			slog.String("request_id", p.id), slog.Any("error", err))
	}
}

// notify sends the notice of a use of a "never ask" rule or a scheduled
// grant. If the notice
// cannot be sent, the request is denied: notify = true promises that no
// use goes unseen (DESIGN.md section 12).
//
// If the approver's own limit stopped the notice (ErrLimit), nothing was
// sent, so the use did not happen: the cause is limit, as for the limit
// per client, and the use does not count for max_per_day. After any other
// error, or a hang-up, the notice may have gone out, so the use still
// counts: an unclear case keeps the stricter count, and the next use may
// ask the person.
func (c *Core) notify(ctx context.Context, p *pending, res *Result) *Result {
	now := c.now()
	nctx, cancel := c.callContext(ctx, now.until(p.deadline))
	err := c.approver.Notify(nctx, p.notice(now))
	cancel()
	out := res
	switch {
	case errors.Is(err, ErrLimit):
		c.uncount(p)
		return c.denied(p, audit.CauseLimit)
	case ctx.Err() != nil:
		out = c.denied(p, audit.CauseCancelled)
	case err != nil:
		out = c.failed(p, err)
	}
	// The use counts, also in a deny. If it was the last, the grant ends.
	c.settle(p, out)
	return out
}

// makeGrantID gives the scheduled grant of p its ID.
func (c *Core) makeGrantID(p *pending) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, err := newID(c.random)
	p.plan.id = id
	return err
}

// approvePlan makes the grant that an approval of p starts (StartGrants),
// and tells res about it. Core.mu must be held.
func (c *Core) approvePlan(p *pending, res *Result) {
	res.Subject.GrantID = p.plan.id
	g := *p.plan
	g.reqID, g.code = p.id, p.code
	g.origin = res.Subject
	g.origin.Secrets = slices.Clone(res.Subject.Secrets)
	g.origin.Hosts = slices.Clone(res.Subject.Hosts)
	g.origin.Windows = slices.Clone(res.Subject.Windows)
	res.plan = &g
	res.GrantID = g.id
	loc := c.clock.Wall().Location()
	res.GrantFrom, res.GrantUntil = g.start.In(loc), g.end.wall.In(loc)
}

// uncount takes back the uses of "never ask" rules that begin counted for
// p.
func (c *Core) uncount(p *pending) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, u := range p.counted {
		c.uses[u.key] = c.uses[u.key].remove(u.day)
	}
	p.counted = nil
	if g := p.used; g != nil && slices.Contains(c.grants, g) {
		g.giveBackUse() // the use did not happen
	}
	p.used = nil
}

// newResult returns the result of p, not yet decided.
func (c *Core) newResult(p *pending) *Result {
	s := p.subject
	s.RequestID = p.id
	s.Secrets = slices.Clone(s.Secrets)
	s.Hosts = slices.Clone(s.Hosts)
	return &Result{
		RequestID: p.id,
		ShortCode: p.code,
		Message:   p.text,
		Subject:   s,
		core:      c,
		at:        c.clock.Wall(),
	}
}

// denied returns a deny of p for cause.
func (c *Core) denied(p *pending, cause audit.Cause) *Result {
	res := c.newResult(p)
	res.Cause = cause
	return res
}

// failed returns a deny of p because the approver failed with err.
func (c *Core) failed(p *pending, err error) *Result {
	res := c.denied(p, audit.CauseError)
	res.ErrorCode = audit.CodeApproverFailed
	res.Err = err
	return res
}

// ended returns the deny of p when ctx ended or the approver stopped.
func (c *Core) ended(ctx context.Context, p *pending) *Result {
	if ctx.Err() != nil {
		return c.denied(p, audit.CauseCancelled)
	}
	return c.failed(p, ErrStopped)
}

// finish records res as the end of p. Core.mu must be held.
func (c *Core) finish(p *pending, res *Result) *Result {
	p.state = stateDone
	p.result = res
	return res
}
