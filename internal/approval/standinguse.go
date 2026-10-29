package approval

import (
	"context"
	"encoding/hex"
	"log/slog"
	"slices"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/grantkey"
)

// MaxUnknownTokensPerMinute is the most unknown tokens of one client that
// raise an alarm, and get entries in the audit log, in any 60 seconds
// (DESIGN.md section 8). The others are denied with cause limit.
const MaxUnknownTokensPerMinute = 3

// Alarm is what the approver shows for an alarm of a standing grant: a
// message with a sound. It holds no token.
type Alarm struct {
	RequestID, ShortCode string
	Client               string
	Secrets              []string
	// GrantID is "" for an unknown token.
	GrantID string
	Cause   audit.AlarmCause
	// Ended says that the alarm ended the grant.
	Ended bool
}

// Alarmer is an Approver that can also send alarms. The core sends an
// alarm only to an approver that has this method. It counts toward the
// same limit of notices as Notify does.
type Alarmer interface {
	Alarm(ctx context.Context, a Alarm) error
}

// StandingRequest is a request for secrets with a standing grant token
// (DESIGN.md section 8). The broker has checked the secret names.
type StandingRequest struct {
	Client  string
	Secrets []string
	Claim   Claim
	// Token is the hash of the token that the client sent, or nil when
	// the header was not a valid token.
	Token *[32]byte
}

// standingUse is what a Result of UseStanding keeps.
type standingUse struct {
	p        *pending
	g        *grant
	prevHash [32]byte
	newHash  [32]byte
	token    grantkey.Token
	alarm    audit.AlarmCause
	grantID  string // of the alarm
	ended    bool
	// markG is the grant whose daily outside_window mark this use took, and
	// markPrev the mark before. SendAlarm gives the mark back if the alarm
	// is not sent.
	markG    *grant
	markPrev string
	markNow  string
}

// UseStanding decides a request with a token: the use path of a standing
// grant (DESIGN.md section 8). It never asks the person. For an allowed
// request, the token has been replaced already: the broker writes
// Events() first, then calls SendNotice, and hands out nothing if either
// fails (the first by calling Undo itself). For a denied request it writes
// Events(), then calls SendAlarm.
func (c *Core) UseStanding(r StandingRequest) *Result {
	p := &pending{start: c.now()}
	if err := c.register(p); err != nil {
		return &Result{Cause: audit.CauseError, Err: err, at: p.start.wall}
	}
	defer c.leave(p)
	p.deadline = p.start.add(c.timeout(audit.KindSecrets))
	if !c.check(&Request{Client: r.Client, Kind: audit.KindSecrets, Secrets: r.Secrets, Claim: r.Claim}, p) {
		return c.denied(p, audit.CauseNotAllowed)
	}
	tok, err := grantkey.New()
	if err != nil {
		res := c.denied(p, audit.CauseError)
		res.Err = err
		return res
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return c.failed(p, ErrStopped)
	}
	now := c.now()
	c.sweepGrants(now)
	cs := c.client(p.client)
	// Every grant and hash is compared, with no early exit.
	// A token of a grant of another client has left its machine: that grant
	// is the one that is named and ended (foreign).
	var cur, old, foreign *grant
	if r.Token != nil {
		for _, g := range c.grants {
			if !g.standing() {
				continue
			}
			mine := g.client == p.client
			if grantkey.Equal(g.tokenHash, *r.Token) {
				if mine {
					cur = g
				} else {
					foreign = g
				}
			}
			for _, h := range g.oldHashes {
				if grantkey.Equal(h, *r.Token) {
					if mine {
						old = g
					} else {
						foreign = g
					}
				}
			}
		}
	}
	deny := func(g *grant, cause audit.AlarmCause, end bool) *Result {
		res := c.denied(p, audit.CauseNotAllowed)
		su := &standingUse{p: p, alarm: cause}
		if g != nil {
			su.grantID, res.Subject.GrantID = g.id, g.id
		}
		if end {
			su.ended = true
			res.ended = append(res.ended, c.endWhere(func(x *grant) audit.EndCause {
				if x == g {
					return audit.EndAlarm
				}
				return ""
			})...)
		}
		res.su = su
		return res
	}
	switch {
	case cur == nil && old == nil && foreign != nil:
		return deny(foreign, audit.AlarmOldToken, true)
	case cur == nil && old == nil:
		if cs.unknown.recent(now.mono) >= MaxUnknownTokensPerMinute {
			return c.denied(p, audit.CauseLimit)
		}
		cs.unknown = cs.unknown.add(now.mono, MaxUnknownTokensPerMinute)
		return deny(nil, audit.AlarmUnknownToken, false)
	case cur == nil:
		return deny(old, audit.AlarmOldToken, true)
	}
	g := cur
	for _, it := range p.items {
		if !g.covers(p.client, it.ref, "", "") {
			return c.denied(p, audit.CauseNotAllowed) // a client's mistake, not an alarm
		}
	}
	switch g.tryUse(now) {
	case useNone:
		return c.denied(p, audit.CauseNotAllowed)
	case useOutsideWindow:
		res := deny(g, audit.AlarmOutsideWindow, false)
		if mark := now.wall.Format("2006-01-02"); g.alarmMark == mark {
			res.su.alarm = "" // one alarm in a day
		} else {
			// The mark is taken now, so a second request does not send a
			// second alarm. SendAlarm gives it back if the alarm is not sent.
			res.su.markG, res.su.markPrev, res.su.markNow = g, g.alarmMark, mark
			g.alarmMark = mark
		}
		return res
	case useOverUses:
		return deny(g, audit.AlarmOverUses, true)
	}
	if cs.notices.recent(now.mono) >= MaxNoticesPerMinute {
		g.giveBackUse()
		return c.denied(p, audit.CauseLimit)
	}
	cs.notices = cs.notices.add(now.mono, MaxNoticesPerMinute)
	su := &standingUse{p: p, g: g, prevHash: g.tokenHash, newHash: grantkey.Hash(tok), token: tok}
	g.oldHashes = append(g.oldHashes, g.tokenHash)
	g.tokenHash = su.newHash
	res := c.newResult(p)
	res.Allowed = true
	res.usedID = g.id
	res.su = su
	res.vias = make([]audit.Via, len(p.items))
	for i := range res.vias {
		res.vias[i] = audit.ViaStanding
	}
	return res
}

// NewToken returns the new token of an allowed UseStanding result. The
// broker puts it only into the answer.
func (r *Result) NewToken() (grantkey.Token, bool) {
	if r == nil || r.su == nil || !r.Allowed {
		return grantkey.Token{}, false
	}
	return r.su.token, true
}

// Undo takes back the use and the new token of an allowed UseStanding
// result, because the use did not happen: the old token is valid again.
func (r *Result) Undo() {
	if r == nil || r.su == nil || r.su.g == nil || r.core == nil {
		return
	}
	c, su := r.core, r.su
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Contains(c.grants, su.g) || su.g.tokenHash != su.newHash {
		return
	}
	su.g.tokenHash = su.prevHash
	if n := len(su.g.oldHashes); n > 0 {
		su.g.oldHashes = su.g.oldHashes[:n-1]
	}
	su.g.giveBackUse()
}

// SendNotice sends the silent notice of an allowed UseStanding result. If
// it cannot be sent, it undoes the use and returns the error: the request
// is then denied, and the old token stays valid.
func (r *Result) SendNotice(ctx context.Context) error {
	c, p := r.core, r.su.p
	now := c.now()
	pr := p.notice(now)
	pr.Via = audit.ViaStanding
	nctx, cancel := c.callContext(ctx, now.until(p.deadline))
	err := c.approver.Notify(nctx, pr)
	cancel()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		r.Undo()
	}
	return err
}

// SendAlarm sends the alarm of a denied UseStanding result, with a sound,
// if there is one. It is best effort: the request is denied anyway. The
// entry of the alarm is in Events.
func (r *Result) SendAlarm(ctx context.Context) {
	if r == nil || r.su == nil || r.su.alarm == "" || r.Allowed || r.core == nil {
		return
	}
	c, su := r.core, r.su
	al, ok := c.approver.(Alarmer)
	if !ok {
		c.giveBackMark(su)
		return
	}
	actx, cancel := c.callContext(context.WithoutCancel(ctx), endTimeout)
	defer cancel()
	err := al.Alarm(actx, Alarm{
		RequestID: r.RequestID, ShortCode: r.ShortCode, Client: r.Subject.Client,
		Secrets: slices.Clone(r.Subject.Secrets), GrantID: su.grantID, Cause: su.alarm, Ended: su.ended,
	})
	if err != nil {
		c.giveBackMark(su)
		c.logger.LogAttrs(actx, slog.LevelWarn, "approval: cannot send the alarm of a standing grant",
			slog.String("request_id", r.RequestID), slog.String("cause", string(su.alarm)), slog.Any("error", err))
	}
}

// giveBackMark takes back the daily outside_window mark that su took, because
// its alarm was not sent: the next request may send one. A later mark of the
// same grant is left alone.
func (c *Core) giveBackMark(su *standingUse) {
	if su.markG == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if su.markG.alarmMark == su.markNow {
		su.markG.alarmMark = su.markPrev
	}
}

// newTokenHash is the hash of the new token in hex, for the audit log.
func (r *Result) newTokenHash() string {
	if r.su == nil {
		return ""
	}
	return hex.EncodeToString(r.su.newHash[:])
}
