package approval

import (
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/audit"
)

// DropReason says why Restore did not open a grant again (DESIGN.md
// section 8, "Grants after a restart").
type DropReason string

const (
	// DropEnded: its end passed while the broker was stopped, or it has
	// no use left.
	DropEnded DropReason = "ended"
	// DropConfig: its secret, key or host is gone from the config, or its
	// rule no longer allows that kind of grant, or the client has too many
	// grants under the limits of now.
	DropConfig DropReason = "config"
	// DropClient: its client is gone from the config.
	DropClient DropReason = "client"
)

// RestoredGrant is a grant that Restore opened again, or dropped.
type RestoredGrant struct {
	// Subject is the subject of the request that made the grant, as the
	// log holds it, with its grant_id. A dropped grant gets a grant_ended
	// entry with it.
	Subject audit.Subject
	// UsesLeft is the number of uses left.
	UsesLeft int
	// Reason is why a dropped grant was dropped; "" for an open one.
	Reason DropReason
}

// logGrant is what Restore read from the log about one grant.
type logGrant struct {
	subject  audit.Subject
	approved time.Time
	standing bool
	uses     int // a scheduled grant: the uses left
	ended    bool
	// reason, if set, drops the grant with it.
	reason DropReason
	// using are the uses whose grant_used came, and whose secret_sent or
	// signed has not come yet, by request ID, with the new token hash of
	// a standing use.
	using map[string]logUse
	// A standing grant: its token hash now and before, and the times of
	// its uses. renewOf is the grant that a renewal renews, until the
	// renewal has the token (handed).
	token    [32]byte
	old      [][32]byte
	useTimes []time.Time
	renewOf  string
	handed   bool
}

// logUse is one grant_used entry.
type logUse struct {
	at      time.Time
	newHash [32]byte
}

// The reasons of a standing grant only.
const (
	// DropHead: a use of the grant is after the head entry: its Append
	// never returned, so the client may hold a token that the log does
	// not prove.
	DropHead DropReason = "head"
)

// Restore opens again the scheduled and standing grants that the audit
// log recs holds (DESIGN.md section 8, "Grants after a restart"). recs are
// the records of audit.ReadRecords, of a log whose chain verified, and
// head is the seq of the entry in the head file; the broker checks both,
// and the clock, before. Call it once, at start, before the first request.
//
// The rules:
//
//   - Only the entries after the last grants_reset entry count.
//   - A grant comes from an approving decision of a preapprove request
//     with a grant_id and an end, or of a standing request with a
//     token_hash, or from a renew decision, at or before head. A login
//     pre-approval has no end and is not opened again.
//   - A denied entry of the same request after it means that the tap made
//     no grant, and a grant_ended entry of the grant ends it.
//   - A grant_used entry of the grant counts as a use only when a
//     secret_sent or signed entry of the same request follows it: before
//     that, nothing was sent. A standing use moves the token to its
//     new_token_hash only then. A standing use after head drops the grant.
//   - A renewal takes the token of the grant it renews at the first use
//     of it, or when that grant has ended.
//   - The grant must pass the checks of a new request against the config
//     of now, with the approval as the time of the check, and its end must
//     not have passed.
//
// It returns the grants that are open again and the ones it dropped.
// Claimed text in an entry, such as a reason, never changes what it opens.
func (c *Core) Restore(recs []audit.Record, head uint64) (open, dropped []RestoredGrant, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.restored || c.stopped {
		return nil, nil, errors.New("approval: Restore runs once, at start; restart the broker")
	}
	c.restored = true
	from := 0
	for i, r := range recs {
		if _, ok := r.Event.(audit.GrantsReset); ok {
			from = i + 1
		}
	}
	grants := make(map[string]*logGrant)
	var order []string
	byRequest := make(map[string]string) // the request ID of a decision, to its grant ID
	add := func(r audit.Record, g *logGrant) {
		g.approved, g.using = r.Time, make(map[string]logUse)
		grants[g.subject.GrantID] = g
		order = append(order, g.subject.GrantID)
		byRequest[g.subject.RequestID] = g.subject.GrantID
	}
	for _, r := range recs[from:] {
		switch e := r.Event.(type) {
		case audit.Decision:
			s := e.Subject
			if r.Seq > head || s.GrantID == "" || s.NotAfter == "" || s.Logins != "" || grants[s.GrantID] != nil {
				continue
			}
			switch {
			case e.Answer == audit.AnswerApproveOnce && s.Kind == audit.KindPreapprove:
				add(r, &logGrant{subject: s, uses: s.Uses})
			case e.Answer == audit.AnswerApproveOnce && s.Kind == audit.KindStanding:
				g := &logGrant{subject: s, standing: true}
				if !decodeHash(&g.token, e.TokenHash) {
					continue
				}
				add(r, g)
			case e.Answer == audit.AnswerRenew && s.Kind == audit.KindStanding:
				if o := grants[e.RenewOf]; o != nil && o.standing && !o.ended {
					add(r, &logGrant{subject: s, standing: true, renewOf: e.RenewOf})
				}
			}
		case audit.Denied:
			if g := grants[byRequest[e.RequestID]]; g != nil {
				g.ended = true // the tap made no grant
			}
		case audit.GrantEnded:
			if g := grants[e.GrantID]; g != nil {
				g.ended = true
			}
		case audit.GrantUsed:
			g := grants[e.GrantID]
			if g == nil || g.ended || g.standing != (e.Via == audit.ViaStanding) || (!g.standing && e.Via != audit.ViaScheduled) {
				continue
			}
			u := logUse{at: r.Time}
			if g.standing && (r.Seq > head || !decodeHash(&u.newHash, e.NewTokenHash)) {
				g.reason = DropHead
				if o := grants[g.renewOf]; o != nil && !g.handed {
					o.reason = DropHead
				}
				continue
			}
			if g.renewOf != "" && !g.handed {
				handOverLog(grants[g.renewOf], g)
			}
			g.using[e.RequestID] = u
		case audit.SecretSent:
			countUse(grants, e.RequestID)
		case audit.Signed:
			countUse(grants, e.RequestID)
		}
	}
	now := c.now()
	// since is when the broker stopped: the time of the last entry. The
	// windows and ends between it and now passed while the broker was
	// stopped (DESIGN.md section 8, "Windows missed while stopped").
	since := now.wall
	// The log holds UTC times; the windows are in the clock's own zone.
	if n := len(recs); n > 0 && recs[n-1].Time.Before(since) {
		since = recs[n-1].Time.In(since.Location())
	}
	for _, id := range order {
		lg := grants[id]
		if o := grants[lg.renewOf]; o != nil && !lg.handed && !lg.ended {
			// A renewal that waits: it takes the token at the end of the
			// grant it renews, or when that grant ended as renewed.
			// When that grant is dropped, or ended in another way, so is
			// the renewal.
			if o.reason == "" && !o.ended && now.wall.Before(endOf(o)) {
				continue // it is linked to o below
			}
			if o.reason != "" || o.ended {
				lg.ended = true
				continue
			}
			handOverLog(o, lg)
		}
		if lg.ended {
			continue
		}
		rg := RestoredGrant{Subject: lg.subject, UsesLeft: lg.uses}
		if lg.standing {
			rg.UsesLeft = noLimit
		}
		g, reason := c.rebuild(lg, now, since)
		if g == nil {
			rg.Reason = reason
			dropped = append(dropped, rg)
			c.queueNotUsed(lg, reason)
			continue
		}
		c.grants = append(c.grants, g)
		open = append(open, rg)
	}
	// Link each waiting renewal to the grant it renews.
	for _, id := range order {
		lg := grants[id]
		if lg.renewOf == "" || lg.handed || lg.ended {
			continue
		}
		o, n := c.restoredGrant(lg.renewOf), (*grant)(nil)
		if o != nil {
			n = c.rebuildRenewal(lg, o, now)
		}
		rg := RestoredGrant{Subject: lg.subject, UsesLeft: noLimit}
		if n == nil {
			rg.Reason = DropConfig
			dropped = append(dropped, rg)
			continue
		}
		n.renewOf, o.next = o, n
		c.grants = append(c.grants, n)
		open = append(open, rg)
	}
	if len(open) > 0 || len(c.msgQueue) > 0 {
		c.wakeGrants()
	}
	return open, dropped, nil
}

// queueNotUsed queues the "not used" notice of the scheduled grant lg,
// when its end passed while the broker was stopped and it had uses left,
// as at an end while the broker runs. Its message is not known, so only
// the notice is sent. It holds no claimed text. Core.mu must be held.
func (c *Core) queueNotUsed(lg *logGrant, reason DropReason) {
	r, ok := lg.request()
	if reason != DropEnded || lg.standing || lg.uses < 1 || !ok || lg.uses > r.Uses {
		return
	}
	s := lg.subject
	code, err := newCode(c.random)
	if err != nil {
		return // the start notice lists the grant anyway
	}
	loc := c.clock.Wall().Location()
	p := Prompt{
		RequestID: s.RequestID, ShortCode: code, Kind: s.Kind, Client: s.Client,
		Secrets: slices.Clone(s.Secrets), Key: s.Key, Hosts: slices.Clone(s.Hosts), RemoteUser: s.RemoteUser,
		Uses: r.Uses, From: r.NotBefore.In(loc), Until: r.NotAfter.In(loc),
	}
	c.msgQueue = append(c.msgQueue, msgUpdate{prompt: p, ending: Ending{UsesLeft: lg.uses}, notice: true, grantID: s.GrantID})
}

// handOverLog gives the renewal n the token, the old tokens and the uses
// of o, and ends o, as handOver does.
func handOverLog(o, n *logGrant) {
	n.token, n.old, n.useTimes = o.token, o.old, o.useTimes
	n.handed, o.ended = true, true
}

// endOf returns the end of the grant lg, or the zero time if it does not
// parse, so the grant counts as ended.
func endOf(lg *logGrant) time.Time {
	t, _ := time.Parse(time.RFC3339, lg.subject.NotAfter)
	return t
}

// decodeHash decodes 64 hex digits into h, and refuses a zero hash.
func decodeHash(h *[32]byte, s string) bool {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return false
	}
	copy(h[:], b)
	return *h != [32]byte{}
}

// countUse counts the use of the request id, if a grant_used came for it.
func countUse(grants map[string]*logGrant, id string) {
	for _, g := range grants {
		u, ok := g.using[id]
		if !ok {
			continue
		}
		delete(g.using, id)
		if !g.standing {
			g.uses--
			continue
		}
		g.old = append(g.old, g.token)
		g.token = u.newHash
		g.useTimes = append(g.useTimes, u.at)
	}
}

// restoredGrant returns the grant with the ID id in c.grants, or nil.
// Core.mu must be held.
func (c *Core) restoredGrant(id string) *grant {
	for _, g := range c.grants {
		if g.id == id {
			return g
		}
	}
	return nil
}

// request returns the request that made lg, for the checks of now.
func (lg *logGrant) request() (*Request, bool) {
	s := lg.subject
	notBefore, err1 := time.Parse(time.RFC3339, s.NotBefore)
	notAfter, err2 := time.Parse(time.RFC3339, s.NotAfter)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	r := &Request{
		Client: s.Client, Kind: s.Kind, Secrets: s.Secrets, Key: s.Key, RemoteUser: s.RemoteUser,
		Hosts: s.Hosts, Uses: s.Uses, NotBefore: notBefore, NotAfter: notAfter, TokenHash: lg.token,
	}
	if len(s.ProjectSecrets) > 0 {
		r.Projects = make(map[string]ProjectSecret, len(s.ProjectSecrets))
		for _, ps := range s.ProjectSecrets {
			section, key, _ := strings.Cut(ps.Name, "/")
			r.Projects[ps.Name] = ProjectSecret{Section: section, Key: key, ID: ps.ID}
		}
	}
	for _, text := range s.Windows {
		w, ok := parseWindowText(text)
		if !ok {
			return nil, false
		}
		r.Windows = append(r.Windows, w)
	}
	return r, true
}

// rebuild makes the grant lg again, with the checks of a new request.
// Core.mu must be held.
func (c *Core) rebuild(lg *logGrant, now moment, since time.Time) (*grant, DropReason) {
	s := lg.subject
	cfg := c.conf()
	if lg.reason != "" {
		return nil, lg.reason
	}
	if _, ok := cfg.Clients[s.Client]; !ok {
		return nil, DropClient
	}
	r, ok := lg.request()
	if !ok || (!lg.standing && lg.uses < 1) || !now.wall.Before(r.NotAfter) {
		return nil, DropEnded
	}
	g, ok := c.checkAgain(r, lg, now, since)
	if !ok {
		return nil, DropConfig
	}
	if g.standing() {
		if c.standingCount(s.Client) >= cfg.Standing.MaxGrants {
			return nil, DropConfig
		}
		return g, ""
	}
	if c.scheduledCount(s.Client) >= cfg.Preapprove.MaxGrants {
		return nil, DropConfig
	}
	g.uses = lg.uses
	return g, ""
}

// rebuildRenewal makes the renewal lg of the open grant o again. Core.mu
// must be held.
func (c *Core) rebuildRenewal(lg *logGrant, o *grant, now moment) *grant {
	lg.token = o.tokenHash // only for the checks: a renewal has no token until the handover
	r, ok := lg.request()
	if !ok || !now.wall.Before(r.NotAfter) {
		return nil
	}
	n, ok := c.checkAgain(r, lg, now, now.wall)
	if !ok {
		return nil
	}
	n.tokenHash, n.oldHashes = [32]byte{}, nil
	n.code, n.start = o.code, time.Time{}
	return n
}

// checkAgain runs the checks of a new request on r, with the approval of
// lg as the time of the check, so a grant that was made far ahead passes
// the limit of how far ahead it may start. It returns the grant of the
// checks with the state that the log holds. A standing grant is scanned
// for missed windows from since on. Core.mu must be held.
func (c *Core) checkAgain(r *Request, lg *logGrant, now moment, since time.Time) (*grant, bool) {
	p := &pending{start: moment{wall: lg.approved, mono: now.mono}}
	if !c.check(r, p) || p.plan == nil || p.plan.standing() != lg.standing {
		return nil, false
	}
	s := lg.subject
	g := p.plan
	g.id, g.reqID, g.origin, g.approved = s.GrantID, s.RequestID, s, lg.approved
	// The log has no short code: the grant gets a new one, for its alarms
	// and notices. Without one, the approver refuses them; that is logged.
	if code, err := newCode(c.random); err == nil {
		g.code = code
	}
	g.end.mono = now.mono.Add(g.end.wall.Sub(now.wall))
	if !g.standing() {
		return g, true
	}
	g.tokenHash, g.oldHashes = lg.token, slices.Clone(lg.old)
	if g.oldHashes == nil {
		g.oldHashes = [][32]byte{}
	}
	// The windows that ended since since are scanned at the first wake:
	// one that ended while the broker was stopped, with no use, raises
	// the missed-window alarm.
	g.scanned = since
	for _, t := range lg.useTimes {
		t = t.In(since.Location())
		if key, left, in := windowAt(g.windows, t); in {
			if key.after(g.winKey) {
				g.winKey, g.winUsed = key, 0
			}
			g.winUsed++
			if t.Add(left).After(since) {
				if g.used == nil {
					g.used = make(map[windowKey]bool)
				}
				g.used[key] = true
			}
		}
		g.lastUse = t
	}
	if g.start.After(g.scanned) {
		g.scanned = g.start
	}
	g.warnAt = c.warnTime(g, now.wall)
	return g, true
}

// parseWindowText reads a window as windowText writes it, such as "daily
// 03:00-05:00" or "mon,thu 10:30-11:00". Only that form passes.
func parseWindowText(text string) (WindowSpec, bool) {
	days, span, ok := strings.Cut(text, " ")
	fromText, toText, ok2 := strings.Cut(span, "-")
	if !ok || !ok2 {
		return WindowSpec{}, false
	}
	var spec WindowSpec
	if days != "daily" {
		for _, name := range strings.Split(days, ",") {
			i := slices.Index(dayNames[:], name)
			if i < 0 {
				return WindowSpec{}, false
			}
			spec.Days = append(spec.Days, time.Weekday(i))
		}
	}
	var ok3, ok4 bool
	spec.From, ok3 = parseClock(fromText)
	spec.To, ok4 = parseClock(toText)
	w, valid := toWindow(spec)
	return spec, ok3 && ok4 && valid && windowText(w) == text
}

// parseClock reads "HH:MM", from 00:00 to 24:00.
func parseClock(s string) (time.Duration, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h, err1 := strconv.Atoi(s[:2])
	m, err2 := strconv.Atoi(s[3:])
	if err1 != nil || err2 != nil || h < 0 || m < 0 || m > 59 || h > 24 || (h == 24 && m != 0) {
		return 0, false
	}
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute, true
}
