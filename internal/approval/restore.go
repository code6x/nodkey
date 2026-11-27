package approval

import (
	"errors"
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
	uses     int
	ended    bool
	// using are the request IDs of the uses whose grant_used came, and
	// whose secret_sent or signed has not come yet.
	using map[string]bool
}

// Restore opens again the scheduled grants that the audit log recs holds
// (DESIGN.md section 8, "Grants after a restart"). recs are the records
// of audit.ReadRecords, of a log whose chain verified, and head is the seq
// of the entry in the head file; the broker checks both, and the clock,
// before. Call it once, at start, before the first request.
//
// The rules:
//
//   - Only the entries after the last grants_reset entry count.
//   - A grant comes from an approving decision of a preapprove request
//     with a grant_id and an end, at or before head. A login pre-approval
//     has no end and is not opened again.
//   - A denied entry of the same request after it means that the tap made
//     no grant, and a grant_ended entry of the grant ends it.
//   - A grant_used entry of the grant counts as a use only when a
//     secret_sent or signed entry of the same request follows it: before
//     that, nothing was sent.
//   - The grant must pass the checks of a new request against the config
//     of now, except its start, and its end must not have passed.
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
	for _, r := range recs[from:] {
		switch e := r.Event.(type) {
		case audit.Decision:
			s := e.Subject
			if r.Seq > head || e.Answer != audit.AnswerApproveOnce || s.Kind != audit.KindPreapprove ||
				s.GrantID == "" || s.NotAfter == "" || s.Logins != "" || grants[s.GrantID] != nil {
				continue
			}
			grants[s.GrantID] = &logGrant{subject: s, approved: r.Time, uses: s.Uses, using: make(map[string]bool)}
			order = append(order, s.GrantID)
			byRequest[s.RequestID] = s.GrantID
		case audit.Denied:
			if g := grants[byRequest[e.RequestID]]; g != nil {
				g.ended = true // the tap made no grant
			}
		case audit.GrantEnded:
			if g := grants[e.GrantID]; g != nil {
				g.ended = true
			}
		case audit.GrantUsed:
			if g := grants[e.GrantID]; g != nil && e.Via == audit.ViaScheduled {
				g.using[e.RequestID] = true
			}
		case audit.SecretSent:
			countUse(grants, e.RequestID)
		case audit.Signed:
			countUse(grants, e.RequestID)
		}
	}
	now := c.now()
	for _, id := range order {
		lg := grants[id]
		if lg.ended {
			continue
		}
		rg := RestoredGrant{Subject: lg.subject, UsesLeft: lg.uses}
		if g, reason := c.rebuildScheduled(lg, now); g != nil {
			c.grants = append(c.grants, g)
			open = append(open, rg)
		} else {
			rg.Reason = reason
			dropped = append(dropped, rg)
		}
	}
	if len(open) > 0 {
		c.wakeGrants()
	}
	return open, dropped, nil
}

// countUse counts the use of the request id, if a grant_used of a
// scheduled grant came for it.
func countUse(grants map[string]*logGrant, id string) {
	for _, g := range grants {
		if g.using[id] {
			delete(g.using, id)
			g.uses--
		}
	}
}

// rebuildScheduled makes the grant lg again, with the checks of a new
// request. Core.mu must be held.
func (c *Core) rebuildScheduled(lg *logGrant, now moment) (*grant, DropReason) {
	s := lg.subject
	cfg := c.conf()
	if _, ok := cfg.Clients[s.Client]; !ok {
		return nil, DropClient
	}
	notBefore, err1 := time.Parse(time.RFC3339, s.NotBefore)
	notAfter, err2 := time.Parse(time.RFC3339, s.NotAfter)
	if err1 != nil || err2 != nil || lg.uses < 1 || !now.wall.Before(notAfter) {
		return nil, DropEnded
	}
	r := &Request{
		Client: s.Client, Kind: audit.KindPreapprove, Secrets: s.Secrets, Key: s.Key, RemoteUser: s.RemoteUser,
		Hosts: s.Hosts, Uses: s.Uses, NotBefore: notBefore, NotAfter: notAfter,
	}
	if len(s.ProjectSecrets) > 0 {
		r.Projects = make(map[string]ProjectSecret, len(s.ProjectSecrets))
		for _, ps := range s.ProjectSecrets {
			section, key, _ := strings.Cut(ps.Name, "/")
			r.Projects[ps.Name] = ProjectSecret{Section: section, Key: key, ID: ps.ID}
		}
	}
	// The start of the check is the approval, so a grant that was made
	// far ahead passes the limit of how far ahead it may start.
	p := &pending{start: moment{wall: lg.approved, mono: now.mono}}
	if !c.check(r, p) || p.plan == nil || c.scheduledCount(s.Client) >= cfg.Preapprove.MaxGrants {
		return nil, DropConfig
	}
	g := p.plan
	g.id, g.reqID, g.origin, g.uses, g.approved = s.GrantID, s.RequestID, s, lg.uses, lg.approved
	g.end.mono = now.mono.Add(g.end.wall.Sub(now.wall))
	return g, ""
}
