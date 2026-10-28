package broker

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/transport"
)

// maxPreapproveUses is the most uses that the broker looks at. The core
// holds the real limit, max_uses of [preapprove], which is lower.
const maxPreapproveUses = 1 << 20

// preapprove answers a request for a scheduled grant: nodkey preapprove
// (DESIGN.md section 8). The broker hands out nothing for it; an approval
// only starts the grant.
func (rq *request) preapprove(ctx context.Context, r *http.Request) {
	req, err := transport.ReadJSON[api.PreapproveRequest](rq.w, r)
	if err != nil {
		rq.deniedBody()
		return
	}
	cl := approval.Claim{Reason: freeText(req.Reason, maxReasonRunes)}
	sub, from, until, ok := rq.s.checkPreapprove(rq.client, req)
	sub.Reason = cl.Reason
	rq.pre = sub
	rq.releaseBody()
	if !ok {
		rq.deny(sub, audit.CauseNotAllowed, "", http.StatusForbidden)
		return
	}
	res, _, ok := rq.decide(ctx, &approval.Request{
		Client: rq.client, Kind: audit.KindPreapprove, Secrets: sub.Secrets, Key: sub.Key,
		RemoteUser: sub.RemoteUser, Hosts: sub.Hosts, Uses: int(req.Uses), NotBefore: from, NotAfter: until, Claim: cl,
	})
	if !ok {
		return
	}
	// The grant is all that an approval gives. When the client has hung
	// up, no grant starts.
	if ctx.Err() != nil {
		rq.cancelled()
		return
	}
	if rq.s.startHook != nil {
		rq.s.startHook("before")
	}
	res.StartGrants()
	if rq.s.startHook != nil {
		rq.s.startHook("after")
	}
	if res.GrantStopped() {
		// The approver stopped while the request waited: as for any
		// request that the stop meets after the tap.
		rq.fail(audit.CodeApproverFailed)
		return
	}
	if !res.GrantStarted() {
		// The end came, a later Deny came, or the client has too many
		// grants: the tap made no grant.
		rq.ended = true
		_, _ = rq.s.append(audit.Denied{Subject: rq.sub, Cause: audit.CauseLimit})
		rq.answer(statusFor(audit.CauseLimit))
		return
	}
	rq.ended = true
	// A grant that the client cannot learn of is cancelled: nobody could
	// cancel it, and it could live for days.
	if ctx.Err() != nil {
		rq.dropGrant(res.GrantID)
		rq.answer(http.StatusForbidden)
		return
	}
	rq.answered = true
	err = transport.WriteJSON(rq.w, http.StatusOK, api.PreapproveAnswer{
		ID: res.GrantID, From: res.GrantFrom.Format(time.RFC3339), Until: res.GrantUntil.Format(time.RFC3339),
	})
	if err == nil {
		// writeBody does not flush; a hang-up shows here, not at Write.
		if err = http.NewResponseController(rq.w).Flush(); errors.Is(err, http.ErrNotSupported) {
			err = nil
		}
	}
	if err != nil {
		rq.s.log.Warn("broker: cannot write the answer; the new grant is cancelled",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client))
		rq.dropGrant(res.GrantID)
	}
}

// dropGrant cancels the grant id of this client in the core, and writes its
// grant_ended entry, as cancelGrant does.
func (rq *request) dropGrant(id string) {
	ev, ok := rq.core.CancelGrant(rq.client, id)
	if !ok {
		return
	}
	if _, err := rq.s.append(ev); err != nil {
		rq.s.log.Warn("broker: a scheduled grant was cancelled, but its audit entry could not be written",
			slog.String("client", rq.client))
	}
}

// checkPreapprove checks the names, the times and the number of uses of a
// request for a scheduled grant: either 1 to api.MaxSecrets secrets, or a
// key with a remote user and hosts as for nodkey ssh-grant, each name in
// the config and allowed for client. Times without an offset are read in
// the broker's local time. It returns the subject for the audit log with
// the names that passed, the two times, and whether every check passed.
// The approval core checks the rules, the limits and the span.
func (s *Service) checkPreapprove(client string, req *api.PreapproveRequest) (sub audit.Subject, from, until time.Time, ok bool) {
	ok = req.Uses >= 1 && req.Uses <= maxPreapproveUses
	var err1, err2 error
	from, err1 = api.ParseTime(req.From, time.Local)
	until, err2 = api.ParseTime(req.Until, time.Local)
	if err1 != nil || err2 != nil {
		ok = false
	}
	if len(req.Secrets) > 0 {
		ok = ok && req.Key == "" && req.User == "" && len(req.Hosts) == 0
		seen := make(map[string]bool, len(req.Secrets))
		for _, name := range req.Secrets {
			if seen[name] {
				continue
			}
			seen[name] = true
			sec, known := s.cfg.Secrets[name]
			if !known || !slices.Contains(sec.Clients, client) {
				ok = false
				continue
			}
			sub.Secrets = append(sub.Secrets, sec.Name)
		}
		return sub, from, until, ok
	}
	k, known := s.cfg.Keys[req.Key]
	if known && slices.Contains(k.Clients, client) {
		sub.Key = k.Name
	} else {
		known, ok = false, false
	}
	if sshauth.ValidUser(req.User) {
		sub.RemoteUser = req.User
	} else {
		ok = false
	}
	ok = s.checkHosts(k, known, req.Hosts, &sub) && ok
	return sub, from, until, ok
}

// cancelGrant answers the cancel of a scheduled grant: nodkey preapprove
// --cancel. It needs no tap, because it only takes a right away. The
// answer is the same for an ID that is not known, one that has ended and
// one that belongs to another client. The grant is cancelled before its
// grant_ended entry is written, so a failed write cannot keep it alive.
func (rq *request) cancelGrant(r *http.Request) {
	req, err := transport.ReadJSON[api.PreapproveCancelRequest](rq.w, r)
	rq.releaseBody()
	if err != nil {
		rq.answered = true
		return
	}
	ev, ok := rq.core.CancelGrant(rq.client, req.ID)
	if !ok {
		rq.answer(http.StatusForbidden)
		return
	}
	if _, err := rq.s.append(ev); err != nil {
		rq.s.log.Warn("broker: a scheduled grant was cancelled, but its audit entry could not be written",
			slog.String("client", rq.client))
	}
	rq.answerJSON(api.PreapproveCancelAnswer{ID: req.ID})
}
