package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/grantkey"
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
	standing := len(req.Windows) > 0
	var sub audit.Subject
	var from, until time.Time
	var ok bool
	var specs []approval.WindowSpec
	if standing {
		rq.kind = audit.KindStanding
		sub, from, until, specs, ok = rq.s.checkStanding(rq.client, req)
	} else {
		sub, from, until, ok = rq.s.checkPreapprove(rq.client, req)
	}
	sub.Reason = cl.Reason
	rq.pre = sub
	rq.releaseBody()
	if !ok {
		rq.deny(sub, audit.CauseNotAllowed, "", http.StatusForbidden)
		return
	}
	ar := &approval.Request{
		Client: rq.client, Kind: audit.KindPreapprove, Secrets: sub.Secrets, Key: sub.Key,
		RemoteUser: sub.RemoteUser, Hosts: sub.Hosts, Uses: int(req.Uses), NotBefore: from, NotAfter: until, Claim: cl,
	}
	var token grantkey.Token
	if standing {
		// The broker makes the token now; the core keeps its hash only.
		// The token goes into the answer once, and nowhere else.
		var err error
		if token, err = grantkey.New(); err != nil {
			rq.s.log.Error("broker: cannot make a grant token; the request is denied")
			rq.recordDenied(sub, audit.CauseError, audit.CodeApproverFailed, false)
			rq.answer(http.StatusServiceUnavailable)
			return
		}
		ar.Kind, ar.Windows, ar.TokenHash = audit.KindStanding, specs, grantkey.Hash(token)
	}
	res, _, ok := rq.decide(ctx, ar)
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
	ans := api.PreapproveAnswer{
		ID: res.GrantID, From: res.GrantFrom.Format(time.RFC3339), Until: res.GrantUntil.Format(time.RFC3339),
	}
	if standing {
		ans.GrantToken = token.Reveal()
	}
	err = transport.WriteJSON(rq.w, http.StatusOK, ans)
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

// checkStanding checks the names, the times and the windows of a request
// for a standing grant: secrets only, each in the config and allowed for
// client. From and until are read as for a scheduled grant. The approval
// core checks the rules, the limits and the windows against [standing].
func (s *Service) checkStanding(client string, req *api.PreapproveRequest) (sub audit.Subject, from, until time.Time, specs []approval.WindowSpec, ok bool) {
	ok = req.Uses >= 1 && req.Uses <= maxPreapproveUses && len(req.Secrets) > 0 &&
		req.Key == "" && req.User == "" && len(req.Hosts) == 0
	var err1, err2 error
	from, err1 = api.ParseTime(req.From, time.Local)
	until, err2 = api.ParseTime(req.Until, time.Local)
	if err1 != nil || err2 != nil {
		ok = false
	}
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
	for _, w := range req.Windows {
		spec, valid := windowSpec(w)
		ok = ok && valid
		specs = append(specs, spec)
	}
	return sub, from, until, specs, ok
}

// windowSpec reads a window of the request. It reports false for a window
// that does not have the form that api.Window.Check allows.
func windowSpec(w api.Window) (approval.WindowSpec, bool) {
	from, ok1 := api.ParseClock(w.From)
	to, ok2 := api.ParseClock(w.To)
	spec := approval.WindowSpec{From: time.Duration(from) * time.Minute, To: time.Duration(to) * time.Minute}
	ok := ok1 && ok2
	switch w.Kind {
	case api.WindowDaily:
		ok = ok && len(w.Days) == 0
	case api.WindowWeekly:
		ok = ok && len(w.Days) > 0
		for _, d := range w.Days {
			i := slices.Index(api.Weekdays[:], d)
			if i < 0 {
				ok = false
				continue
			}
			spec.Days = append(spec.Days, time.Weekday((i+1)%7)) // api.Weekdays starts on Monday
		}
	default:
		ok = false
	}
	return spec, ok
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

// stopNoticeTimeout bounds the stop notice, so a stop never waits long for
// a Telegram that does not answer. It is a variable only so that a test
// can make it short.
var stopNoticeTimeout = 5 * time.Second

// maxStopNoticeGrants is the most grants that the stop notice lists. The
// rest is counted.
const maxStopNoticeGrants = 20

// droppedGrants collects the scheduled grants that a stop dropped.
type droppedGrants struct {
	mu  sync.Mutex
	evs []audit.GrantEnded
}

// note keeps ev if it is the end of a grant by the stop.
func (d *droppedGrants) note(ev audit.GrantEnded) {
	if ev.Cause != audit.EndStopped {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.evs = append(d.evs, ev)
}

// list returns the notes.
func (d *droppedGrants) list() []audit.GrantEnded {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.evs)
}

// sendStopNotice sends one notice that lists the scheduled grants that the
// stop dropped: ID, client, secrets or key, and uses left (DESIGN.md
// section 8). It sends nothing when there are none. It makes one try, with
// stopNoticeTimeout; a notice that does not go out is logged, and the
// grant_ended entries are in the audit log.
func (s *Service) sendStopNotice(ctx context.Context, notice NoticeFunc, dropped []audit.GrantEnded) {
	if notice == nil || len(dropped) == 0 {
		return
	}
	defer s.recoverGoroutine("sending the stop notice")
	var b strings.Builder
	fmt.Fprintf(&b, "The broker stopped. It dropped %d scheduled grant(s); jobs that need them will ask for a tap:", len(dropped))
	for i, ev := range dropped {
		if i == maxStopNoticeGrants {
			fmt.Fprintf(&b, "\n... and %d more", len(dropped)-i)
			break
		}
		what := ev.Key
		if len(ev.Secrets) > 0 {
			what = strings.Join(ev.Secrets, ", ")
		}
		fmt.Fprintf(&b, "\n%s: %s, %s, %d use(s) left", ev.GrantID, ev.Client, what, ev.UsesLeft)
	}
	nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopNoticeTimeout)
	defer cancel()
	if err := notice(nctx, b.String()); err != nil {
		s.log.Warn("broker: cannot send the stop notice about the dropped scheduled grants",
			slog.String("error", errorText(err)))
	}
}
