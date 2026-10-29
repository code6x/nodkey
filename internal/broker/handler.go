package broker

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/transport"
)

// endpoint is one path of the API.
type endpoint struct {
	path string
	kind audit.Kind // the kind of request in the audit log; "" for PathKeys
}

// endpoints are the paths of the API (package api).
var endpoints = []endpoint{
	{api.PathKeys, ""},
	{api.PathSecrets, audit.KindSecrets},
	{api.PathSign, audit.KindSSHLogin},
	{api.PathSSHGrant, audit.KindSSHGrant},
	{api.PathPreapprove, audit.KindPreapprove},
	{api.PathPreapproveCancel, ""},
}

// route returns the endpoint of r, or the status of the answer: 404 for a
// path that the API does not have, and 405 for a method other than POST.
// It compares the request target exactly as the client sent it: no other
// spelling of the path, and no query. So "OPTIONS *" and "PRI *" get 404.
func route(r *http.Request) (endpoint, int) {
	for _, ep := range endpoints {
		if r.RequestURI != ep.path {
			continue
		}
		if r.Method != http.MethodPost {
			return endpoint{}, http.StatusMethodNotAllowed
		}
		return ep, 0
	}
	return endpoint{}, http.StatusNotFound
}

// ServeHTTP answers one request of a client (see the package comment for
// the steps). Every answer goes through transport.WriteJSON,
// transport.WriteError or transport.WriteProcessing, and has the broker's
// version in its header.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.version != "" {
		// First, so that every answer has it, whatever its status.
		w.Header().Set(api.VersionHeader, s.version)
	}
	client, ok := transport.ClientName(r.Context())
	if !ok {
		transport.WriteError(w, http.StatusForbidden)
		return
	}
	s.checkVersion(client, r.Header)
	ep, status := route(r)
	if status != 0 {
		if status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", http.MethodPost)
		}
		transport.WriteError(w, status)
		return
	}
	adm := s.enter(client)
	defer s.leave(client, adm)
	rq := &request{s: s, w: w, client: client, kind: ep.kind, core: adm.core}
	if adm.status != 0 {
		if ep.kind != "" && adm.cause != "" {
			// These refusals do not count toward the cap, so their
			// entries are limited per minute.
			rq.recordDenied(audit.Subject{}, adm.cause, adm.code, true)
		}
		rq.answer(adm.status)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(s.stopCtx, cancel) // Close ends the request
	defer stop()
	defer rq.recoverPanic()
	defer rq.clearValues()
	defer rq.releaseBody()
	if !rq.takeBody(ctx) {
		return
	}
	switch ep.path {
	case api.PathKeys:
		rq.listKeys(r)
	case api.PathSecrets:
		rq.secrets(ctx, r)
	case api.PathSign:
		rq.sign(ctx, r)
	case api.PathSSHGrant:
		rq.grant(ctx, r)
	case api.PathPreapprove:
		rq.preapprove(ctx, r)
	case api.PathPreapproveCancel:
		rq.cancelGrant(r)
	}
}

// admission says whether the Service takes a request.
type admission struct {
	core    *approval.Core // nil when the request is refused
	tracked bool           // Close waits for the request
	counted bool           // the request counts toward the client's cap
	status  int            // 0, or the status of the refusal
	cause   audit.Cause    // the cause of the refusal in the audit log; "" for no entry
	code    audit.Code     // the code of the refusal's error entry, if any
}

// enter decides whether the Service takes a request of client. It refuses
// every request before Run, after Close, after a failed audit write
// (without an audit entry: the broker is starting or stopping, or the log
// cannot be written), after the approver stopped, and over the client's
// cap of requests in progress.
func (s *Service) enter(client string) admission {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.core == nil {
		return admission{status: http.StatusServiceUnavailable}
	}
	s.requests.Add(1)
	switch {
	case s.broken.Load():
		return admission{tracked: true, status: http.StatusServiceUnavailable}
	case s.coreStopped.Load():
		return admission{tracked: true, status: http.StatusServiceUnavailable,
			cause: audit.CauseError, code: audit.CodeApproverFailed}
	case s.inflight[client] >= s.maxPerClient:
		return admission{tracked: true, status: http.StatusTooManyRequests, cause: audit.CauseLimit}
	}
	s.inflight[client]++
	return admission{core: s.core, tracked: true, counted: true}
}

// leave ends a request that enter took.
func (s *Service) leave(client string, a admission) {
	if a.counted {
		s.mu.Lock()
		if s.inflight[client]--; s.inflight[client] <= 0 {
			delete(s.inflight, client)
		}
		s.mu.Unlock()
	}
	if a.tracked {
		s.requests.Done()
	}
}

// statusFor returns the status of the answer to a request that was denied
// for cause: 429 for a limit, 503 when something failed, and 403 for the
// rest (denied by the person or by a check, expired, cancelled). It never
// says more, such as which name was wrong.
func statusFor(cause audit.Cause) int {
	switch cause {
	case audit.CauseLimit:
		return http.StatusTooManyRequests
	case audit.CauseError:
		return http.StatusServiceUnavailable
	default:
		return http.StatusForbidden
	}
}

// receipt shows that the entries that decided a request are on disk. Only
// request.decide makes a valid one, after every audit write worked; a
// fetch or a signature needs it (DESIGN.md section 9).
type receipt struct {
	last audit.Anchor // the anchor of the last entry
}

func (r receipt) valid() bool { return r.last.Seq > 0 }

// request is one request in progress.
type request struct {
	s      *Service
	w      http.ResponseWriter
	client string
	kind   audit.Kind
	core   *approval.Core

	// pre holds the names that passed the broker's checks so far, and the
	// claimed text once it is safe, before the core gives the request an
	// ID. A panic before that writes it under an ID of the broker.
	pre audit.Subject
	// inDecide is true while the core decides the request.
	inDecide bool
	// sub names the request in the audit log, once it has an ID. It holds
	// only checked names and claimed text that is safe.
	sub audit.Subject
	// ended is true when the last entry of the request is written, or
	// when no more entries can be written.
	ended bool
	// answered is true when the answer is written.
	answered bool
	// failCode is the code of the error entry if the request panics now.
	failCode audit.Code
	// values are the values fetched so far; they are cleared on every
	// path.
	values []store.Value
	// body is set while the request holds a place to read and decode its
	// body; calling it gives the place back.
	body func()
}

// answer answers with an error status, unless the request has its answer.
// Once Close has begun, every request in progress gets 503: the broker
// stops, and the client did not get a deny.
func (rq *request) answer(status int) {
	if rq.answered {
		return
	}
	rq.answered = true
	if rq.s.stopping() {
		status = http.StatusServiceUnavailable
	}
	transport.WriteError(rq.w, status)
}

// takeBody waits for a place to read and decode the body of the request:
// one of the client's maxBodiesPerClient, then one of maxBodies. A request
// that waits longer than bodyWait is denied for a limit (429). It reports
// whether the request got a place; if not, the request has its answer.
func (rq *request) takeBody(ctx context.Context) bool {
	mine, all := rq.s.clientBodies[rq.client], rq.s.bodies
	if mine == nil {
		rq.answer(http.StatusForbidden) // never: every client of the config has places
		return false
	}
	t := time.NewTimer(bodyWait)
	defer t.Stop()
	got := 0
	for _, slots := range []chan struct{}{mine, all} {
		select {
		case slots <- struct{}{}:
			got++
			continue
		case <-ctx.Done():
		case <-t.C:
		}
		if got > 0 {
			<-mine
		}
		cause := audit.CauseLimit
		if ctx.Err() != nil {
			cause = audit.CauseCancelled // Close ended the wait
		}
		if rq.kind != "" {
			rq.recordDenied(audit.Subject{}, cause, "", true)
		}
		rq.answer(statusFor(cause))
		return false
	}
	rq.body = func() {
		<-all
		<-mine
	}
	return true
}

// releaseBody gives back the place of takeBody, once the body is read,
// checked and its claimed text is safe.
func (rq *request) releaseBody() {
	if rq.body != nil {
		rq.body()
		rq.body = nil
	}
}

// answerJSON answers with 200 and v.
func (rq *request) answerJSON(v any) {
	rq.answered = true
	if err := transport.WriteJSON(rq.w, http.StatusOK, v); err != nil {
		rq.s.log.Warn("broker: cannot write the answer; the client may not have it",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client))
	}
}

// newRequestID returns a new request ID, as the approval core makes them:
// 16 random bytes in base64url without padding.
func newRequestID(random io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// deny denies the request before the approval core sees it: a body that is
// not valid, or a check that failed. It records the request
// (recordDenied), then answers with status, unless the request has its
// answer already.
func (rq *request) deny(sub audit.Subject, cause audit.Cause, code audit.Code, status int) {
	rq.recordDenied(sub, cause, code, false)
	rq.answer(status)
}

// recordDenied writes the entries of a request that the broker denies
// itself, before the approval core gives it an ID: a request entry and a
// denied entry for cause, with an error entry for code before it, under a
// new request ID, and with sub's names and claimed text. When limited is
// set, it writes them only while the client has fewer than
// refusedEntriesPerMinute such requests in the minute; it counts the
// others for the log. A refused request that does not count toward the cap
// of requests in progress is limited, so that it cannot fill the disk
// fast.
func (rq *request) recordDenied(sub audit.Subject, cause audit.Cause, code audit.Code, limited bool) {
	rq.ended = true
	if limited && !rq.s.refusedAllowed(rq.client) {
		return
	}
	id, err := newRequestID(rq.s.random)
	if err != nil {
		rq.s.log.Error("broker: cannot make a request ID; the request is denied without an audit entry")
		return
	}
	sub.RequestID, sub.Client, sub.Kind = id, rq.client, rq.kind
	rq.sub = sub
	events := []audit.Event{audit.Request{Subject: sub}}
	if code != "" {
		events = append(events, audit.Failure{Subject: sub, Code: code})
	}
	events = append(events, audit.Denied{Subject: sub, Cause: cause})
	for _, ev := range events {
		if _, err := rq.s.append(ev); err != nil {
			return
		}
	}
}

// refusedAllowed reports whether the entries of one more refused request
// of client may be written now (refusedEntriesPerMinute).
func (s *Service) refusedAllowed(client string) bool {
	l := s.refusedEntries[client]
	return l == nil || l.allow()
}

// deniedBody records a request whose body ReadJSON refused; ReadJSON has
// answered it.
func (rq *request) deniedBody() {
	rq.answered = true
	rq.deny(audit.Subject{}, audit.CauseNotAllowed, "", http.StatusBadRequest)
}

// decide asks the approval core about ar, which holds only checked data,
// with a context that ends when the client hangs up. Then it writes the
// entries of the result to the audit log, in order. It returns the result
// and, when every entry is on disk, a valid receipt. A request that is not
// allowed, or whose entries could not be written, gets its answer here,
// and ok is false.
func (rq *request) decide(ctx context.Context, ar *approval.Request) (res *approval.Result, rc receipt, ok bool) {
	ar.OnWait = rq.onWait
	rq.failCode = audit.CodeApproverFailed
	rq.inDecide = true
	res = rq.core.Decide(ctx, ar)
	rq.inDecide = false
	return rq.settle(res)
}

// settle writes the entries of res, and answers a request that is not
// allowed (see decide).
func (rq *request) settle(res *approval.Result) (*approval.Result, receipt, bool) {
	var rc receipt
	rq.sub = res.Subject
	if res.Err != nil {
		// Result.Err goes to the journal, never to the audit log.
		rq.s.log.Warn("broker: the approver failed; the request is denied",
			slog.String("request_id", res.RequestID), slog.String("client", rq.client),
			slog.String("error", errorText(res.Err)))
	}
	rq.ended = true // until every entry is written
	if !res.Allowed && res.Cause == audit.CauseLimit && !rq.s.refusedAllowed(rq.client) {
		// A client can send requests that a limit denies fast: their
		// entries are limited per minute, and only counted after that.
		rq.answer(statusFor(res.Cause))
		return res, receipt{}, false
	}
	for _, ev := range res.Events() {
		a, err := rq.s.append(ev)
		if err != nil {
			rq.answer(http.StatusServiceUnavailable)
			return res, receipt{}, false
		}
		rc.last = a
	}
	if !res.Allowed {
		rq.answer(statusFor(res.Cause))
		return res, receipt{}, false
	}
	rq.ended = false // secret_sent or signed comes later
	if rq.s.coreStopped.Load() || rq.s.broken.Load() {
		// The approver stopped, or the audit log broke, while the core
		// decided: the broker denies everything now, also what a grant
		// allows.
		rq.fail(audit.CodeApproverFailed)
		return res, receipt{}, false
	}
	return res, rc, true
}

// onWait tells the client the short code when its request starts to wait
// for the person: a 102 Processing answer, with a short write deadline.
// The core calls it in the request's own goroutine, before it sends the
// message.
func (rq *request) onWait(code string) {
	if !api.ValidShortCode(code) {
		return
	}
	h := make(http.Header, 1)
	h.Set(api.ShortCodeHeader, code)
	if err := transport.WriteProcessing(rq.w, h); err != nil {
		rq.s.log.Debug("broker: cannot tell the client the short code", slog.String("client", rq.client))
	}
}

// fail denies an approved request because a later step failed: an error
// entry with code, a denied entry, and the answer 503.
func (rq *request) fail(code audit.Code) {
	rq.ended = true
	if _, err := rq.s.append(audit.Failure{Subject: rq.sub, Code: code}); err == nil {
		_, _ = rq.s.append(audit.Denied{Subject: rq.sub, Cause: audit.CauseError})
	}
	rq.answer(http.StatusServiceUnavailable)
}

// cancelled denies an approved request whose client hung up, or that
// Close ended, before anything was handed out.
func (rq *request) cancelled() {
	rq.ended = true
	_, _ = rq.s.append(audit.Denied{Subject: rq.sub, Cause: audit.CauseCancelled})
	rq.answer(http.StatusForbidden)
}

// handOut writes ev, secret_sent or signed, just before the answer that
// hands something out. Without that entry on disk, nothing is sent: the
// answer is 503, and handOut returns false.
func (rq *request) handOut(rc receipt, ev audit.Event) bool {
	rq.ended = true
	if !rc.valid() {
		rq.answer(http.StatusServiceUnavailable)
		return false
	}
	if _, err := rq.s.append(ev); err != nil {
		rq.answer(http.StatusServiceUnavailable)
		return false
	}
	return true
}

// clearValues clears the fetched values.
func (rq *request) clearValues() {
	for _, v := range rq.values {
		v.Clear()
	}
	rq.values = nil
}

// recoverPanic ends a request that panicked. It clears the fetched values,
// writes the entries that end the request, if it has an ID, and logs where
// the panic happened, but not the panic value, which can hold anything
// from the request. Then it drops the connection without an answer, as the
// answer may be half written. It must be called by defer.
func (rq *request) recoverPanic() {
	v := recover()
	if v == nil {
		return
	}
	rq.clearValues()
	rq.releaseBody()
	if err, ok := v.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
		rq.s.log.Error("broker: a request panicked; it is denied, and the panic value is not logged",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client),
			slog.String("where", panicPlace()))
	}
	switch {
	case rq.ended || rq.kind == "" || rq.s.broken.Load():
		// Nothing to write, or the log cannot take it: never wait for a
		// broken log here.
	case rq.sub.RequestID != "":
		// After the core decided: the step that panicked failed.
		rq.ended = true
		ok := true
		if rq.failCode != "" {
			_, err := rq.s.append(audit.Failure{Subject: rq.sub, Code: rq.failCode})
			ok = err == nil
		}
		if ok {
			_, _ = rq.s.append(audit.Denied{Subject: rq.sub, Cause: audit.CauseError})
		}
	case rq.inDecide:
		// The approver, or OnWait, panicked while the core decided; the
		// core has forgotten the request's ID.
		rq.recordDenied(rq.pre, audit.CauseError, audit.CodeApproverFailed, false)
	default:
		// Before the core: the body or the checks could not be finished.
		rq.recordDenied(rq.pre, audit.CauseNotAllowed, "", false)
	}
	panic(http.ErrAbortHandler)
}
