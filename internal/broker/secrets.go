package broker

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/grantkey"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/transport"
)

// secrets answers a request for secrets: nodkey run (DESIGN.md section
// 5).
func (rq *request) secrets(ctx context.Context, r *http.Request) {
	req, err := transport.ReadJSON[api.SecretsRequest](rq.w, r)
	if err != nil {
		rq.deniedBody()
		return
	}
	names, passed, ok := rq.s.checkSecrets(rq.client, req)
	rq.pre = audit.Subject{Secrets: passed}
	cl := approval.Claim{
		Vars:    varsText(req.Secrets),
		Command: claim.Command(req.Command, maxCommandRunes),
		Dir:     freeText(req.Dir, maxDirRunes),
		Reason:  freeText(req.Reason, maxReasonRunes),
	}
	rq.pre.Command, rq.pre.Reason = cl.Command, cl.Reason
	rq.releaseBody()
	if !ok {
		// No message for a name the client may not use, or for a
		// variable on the deny list (DESIGN.md section 5). The audit log
		// gets only the names that passed.
		rq.deny(rq.pre, audit.CauseNotAllowed, "", http.StatusForbidden)
		rq.logDeniedVar(req.Secrets)
		return
	}
	var res *approval.Result
	var rc receipt
	if tokens := r.Header.Values(api.GrantTokenHeader); len(tokens) > 0 {
		// A request with a token never asks the person (DESIGN.md section 8).
		res, rc, ok = rq.decideStanding(ctx, names, cl, tokens)
	} else {
		res, rc, ok = rq.decide(ctx, &approval.Request{
			Client: rq.client, Kind: audit.KindSecrets, Secrets: names, Claim: cl,
		})
	}
	if !ok {
		return
	}
	// A standing grant has a new token now. If nothing is answered, the
	// client never gets it, so the use is undone and the old token stays
	// valid (DESIGN.md section 8).
	handed := false
	defer func() {
		if !handed {
			res.Undo()
		}
	}()
	// The decision entry is on disk: the grants of an "Approve N min" tap
	// may start, before anything is handed out.
	res.StartGrants()
	values, ok := rq.fetch(ctx, rc, names)
	if !ok {
		return
	}
	ans := api.SecretsAnswer{Secrets: make([]api.SecretValue, len(req.Secrets))}
	if tok, rotated := res.NewToken(); rotated {
		ans.GrantToken = tok.Reveal()
	}
	for i, ref := range req.Secrets {
		// The value goes from Bytes into the answer, without a copy.
		ans.Secrets[i] = api.SecretValue{Var: ref.Var, Value: values[ref.Name].Bytes()}
	}
	// Encode writes the answer into one buffer, which is cleared after
	// the answer: the only copy of the values besides the store's.
	body, err := ans.Encode()
	defer clear(body)
	if err != nil {
		rq.s.log.Warn("broker: a secret value is longer than the broker hands out; the request is denied",
			slog.String("request_id", rq.sub.RequestID), slog.Int("max_value", api.MaxValue),
			slog.Int("max_values", api.MaxValues))
		rq.fail(audit.CodeStoreFailed)
		return
	}
	if ctx.Err() != nil {
		rq.cancelled()
		return
	}
	if !rq.handOut(rc, audit.SecretSent{Subject: rq.sub}) {
		return
	}
	rq.answered = true
	handed = true
	if err := transport.WriteJSONBody(rq.w, http.StatusOK, body); err != nil {
		rq.s.log.Warn("broker: cannot write the answer; the client may not have it",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client))
	}
}

// checkSecrets checks the variables and the secret names of req: 1 to
// api.MaxSecrets variables, each with a valid name that is not on the
// deny list (api.DeniedVar), none twice, and each secret in the config and
// allowed for client. It returns the secret names in the order of the
// request, for the core, and the names that passed, once each, for the
// audit log.
func (s *Service) checkSecrets(client string, req *api.SecretsRequest) (names, passed []string, ok bool) {
	ok = len(req.Secrets) > 0 && len(req.Secrets) <= api.MaxSecrets
	vars := make(map[string]bool, len(req.Secrets))
	seen := make(map[string]bool, len(req.Secrets))
	for _, ref := range req.Secrets {
		_, denied := api.DeniedVar(ref.Var)
		if !api.ValidVar(ref.Var) || denied || vars[ref.Var] {
			ok = false
		}
		vars[ref.Var] = true
		sec, known := s.cfg.Secrets[ref.Name]
		if !known || !slices.Contains(sec.Clients, client) {
			ok = false
			continue
		}
		names = append(names, sec.Name)
		if !seen[sec.Name] {
			seen[sec.Name] = true
			passed = append(passed, sec.Name)
		}
	}
	return names, passed, ok
}

// logDeniedVar logs why the broker refused a request with a variable on
// the deny list (DESIGN.md section 5): a fixed text, and the entry of the
// list, such as PATH or LD_*. It never logs a name that the client chose:
// for a prefix, it logs only the prefix. An agent can send many such
// requests, so these lines are limited per minute, together with those
// about refused SSH logins.
func (rq *request) logDeniedVar(refs []api.SecretRef) {
	for _, ref := range refs {
		prefix, denied := api.DeniedVar(ref.Var)
		if !denied {
			continue
		}
		entry := prefix + "*"
		if prefix == "" {
			entry = ref.Var // equal to a name on the list
		}
		if rq.s.refusedLines.allow() {
			rq.s.log.Info("broker: refused a request for secrets: a variable is on the deny list, because "+
				"programs show or run the value of such a variable (DESIGN.md section 5)",
				slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client),
				slog.String("deny_list", entry))
		}
		return
	}
}

// fetch gets the value of each secret of names from its store, once each,
// in order. It needs the receipt of the decision. The values go to
// rq.values too, so they are cleared on every path. Any error denies the
// whole request.
func (rq *request) fetch(ctx context.Context, rc receipt, names []string) (map[string]store.Value, bool) {
	if !rc.valid() {
		rq.fail(audit.CodeStoreFailed)
		return nil, false
	}
	rq.failCode = audit.CodeStoreFailed
	values := make(map[string]store.Value, len(names))
	for _, name := range names {
		if _, done := values[name]; done {
			continue
		}
		// A handler stops before a fetch when its context has ended.
		if ctx.Err() != nil {
			rq.cancelled()
			return nil, false
		}
		sec := rq.s.cfg.Secrets[name]
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		ref := sec.ID
		if sec.Field != "" {
			ref += "/" + sec.Field // a 1password store: the item and its field
		}
		v, err := rq.s.stores[sec.Store].Fetch(fctx, ref)
		cancel()
		if err != nil {
			v.Clear()
			if ctx.Err() != nil {
				rq.cancelled()
				return nil, false
			}
			// Store errors are fixed texts: the store, the step, a reason
			// and an exit code, never the program's output.
			rq.s.log.Warn("broker: a store failed; the request is denied",
				slog.String("request_id", rq.sub.RequestID), slog.String("store", sec.Store),
				slog.String("error", errorText(err)))
			if errors.Is(err, store.ErrRateLimited) {
				rq.s.rateLimited(sec.Store)
			}
			rq.fail(audit.CodeStoreFailed)
			return nil, false
		}
		rq.values = append(rq.values, v)
		values[name] = v
	}
	return values, true
}

// decideStanding decides a request that has the header of a standing grant
// token (DESIGN.md section 8). The core never asks the person. It writes
// the entries, sends the alarm of a denied request, and sends the silent
// notice of an allowed one. It returns ok only when every step worked; the
// request has its answer otherwise. If a step fails after the new token
// was made, the use is undone, so the old token stays valid.
func (rq *request) decideStanding(ctx context.Context, names []string, cl approval.Claim, tokens []string) (*approval.Result, receipt, bool) {
	var hash *[32]byte
	if len(tokens) == 1 {
		if t, err := grantkey.Parse(tokens[0]); err == nil {
			h := grantkey.Hash(t)
			hash = &h
		}
	}
	rq.failCode = audit.CodeApproverFailed
	res := rq.core.UseStanding(approval.StandingRequest{Client: rq.client, Secrets: names, Claim: cl, Token: hash})
	res, rc, ok := rq.settle(res)
	if !ok {
		if res.Allowed {
			res.Undo() // the entry could not be written, or the broker stops
		}
		res.SendAlarm(ctx)
		return res, rc, false
	}
	if err := res.SendNotice(ctx); err != nil {
		rq.s.log.Warn("broker: cannot send the notice of a standing grant use; the request is denied",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client),
			slog.String("error", errorText(err)))
		rq.fail(audit.CodeApproverFailed)
		return res, rc, false
	}
	return res, rc, true
}
