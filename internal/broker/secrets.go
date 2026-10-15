package broker

import (
	"context"
	"log/slog"
	"net/http"
	"slices"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
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
		// No message for a name the client may not use (DESIGN.md
		// section 5). The audit log gets only the names that passed.
		rq.deny(rq.pre, audit.CauseNotAllowed, "", http.StatusForbidden)
		return
	}
	res, rc, ok := rq.decide(ctx, &approval.Request{
		Client: rq.client, Kind: audit.KindSecrets, Secrets: names, Claim: cl,
	})
	if !ok {
		return
	}
	// The decision entry is on disk: the grants of an "Approve N min" tap
	// may start, before anything is handed out.
	res.StartGrants()
	values, ok := rq.fetch(ctx, rc, names)
	if !ok {
		return
	}
	ans := api.SecretsAnswer{Secrets: make([]api.SecretValue, len(req.Secrets))}
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
	if err := transport.WriteJSONBody(rq.w, http.StatusOK, body); err != nil {
		rq.s.log.Warn("broker: cannot write the answer; the client may not have it",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client))
	}
}

// checkSecrets checks the variables and the secret names of req: 1 to
// api.MaxSecrets variables, each with a valid name, none twice, and each
// secret in the config and allowed for client. It returns the secret names
// in the order of the request, for the core, and the names that passed,
// once each, for the audit log.
func (s *Service) checkSecrets(client string, req *api.SecretsRequest) (names, passed []string, ok bool) {
	ok = len(req.Secrets) > 0 && len(req.Secrets) <= api.MaxSecrets
	vars := make(map[string]bool, len(req.Secrets))
	seen := make(map[string]bool, len(req.Secrets))
	for _, ref := range req.Secrets {
		if !api.ValidVar(ref.Var) || vars[ref.Var] {
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
		v, err := rq.s.stores[sec.Store].Fetch(fctx, sec.ID)
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
			rq.fail(audit.CodeStoreFailed)
			return nil, false
		}
		rq.values = append(rq.values, v)
		values[name] = v
	}
	return values, true
}
