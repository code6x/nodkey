package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/grantkey"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/totp"
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
	if !ok {
		rq.releaseBody()
		// No message for a name the client may not use, or for a
		// variable on the deny list (DESIGN.md section 5). The audit log
		// gets only the names that passed.
		rq.deny(rq.pre, audit.CauseNotAllowed, "", http.StatusForbidden)
		rq.logDeniedVar(req.Secrets)
		return
	}
	// The place of the body is held while the stores list the projects,
	// so one client cannot keep the stores busy with many requests.
	resolved := rq.resolveProjects(ctx, names)
	rq.releaseBody()
	if !resolved {
		return
	}
	var res *approval.Result
	var rc receipt
	if tokens := r.Header.Values(api.GrantTokenHeader); len(tokens) > 0 {
		// A request with a token never asks the person (DESIGN.md section 8).
		res, rc, ok = rq.decideStanding(ctx, approval.StandingRequest{
			Client: rq.client, Secrets: names, Projects: rq.projects, Claim: cl,
		}, tokens)
	} else {
		res, rc, ok = rq.decide(ctx, &approval.Request{
			Client: rq.client, Kind: audit.KindSecrets, Secrets: names, Projects: rq.projects, Claim: cl,
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
	rq.decided = res.Config()
	values, ok := rq.fetch(ctx, rc, names)
	if !ok {
		return
	}
	// A fetch can take long: a reload during it may have taken the access
	// away. The values are in rq.values, so they are cleared.
	if !rq.stillAllowed(rq.decided, names, "", nil) {
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
// allowed for client. The kind of each variable must match the config: a
// secret with totp = true only as api.KindTOTP, and api.KindTOTP only for
// such a secret, at most once in a request (DESIGN.md section 5, "TOTP
// codes"). It returns the secret names in the order of the
// request, for the core, and the names that passed, once each, for the
// audit log.
func (s *Service) checkSecrets(client string, req *api.SecretsRequest) (names, passed []string, ok bool) {
	ok = len(req.Secrets) > 0 && len(req.Secrets) <= api.MaxSecrets
	vars := make(map[string]bool, len(req.Secrets))
	seen := make(map[string]bool, len(req.Secrets))
	cfg := s.view().cfg
	codes := 0
	for _, ref := range req.Secrets {
		_, denied := api.DeniedVar(ref.Var)
		if !api.ValidVar(ref.Var) || denied || vars[ref.Var] {
			ok = false
		}
		vars[ref.Var] = true
		if !secretAllowed(cfg, client, ref.Name) {
			ok = false
			continue
		}
		if ref.Kind == api.KindTOTP {
			codes++
		}
		// A project secret is never a TOTP code: its Secrets entry is
		// missing, so its TOTP is false.
		if wantTOTP := ref.Kind == api.KindTOTP; wantTOTP != cfg.Secrets[ref.Name].TOTP || codes > 1 {
			ok = false
			continue
		}
		names = append(names, ref.Name)
		if _, isProject, _ := config.ParseSecretName(ref.Name); isProject {
			continue // the audit log gets it once it is found (resolveProjects)
		}
		if !seen[ref.Name] {
			seen[ref.Name] = true
			passed = append(passed, ref.Name)
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
	if !rq.stillAllowed(rq.decided, names, "", nil) {
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
		storeName, fetch := rq.fetcher(name)
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		v, err := fetch(fctx)
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
				slog.String("request_id", rq.sub.RequestID), slog.String("store", storeName),
				slog.String("error", errorText(err)))
			if errors.Is(err, store.ErrRateLimited) {
				rq.s.rateLimited(storeName)
			}
			rq.fail(audit.CodeStoreFailed)
			return nil, false
		}
		rq.values = append(rq.values, v)
		values[name] = v
	}
	return values, true
}

// fetcher returns the store of the secret name and the function that
// gets its value. A project secret is got by its ID from the store of its
// project, and the answer must have the key and the project of the list
// (DESIGN.md section 14, "Projects"). A name that the request did not
// resolve gets a function that fails.
func (rq *request) fetcher(name string) (string, func(context.Context) (store.Value, error)) {
	if pn, isProject, _ := config.ParseSecretName(name); isProject {
		p := rq.v.cfg.Projects[pn.Section]
		ps, isPS := rq.s.stores[p.Store].(store.ProjectStore)
		listed, found := rq.listed[name]
		return p.Store, func(ctx context.Context) (store.Value, error) {
			if !isPS || !found {
				return store.Value{}, store.ErrBadID
			}
			return ps.FetchListed(ctx, listed)
		}
	}
	sec := rq.v.cfg.Secrets[name]
	if sec.TOTP {
		return sec.Store, func(ctx context.Context) (store.Value, error) { return rq.totpCode(ctx, name, sec) }
	}
	ref := sec.ID
	switch {
	case sec.Field != "":
		ref += "/" + sec.Field // a 1password store: the item and its field
	case sec.SecretName != "":
		// An infisical store: the project, environment, path and name.
		ref = store.InfisicalRef(sec.Project, sec.Environment, sec.Path, sec.SecretName)
	}
	return sec.Store, func(ctx context.Context) (store.Value, error) { return rq.s.stores[sec.Store].Fetch(ctx, ref) }
}

// decideStanding decides a request for secrets or for a signature that has
// the header of a standing grant token (DESIGN.md section 8). The core never asks the person. It writes
// the entries, sends the alarm of a denied request, and sends the silent
// notice of an allowed one. It returns ok only when every step worked; the
// request has its answer otherwise. If a step fails after the new token
// was made, the use is undone, so the old token stays valid.
func (rq *request) decideStanding(ctx context.Context, sr approval.StandingRequest, tokens []string) (*approval.Result, receipt, bool) {
	var hash *[32]byte
	if len(tokens) == 1 {
		if t, err := grantkey.Parse(tokens[0]); err == nil {
			h := grantkey.Hash(t)
			hash = &h
		}
	}
	rq.failCode = audit.CodeApproverFailed
	sr.Token = hash
	res := rq.core.UseStanding(sr)
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

// errBadTOTPSeed is the error of a login.totp field that internal/totp
// does not read. It never holds the field.
var errBadTOTPSeed = errors.New("the TOTP seed in the item's login.totp field is not in a form nodkey reads; " +
	"see DESIGN.md section 21.5")

// totpCode makes the current TOTP code of the secret sec, a secret with
// totp = true (DESIGN.md section 5, "TOTP codes"). The store hands the
// seed only to the broker; the broker makes the code and clears the seed
// and the key at once. Each call fetches the item again, so each use of a
// grant gets the code of its own moment. Any error means deny. The error
// names the store and the secret and says how to fix it; it never holds
// the seed or the code.
func (rq *request) totpCode(ctx context.Context, name string, sec config.Secret) (store.Value, error) {
	ts, ok := rq.s.stores[sec.Store].(store.TOTPStore)
	if !ok {
		return store.Value{}, fmt.Errorf("store %q: secret %q: the store cannot hand out TOTP codes; "+
			`totp = true needs a store of type = "bw"`, sec.Store, name)
	}
	seed, err := ts.FetchTOTP(ctx, sec.ID)
	defer seed.Clear()
	switch {
	case errors.Is(err, store.ErrNoTOTP):
		return store.Value{}, fmt.Errorf("%w; put the seed into the item in Bitwarden, or remove "+
			"totp = true from [secret.%s]", err, name)
	case err != nil:
		return store.Value{}, err
	}
	key, err := totp.Parse(seed.Bytes())
	if err != nil {
		// The errors of totp.Parse are fixed texts that say what to fix;
		// they never hold the field. Any other error gets errBadTOTPSeed.
		known := errBadTOTPSeed
		for _, e := range []error{totp.ErrEmpty, totp.ErrForm, totp.ErrBase32, totp.ErrAlgorithm, totp.ErrDigits,
			totp.ErrPeriod} {
			if errors.Is(err, e) {
				known = e
			}
		}
		return store.Value{}, fmt.Errorf("store %q: secret %q: %w", sec.Store, name, known)
	}
	defer key.Clear()
	code, err := key.Code(rq.s.nowTime())
	if err != nil {
		return store.Value{}, fmt.Errorf("store %q: secret %q: %w", sec.Store, name, err)
	}
	return store.NewValue([]byte(code)), nil
}
