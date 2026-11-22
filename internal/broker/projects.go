package broker

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
)

// secretAllowed is the broker's first check of a secret name that client
// asks for. A name of a [secret.*] section must list client. A name
// SECTION/KEY needs a [project.*] section SECTION, and client in its
// clients or in the clients of a [secret.*] entry of a bws store, which
// may win over the project's rule. The broker checks the rule of the
// secret itself only after it has found the secret (resolveProjects), and
// the core checks it again.
func secretAllowed(cfg *config.Broker, client, name string) bool {
	pn, isProject, valid := config.ParseSecretName(name)
	switch {
	case !valid:
		return false
	case !isProject:
		sec, known := cfg.Secrets[name]
		return known && slices.Contains(sec.Clients, client)
	}
	p, known := cfg.Projects[pn.Section]
	if !known {
		return false
	}
	if slices.Contains(p.Clients, client) {
		return true
	}
	for _, s := range cfg.Secrets {
		if cfg.Stores[s.Store].Type == config.StoreBWS && slices.Contains(s.Clients, client) {
			return true
		}
	}
	return false
}

// resolveProjects finds the secret of each name SECTION/KEY of names in
// its project (DESIGN.md section 14, "Projects"): it runs "bws secret
// list" once for each project, and looks for the key exactly. A KEY that
// is a UUID is matched only with the secret IDs, in lower case, never with
// the keys: so a key that is another secret's ID cannot take its place.
// The result goes to rq.projects and rq.listed. A key that is not in the project is
// refused; so is a key that two secrets of the project have, with a line
// in the journal that names the section and the key. Each name that it
// finds goes to rq.pre.Secrets; a name that the client made up never
// does. A secret whose rule
// does not list the client is refused. On a refusal or an error it has
// answered the request, and ok is false.
func (rq *request) resolveProjects(ctx context.Context, names []string) bool {
	cfg := rq.v.cfg
	lists := make(map[string][]store.ProjectSecret) // by section
	for _, name := range names {
		pn, isProject, _ := config.ParseSecretName(name)
		if !isProject {
			continue
		}
		if _, done := rq.listed[name]; done {
			continue
		}
		p := cfg.Projects[pn.Section]
		list, done := lists[pn.Section]
		if !done {
			var ok bool
			if list, ok = rq.listProject(ctx, p); !ok {
				return false
			}
			lists[pn.Section] = list
		}
		found := findProjectSecret(list, pn.Key)
		switch len(found) {
		case 0:
			// The key was chosen by the client, and is not in Bitwarden:
			// the audit log does not get it.
			rq.refuseProject("the key is not in the project, or the machine account cannot read it", "")
			return false
		case 1:
		default:
			rq.pre.Secrets = append(rq.pre.Secrets, name)
			if config.IsUUID(pn.Key) {
				// IDs are unique in Bitwarden: the list of the store is wrong.
				rq.refuseProject("the store listed two or more secrets with this ID; check the store with \"nodkey doctor broker\"", name)
				return false
			}
			// Bitwarden does not keep keys unique in a project. The broker
			// cannot tell which secret is meant (DESIGN.md section 14).
			rq.refuseProject("two or more secrets of the project have this key; give each a key of its own in Bitwarden", name)
			return false
		}
		rq.pre.Secrets = append(rq.pre.Secrets, name) // it is in the project
		ps := approval.ProjectSecret{Section: pn.Section, Key: pn.Key, ID: found[0].ID}
		if found[0].Key != pn.Key && config.ValidKey(found[0].Key) {
			ps.Shown = found[0].Key // asked by its ID; the message shows the key
		}
		rule, ok := cfg.RuleFor(pn.Section, ps.ID)
		if !ok || !slices.Contains(rule.Clients, rq.client) {
			rq.refuseProject("the secret has no clear rule, or its rule does not list this client", "")
			return false
		}
		if rq.projects == nil {
			rq.projects = make(map[string]approval.ProjectSecret)
			rq.listed = make(map[string]store.ProjectSecret)
		}
		rq.projects[name], rq.listed[name] = ps, found[0]
	}
	return true
}

// findProjectSecret returns the secrets of list that the part KEY of a
// name SECTION/KEY asks for: by the ID when key is a UUID, else by the key,
// exactly. A secret with a key that breaks the name rule has Key "", and
// key is never "", so it is found only by its ID.
func findProjectSecret(list []store.ProjectSecret, key string) []store.ProjectSecret {
	var found []store.ProjectSecret
	byID := config.IsUUID(key)
	id := strings.ToLower(key)
	for _, s := range list {
		if (byID && s.ID == id) || (!byID && key != "" && s.Key == key) {
			found = append(found, s)
		}
	}
	return found
}

// listProject runs "bws secret list" for the project p. On an error it
// has answered the request, and ok is false.
func (rq *request) listProject(ctx context.Context, p config.Project) ([]store.ProjectSecret, bool) {
	ps, isPS := rq.s.stores[p.Store].(store.ProjectStore)
	if !isPS {
		rq.recordDenied(rq.pre, audit.CauseError, audit.CodeStoreFailed, false)
		rq.answer(http.StatusServiceUnavailable)
		return nil, false
	}
	if ctx.Err() != nil {
		rq.recordDenied(rq.pre, audit.CauseCancelled, "", false)
		rq.answer(http.StatusForbidden)
		return nil, false
	}
	lctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	list, err := ps.ListSecrets(lctx, p.Project)
	cancel()
	if err == nil {
		return list, true
	}
	if ctx.Err() != nil {
		rq.recordDenied(rq.pre, audit.CauseCancelled, "", false)
		rq.answer(http.StatusForbidden)
		return nil, false
	}
	rq.s.log.Warn("broker: a store failed to list the secrets of a project; the request is denied",
		slog.String("client", rq.client), slog.String("store", p.Store), slog.String("project", p.Name),
		slog.String("error", errorText(err)))
	if errors.Is(err, store.ErrRateLimited) {
		rq.s.rateLimited(p.Store)
	}
	rq.recordDenied(rq.pre, audit.CauseError, audit.CodeStoreFailed, false)
	rq.answer(http.StatusServiceUnavailable)
	return nil, false
}

// refuseProject denies a request for a project secret that a check
// refused, with a fixed reason in the journal. name is the secret
// SECTION/KEY when the journal may show it: only for a key or an ID that
// two secrets have. The key follows the name rule; a value is never shown.
func (rq *request) refuseProject(reason, name string) {
	attrs := []any{slog.String("client", rq.client), slog.String("reason", reason)}
	if name != "" {
		attrs = append(attrs, slog.String("secret", name))
	}
	if rq.s.refusedLines.allow() {
		rq.s.log.Info("broker: refused a request for a project secret (DESIGN.md section 14, \"Projects\")", attrs...)
	}
	rq.deny(rq.pre, audit.CauseNotAllowed, "", http.StatusForbidden)
}
