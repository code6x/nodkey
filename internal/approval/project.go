package approval

import (
	"slices"
	"strings"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// ProjectSecret is a secret of a [project.*] section that the broker has
// found for a name SECTION/KEY (DESIGN.md section 14, "Projects"): the
// broker read the key and the ID from "bws secret list". The core keeps
// grants per ID, not per name.
type ProjectSecret struct {
	Section string
	Key     string
	ID      string // a UUID in lower case
}

// Name returns SECTION/KEY.
func (s ProjectSecret) Name() string { return s.Section + "/" + s.Key }

// projectRef returns the ref of the secret id of the project section.
func projectRef(section, id string) ref {
	return ref{project: true, name: section + "/" + strings.ToLower(id)}
}

// splitProjectRef returns the section and the ID of a project ref.
func splitProjectRef(r ref) (section, id string) {
	section, id, _ = strings.Cut(r.name, "/")
	return section, id
}

// idEnd returns the last 8 characters of a secret ID, which the message
// shows.
func idEnd(id string) string { return id[len(id)-8:] }

// text returns how a message shows r in a list of grants: the name of a
// [secret.*] section, or for a project secret the section and the end of
// the ID, such as "ci (project rule, ID …1a2b3c4d)".
func (r ref) text() string {
	if !r.project {
		return r.name
	}
	section, id := splitProjectRef(r)
	return section + " (project rule, ID …" + idEnd(id) + ")"
}

// secretItem returns the item, the clients and the text of the message
// for the secret name of a request of p. A name SECTION/KEY must be in
// projects, with the ID that the broker found. Its rule is the one of
// config.Broker.RuleFor: a [secret.*] entry with the same ID wins
// completely, and its grants are the entry's. ok is false when the name
// is not in the config, or not in projects, or has no clear rule.
func secretItem(p *pending, name string, projects map[string]ProjectSecret) (it item, clients []string, label string, ok bool) {
	pn, isProject, valid := config.ParseSecretName(name)
	if !valid {
		return item{}, nil, "", false
	}
	if !isProject {
		s, known := p.cfg.Secrets[name]
		if !known {
			return item{}, nil, "", false
		}
		return item{ref: ref{name: name}, rule: s.Rule}, s.Clients, name, true
	}
	ps, found := projects[name]
	if !found || ps.Section != pn.Section || ps.Key != pn.Key || !loginItemPattern.MatchString(ps.ID) {
		return item{}, nil, "", false
	}
	pr, ok := p.cfg.RuleFor(ps.Section, ps.ID)
	if !ok {
		return item{}, nil, "", false
	}
	if pr.Entry != "" {
		return item{ref: ref{name: pr.Entry}, rule: pr.Rule}, pr.Clients, name + " (rule of secret " + pr.Entry +
			", ID …" + idEnd(ps.ID) + ")", true
	}
	if pr.Rule.Ask == config.AskNever {
		return item{}, nil, "", false // the config never allows it; check again
	}
	return item{ref: projectRef(ps.Section, ps.ID), rule: pr.Rule}, pr.Clients,
		name + " (project rule, ID …" + idEnd(ps.ID) + ")", true
}

// addSecret adds the secret of name, with its label, to p, and to the
// subject. A project secret adds its ID to the subject too. It reports
// false, and adds nothing, when another name of the request is the same
// secret already, such as an entry and SECTION/KEY with its ID: the
// request is denied.
func (p *pending) addSecret(name, label string, it item, projects map[string]ProjectSecret) bool {
	if slices.ContainsFunc(p.items, func(o item) bool { return o.ref == it.ref }) {
		return false
	}
	p.items = append(p.items, it)
	p.subject.Secrets = append(p.subject.Secrets, name)
	p.labels = append(p.labels, label)
	if ps, ok := projects[name]; ok && strings.Contains(name, "/") {
		p.subject.ProjectSecrets = append(p.subject.ProjectSecrets, audit.ProjectSecret{Name: name, ID: ps.ID})
	}
	return true
}

// keepsProject reports whether the config next still gives the project
// secret of r to client with the same rule as old.
func keepsProject(old, next *config.Broker, r ref, client string) bool {
	section, id := splitProjectRef(r)
	pr, ok := next.RuleFor(section, id)
	return ok && pr.Entry == "" && old.SameProjectSecret(next, section, id, client) &&
		slices.Contains(pr.Clients, client)
}
