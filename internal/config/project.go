package config

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// Project is a [project.NAME] section: every secret of one Bitwarden
// Secrets Manager project, with one rule (DESIGN.md section 14,
// "Projects"). A client asks for a secret of it as NAME/KEY.
type Project struct {
	Name    string
	Store   string   // a name in Broker.Stores, of type bws
	Project string   // the project's ID, a UUID in lower case
	Clients []string // the names in Broker.Clients that may ask for its secrets
	Rule    Rule     // never "never"
}

type projectSection struct {
	Store   string   `toml:"store"`
	Project string   `toml:"project"`
	Clients []string `toml:"clients"`
	ruleKeys
}

// ProjectName is a secret name of the form SECTION/KEY, split.
type ProjectName struct {
	Section string // the name of the [project.*] section
	Key     string // the secret's key in Bitwarden
}

// String returns SECTION/KEY.
func (n ProjectName) String() string { return n.Section + "/" + n.Key }

// ParseSecretName reads a secret name that a client asks for. A name
// with no "/" is the name of a [secret.*] section: project is false. A
// name with one "/" is SECTION/KEY of a [project.*] section: each part
// must follow the name rule (namePattern), so each is at most 64 bytes.
// A name with two or more "/" is not valid (ok is false), and so is a
// name that breaks the name rule.
func ParseSecretName(name string) (n ProjectName, project, ok bool) {
	section, key, found := strings.Cut(name, "/")
	if !found {
		return ProjectName{}, false, namePattern.MatchString(name)
	}
	if !namePattern.MatchString(section) || !namePattern.MatchString(key) {
		return ProjectName{}, true, false
	}
	return ProjectName{Section: section, Key: key}, true, true
}

// MaxNameLen is the most bytes of a name that follows the name rule.
const MaxNameLen = 64

// ValidKey reports whether key, the key of a secret in Bitwarden, follows
// the name rule. Only such a key can be asked for, and only such a key is
// shown (DESIGN.md section 14, "Projects").
func ValidKey(key string) bool { return namePattern.MatchString(key) }

// addProjects checks the [project.*] sections and adds them to b.Projects.
func (b *Broker) addProjects(m map[string]projectSection) error {
	projects := make(map[string]string) // project ID -> section name
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if err := checkName("project", name); err != nil {
			return err
		}
		sec := sectionName("project", name)
		s := m[name]
		if s.Store == "" {
			return fmt.Errorf(`%s: is missing; name a [store.*] section of type = "bws"`, place(sec, "store"))
		}
		st, ok := b.Stores[s.Store]
		if !ok {
			return fmt.Errorf("%s: no [store.*] section has this name", place(sec, "store"))
		}
		if st.Type != StoreBWS {
			return fmt.Errorf(`%s: must name a store of type = "bws"; a project is a Bitwarden Secrets Manager `+
				`project (DESIGN.md section 14, "Projects")`, place(sec, "store"))
		}
		if !uuidPattern.MatchString(s.Project) {
			return fmt.Errorf(`%s: must be the ID of the project, a UUID such as "00000000-0000-0000-0000-000000000000"; `+
				`"bws project list" shows it`, place(sec, "project"))
		}
		id := strings.ToLower(s.Project)
		if other, ok := projects[id]; ok {
			return fmt.Errorf("%s: %s has the same project; one project may be in one [project.*] section only, "+
				"else its secrets would have two rules", place(sec, "project"), sectionName("project", other))
		}
		projects[id] = name
		clients, err := b.clientList(sec, s.Clients)
		if err != nil {
			return err
		}
		if s.Ask == string(AskNever) {
			return fmt.Errorf(`%s: "never" is not allowed for a project: it would give every secret of the project `+
				`without a tap, also secrets added later; use "always" or "window", or a [secret.*] section for one secret`,
				place(sec, "ask"))
		}
		rule, err := parseRule(sec, s.ruleKeys)
		if err != nil {
			return err
		}
		b.Projects[name] = Project{Name: name, Store: s.Store, Project: id, Clients: clients, Rule: rule}
	}
	return nil
}

// ProjectRule is the rule that applies to one secret of a project.
type ProjectRule struct {
	// Entry is the name of the [secret.*] section with the same secret ID,
	// in a store of type bws; "" when the project's rule applies. The
	// entry's rule wins completely (DESIGN.md section 14, "Projects").
	Entry   string
	Clients []string
	Rule    Rule
}

// RuleFor returns the rule for the secret id of the project section:
// the rule of the one [secret.*] entry with that ID in any store of type
// bws, or else the project's rule. Nothing is merged. ok is false, and the
// request must be denied, when the section is not in the config, when id
// is not a UUID, or when two or more entries have that ID: there is no
// clear winner.
func (b *Broker) RuleFor(section, id string) (r ProjectRule, ok bool) {
	p, found := b.Projects[section]
	if !found || !uuidPattern.MatchString(id) {
		return ProjectRule{}, false
	}
	var entries []string
	for _, name := range slices.Sorted(maps.Keys(b.Secrets)) {
		s := b.Secrets[name]
		if b.Stores[s.Store].Type == StoreBWS && strings.EqualFold(s.ID, id) {
			entries = append(entries, name)
		}
	}
	switch len(entries) {
	case 0:
		return ProjectRule{Clients: p.Clients, Rule: p.Rule}, true
	case 1:
		s := b.Secrets[entries[0]]
		return ProjectRule{Entry: s.Name, Clients: s.Clients, Rule: s.Rule}, true
	}
	return ProjectRule{}, false
}

// SameProjectSecret reports whether client may still get the secret id
// through the project section in next as it could in b: the client is
// the same, the section has the same store and project, and the same
// rule applies to the secret, with client in its clients. A rule that
// moves from the project to a [secret.*] entry, or back, is not the same.
func (b *Broker) SameProjectSecret(next *Broker, section, id, client string) bool {
	op, ok1 := b.Projects[section]
	np, ok2 := next.Projects[section]
	if !ok1 || !ok2 || !b.SameClient(next, client) || op.Store != np.Store || op.Project != np.Project {
		return false
	}
	or, ok1 := b.RuleFor(section, id)
	nr, ok2 := next.RuleFor(section, id)
	if !ok1 || !ok2 || or.Entry != nr.Entry || !slices.Contains(or.Clients, client) ||
		!slices.Contains(nr.Clients, client) {
		return false
	}
	if or.Entry != "" {
		return b.SameSecret(next, or.Entry, client)
	}
	return reflect.DeepEqual(or.Rule, nr.Rule)
}
