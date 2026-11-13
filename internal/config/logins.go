package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Logins is a [logins.NAME] section: the website logins of one Bitwarden
// collection (DESIGN.md section 21).
type Logins struct {
	Name       string
	Store      string   // a name in Broker.Stores, of type bw
	Collection string   // the collection's ID, a UUID in lower case
	Clients    []string // the names in Broker.Clients that may ask for a login
	Rule       Rule
	// Items are the rules of single items, by item ID in lower case. The
	// rule of an item replaces the collection's rule completely.
	Items map[string]LoginItemRule
}

// LoginItemRule is a [[logins.NAME.items]] table: the rule of one item.
type LoginItemRule struct {
	ID      string // the item's ID, a UUID in lower case
	Clients []string
	Rule    Rule
}

// RuleFor returns the clients and the rule for the item id: the item's
// own rule when it has one, and else the collection's. Nothing is merged
// (owner, 2026-11-11). The broker calls it on each request, after it has
// found the item. An id that is not a UUID gets ok = false: the request
// must be denied, so that an ID in another form never falls back to the
// collection's rule.
func (l Logins) RuleFor(id string) (clients []string, rule Rule, ok bool) {
	if !uuidPattern.MatchString(id) {
		return nil, Rule{}, false
	}
	if r, found := l.Items[strings.ToLower(id)]; found {
		return r.Clients, r.Rule, true
	}
	return l.Clients, l.Rule, true
}

type (
	loginsSection struct {
		Store      string             `toml:"store"`
		Collection string             `toml:"collection"`
		Clients    []string           `toml:"clients"`
		Items      []loginItemSection `toml:"items"`
		ruleKeys
	}
	loginItemSection struct {
		ID      string   `toml:"id"`
		Clients []string `toml:"clients"`
		ruleKeys
	}
)

// addLogins checks the [logins.*] sections and adds them to b.Logins.
func (b *Broker) addLogins(m map[string]loginsSection) error {
	collections := make(map[string]string) // collection ID -> section name
	items := make(map[string]string)       // item ID -> section name
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if err := checkName("logins", name); err != nil {
			return err
		}
		sec := sectionName("logins", name)
		s := m[name]
		if s.Store == "" {
			return fmt.Errorf("%s: is missing; name a [store.*] section of type = \"bw\"", place(sec, "store"))
		}
		st, ok := b.Stores[s.Store]
		if !ok {
			return fmt.Errorf("%s: no [store.*] section has this name", place(sec, "store"))
		}
		if st.Type != StoreBW {
			return fmt.Errorf(`%s: must name a store of type = "bw"; website logins come only from the Bitwarden `+
				`Password Manager (DESIGN.md section 21)`, place(sec, "store"))
		}
		if !uuidPattern.MatchString(s.Collection) {
			return fmt.Errorf(`%s: must be the ID of the collection, a UUID such as "00000000-0000-0000-0000-000000000000"; `+
				`"bw list collections" shows it`, place(sec, "collection"))
		}
		col := strings.ToLower(s.Collection)
		if other, ok := collections[col]; ok {
			return fmt.Errorf("%s: %s has the same collection; one collection may be in one [logins.*] section only",
				place(sec, "collection"), sectionName("logins", other))
		}
		collections[col] = name
		clients, rule, err := b.loginRule(sec, s.Clients, s.ruleKeys)
		if err != nil {
			return err
		}
		l := Logins{Name: name, Store: s.Store, Collection: col, Clients: clients, Rule: rule,
			Items: make(map[string]LoginItemRule)}
		for i, it := range s.Items {
			isec := fmt.Sprintf("[[%s.items]] number %d", strings.Trim(sec, "[]"), i+1)
			if !uuidPattern.MatchString(it.ID) {
				return fmt.Errorf(`%s: must be the item's ID, a UUID such as "00000000-0000-0000-0000-000000000000"`,
					place(isec, "id"))
			}
			id := strings.ToLower(it.ID)
			if other, ok := items[id]; ok {
				return fmt.Errorf("%s: %s has a rule for the same item; one item may have one rule",
					place(isec, "id"), sectionName("logins", other))
			}
			items[id] = name
			c, r, err := b.loginRule(isec, it.Clients, it.ruleKeys)
			if err != nil {
				return err
			}
			l.Items[id] = LoginItemRule{ID: id, Clients: c, Rule: r}
		}
		b.Logins[name] = l
	}
	return nil
}

// loginRule checks the clients and the rule of a [logins.*] section or of
// one of its items. ask = "never" is refused: a website login always
// needs a tap or a grant that came from one.
func (b *Broker) loginRule(sec string, names []string, k ruleKeys) ([]string, Rule, error) {
	clients, err := b.clientList(sec, names)
	if err != nil {
		return nil, Rule{}, err
	}
	if k.Ask == string(AskNever) {
		return nil, Rule{}, fmt.Errorf(`%s: "never" is not allowed for website logins; use "always" or "window"`,
			place(sec, "ask"))
	}
	rule, err := parseRule(sec, k)
	if err != nil {
		return nil, Rule{}, err
	}
	return clients, rule, nil
}
