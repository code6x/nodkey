package config

import (
	"slices"
	"strings"
	"testing"
)

const (
	testCol   = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	testCol2  = "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
	testItem  = "6F1E2D3C-4B5A-4987-8A6B-5C4D3E2F1A0B"
	testItem2 = "7a2e3d4c-5b6a-4f98-9b7c-6d5e4f3a2b1c"
)

// loginsTOML is a [logins.web] section with a looser rule for testItem
// (another client, a window) and a stricter one for testItem2.
const loginsTOML = `[logins.web]
store = "vault"
collection = "` + testCol + `"
clients = ["laptop"]
ask = "window"
window = "15m"
preapprove = true

[[logins.web.items]]
id = "` + testItem + `"
clients = ["laptop", "backup-box"]
ask = "window"
window = "30m"

[[logins.web.items]]
id = "` + testItem2 + `"
clients = ["backup-box"]
ask = "always"

[key.deploy]`

// loginsNoItems is loginsTOML with no item rules.
const loginsNoItems = `[logins.web]
store = "vault"
collection = "` + testCol + `"
clients = ["laptop"]
ask = "window"
window = "15m"
preapprove = true

[key.deploy]`

func addLoginsEdit(section string) edit { return edit{"[key.deploy]", section} }

func TestLoginsConfig(t *testing.T) {
	e := newBrokerEnv(t)
	b, err := loadBroker(e.write(t, addLoginsEdit(loginsTOML)), "")
	if err != nil {
		t.Fatalf("loadBroker: %v", err)
	}
	l, ok := b.Logins["web"]
	if !ok || l.Store != "vault" || l.Collection != testCol || !slices.Equal(l.Clients, []string{"laptop"}) ||
		l.Rule.Ask != AskWindow || !l.Rule.Preapprove || len(l.Items) != 2 {
		t.Fatalf("logins = %+v", l)
	}
	// The collection's rule.
	clients, rule, ok := l.RuleFor("8b3f4e5d-6c7b-4a09-8c8d-7e6f5a4b3c2d")
	if !ok || !slices.Equal(clients, []string{"laptop"}) || rule.Ask != AskWindow || !rule.Preapprove {
		t.Errorf("collection rule = %v %+v", clients, rule)
	}
	// A looser item rule wins completely: another client, a longer window,
	// and no preapprove, because nothing is merged.
	clients, rule, _ = l.RuleFor(strings.ToLower(testItem))
	if !slices.Equal(clients, []string{"laptop", "backup-box"}) || rule.Ask != AskWindow || rule.Preapprove ||
		rule.Window.Minutes() != 30 {
		t.Errorf("looser item rule = %v %+v", clients, rule)
	}
	// A stricter item rule wins completely: laptop, in the collection's
	// clients, is refused for it.
	clients, rule, _ = l.RuleFor(strings.ToUpper(testItem2))
	if slices.Contains(clients, "laptop") || rule.Ask != AskAlways {
		t.Errorf("stricter item rule = %v %+v", clients, rule)
	}
	// An ID in another form never falls back to the collection's rule.
	for _, id := range []string{" " + testItem2, "{" + testItem2 + "}", "Example shop", ""} {
		if c, _, ok := l.RuleFor(id); ok || c != nil {
			t.Errorf("RuleFor(%q) = %v, %v", id, c, ok)
		}
	}
}

func TestLoginsConfigRefused(t *testing.T) {
	base := strings.TrimSuffix(loginsTOML, "[key.deploy]")
	other := "\n[logins.other]\nstore = \"vault\"\ncollection = \"" + testCol2 + "\"\nclients = [\"laptop\"]\nask = \"always\"\n\n"
	for _, c := range []struct {
		name string
		cfg  string
		want string
	}{
		{"no store", strings.Replace(base, "store = \"vault\"\n", "", 1), "store: is missing"},
		{"unknown store", strings.Replace(base, "store = \"vault\"", "store = \"nope\"", 1), "no [store.*] section"},
		{"not a bw store", strings.Replace(base, "store = \"vault\"", "store = \"main\"", 1), `type = "bw"`},
		{"bad collection", strings.Replace(base, testCol, "agents", 1), "collection: must be the ID"},
		{"same collection twice", base + strings.Replace(other, testCol2, strings.ToUpper(testCol), 1), "same collection"},
		{"no clients", strings.Replace(base, "clients = [\"laptop\"]\nask = \"window\"\nwindow = \"15m\"", "ask = \"window\"\nwindow = \"15m\"", 1), "clients: is missing"},
		{"unknown client", strings.Replace(base, "clients = [\"laptop\"]", "clients = [\"phone\"]", 1), "clients"},
		{"never", strings.Replace(base, "ask = \"window\"\nwindow = \"15m\"\npreapprove = true", "ask = \"never\"", 1), `"never" is not allowed`},
		{"never for an item", strings.Replace(base, "ask = \"always\"", "ask = \"never\"", 1), `"never" is not allowed`},
		{"no ask", strings.Replace(base, "ask = \"window\"\nwindow = \"15m\"\npreapprove = true\n", "", 1), "ask: is missing"},
		{"bad item id", strings.Replace(base, testItem, "Example shop", 1), "[[logins.web.items]] number 1 id: must be the item's ID"},
		{"item twice", base + "[[logins.web.items]]\nid = \"" + strings.ToLower(testItem) + "\"\nclients = [\"laptop\"]\nask = \"always\"\n\n", "one item may have one rule"},
		{"item in two sections", base + other + "[[logins.other.items]]\nid = \"" + testItem2 + "\"\nclients = [\"laptop\"]\nask = \"always\"\n\n", "one item may have one rule"},
		{"unknown key", strings.Replace(base, "preapprove = true", "preapprove = true\nmatch = \"host\"", 1), "match"},
		{"unknown item key", strings.Replace(base, "ask = \"always\"", "ask = \"always\"\nurl = \"https://example.com\"", 1), "url"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			_, err := loadBroker(e.write(t, addLoginsEdit(c.cfg+"[key.deploy]")), "")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one with %q", err, c.want)
			}
		})
	}
}

func TestDiffLogins(t *testing.T) {
	added := addLoginsEdit(loginsTOML)
	for _, c := range []struct {
		diffCase
		widens bool
	}{
		{diffCase{name: "new logins", new: []edit{added}, want: `logins "web": client "laptop" may now ask for a login`}, true},
		{diffCase{name: "another collection", old: []edit{added}, new: []edit{{testCol, testCol2}},
			want: `logins "web": now other logins: collection changed`}, true},
		{diffCase{name: "an item rule removed", old: []edit{added},
			new:  []edit{{"[[logins.web.items]]\nid = \"" + testItem2 + "\"\nclients = [\"backup-box\"]\nask = \"always\"\n", ""}},
			want: "its own rule is removed"}, true},
		{diffCase{name: "an item rule added", old: []edit{addLoginsEdit(loginsNoItems)},
			new:  []edit{{"preapprove = true\n", "preapprove = true\n\n[[logins.web.items]]\nid = \"" + testItem + "\"\nclients = [\"laptop\"]\nask = \"always\"\n"}},
			want: "has its own rule now"}, true},
		{diffCase{name: "an item gets another client", old: []edit{added}, new: []edit{{"clients = [\"backup-box\"]\nask = \"always\"", "clients = [\"backup-box\", \"laptop\"]\nask = \"always\""}},
			want: `item "` + testItem2 + `": client "laptop" may now ask for it`}, true},
		{diffCase{name: "logins removed", old: []edit{added}, new: []edit{{loginsTOML, "[key.deploy]"}},
			want: `logins "web": removed`}, false},
		{diffCase{name: "an item's window", old: []edit{added}, new: []edit{{"window = \"30m\"", "window = \"1h\""}},
			want: `item "` + strings.ToLower(testItem) + `": window changed from 30m to 1h`}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			changes := c.run(t)
			ch, ok := findChange(changes, c.want)
			if !ok {
				t.Fatalf("no change with %q in %v", c.want, changes)
			}
			if ch.Widens != c.widens {
				t.Errorf("%q: widens = %v, want %v", ch.Text, ch.Widens, c.widens)
			}
			if _, ok := findChange(changes, "does not know"); ok {
				t.Errorf("a logins change is not known to config-diff: %v", changes)
			}
		})
	}
}

// TestReloadRefusesLoginsChange: until the broker keeps login grants per
// item, a change of [logins.*] needs a restart.
func TestReloadRefusesLoginsChange(t *testing.T) {
	e := newBrokerEnv(t)
	old, err := loadBroker(e.write(t, addLoginsEdit(loginsTOML)), "")
	if err != nil {
		t.Fatal(err)
	}
	next, err := loadBroker(e.write(t, addLoginsEdit(strings.Replace(loginsTOML, `window = "30m"`, `window = "1h"`, 1))), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := old.ReloadFixed(next); err == nil || !strings.Contains(err.Error(), "[logins.*]") {
		t.Fatalf("ReloadFixed = %v", err)
	}
	same, err := loadBroker(e.write(t, addLoginsEdit(loginsTOML)), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := old.ReloadFixed(same); err != nil {
		t.Fatalf("ReloadFixed of the same logins = %v", err)
	}
}
