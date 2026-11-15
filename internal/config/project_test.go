package config

import (
	"slices"
	"strings"
	"testing"
)

const (
	testProject  = "0A1B2C3D-0000-4000-8000-000000000002"
	testProject2 = "1b2c3d4e-0000-4000-8000-000000000003"
	// testGitHubID is the id of [secret.github-token] in the test config,
	// in a bws store.
	testGitHubID = "00000000-0000-0000-0000-000000000001"
)

// projectTOML is a [project.ci] section of the bws store main.
const projectTOML = `[project.ci]
store = "main"
project = "` + testProject + `"
clients = ["laptop", "backup-box"]
ask = "window"
window = "15m"
preapprove = true

`

func addProject(section string) edit { return edit{"[key.deploy]", section + "[key.deploy]"} }

func TestProjectConfig(t *testing.T) {
	e := newBrokerEnv(t)
	b, err := loadBroker(e.write(t, addProject(projectTOML)), "")
	if err != nil {
		t.Fatalf("loadBroker: %v", err)
	}
	p, ok := b.Projects["ci"]
	if !ok || p.Store != "main" || p.Project != strings.ToLower(testProject) ||
		!slices.Equal(p.Clients, []string{"laptop", "backup-box"}) || p.Rule.Ask != AskWindow || !p.Rule.Preapprove {
		t.Fatalf("the project is %+v", p)
	}
}

// TestProjectConfigRefused: each error stops the broker at the start, and
// a reload, which loads the config the same way.
func TestProjectConfigRefused(t *testing.T) {
	other := "[project.other]\nstore = \"main\"\nproject = \"" + testProject2 + "\"\nclients = [\"laptop\"]\nask = \"always\"\n\n"
	for _, c := range []struct {
		name string
		cfg  string
		want string
	}{
		{"never", strings.Replace(projectTOML, "ask = \"window\"\nwindow = \"15m\"\npreapprove = true", "ask = \"never\"", 1),
			`[project.ci] ask: "never" is not allowed for a project`},
		{"the same project twice", projectTOML + strings.Replace(other, testProject2, strings.ToLower(testProject), 1),
			"[project.other] project: [project.ci] has the same project"},
		{"the same project in another store", projectTOML + strings.Replace(
			strings.Replace(other, testProject2, strings.ToLower(testProject), 1), `store = "main"`, `store = "main2"`, 1) +
			"[store.main2]\ntype = \"bws\"\nprogram = \"{{dir}}/bin/bws\"\ntoken_file = \"${CREDENTIALS_DIRECTORY}/bws-token\"\n\n",
			"has the same project"},
		{"no store", strings.Replace(projectTOML, "store = \"main\"\n", "", 1), "store: is missing"},
		{"unknown store", strings.Replace(projectTOML, `store = "main"`, `store = "nope"`, 1), "no [store.*] section"},
		{"not a bws store", strings.Replace(projectTOML, `store = "main"`, `store = "vault"`, 1), `type = "bws"`},
		{"bad project", strings.Replace(projectTOML, testProject, "ci", 1), "project: must be the ID"},
		{"no clients", strings.Replace(projectTOML, "clients = [\"laptop\", \"backup-box\"]\n", "", 1), "clients: is missing"},
		{"unknown client", strings.Replace(projectTOML, `"backup-box"`, `"phone"`, 1), "clients"},
		{"no ask", strings.Replace(projectTOML, "ask = \"window\"\n", "", 1), "ask"},
		{"unknown key", strings.Replace(projectTOML, "preapprove = true", "preapprove = true\nkey = \"X\"", 1), "key"},
		{"a bad name", strings.Replace(projectTOML, "[project.ci]", "[project.\"c/i\"]", 1), "[project.*]: the name of a section"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			_, err := loadBroker(e.write(t, addProject(c.cfg)), "")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one with %q", err, c.want)
			}
		})
	}
}

// TestParseSecretName: a plain name, SECTION/KEY with each part by the
// name rule (so the whole is at most 129 bytes), and nothing else.
func TestParseSecretName(t *testing.T) {
	n64 := strings.Repeat("n", 64)
	for _, c := range []struct {
		name             string
		project, ok      bool
		section, keyPart string
	}{
		{"github-token", false, true, "", ""},
		{"ci/GITHUB_TOKEN", true, true, "ci", "GITHUB_TOKEN"},
		{n64 + "/" + n64, true, true, n64, n64}, // 129 bytes
		{n64 + "n/k", true, false, "", ""},
		{"c/" + n64 + "n", true, false, "", ""},
		{n64 + "n", false, false, "", ""},
		{"a/b/c", true, false, "", ""},
		{"/k", true, false, "", ""},
		{"c/", true, false, "", ""},
		{"c/.k", true, false, "", ""},
		{"c/k k", true, false, "", ""},
		{"", false, false, "", ""},
	} {
		pn, project, ok := ParseSecretName(c.name)
		if project != c.project || ok != c.ok || pn.Section != c.section || pn.Key != c.keyPart {
			t.Errorf("ParseSecretName(%q) = %+v, %v, %v", c.name, pn, project, ok)
		}
		if ok && project && pn.String() != c.name {
			t.Errorf("String() = %q", pn.String())
		}
	}
}

// TestProjectRuleFor: a [secret.*] entry with the secret's ID in a bws
// store wins completely, also from another bws store; two entries give
// no rule; an entry in a store of another type does not count.
func TestProjectRuleFor(t *testing.T) {
	e := newBrokerEnv(t)
	b, err := loadBroker(e.write(t, addProject(projectTOML)), "")
	if err != nil {
		t.Fatal(err)
	}
	const free = "00000000-0000-0000-0000-0000000000ff"
	if r, ok := b.RuleFor("ci", free); !ok || r.Entry != "" || r.Rule != b.Projects["ci"].Rule {
		t.Errorf("a secret with no entry: %+v, %v", r, ok)
	}
	r, ok := b.RuleFor("ci", strings.ToUpper(testGitHubID))
	if !ok || r.Entry != "github-token" || !slices.Equal(r.Clients, b.Secrets["github-token"].Clients) {
		t.Errorf("a secret with an entry: %+v, %v", r, ok)
	}
	for _, bad := range []struct{ section, id string }{{"nope", free}, {"ci", "x"}, {"ci", ""}} {
		if _, ok := b.RuleFor(bad.section, bad.id); ok {
			t.Errorf("RuleFor(%q, %q) is ok", bad.section, bad.id)
		}
	}
	// An entry in another bws store wins too.
	two := *b
	two.Stores = map[string]Store{"main": b.Stores["main"], "vault": b.Stores["vault"], "main2": {Name: "main2", Type: StoreBWS}}
	two.Secrets = map[string]Secret{"other": {Name: "other", Store: "main2", ID: free, Clients: []string{"backup-box"}}}
	if r, ok := two.RuleFor("ci", free); !ok || r.Entry != "other" {
		t.Errorf("an entry in another bws store: %+v, %v", r, ok)
	}
	// Two entries: no clear winner.
	two.Secrets["again"] = Secret{Name: "again", Store: "main", ID: strings.ToUpper(free), Clients: []string{"laptop"}}
	if r, ok := two.RuleFor("ci", free); ok {
		t.Errorf("two entries: %+v, ok", r)
	}
	// An entry of a bw store has another kind of ID.
	two.Secrets = map[string]Secret{"pw": {Name: "pw", Store: "vault", ID: free, Clients: []string{"backup-box"}}}
	if r, ok := two.RuleFor("ci", free); !ok || r.Entry != "" {
		t.Errorf("an entry in a bw store: %+v, %v", r, ok)
	}
}

// TestSameProjectSecret: a grant of a project secret stays only while the
// same rule of the project gives it to the client. An entry for the
// secret that a reload adds ends it.
func TestSameProjectSecret(t *testing.T) {
	e := newBrokerEnv(t)
	old, err := loadBroker(e.write(t, addProject(projectTOML)), "")
	if err != nil {
		t.Fatal(err)
	}
	const id = "00000000-0000-0000-0000-0000000000ff"
	if !old.SameProjectSecret(old, "ci", id, "laptop") {
		t.Error("the same config does not keep the grant")
	}
	for _, c := range []struct {
		name string
		cfg  string
	}{
		{"another window", strings.Replace(projectTOML, `window = "15m"`, `window = "10m"`, 1)},
		{"no client", strings.Replace(projectTOML, `"laptop", `, "", 1)},
		{"another project", strings.Replace(projectTOML, testProject, testProject2, 1)},
		{"no section", ""},
		{"an entry for the secret", projectTOML + "[secret.ci-one]\nstore = \"main\"\nid = \"" + id +
			"\"\nclients = [\"laptop\"]\nask = \"window\"\nwindow = \"15m\"\n\n"},
	} {
		next, err := loadBroker(e.write(t, addProject(c.cfg)), "")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if old.SameProjectSecret(next, "ci", id, "laptop") {
			t.Errorf("%s: the grant stays", c.name)
		}
		if err := old.ReloadFixed(next); err != nil {
			t.Errorf("%s: a reload is refused: %v", c.name, err)
		}
	}
}

func TestDiffProjects(t *testing.T) {
	added := addProject(projectTOML)
	for _, c := range []struct {
		diffCase
		widens bool
	}{
		{diffCase{name: "new project", new: []edit{added}, want: `project "ci": client "laptop" may now ask for its secrets`}, true},
		{diffCase{name: "another project", old: []edit{added}, new: []edit{{testProject, testProject2}},
			want: `project "ci": now other secrets: project changed`}, true},
		{diffCase{name: "removed", old: []edit{added}, new: []edit{{projectTOML, ""}}, want: `project "ci": removed`}, false},
		{diffCase{name: "a window", old: []edit{added}, new: []edit{{"\"backup-box\"]\nask = \"window\"\nwindow = \"15m\"", "\"backup-box\"]\nask = \"window\"\nwindow = \"1h\""}},
			want: `project "ci": window changed from 15m to 1h`}, true},
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
				t.Errorf("a project change is not known to config-diff: %v", changes)
			}
		})
	}
}
