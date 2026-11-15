package broker

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
)

const (
	projectCI = "0a1b2c3d-0000-4000-8000-0000000000c1"
	idCI1     = "0a1b2c3d-0000-4000-8000-00000000a001"
	idCI2     = "0a1b2c3d-0000-4000-8000-00000000a002"
)

// projectEnv starts a broker with a [project.ci] section of the store
// main: laptop may ask, with a 15 minute window. The project has the
// secret GITHUB_TOKEN (idCI1); idCI2 has a value but no key yet. change,
// if set, changes the config.
func projectEnv(t *testing.T, change func(*config.Broker), opts envOptions) *env {
	t.Helper()
	opts.config = func(c *config.Broker) {
		c.Projects = map[string]config.Project{"ci": {Name: "ci", Store: "main", Project: projectCI,
			Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute}}}
		if change != nil {
			change(c)
		}
	}
	e := newEnv(t, opts)
	e.values["ci1"], e.values["ci2"] = madeUp("ci1"), madeUp("ci2")
	e.main.set(func(f *fakeStore) {
		f.items[idCI1], f.items[idCI2] = e.values["ci1"], e.values["ci2"]
		f.projects[projectCI] = []store.ProjectSecret{{ID: idCI1, Key: "GITHUB_TOKEN", Project: projectCI}}
	})
	return e
}

// approveProject asks for name as GH_TOKEN, checks the text of the
// message, taps answer and returns the value.
func approveProject(t *testing.T, e *env, n int, name, label string, answer audit.Answer) string {
	t.Helper()
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", name))
	asked := e.waitAsked(n)
	pr := asked[n-1].Prompt
	if !slices.Equal(pr.Secrets, []string{label}) {
		t.Fatalf("the message shows %q, want %q", pr.Secrets, label)
	}
	e.tap(pr.RequestID, answer)
	return secretsOf(t, p.wait(t))["GH_TOKEN"]
}

// TestProjectSecret: a client gets a secret of a project by SECTION/KEY.
// The message shows the name, the project rule and the end of the ID.
// The audit log has the ID.
func TestProjectSecret(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	if got := approveProject(t, e, 1, "ci/GITHUB_TOKEN", "ci/GITHUB_TOKEN (project rule, ID …0000a001)",
		audit.AnswerApproveOnce); got != e.values["ci1"] {
		t.Error("the answer does not hold the value of the project secret")
	}
	if !strings.Contains(e.approver.Asked()[0].Text, "ci/GITHUB_TOKEN (project rule, ID …0000a001)") {
		t.Errorf("the message text is %q", e.approver.Asked()[0].Text)
	}
	req, ok := e.audit.all()[0].(audit.Request)
	if !ok || !slices.Equal(req.Secrets, []string{"ci/GITHUB_TOKEN"}) ||
		!slices.Equal(req.ProjectSecrets, []audit.ProjectSecret{{Name: "ci/GITHUB_TOKEN", ID: idCI1}}) {
		t.Errorf("the request entry is %+v", e.audit.all()[0])
	}
	e.main.checkCleared(t)
}

// TestProjectSecretRefused: a key that is not in the project, a name with
// two "/", a section that is not in the config, and a client that the
// project does not list are refused with no message and no value.
func TestProjectSecretRefused(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	for _, c := range []struct{ client, name string }{
		{"laptop", "ci/NOPE"},
		{"laptop", "ci/github_token"}, // the key is matched exactly
		{"laptop", "ci/GITHUB_TOKEN/x"},
		{"laptop", "cd/GITHUB_TOKEN"},
		{"ci", "ci/GITHUB_TOKEN"},
		{"laptop", "ci/"},
	} {
		res := e.post(t.Context(), e.httpClient(c.client), api.PathSecrets, secretsRequest("GH_TOKEN", c.name))
		mustStatus(t, res, http.StatusForbidden)
	}
	if n := len(e.approver.Asked()); n != 0 {
		t.Errorf("%d messages, want none", n)
	}
	if e.main.fetched() != 0 {
		t.Error("a value was fetched")
	}
	for _, ev := range e.audit.all() {
		if s := subjectOf(ev); slices.Contains(s.Secrets, "ci/NOPE") || slices.Contains(s.Secrets, "ci/github_token") {
			t.Errorf("the audit log has a key that is not in the project: %+v", ev)
		}
	}
}

// TestProjectSecretLimits: SECTION/KEY of 129 bytes works; a part of 65
// bytes is refused, and the client cannot send more than 129 bytes.
func TestProjectSecretLimits(t *testing.T) {
	section, key := strings.Repeat("s", 64), strings.Repeat("K", 64)
	e := projectEnv(t, func(c *config.Broker) {
		p := c.Projects["ci"]
		p.Name = section
		c.Projects = map[string]config.Project{section: p}
	}, envOptions{})
	e.main.set(func(f *fakeStore) {
		f.projects[projectCI] = append(f.projects[projectCI],
			store.ProjectSecret{ID: idCI2, Key: key, Project: projectCI})
	})
	name := section + "/" + key
	if len(name) != api.MaxSecretName {
		t.Fatalf("the name has %d bytes", len(name))
	}
	if got := approveProject(t, e, 1, name, name+" (project rule, ID …0000a002)", audit.AnswerApproveOnce); got != e.values["ci2"] {
		t.Error("the answer does not hold the value")
	}
	for _, bad := range []string{section + "s/" + key[1:], section[1:] + "/" + key + "K"} {
		res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", bad))
		mustStatus(t, res, http.StatusForbidden)
	}
	res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", name+"K"))
	if res.status == http.StatusOK {
		t.Error("a name of 130 bytes passed")
	}
	if n := len(e.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
}

// TestProjectDuplicateKey: two secrets with the same key in the project:
// the request is refused, with a denied entry that names SECTION/KEY and
// a line in the journal. No value is fetched.
func TestProjectDuplicateKey(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	e.main.set(func(f *fakeStore) {
		f.projects[projectCI] = append(f.projects[projectCI],
			store.ProjectSecret{ID: idCI2, Key: "GITHUB_TOKEN", Project: projectCI})
	})
	res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN"))
	mustStatus(t, res, http.StatusForbidden)
	events := e.audit.all()
	mustEvents(t, events, "request denied:not_allowed")
	if s := subjectOf(events[1]); !slices.Equal(s.Secrets, []string{"ci/GITHUB_TOKEN"}) {
		t.Errorf("the denied entry names %q", s.Secrets)
	}
	if !strings.Contains(e.logs.String(), "two or more secrets of the project have this key") ||
		!strings.Contains(e.logs.String(), "ci/GITHUB_TOKEN") {
		t.Errorf("the journal is %q", e.logs.String())
	}
	if e.main.fetched() != 0 || len(e.approver.Asked()) != 0 {
		t.Error("a value was fetched, or a message sent")
	}
}

// TestProjectGetDiffers: the key or the project in the answer of "bws
// secret get" is not the one of the list: the request is denied after the
// tap, and no value goes out.
func TestProjectGetDiffers(t *testing.T) {
	for _, now := range []store.ProjectSecret{
		{ID: idCI1, Key: "GITHUB_TOKEN_OLD", Project: projectCI},
		{ID: idCI1, Key: "GITHUB_TOKEN", Project: "0a1b2c3d-0000-4000-8000-0000000000c2"},
	} {
		e := projectEnv(t, nil, envOptions{})
		e.main.set(func(f *fakeStore) { f.getAs[idCI1] = now })
		p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN"))
		e.tap(e.waitAsked(1)[0].Prompt.RequestID, audit.AnswerApproveOnce)
		res := p.wait(t)
		if res.status == http.StatusOK {
			t.Fatalf("%+v: the value went out", now)
		}
		if strings.Contains(string(res.body), e.values["ci1"]) {
			t.Fatal("the answer has the value")
		}
		if !slices.ContainsFunc(e.audit.all(), func(ev audit.Event) bool { return eventName(ev) == "secret_sent" }) {
			continue
		}
		t.Errorf("%+v: a secret_sent entry", now)
	}
}

// TestProjectGrantRename: a 15 minute grant for ci/GITHUB_TOKEN is for the
// secret idCI1. When another secret gets the key GITHUB_TOKEN, a request
// for ci/GITHUB_TOKEN asks again, and the old secret's grant does not hand
// out the new one.
func TestProjectGrantRename(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	label := func(id string) string { return "ci/GITHUB_TOKEN (project rule, ID …" + id[len(id)-8:] + ")" }
	if got := approveProject(t, e, 1, "ci/GITHUB_TOKEN", label(idCI1), audit.AnswerApproveWindow); got != e.values["ci1"] {
		t.Fatal("no value")
	}
	// The grant covers the same secret.
	got := secretsOf(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN")))
	if got["GH_TOKEN"] != e.values["ci1"] || len(e.approver.Asked()) != 1 {
		t.Fatal("the grant did not cover the same secret")
	}
	// Someone renames idCI1 and gives its key to idCI2.
	e.main.set(func(f *fakeStore) {
		f.projects[projectCI] = []store.ProjectSecret{
			{ID: idCI1, Key: "OLD_TOKEN", Project: projectCI},
			{ID: idCI2, Key: "GITHUB_TOKEN", Project: projectCI},
		}
	})
	if got := approveProject(t, e, 2, "ci/GITHUB_TOKEN", label(idCI2), audit.AnswerApproveOnce); got != e.values["ci2"] {
		t.Error("no value after the second tap")
	}
	// The grant still covers idCI1 under its new key.
	got = secretsOf(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/OLD_TOKEN")))
	if got["GH_TOKEN"] != e.values["ci1"] || len(e.approver.Asked()) != 2 {
		t.Error("the grant does not cover its secret under a new key")
	}
}

// TestProjectEntryWins: a [secret.*] entry with the ID of a project
// secret wins completely, also from another bws store. When it is
// stricter, a client of the project is refused; when it is looser, its
// window applies. Two entries with the ID deny.
func TestProjectEntryWins(t *testing.T) {
	entry := func(name, st string, clients []string, rule config.Rule) func(*config.Broker) {
		return func(c *config.Broker) {
			c.Secrets[name] = config.Secret{Name: name, Store: st, ID: idCI1, Clients: clients, Rule: rule}
		}
	}
	window := config.Rule{Ask: config.AskWindow, Window: 30 * time.Minute}
	t.Run("stricter", func(t *testing.T) {
		e := projectEnv(t, entry("ci-one", "main", []string{"ci"}, window), envOptions{})
		res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN"))
		mustStatus(t, res, http.StatusForbidden)
		if len(e.approver.Asked()) != 0 || e.main.fetched() != 0 {
			t.Error("a message or a value")
		}
	})
	t.Run("looser", func(t *testing.T) {
		e := projectEnv(t, func(c *config.Broker) {
			p := c.Projects["ci"]
			p.Rule = config.Rule{Ask: config.AskAlways}
			c.Projects["ci"] = p
			entry("ci-one", "main", []string{"laptop"}, window)(c)
		}, envOptions{})
		approveProject(t, e, 1, "ci/GITHUB_TOKEN", "ci/GITHUB_TOKEN (rule of secret ci-one, ID …0000a001)",
			audit.AnswerApproveWindow)
		// The entry's grant covers both names.
		for _, name := range []string{"ci/GITHUB_TOKEN", "ci-one"} {
			got := secretsOf(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", name)))
			if got["GH_TOKEN"] != e.values["ci1"] {
				t.Errorf("%s: no value", name)
			}
		}
		if len(e.approver.Asked()) != 1 {
			t.Error("the entry's window did not apply")
		}
	})
	t.Run("another bws store", func(t *testing.T) {
		e := projectEnv(t, func(c *config.Broker) {
			c.Stores["main2"] = config.Store{Name: "main2", Type: config.StoreBWS}
			entry("ci-one", "main2", []string{"ci"}, window)(c)
		}, envOptions{stores: map[string]store.Store{"main2": newFakeStore()}})
		res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN"))
		mustStatus(t, res, http.StatusForbidden)
	})
	t.Run("two entries", func(t *testing.T) {
		e := projectEnv(t, func(c *config.Broker) {
			entry("ci-one", "main", []string{"laptop"}, window)(c)
			entry("ci-two", "main", []string{"laptop"}, window)(c)
		}, envOptions{})
		res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN"))
		mustStatus(t, res, http.StatusForbidden)
		if len(e.approver.Asked()) != 0 {
			t.Error("a message for a secret with two entries")
		}
	})
}

// TestProjectReloadAddsEntry: after a reload that adds a [secret.*] entry
// for a project secret, the old project grant no longer works: the next
// request asks again.
func TestProjectReloadAddsEntry(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	approveProject(t, e, 1, "ci/GITHUB_TOKEN", "ci/GITHUB_TOKEN (project rule, ID …0000a001)", audit.AnswerApproveWindow)
	next := *e.svc.view().cfg
	next.Secrets = maps.Clone(next.Secrets)
	next.Secrets["ci-one"] = config.Secret{Name: "ci-one", Store: "main", ID: idCI1, Clients: []string{"laptop"},
		Rule: config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute}}
	ended, err := e.svc.Reload(&next, e.svc.view().keys, strings.Repeat("a", 64))
	if err != nil || ended != 1 {
		t.Fatalf("Reload = %d, %v; want 1 grant ended", ended, err)
	}
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN"))
	pr := e.waitAsked(2)[1].Prompt
	if !slices.Equal(pr.Secrets, []string{"ci/GITHUB_TOKEN (rule of secret ci-one, ID …0000a001)"}) {
		t.Errorf("the message shows %q", pr.Secrets)
	}
	e.tap(pr.RequestID, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
}

// TestProjectReloadKeepsGrant: a reload that keeps the project's rule
// keeps its grants.
func TestProjectReloadKeepsGrant(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	approveProject(t, e, 1, "ci/GITHUB_TOKEN", "ci/GITHUB_TOKEN (project rule, ID …0000a001)", audit.AnswerApproveWindow)
	next := *e.svc.view().cfg
	if ended, err := e.svc.Reload(&next, e.svc.view().keys, strings.Repeat("a", 64)); err != nil || ended != 0 {
		t.Fatalf("Reload = %d, %v", ended, err)
	}
	got := secretsOf(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN")))
	if got["GH_TOKEN"] != e.values["ci1"] || len(e.approver.Asked()) != 1 {
		t.Error("the grant did not stay")
	}
}

// TestProjectStoreFails: a failed "bws secret list" denies the request
// with 503 and an error entry; no message is sent.
func TestProjectStoreFails(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	e.main.set(func(f *fakeStore) { f.err = store.ErrFailed })
	res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN"))
	mustStatus(t, res, http.StatusServiceUnavailable)
	if len(e.approver.Asked()) != 0 {
		t.Error("a message was sent")
	}
}

// TestProjectMadeUpKeysNotLogged: a key that the client made up never
// reaches the audit log, on any deny path: two unknown keys, a duplicate
// key before an unknown one, a variable on the deny list, and a bad
// preapprove request.
func TestProjectMadeUpKeysNotLogged(t *testing.T) {
	e := projectEnv(t, nil, envOptions{})
	e.main.set(func(f *fakeStore) {
		f.projects[projectCI] = append(f.projects[projectCI],
			store.ProjectSecret{ID: idCI1, Key: "DUP", Project: projectCI},
			store.ProjectSecret{ID: idCI2, Key: "DUP", Project: projectCI})
	})
	c := e.httpClient("laptop")
	two := func(a, b string) api.SecretsRequest {
		r := secretsRequest("A", a)
		r.Secrets = append(r.Secrets, api.SecretRef{Var: "B", Name: b})
		return r
	}
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, two("ci/MADEUP1", "ci/MADEUP2")), http.StatusForbidden)
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, two("ci/DUP", "ci/MADEUP3")), http.StatusForbidden)
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("PATH", "ci/MADEUP4")), http.StatusForbidden)
	pre := api.PreapproveRequest{Secrets: []string{"ci/MADEUP5"}, Uses: 1, From: "bad", Until: "bad"}
	mustStatus(t, e.post(t.Context(), c, api.PathPreapprove, pre), http.StatusForbidden)
	text := encodeEvents(t, e.audit.all()) + e.logs.String()
	if strings.Contains(text, "MADEUP") {
		t.Errorf("a made-up key is in the audit log or the journal: %s", text)
	}
	if !strings.Contains(encodeEvents(t, e.audit.all()), "ci/DUP") {
		t.Error("the duplicate key is not in the audit log")
	}
}

// TestProjectSameSecretTwice: an entry and SECTION/KEY with its ID name
// the same secret; one request with both is denied.
func TestProjectSameSecretTwice(t *testing.T) {
	e := projectEnv(t, func(c *config.Broker) {
		c.Secrets["ci-one"] = config.Secret{Name: "ci-one", Store: "main", ID: idCI1, Clients: []string{"laptop"},
			Rule: config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute}}
	}, envOptions{})
	r := secretsRequest("A", "ci-one")
	r.Secrets = append(r.Secrets, api.SecretRef{Var: "B", Name: "ci/GITHUB_TOKEN"})
	mustStatus(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, r), http.StatusForbidden)
	if len(e.approver.Asked()) != 0 || e.main.fetched() != 0 {
		t.Error("a message or a value")
	}
}

// TestProjectPreapprove: a scheduled grant of a project secret is for its
// ID, and a request for SECTION/KEY uses it with no tap.
func TestProjectPreapprove(t *testing.T) {
	e := projectEnv(t, func(c *config.Broker) {
		p := c.Projects["ci"]
		p.Rule.Preapprove = true
		c.Projects["ci"] = p
		c.Preapprove = config.PreapproveLimits{MaxAhead: 24 * time.Hour, MaxOpen: 24 * time.Hour, MaxUses: 5, MaxGrants: 5}
	}, envOptions{})
	c := e.httpClient("laptop")
	from, until := noon.Add(-time.Minute).Format(time.RFC3339), noon.Add(time.Hour).Format(time.RFC3339)
	p := e.start(c, api.PathPreapprove, api.PreapproveRequest{Secrets: []string{"ci/GITHUB_TOKEN"}, Uses: 1, From: from, Until: until})
	pr := e.waitAsked(1)[0].Prompt
	if !slices.Equal(pr.Secrets, []string{"ci/GITHUB_TOKEN (project rule, ID …0000a001)"}) {
		t.Fatalf("the message shows %q", pr.Secrets)
	}
	e.tap(pr.RequestID, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusOK)
	got := secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "ci/GITHUB_TOKEN")))
	if got["GH_TOKEN"] != e.values["ci1"] || len(e.approver.Asked()) != 1 {
		t.Error("the scheduled grant was not used")
	}
}
