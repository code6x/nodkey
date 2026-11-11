package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// diffCase is a change of the valid config and of known_hosts.
type diffCase struct {
	name  string
	old   []edit                           // edits of the old config
	new   []edit                           // edits of the new config
	hosts func(e *brokerEnv) []string      // the lines of the new known_hosts, if set
	files func(t *testing.T, e *brokerEnv) // run before the new config is loaded, if set
	want  string                           // in a line of the diff
}

func (c diffCase) run(t *testing.T) []Change {
	t.Helper()
	e := newBrokerEnv(t)
	old, err := loadBroker(e.write(t, c.old...), "")
	if err != nil {
		t.Fatalf("the old config: %v", err)
	}
	if c.hosts != nil {
		writeFile(t, e.dir, "known_hosts", strings.Join(c.hosts(e), "\n")+"\n", 0o644)
	}
	if c.files != nil {
		c.files(t, e)
	}
	next, err := loadBroker(e.write(t, append(slices.Clone(c.old), c.new...)...), "")
	if err != nil {
		t.Fatalf("the new config: %v", err)
	}
	return Diff(old, next)
}

func (e *brokerEnv) hostLines(names ...string) []string {
	var lines []string
	for _, name := range names {
		lines = append(lines, knownHostsLine(name, e.hosts[name]))
	}
	return lines
}

// findChange returns the change whose line has want.
func findChange(changes []Change, want string) (Change, bool) {
	for _, c := range changes {
		if strings.Contains(c.Text, want) {
			return c, true
		}
	}
	return Change{}, false
}

const standingTOML = "\n[standing]\n"

// TestDiffMarksWidening: each kind of change that widens access or
// weakens a control (issue #174) is marked.
func TestDiffMarksWidening(t *testing.T) {
	newClient := "[client.new-box]\npin = \"" + testPin("new-box").String() + "\"\n\n[client.backup-box]"
	for _, c := range []diffCase{
		{name: "a new client", new: []edit{{"[client.backup-box]", newClient}}, want: `client "new-box": new client`},
		{name: "a secret for another client",
			new:  []edit{{"clients = [\"laptop\"]\nask = \"window\"\nwindow = \"15m\"\n\n[secret.db", "clients = [\"laptop\", \"backup-box\"]\nask = \"window\"\nwindow = \"15m\"\n\n[secret.db"}},
			want: `secret "github-token": client "backup-box" may now ask for it`},
		{name: "a new secret", new: []edit{{"[key.deploy]",
			"[secret.new]\nstore = \"main\"\nid = \"00000000-0000-0000-0000-00000000000c\"\nclients = [\"laptop\"]\nask = \"always\"\n\n[key.deploy]"}},
			want: `secret "new": client "laptop" may now ask for it`},
		{name: "a key for another client",
			new:  []edit{{"clients = [\"laptop\"]\nask = \"window\"\nwindow = \"15m\"\nhosts", "clients = [\"laptop\", \"backup-box\"]\nask = \"window\"\nwindow = \"15m\"\nhosts"}},
			want: `SSH key "deploy": client "backup-box" may now use it`},
		{name: "a never rule", new: []edit{{"clients = [\"laptop\", \"backup-box\"]\nask = \"always\"", "clients = [\"laptop\"]\nask = \"never\""}},
			want: `secret "db-password": new rule: never ask`},
		{name: "always to window", new: []edit{{"ask = \"always\"\n\n[secret.backup-token]", "ask = \"window\"\nwindow = \"5m\"\n\n[secret.backup-token]"}},
			want: `secret "db-password": ask changed from "always" to "window"`},
		{name: "a longer window", new: []edit{{"window = \"15m\"\n\n[secret.db-password]", "window = \"1h\"\n\n[secret.db-password]"}},
			want: `secret "github-token": window changed from 15m to 1h`},
		{name: "wider hours", new: []edit{{"23:30-00:30", "23:00-00:30"}}, want: `hours changed from "23:30-00:30" to "23:00-00:30"`},
		{name: "no hours", new: []edit{{"hours = \"23:30-00:30\"\n", ""}}, want: `hours changed from "23:30-00:30" to any time`},
		{name: "a higher max_per_day", new: []edit{{"max_per_day = 2", "max_per_day = 3"}}, want: "max_per_day changed from 2 to 3"},
		{name: "no max_per_day", new: []edit{{"max_per_day = 2\n", ""}}, want: "max_per_day changed from 2 to no limit"},
		{name: "notify off", new: []edit{{"hosts = [\"db-1\"]", "hosts = [\"db-1\"]\nnotify = false"}},
			want: `SSH key "backup": notify changed from true to false`},
		{name: "more hosts", new: []edit{{`hosts = ["web-1", "web-2"]`, `hosts = ["web-1", "web-2", "db-1"]`}},
			want: `SSH key "deploy": new host "db-1"`},
		{name: "any host", new: []edit{{"hosts = [\"web-1\", \"web-2\"]\n", ""}},
			want: `SSH key "deploy": may now log in to every host in known_hosts`},
		{name: "preapprove", new: []edit{{"window = \"15m\"\n\n[secret.db-password]", "window = \"15m\"\npreapprove = true\n\n[secret.db-password]"}},
			want: `secret "github-token": preapprove changed from false to true`},
		{name: "standing", old: []edit{{"[client.laptop]", standingTOML + "\n[client.laptop]"}},
			new:  []edit{{"window = \"15m\"\n\n[secret.db-password]", "window = \"15m\"\nstanding = true\n\n[secret.db-password]"}},
			want: `secret "github-token": standing changed from false to true`},
		{name: "a [standing] section", new: []edit{{"[client.laptop]", standingTOML + "\n[client.laptop]"}},
			want: "[standing]: new: standing grants are allowed"},
		{name: "a longer [standing] limit", old: []edit{{"[client.laptop]", standingTOML + "\n[client.laptop]"}},
			new: []edit{{standingTOML, standingTOML + "max_days = 120\n"}}, want: "[standing] max_days: changed from 90 to 120"},
		{name: "a wider [preapprove] limit", new: []edit{{"[client.laptop]", "[preapprove]\nmax_uses = 20\n\n[client.laptop]"}},
			want: "[preapprove] max_uses: changed from 10 to 20"},
		{name: "another approver", new: []edit{{"user_id = 123456789", "user_id = 987654321"}},
			want: "[telegram] user_id: the approver changed from 123456789 to 987654321"},
		{name: "another notice chat", new: []edit{{"user_id = 123456789", "user_id = 123456789\nnotice_chat_id = -100123"}},
			want: "[telegram] notice_chat_id"},
		{name: "a longer timeout", new: []edit{{"user_id = 123456789", "user_id = 123456789\ntimeout = \"300s\""}},
			want: "[telegram] timeout: changed from 2m to 5m"},
		{name: "another bot token file", new: []edit{{"/telegram-token", "/bws-token"}}, want: "[telegram] token_file"},
		{name: "a new pin", new: []edit{{"{{pin laptop}}", testPin("other").String()}}, want: `client "laptop": new pin`},
		{name: "another store program", new: []edit{{"{{dir}}/bin/bws", "{{dir}}/bin/bw"}}, want: `store "main": program changed`},
		{name: "another store token", new: []edit{{"/bws-token", "/ssh-backup"}}, want: `store "main": token_file changed`},
		{name: "another store password", new: []edit{{"/bw-master-password", "/ssh-backup"}}, want: `store "vault": password_file changed`},
		{name: "a secret in another store", new: []edit{{"store = \"main\"\nid = \"00000000-0000-0000-0000-000000000001\"",
			"store = \"vault\"\nid = \"00000000-0000-0000-0000-000000000001\""}},
			want: `secret "github-token": now another item: store changed from "main" to "vault"`},
		{name: "another item", new: []edit{{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000009"}},
			want: `secret "github-token": now another item: id changed`},
		{name: "another key file", new: []edit{{"/ssh-deploy", "/bw-master-password"}}, want: `SSH key "deploy": file changed`},
		{name: "listen", new: []edit{{"192.0.2.10:7743", "192.0.2.11:7743"}}, want: `listen: changed from "192.0.2.10:7743" to "192.0.2.11:7743"`},
		{name: "tls_key", new: []edit{{"/broker-tls-key", "/ssh-backup"}}, want: "tls_key: changed"},
		{name: "audit_log", new: []edit{{"/audit.jsonl", "/audit2.jsonl"}}, want: "audit_log: changed"},
		{name: "known_hosts path", new: []edit{{"{{dir}}/known_hosts", "{{dir}}/known_hosts2"}},
			files: func(t *testing.T, e *brokerEnv) {
				writeFile(t, e.dir, "known_hosts2", strings.Join(e.hostLines("web-1", "web-2", "db-1"), "\n")+"\n", 0o644)
			}, want: "known_hosts: changed"},
		{name: "a new host", hosts: func(e *brokerEnv) []string {
			e.hosts["db-2"] = newHostKey(t)
			return e.hostLines("web-1", "web-2", "db-1", "db-2")
		}, want: `known_hosts: new host "db-2"`},
		{name: "a new host key", hosts: func(e *brokerEnv) []string {
			e.hosts["web-1"] = newHostKey(t)
			return e.hostLines("web-1", "web-2", "db-1")
		}, want: `known_hosts: host "web-1" has a new host key SHA256:`},
		{name: "no update check", new: []edit{{"[client.laptop]", "[updates]\ncheck = false\n\n[client.laptop]"}},
			want: "[updates] check: changed from true to false"},
	} {
		t.Run(c.name, func(t *testing.T) {
			changes := c.run(t)
			got, ok := findChange(changes, c.want)
			if !ok || !got.Widens || !strings.HasPrefix(got.String(), "⚠ ") {
				t.Fatalf("no marked change with %q; the diff:\n%s", c.want, diffText(changes))
			}
			if _, ok := findChange(changes, "does not know"); ok {
				t.Errorf("a known change is also an unknown one:\n%s", diffText(changes))
			}
		})
	}
}

// TestDiffNarrowing: a change that narrows access is a plain line.
func TestDiffNarrowing(t *testing.T) {
	for _, c := range []diffCase{
		{name: "a client removed", new: []edit{{"\"laptop\", \"backup-box\"", "\"laptop\""}, {"clients = [\"backup-box\"]\nask = \"never\"\nhours", "clients = [\"laptop\"]\nask = \"never\"\nhours"},
			{"clients = [\"backup-box\"]\nask = \"never\"\nhosts", "clients = [\"laptop\"]\nask = \"never\"\nhosts"},
			{"[client.backup-box]\npin = \"{{pin backup-box}}\"\n", ""}}, want: `client "backup-box": removed`},
		{name: "a shorter window", new: []edit{{"window = \"15m\"\n\n[secret.db-password]", "window = \"5m\"\n\n[secret.db-password]"}},
			want: "window changed from 15m to 5m"},
		{name: "never to always", new: []edit{{"ask = \"never\"\nhours = \"23:30-00:30\"\nmax_per_day = 2\nnotify = false", "ask = \"always\""}},
			want: `secret "backup-token": ask changed from "never" to "always"`},
		{name: "fewer hosts", new: []edit{{`hosts = ["web-1", "web-2"]`, `hosts = ["web-1"]`}}, want: `SSH key "deploy": host "web-2" removed`},
		{name: "a lower max_per_day", new: []edit{{"max_per_day = 2", "max_per_day = 1"}}, want: "max_per_day changed from 2 to 1"},
		{name: "narrower hours", new: []edit{{"23:30-00:30", "23:45-00:15"}}, want: "hours changed"},
		{name: "notify on", new: []edit{{"notify = false", "notify = true"}}, want: "notify changed from false to true"},
		{name: "a host removed", hosts: func(e *brokerEnv) []string { return e.hostLines("web-1", "web-2", "db-1") },
			new: []edit{{`hosts = ["web-1", "web-2"]`, `hosts = ["web-1"]`}}, want: `host "web-2" removed`},
	} {
		t.Run(c.name, func(t *testing.T) {
			changes := c.run(t)
			got, ok := findChange(changes, c.want)
			if !ok || got.Widens || !strings.HasPrefix(got.String(), "  ") {
				t.Fatalf("no plain change with %q; the diff:\n%s", c.want, diffText(changes))
			}
		})
	}
}

// TestDiffNeverParts: notify, max_per_day and hours are compared only
// between two "never" rules; a move to "never" shows them on its line.
func TestDiffNeverParts(t *testing.T) {
	changes := diffCase{new: []edit{{"ask = \"never\"\nhours = \"23:30-00:30\"\nmax_per_day = 2\nnotify = false", "ask = \"always\""}}}.run(t)
	if len(changes) != 1 || changes[0].Widens {
		t.Errorf("never to always:\n%s", diffText(changes))
	}
	changes = diffCase{new: []edit{{"clients = [\"laptop\", \"backup-box\"]\nask = \"always\"",
		"clients = [\"laptop\"]\nask = \"never\"\nmax_per_day = 5\nnotify = false"}}}.run(t)
	got, ok := findChange(changes, `new rule: never ask (ask changed from "always" to "never"), with notify false, max_per_day 5, hours any time`)
	if !ok || !got.Widens {
		t.Errorf("always to never:\n%s", diffText(changes))
	}
	if _, ok := findChange(changes, "max_per_day changed"); ok {
		t.Errorf("a line for max_per_day:\n%s", diffText(changes))
	}
}

// TestDiffSameMeaning: comments, order and spaces alone are no change.
func TestDiffSameMeaning(t *testing.T) {
	c := diffCase{
		new: []edit{
			{"# A broker config for tests.", "# Another comment.\n\n\n"},
			{"user_id = 123456789", "user_id    =   123456789   # the approver"},
			{"\"laptop\", \"backup-box\"", "\"backup-box\",\"laptop\""},
			// [key.backup] moves before [key.deploy].
			{"[key.deploy]", "[key.backup]\nfile = \"${CREDENTIALS_DIRECTORY}/ssh-backup\"\nclients = [\"backup-box\"]\n" +
				"ask = \"never\"\nhosts = [\"db-1\"]\n\n[key.deploy]"},
			{"\n[key.backup]\nfile = \"${CREDENTIALS_DIRECTORY}/ssh-backup\"\nclients = [\"backup-box\"]\nask = \"never\"\nhosts = [\"db-1\"]\n", "\n"},
		},
		hosts: func(e *brokerEnv) []string {
			return append([]string{"# the hosts", ""}, e.hostLines("db-1", "web-2", "web-1")...)
		},
	}
	if changes := c.run(t); len(changes) != 0 {
		t.Fatalf("the diff:\n%s", diffText(changes))
	}
}

// TestDiffComparesEveryField: each field of the types of the config is in
// compared, or is a type in compared itself. So a field that is added
// later and not compared by name is found by unknown.
func TestDiffComparesEveryField(t *testing.T) {
	for typ, names := range compared {
		for i := range typ.NumField() {
			f := typ.Field(i)
			if slices.Contains(names, f.Name) {
				continue
			}
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Map {
				ft = ft.Elem()
			}
			if _, ok := compared[ft]; !ok {
				t.Errorf("%s.%s is neither compared by name nor a type in compared; unknown compares it, "+
					"so each of its changes is marked as one that config-diff does not know", typ.Name(), f.Name)
			}
		}
	}
}

// TestDiffUnknownIsMarked: a change of a field that Diff does not compare
// by name is marked.
func TestDiffUnknownIsMarked(t *testing.T) {
	saved := compared[reflect.TypeFor[Telegram]()]
	t.Cleanup(func() { compared[reflect.TypeFor[Telegram]()] = saved })
	// As if Telegram had a new field that Diff does not know.
	compared[reflect.TypeFor[Telegram]()] = slices.DeleteFunc(slices.Clone(saved), func(s string) bool { return s == "NoticeChatID" })
	changes := diffCase{new: []edit{{"user_id = 123456789", "user_id = 123456789\nnotice_chat_id = -100123"}}}.run(t)
	got, ok := findChange(changes, "a change that config-diff does not know")
	if !ok || !got.Widens {
		t.Fatalf("the diff:\n%s", diffText(changes))
	}
	// The same config: no change.
	if changes := (diffCase{}).run(t); len(changes) != 0 {
		t.Fatalf("the same config:\n%s", diffText(changes))
	}
}

func diffText(changes []Change) string {
	var b strings.Builder
	for _, c := range changes {
		b.WriteString(c.String() + "\n")
	}
	return b.String()
}

// TestDiffNtfy: a change of the channel, or of the ntfy server, a topic or
// the token file, is marked; a shorter timeout is not.
func TestDiffNtfy(t *testing.T) {
	tg := reloadBase()
	nt := reloadCopy(tg)
	nt.Telegram = Telegram{}
	nt.Ntfy = &Ntfy{Server: "https://ntfy.example.com", RequestTopic: "a", AnswerTopic: "b", TokenFile: "/t",
		Timeout: 2 * time.Minute, SSHTimeout: time.Minute}
	for _, c := range []struct {
		name      string
		old, next *Broker
		want      string
		widens    bool
	}{
		{"to ntfy", tg, nt, "changed from [telegram] to [ntfy]", true},
		{"to telegram", nt, tg, "changed from [ntfy] to [telegram]", true},
		{"another server", nt, ntfyWith(nt, func(n *Ntfy) { n.Server = "https://other.example.com" }), "[ntfy] server", true},
		{"another topic", nt, ntfyWith(nt, func(n *Ntfy) { n.AnswerTopic = "c" }), "[ntfy] answer_topic", true},
		{"another token", nt, ntfyWith(nt, func(n *Ntfy) { n.TokenFile = "/u" }), "[ntfy] token_file", true},
		{"a shorter timeout", nt, ntfyWith(nt, func(n *Ntfy) { n.Timeout = time.Minute }), "[ntfy] timeout", false},
		{"a longer ssh_timeout", nt, ntfyWith(nt, func(n *Ntfy) { n.SSHTimeout = 2 * time.Minute }), "[ntfy] ssh_timeout", true},
	} {
		changes := Diff(c.old, c.next)
		got, ok := findChange(changes, c.want)
		if !ok || got.Widens != c.widens || len(changes) != 1 {
			t.Errorf("%s: the diff:\n%s", c.name, diffText(changes))
		}
	}
}

func ntfyWith(b *Broker, f func(*Ntfy)) *Broker {
	c := reloadCopy(b)
	n := *b.Ntfy
	f(&n)
	c.Ntfy = &n
	return c
}
