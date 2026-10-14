package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// validBroker is a valid broker config. {{dir}} and {{pin NAME}} are
// filled in by brokerEnv.write. All names and numbers are made up.
const validBroker = `# A broker config for tests.
listen = "192.0.2.10:7743"
tls_key = "${CREDENTIALS_DIRECTORY}/broker-tls-key"
audit_log = "{{dir}}/audit.jsonl"
known_hosts = "{{dir}}/known_hosts"

[telegram]
token_file = "${CREDENTIALS_DIRECTORY}/telegram-token"
user_id = 123456789

[client.laptop]
pin = "{{pin laptop}}"

[client.backup-box]
pin = "{{pin backup-box}}"

[store.main]
type = "bws"
program = "{{dir}}/bin/bws"
token_file = "${CREDENTIALS_DIRECTORY}/bws-token"

[store.vault]
type = "bw"
program = "{{dir}}/bin/bw"
password_file = "${CREDENTIALS_DIRECTORY}/bw-master-password"

[secret.github-token]
store = "main"
id = "00000000-0000-0000-0000-000000000001"
clients = ["laptop"]
ask = "window"
window = "15m"

[secret.db-password]
store = "vault"
id = "00000000-0000-0000-0000-00000000000A"
clients = ["laptop", "backup-box"]
ask = "always"

[secret.backup-token]
store = "main"
id = "00000000-0000-0000-0000-00000000000b"
clients = ["backup-box"]
ask = "never"
hours = "23:30-00:30"
max_per_day = 2
notify = false

[key.deploy]
file = "${CREDENTIALS_DIRECTORY}/ssh-deploy"
clients = ["laptop"]
ask = "window"
window = "15m"
hosts = ["web-1", "web-2"]

[key.backup]
file = "${CREDENTIALS_DIRECTORY}/ssh-backup"
clients = ["backup-box"]
ask = "never"
hosts = ["db-1"]
`

// privateFiles are the files in the credentials directory that the valid
// config names.
var privateFiles = []string{"broker-tls-key", "telegram-token", "bws-token", "bw-master-password", "ssh-deploy", "ssh-backup"}

// brokerEnv is a temporary setup for a broker config: a directory for the
// config, known_hosts and the audit log, and one that stands in for
// $CREDENTIALS_DIRECTORY.
type brokerEnv struct {
	dir   string
	creds string
	hosts map[string]ssh.PublicKey
}

func newBrokerEnv(t *testing.T) *brokerEnv {
	t.Helper()
	e := &brokerEnv{dir: privateTempDir(t), creds: privateTempDir(t), hosts: make(map[string]ssh.PublicKey)}
	t.Setenv("CREDENTIALS_DIRECTORY", e.creds)
	var lines []string
	for _, name := range []string{"web-1", "web-2", "db-1"} {
		e.hosts[name] = newHostKey(t)
		lines = append(lines, knownHostsLine(name, e.hosts[name]))
	}
	writeFile(t, e.dir, "known_hosts", strings.Join(lines, "\n")+"\n", 0o644)
	for _, name := range privateFiles {
		writeFile(t, e.creds, name, "made-up test content\n", 0o600)
	}
	bin := mkdir(t, e.dir, "bin", 0o755)
	for _, name := range []string{"bws", "bw"} {
		writeFile(t, bin, name, "#!/bin/sh\nexit 1\n", 0o755)
	}
	return e
}

// edit replaces the first old in a config with new.
type edit struct{ old, new string }

// write writes the valid config with the edits and returns its path.
func (e *brokerEnv) write(t *testing.T, edits ...edit) string {
	t.Helper()
	cfg := validBroker
	for _, ed := range edits {
		if !strings.Contains(cfg, ed.old) {
			t.Fatalf("the config does not hold %q", ed.old)
		}
		cfg = strings.Replace(cfg, ed.old, ed.new, 1)
	}
	cfg = strings.NewReplacer(
		"{{dir}}", e.dir,
		"{{pin laptop}}", testPin("laptop").String(),
		"{{pin backup-box}}", testPin("backup-box").String(),
	).Replace(cfg)
	return writeFile(t, e.dir, "broker.toml", cfg, 0o644)
}

func TestLoadBrokerValid(t *testing.T) {
	e := newBrokerEnv(t)
	path := e.write(t)
	b, err := LoadBroker(path)
	if err != nil {
		t.Fatalf("LoadBroker: %v", err)
	}
	check := func(what string, got, want any) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %v, want %v", what, got, want)
		}
	}
	check("Path", b.Path, path)
	check("Listen", b.Listen, netip.MustParseAddrPort("192.0.2.10:7743"))
	check("TLSKey", b.TLSKey, e.creds+"/broker-tls-key")
	check("AuditLog", b.AuditLog, e.dir+"/audit.jsonl")
	check("KnownHostsFile", b.KnownHostsFile, e.dir+"/known_hosts")
	for name, key := range e.hosts {
		got, ok := b.KnownHosts.NameFor(key)
		check("KnownHosts.NameFor("+name+")", got, name)
		check("KnownHosts.NameFor("+name+") found", ok, true)
	}

	check("Telegram.TokenFile", b.Telegram.TokenFile, e.creds+"/telegram-token")
	check("Telegram.UserID", b.Telegram.UserID, int64(123456789))
	check("Telegram.NoticeChatID (default)", b.Telegram.NoticeChatID, int64(123456789))
	check("Telegram.Timeout (default)", b.Telegram.Timeout, 120*time.Second)
	check("Telegram.SSHTimeout (default)", b.Telegram.SSHTimeout, 90*time.Second)

	check("number of clients", len(b.Clients), 2)
	check("Clients[laptop]", b.Clients["laptop"], Client{Name: "laptop", Pin: testPin("laptop")})
	check("Clients[backup-box]", b.Clients["backup-box"], Client{Name: "backup-box", Pin: testPin("backup-box")})

	check("number of stores", len(b.Stores), 2)
	check("Stores[main]", b.Stores["main"], Store{Name: "main", Type: StoreBWS, Program: e.dir + "/bin/bws", TokenFile: e.creds + "/bws-token"})
	check("Stores[vault]", b.Stores["vault"], Store{Name: "vault", Type: StoreBW, Program: e.dir + "/bin/bw", PasswordFile: e.creds + "/bw-master-password"})

	check("number of secrets", len(b.Secrets), 3)
	gh := b.Secrets["github-token"]
	check("github-token store", gh.Store, "main")
	check("github-token id", gh.ID, "00000000-0000-0000-0000-000000000001")
	check("github-token clients", strings.Join(gh.Clients, ","), "laptop")
	check("github-token rule", gh.Rule, Rule{Ask: AskWindow, Window: 15 * time.Minute})
	db := b.Secrets["db-password"]
	check("db-password id", db.ID, "00000000-0000-0000-0000-00000000000A")
	check("db-password clients", strings.Join(db.Clients, ","), "laptop,backup-box")
	check("db-password rule", db.Rule, Rule{Ask: AskAlways})
	bt := b.Secrets["backup-token"]
	if bt.Rule.Hours == nil {
		t.Fatal("backup-token: Rule.Hours is nil")
	}
	check("backup-token hours", *bt.Rule.Hours, Hours{From: 23*time.Hour + 30*time.Minute, To: 30 * time.Minute})
	bt.Rule.Hours = nil
	check("backup-token rule", bt.Rule, Rule{Ask: AskNever, Notify: false, MaxPerDay: 2})

	check("number of keys", len(b.Keys), 2)
	deploy := b.Keys["deploy"]
	check("deploy file", deploy.File, e.creds+"/ssh-deploy")
	check("deploy clients", strings.Join(deploy.Clients, ","), "laptop")
	check("deploy hosts", strings.Join(deploy.Hosts, ","), "web-1,web-2")
	check("deploy rule", deploy.Rule, Rule{Ask: AskWindow, Window: 15 * time.Minute})
	backup := b.Keys["backup"]
	check("backup hosts", strings.Join(backup.Hosts, ","), "db-1")
	check("backup rule (notify by default)", backup.Rule, Rule{Ask: AskNever, Notify: true})
}

func TestLoadBrokerOptionalValues(t *testing.T) {
	e := newBrokerEnv(t)
	path := e.write(t,
		edit{"user_id = 123456789", "user_id = 123456789\nnotice_chat_id = -1001234567890\ntimeout = \"10m\"\nssh_timeout = \"110s\""},
		edit{"hosts = [\"web-1\", \"web-2\"]", "hosts = []"},
		edit{"max_per_day = 2\nnotify = false\n", ""},
		// The item of the "never" secret, with another rule for another client.
		edit{"[key.deploy]", "[secret.backup-token-by-hand]\nstore = \"main\"\nid = \"00000000-0000-0000-0000-00000000000B\"\n" +
			"clients = [\"laptop\"]\nask = \"always\"\n\n[key.deploy]"},
	)
	b, err := LoadBroker(path)
	if err != nil {
		t.Fatalf("LoadBroker: %v", err)
	}
	if b.Telegram.NoticeChatID != -1001234567890 {
		t.Errorf("NoticeChatID = %d, want -1001234567890", b.Telegram.NoticeChatID)
	}
	if b.Telegram.Timeout != 10*time.Minute || b.Telegram.SSHTimeout != 110*time.Second {
		t.Errorf("Timeout, SSHTimeout = %v, %v, want 10m, 1m50s", b.Telegram.Timeout, b.Telegram.SSHTimeout)
	}
	if hosts := b.Keys["deploy"].Hosts; len(hosts) != 0 {
		t.Errorf("deploy hosts = %q, want none (any known host)", hosts)
	}
	if r := b.Secrets["backup-token"].Rule; r.MaxPerDay != 0 || !r.Notify {
		t.Errorf("backup-token rule = %+v, want MaxPerDay 0 (no limit) and Notify true", r)
	}
	if _, ok := b.Secrets["backup-token-by-hand"]; !ok {
		t.Error(`a second secret with the item of a "never" secret, but another rule, was not loaded`)
	}

	path = e.write(t,
		edit{"user_id = 123456789", "user_id = 123456789\ntimeout = \"15s\"\nssh_timeout = \"15s\""},
		edit{"max_per_day = 2", "max_per_day = 1"},
	)
	if b, err = LoadBroker(path); err != nil {
		t.Fatalf("LoadBroker with the shortest timeouts and max_per_day = 1: %v", err)
	}
	if b.Telegram.Timeout != 15*time.Second || b.Telegram.SSHTimeout != 15*time.Second {
		t.Errorf("Timeout, SSHTimeout = %v, %v, want 15s, 15s", b.Telegram.Timeout, b.Telegram.SSHTimeout)
	}
	if got := b.Secrets["backup-token"].Rule.MaxPerDay; got != 1 {
		t.Errorf("backup-token MaxPerDay = %d, want 1", got)
	}
}

func TestLoadBrokerErrors(t *testing.T) {
	pin := testPin("laptop").String()
	bare := strings.TrimPrefix(pin, "sha256:")
	long := strings.Repeat("a", 65)
	tests := []struct {
		name           string
		edits          []edit
		knownHosts     string      // replaces the known_hosts file when not empty
		configMode     os.FileMode // the mode of the config file, when not 0
		knownHostsMode os.FileMode // the mode of known_hosts, when not 0
		unsetCreds     bool        // unset CREDENTIALS_DIRECTORY
		setup          func(t *testing.T, e *brokerEnv)
		want           string
		notWant        string // text the error must not hold, such as a value
	}{
		// TOML
		{name: "syntax error", edits: []edit{{"user_id = 123456789", "user_id = abcSECRETdef"}},
			want: "line 9, column 11: not valid TOML, or a number out of range", notWant: "SECRET"},
		{name: "pasted text as a key", edits: []edit{{"user_id = 123456789", "user_id = 123456789\nc2VjcmV0SECRETdGV4dA"}},
			want: "line 10, column", notWant: "SECRET"},
		{name: "config file writable by group", configMode: 0o664,
			want: "group or others can write to it (mode 0664)"},
		{name: "config file writable by others", configMode: 0o646,
			want: "group or others can write to it (mode 0646)"},
		{name: "known_hosts writable by group", knownHostsMode: 0o620,
			want: "/known_hosts: group or others can write to it (mode 0620)"},
		{name: "known_hosts writable by others", knownHostsMode: 0o642,
			want: "/known_hosts: group or others can write to it (mode 0642)"},
		{name: "config directory writable by group", setup: func(t *testing.T, e *brokerEnv) { chmod(t, e.dir, 0o770) },
			want: ": group or others can write to this directory (mode 0770)"},
		{name: "known_hosts in a directory writable by others",
			edits: []edit{{"{{dir}}/known_hosts", "{{dir}}/open/known_hosts"}},
			setup: func(t *testing.T, e *brokerEnv) {
				open := mkdir(t, e.dir, "open", 0o777)
				if err := os.Rename(filepath.Join(e.dir, "known_hosts"), filepath.Join(open, "known_hosts")); err != nil {
					t.Fatal(err)
				}
			},
			want: "/open: group or others can write to this directory (mode 0777)"},
		{name: "known_hosts is a link in a directory writable by others",
			edits: []edit{{"{{dir}}/known_hosts", "{{dir}}/links/known_hosts"}},
			setup: func(t *testing.T, e *brokerEnv) {
				symlink(t, filepath.Join(e.dir, "known_hosts"), filepath.Join(mkdir(t, e.dir, "links", 0o757), "known_hosts"))
			},
			want: "/links: group or others can write to this directory (mode 0757)"},
		{name: "split section: a dotted key at the top", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nsecret.github-token.ask = \"always\""},
			{"ask = \"window\"\nwindow = \"15m\"\n", ""},
		}, want: `key "secret.github-token.ask": write it as ask = ... below its own [secret.github-token] header`},
		{name: "split section: [telegram] key at the top", edits: []edit{
			{"user_id = 123456789\n", ""},
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\ntelegram.user_id = 123456789"},
		}, want: `key "telegram.user_id": write it as user_id = ... below its own [telegram] header`},
		{name: "inline table", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nclient.backup-box = { pin = \"{{pin backup-box}}\" }"},
			{"[client.backup-box]\npin = \"{{pin backup-box}}\"\n", ""},
		}, want: "line 3: inline tables ({ ... }) are not allowed"},
		// A key name that is not lower case letters, digits and "_" is not
		// shown, because it may be pasted text. The error counts it.
		{name: "key in another case in an inline table", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nclient.backup-box = { PIN = \"{{pin backup-box}}\" }"},
			{"[client.backup-box]\npin = \"{{pin backup-box}}\"\n", ""},
		}, want: "1 unknown key; an error shows a key name only if it looks like a config key, such as tls_key", notWant: "PIN"},
		{name: "key in another case as a dotted key", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nsecret.github-token.Ask = \"always\""},
			{"ask = \"window\"\nwindow = \"15m\"\n", ""},
		}, want: "1 unknown key;", notWant: "Ask"},
		{name: "section in another case as a dotted key", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nSecret.github-token.ask = \"never\""},
		}, want: "1 unknown key;", notWant: "Secret"},
		{name: "[telegram] key in another case as a dotted key", edits: []edit{
			{"user_id = 123456789\n", ""},
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\ntelegram.USER_ID = 123456789"},
		}, want: "1 unknown key;", notWant: "USER_ID"},
		{name: "key in another case beside the real one in an inline table", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nsecret.other = { store = \"main\", " +
				"id = \"00000000-0000-0000-0000-0000000000cc\", clients = [\"laptop\"], ask = \"always\", ASK = \"never\" }"},
		}, want: "1 unknown key;", notWant: "ASK"},
		{name: "section in another case in an inline table", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nKey.other = { file = \"/x\", clients = [\"laptop\"], ask = \"always\" }"},
		}, want: "unknown keys;", notWant: "Key.other"},
		{name: "section header in another case", edits: []edit{{"[secret.db-password]", "[Secret.db-password]"}},
			want: "unknown keys;", notWant: "Secret"},
		{name: "unknown top-level key", edits: []edit{{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nlistn = \"192.0.2.11:7743\""}},
			want: `unknown key "listn"`},
		{name: "unknown key in a section", edits: []edit{{`window = "15m"`, "window = \"15m\"\nwindw = \"20m\""}},
			want: `unknown key "secret.github-token.windw"`},
		{name: "unknown section", edits: []edit{{"[store.main]", "[stores.main]"}},
			want: `unknown keys "stores.main", "stores.main.program", "stores.main.token_file", "stores.main.type"`},
		{name: "key in upper case", edits: []edit{{`ask = "always"`, "ask = \"always\"\nASK = \"never\""}},
			want: "1 unknown key;", notWant: "ASK"},
		{name: "pasted text as a key name", edits: []edit{{"user_id = 123456789", "user_id = 123456789\nSECRETpass-word_1 = 1"}},
			want: "1 unknown key;", notWant: "SECRET"},
		{name: "pasted text as a key name and a typo", edits: []edit{{"user_id = 123456789", "user_id = 123456789\nghp_madeUpSECRET0 = 1\nusr_id = 1"}},
			want: `unknown key "telegram.usr_id", and 1 more unknown key; an error shows a key name only if`, notWant: "SECRET"},
		{name: "value of the wrong type", edits: []edit{{"user_id = 123456789", `user_id = "123456789"`}},
			want: "line 9: incompatible types: TOML value has type string; destination has type integer", notWant: "user_id"},
		{name: "value of the wrong type in a section with pasted text as its name", edits: []edit{
			{"[secret.db-password]", `[secret."SECRET token"]`}, {`ask = "always"`, "ask = 1"}},
			want: "line 38: incompatible types", notWant: "SECRET"},
		{name: "dotted key in a section with pasted text as its name", edits: []edit{
			{`listen = "192.0.2.10:7743"`, "listen = \"192.0.2.10:7743\"\nsecret.\"SECRET token\".ask = \"never\""}},
			want: "a key is not below the header of its own section", notWant: "SECRET"},

		// top level
		{name: "listen missing", edits: []edit{{"listen = \"192.0.2.10:7743\"\n", ""}},
			want: "listen: is missing"},
		{name: "listen without a port", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "192.0.2.10"`}},
			want: `listen: must be an IP address and a port, such as "192.0.2.10:7743"`},
		{name: "listen on every IPv4 address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "0.0.0.0:7743"`}},
			want: "listen: 0.0.0.0 and :: are not allowed, because the broker would listen on every network"},
		{name: "listen without an address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = ":7743"`}},
			want: "listen: the IP address is missing; without it, the broker would listen on every network"},
		{name: "listen on every IPv6 address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "[::]:7743"`}},
			want: "listen: 0.0.0.0 and :: are not allowed"},
		{name: "listen on every address in IPv6 form", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "[::ffff:0.0.0.0]:7743"`}},
			want: "listen: 0.0.0.0 and :: are not allowed"},
		{name: "listen on every IPv6 address with a zone", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "[::%lo]:7743"`}},
			want: "listen: 0.0.0.0 and :: are not allowed"},
		{name: "listen on a multicast address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "239.0.0.1:7743"`}},
			want: "listen: a multicast or broadcast address is not allowed; use one address of this machine", notWant: "239."},
		{name: "listen on a link-local multicast address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "224.0.0.1:7743"`}},
			want: "listen: a multicast or broadcast address is not allowed", notWant: "224."},
		{name: "listen on an IPv6 link-local multicast address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "[ff02::1]:7743"`}},
			want: "listen: a multicast or broadcast address is not allowed", notWant: "ff02"},
		{name: "listen with an IPv6 zone", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "[fe80::10%lo]:7743"`}},
			want: "listen: an IPv6 zone (the part after %) is not allowed", notWant: "%lo"},
		{name: "listen with a zone that holds a newline, spaces and a slash", edits: []edit{
			{`listen = "192.0.2.10:7743"`, `listen = "[fe80::10%made up/zone\nSECRET]:7743"`}},
			want: "listen: an IPv6 zone (the part after %) is not allowed", notWant: "made up"},
		{name: "listen on an IPv6 link-local address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "[fe80::10]:7743"`}},
			want: "listen: an IPv6 link-local address (fe80::/10) is not allowed", notWant: "fe80::10"},
		{name: "listen on the broadcast address", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "255.255.255.255:7743"`}},
			want: "listen: a multicast or broadcast address is not allowed", notWant: "255."},
		{name: "listen on a host name", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "localhost:7743"`}},
			want: "listen: must be an IP address and a port", notWant: "localhost"},
		{name: "listen on a domain name", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "broker.example.com:7743"`}},
			want: "a host name is not allowed", notWant: "example"},
		{name: "listen with a leading zero", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "192.0.2.010:7743"`}},
			want: "listen: must be an IP address and a port"},
		{name: "listen on port 0", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "192.0.2.10:0"`}},
			want: "listen: the port must be a number from 1 to 65535"},
		{name: "listen on a port above 65535", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "192.0.2.10:65536"`}},
			want: "listen: the port must be a number from 1 to 65535"},
		{name: "listen on a service name", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = "192.0.2.10:https"`}},
			want: "listen: the port must be a number", notWant: "https"},
		{name: "listen with pasted text", edits: []edit{{`listen = "192.0.2.10:7743"`,
			`listen = "0.00000000-0000-0000-0000-000000000000.SECRET:AAAA=="`}},
			want: "listen: ", notWant: "SECRET"},
		{name: "listen as a number", edits: []edit{{`listen = "192.0.2.10:7743"`, `listen = 7743`}},
			want: "line 2: incompatible types"},
		{name: "tls_key missing", edits: []edit{{"tls_key = \"${CREDENTIALS_DIRECTORY}/broker-tls-key\"\n", ""}},
			want: "tls_key: is missing"},
		{name: "audit_log missing", edits: []edit{{"audit_log = \"{{dir}}/audit.jsonl\"\n", ""}},
			want: "audit_log: is missing"},
		{name: "known_hosts missing", edits: []edit{{"known_hosts = \"{{dir}}/known_hosts\"\n", ""}},
			want: "known_hosts: is missing"},
		{name: "relative path", edits: []edit{{`audit_log = "{{dir}}/audit.jsonl"`, `audit_log = "audit-SECRET.jsonl"`}},
			want: "audit_log: must be an absolute path", notWant: "SECRET"},
		{name: "unknown variable in a path", edits: []edit{{"${CREDENTIALS_DIRECTORY}/broker-tls-key", "${CREDENTIALS_DIR}/broker-tls-key"}},
			want: `tls_key: only "${CREDENTIALS_DIRECTORY}/" at the start of a path is expanded`},
		{name: "CREDENTIALS_DIRECTORY not set", unsetCreds: true,
			want: "tls_key: uses ${CREDENTIALS_DIRECTORY}, but it is not set"},

		// [telegram]
		{name: "telegram section missing", edits: []edit{{"[telegram]\ntoken_file = \"${CREDENTIALS_DIRECTORY}/telegram-token\"\nuser_id = 123456789\n", ""}},
			want: "[telegram] token_file: is missing"},
		{name: "token_file missing", edits: []edit{{"token_file = \"${CREDENTIALS_DIRECTORY}/telegram-token\"\n", ""}},
			want: "[telegram] token_file: is missing"},
		{name: "token_file relative", edits: []edit{{"${CREDENTIALS_DIRECTORY}/telegram-token", "123456:SECRET-token"}},
			want: "[telegram] token_file: must be an absolute path", notWant: "SECRET"},
		{name: "user_id missing", edits: []edit{{"user_id = 123456789\n", ""}},
			want: "[telegram] user_id: is missing"},
		{name: "user_id zero", edits: []edit{{"user_id = 123456789", "user_id = 0"}},
			want: "[telegram] user_id: must be more than 0"},
		{name: "user_id negative", edits: []edit{{"user_id = 123456789", "user_id = -123456789"}},
			want: "[telegram] user_id: must be more than 0"},
		{name: "notice_chat_id zero", edits: []edit{{"user_id = 123456789", "user_id = 123456789\nnotice_chat_id = 0"}},
			want: "[telegram] notice_chat_id: must not be 0"},
		{name: "timeout not a duration", edits: []edit{{"user_id = 123456789", "user_id = 123456789\ntimeout = \"2 minutes\""}},
			want: `[telegram] timeout: must be a duration such as "90s" or "15m"`, notWant: "2 minutes"},
		{name: "timeout as a number", edits: []edit{{"user_id = 123456789", "user_id = 123456789\ntimeout = 120"}},
			want: "incompatible types"},
		{name: "timeout too short", edits: []edit{{"user_id = 123456789", "user_id = 123456789\ntimeout = \"14s\""}},
			want: "[telegram] timeout: must be from 15s to 10m"},
		{name: "timeout too long", edits: []edit{{"user_id = 123456789", "user_id = 123456789\ntimeout = \"601s\""}},
			want: "[telegram] timeout: must be from 15s to 10m"},
		{name: "ssh_timeout too short", edits: []edit{{"user_id = 123456789", "user_id = 123456789\nssh_timeout = \"14s\""}},
			want: "[telegram] ssh_timeout: must be from 15s to 1m50s"},
		{name: "ssh_timeout too long", edits: []edit{{"user_id = 123456789", "user_id = 123456789\nssh_timeout = \"111s\""}},
			want: "[telegram] ssh_timeout: must be from 15s to 1m50s"},

		// [client.*]
		// A name that breaks the rule may be pasted text, so the error does
		// not show it.
		{name: "client name with a space", edits: []edit{{"[client.laptop]", `[client."my laptop"]`}},
			want: `[client.*]: the name of a section must be 1 to 64 letters, digits, ".", "_" or "-", ` +
				`starting with a letter or digit; the name is not shown here`, notWant: "my laptop"},
		{name: "client name too long", edits: []edit{{"[client.laptop]", "[client." + long + "]"}},
			want: "[client.*]: the name of a section must be 1 to 64 letters", notWant: long},
		{name: "client name starts with a dot", edits: []edit{{"[client.laptop]", `[client.".laptop"]`}},
			want: "[client.*]: the name of a section must be", notWant: ".laptop"},
		{name: "client name not ASCII", edits: []edit{{"[client.laptop]", `[client."laptоp"]`}},
			want: "[client.*]: the name of a section must be", notWant: "laptоp"},
		{name: "empty client name", edits: []edit{{"[client.laptop]", `[client.""]`}},
			want: "[client.*]: the name of a section must be"},
		{name: "pasted text as a client name", edits: []edit{{"[client.laptop]", `[client."SECRET:token="]`}},
			want: "[client.*]: the name of a section must be", notWant: "SECRET"},
		{name: "pin missing", edits: []edit{{"pin = \"{{pin laptop}}\"\n", ""}},
			want: "[client.laptop] pin: is missing"},
		{name: "pin without prefix", edits: []edit{{"{{pin laptop}}", bare}},
			want: `[client.laptop] pin: must be "sha256:" and 43 base64 characters`, notWant: bare},
		{name: "pin too short", edits: []edit{{"{{pin laptop}}", "sha256:" + bare[:40]}},
			want: "[client.laptop] pin: must be"},
		{name: "pin with padding", edits: []edit{{"{{pin laptop}}", pin + "="}},
			want: "[client.laptop] pin: must be"},
		{name: "two clients with one pin", edits: []edit{{"{{pin backup-box}}", "{{pin laptop}}"}},
			want: "[client.laptop] pin: is the same as the pin of [client.backup-box]"},

		// [store.*]
		{name: "store name with a space", edits: []edit{{"[store.main]", `[store."main store"]`}},
			want: "[store.*]: the name of a section must be", notWant: "main store"},
		{name: "store type missing", edits: []edit{{"type = \"bws\"\n", ""}},
			want: "[store.main] type: is missing"},
		{name: "store type unknown", edits: []edit{{`type = "bws"`, `type = "vault"`}},
			want: `[store.main] type: must be "bws" or "bw"`},
		{name: "store program missing", edits: []edit{{"program = \"{{dir}}/bin/bws\"\n", ""}},
			want: "[store.main] program: is missing"},
		{name: "store program relative", edits: []edit{{`program = "{{dir}}/bin/bws"`, `program = "bws"`}},
			want: "[store.main] program: must be an absolute path"},
		{name: "bws without token_file", edits: []edit{{"token_file = \"${CREDENTIALS_DIRECTORY}/bws-token\"\n", ""}},
			want: `[store.main] token_file: is missing; type = "bws" needs it`},
		{name: "bws with password_file", edits: []edit{{`token_file = "${CREDENTIALS_DIRECTORY}/bws-token"`,
			"token_file = \"${CREDENTIALS_DIRECTORY}/bws-token\"\npassword_file = \"${CREDENTIALS_DIRECTORY}/bw-master-password\""}},
			want: `[store.main] password_file: is not allowed with type = "bws"`},
		{name: "bw without password_file", edits: []edit{{"password_file = \"${CREDENTIALS_DIRECTORY}/bw-master-password\"\n", ""}},
			want: `[store.vault] password_file: is missing; type = "bw" needs it`},
		{name: "bw with token_file", edits: []edit{{`password_file = "${CREDENTIALS_DIRECTORY}/bw-master-password"`,
			"password_file = \"${CREDENTIALS_DIRECTORY}/bw-master-password\"\ntoken_file = \"${CREDENTIALS_DIRECTORY}/bws-token\""}},
			want: `[store.vault] token_file: is not allowed with type = "bw"`},

		// [secret.*]
		{name: "secret name with a space", edits: []edit{{"[secret.github-token]", `[secret."github token"]`}},
			want: "[secret.*]: the name of a section must be", notWant: "github token"},
		{name: "secret store missing", edits: []edit{{"store = \"main\"\nid = \"00000000-0000-0000-0000-000000000001\"", `id = "00000000-0000-0000-0000-000000000001"`}},
			want: "[secret.github-token] store: is missing"},
		{name: "secret store unknown", edits: []edit{{`store = "main"`, `store = "mian"`}},
			want: "[secret.github-token] store: no [store.*] section has this name", notWant: "mian"},
		{name: "secret id missing", edits: []edit{{"id = \"00000000-0000-0000-0000-000000000001\"\n", ""}},
			want: "[secret.github-token] id: is missing"},
		{name: "secret id not a UUID", edits: []edit{{`id = "00000000-0000-0000-0000-000000000001"`, `id = "github SECRET token"`}},
			want: "[secret.github-token] id: must be the item's ID in the store, a UUID", notWant: "SECRET"},
		{name: "secret id with an option", edits: []edit{{`id = "00000000-0000-0000-0000-000000000001"`, `id = "--help"`}},
			want: "[secret.github-token] id: must be"},
		{name: "secret clients missing", edits: []edit{{"clients = [\"laptop\"]\nask = \"window\"", `ask = "window"`}},
			want: "[secret.github-token] clients: is missing or empty"},
		{name: "secret clients empty", edits: []edit{{`clients = ["laptop"]`, `clients = []`}},
			want: "[secret.github-token] clients: is missing or empty"},
		{name: "secret client unknown", edits: []edit{{`clients = ["laptop"]`, `clients = ["laptop", "desktop"]`}},
			want: "[secret.github-token] clients: item 2 is not a [client.*] section", notWant: "desktop"},
		{name: "secret client twice", edits: []edit{{`clients = ["laptop"]`, `clients = ["laptop", "laptop"]`}},
			want: "[secret.github-token] clients: item 2 is listed twice"},

		// rules
		{name: "ask missing", edits: []edit{{"ask = \"window\"\nwindow = \"15m\"", ""}},
			want: `[secret.github-token] ask: is missing; use "always", "window" or "never"`},
		{name: "ask unknown", edits: []edit{{`ask = "window"`, `ask = "sometimes"`}},
			want: `[secret.github-token] ask: must be "always", "window" or "never"`, notWant: "sometimes"},
		{name: "ask in upper case", edits: []edit{{`ask = "window"`, `ask = "Window"`}},
			want: `[secret.github-token] ask: must be "always", "window" or "never"`},
		{name: "always with window", edits: []edit{{`ask = "always"`, "ask = \"always\"\nwindow = \"15m\""}},
			want: `[secret.db-password] window: is not allowed with ask = "always"`},
		{name: "always with notify", edits: []edit{{`ask = "always"`, "ask = \"always\"\nnotify = true"}},
			want: `[secret.db-password] notify: is not allowed with ask = "always"`},
		{name: "always with max_per_day", edits: []edit{{`ask = "always"`, "ask = \"always\"\nmax_per_day = 1"}},
			want: `[secret.db-password] max_per_day: is not allowed with ask = "always"`},
		{name: "always with hours", edits: []edit{{`ask = "always"`, "ask = \"always\"\nhours = \"03:00-03:20\""}},
			want: `[secret.db-password] hours: is not allowed with ask = "always"`},
		{name: "window rule without window", edits: []edit{{"ask = \"window\"\nwindow = \"15m\"", `ask = "window"`}},
			want: `[secret.github-token] window: is missing; ask = "window" needs it`},
		{name: "window zero", edits: []edit{{`window = "15m"`, `window = "0s"`}},
			want: "[secret.github-token] window: must be at least 1m and at most 8h"},
		{name: "window negative", edits: []edit{{`window = "15m"`, `window = "-15m"`}},
			want: "[secret.github-token] window: must be at least 1m and at most 8h"},
		{name: "window under a minute", edits: []edit{{`window = "15m"`, `window = "59s"`}},
			want: "[secret.github-token] window: must be at least 1m and at most 8h"},
		{name: "window too long", edits: []edit{{`window = "15m"`, `window = "8h0m1s"`}},
			want: "[secret.github-token] window: must be at least 1m and at most 8h"},
		{name: "window not a duration", edits: []edit{{`window = "15m"`, `window = "15 minutes"`}},
			want: "[secret.github-token] window: must be a duration", notWant: "15 minutes"},
		{name: "window as a number", edits: []edit{{`window = "15m"`, `window = 15`}},
			want: "incompatible types"},
		{name: "window with notify", edits: []edit{{`window = "15m"`, "window = \"15m\"\nnotify = false"}},
			want: `[secret.github-token] notify: is not allowed with ask = "window"`},
		{name: "window with max_per_day", edits: []edit{{`window = "15m"`, "window = \"15m\"\nmax_per_day = 3"}},
			want: `[secret.github-token] max_per_day: is not allowed with ask = "window"`},
		{name: "window with hours", edits: []edit{{`window = "15m"`, "window = \"15m\"\nhours = \"03:00-03:20\""}},
			want: `[secret.github-token] hours: is not allowed with ask = "window"`},
		{name: "never with window", edits: []edit{{`hours = "23:30-00:30"`, "hours = \"23:30-00:30\"\nwindow = \"15m\""}},
			want: `[secret.backup-token] window: is not allowed with ask = "never"`},
		{name: "never with two clients", edits: []edit{{"clients = [\"backup-box\"]\nask = \"never\"\nhours", "clients = [\"backup-box\", \"laptop\"]\nask = \"never\"\nhours"}},
			want: `[secret.backup-token] clients: ask = "never" needs exactly one client`},
		{name: "never with max_per_day zero", edits: []edit{{"max_per_day = 2", "max_per_day = 0"}},
			want: "[secret.backup-token] max_per_day: must be 1 or more; for no limit, leave max_per_day out"},
		{name: "never with a negative max_per_day", edits: []edit{{"max_per_day = 2", "max_per_day = -1"}},
			want: "[secret.backup-token] max_per_day: must be 1 or more"},
		{name: "two never secrets for one store item", edits: []edit{{"[key.deploy]",
			"[secret.backup-token-2]\nstore = \"main\"\nid = \"00000000-0000-0000-0000-00000000000B\"\n" +
				"clients = [\"laptop\"]\nask = \"never\"\n\n[key.deploy]"}},
			want: `[secret.backup-token-2] id: [secret.backup-token] also has ask = "never" for this item ID`},
		{name: "two never secrets for one item through two stores", edits: []edit{{"[key.deploy]",
			"[store.main-2]\ntype = \"bws\"\nprogram = \"{{dir}}/bin/bws\"\ntoken_file = \"${CREDENTIALS_DIRECTORY}/bws-token\"\n\n" +
				"[secret.backup-token-2]\nstore = \"main-2\"\nid = \"00000000-0000-0000-0000-00000000000b\"\n" +
				"clients = [\"laptop\"]\nask = \"never\"\n\n[key.deploy]"}},
			want: `[secret.backup-token-2] id: [secret.backup-token] also has ask = "never" for this item ID`},
		{name: "never with notify not a bool", edits: []edit{{"notify = false", `notify = "no"`}},
			want: "incompatible types"},
		{name: "hours without a leading zero", edits: []edit{{`hours = "23:30-00:30"`, `hours = "3:00-3:20"`}},
			want: `[secret.backup-token] hours: must look like "03:00-03:20"`, notWant: "3:00-3:20"},
		{name: "hours with one time", edits: []edit{{`hours = "23:30-00:30"`, `hours = "03:00"`}},
			want: `[secret.backup-token] hours: must look like "03:00-03:20"`},
		{name: "hours with hour 24", edits: []edit{{`hours = "23:30-00:30"`, `hours = "23:00-24:00"`}},
			want: `[secret.backup-token] hours: must look like "03:00-03:20"`},
		{name: "hours with minute 60", edits: []edit{{`hours = "23:30-00:30"`, `hours = "03:60-04:00"`}},
			want: `[secret.backup-token] hours: must look like "03:00-03:20"`},
		{name: "hours with spaces", edits: []edit{{`hours = "23:30-00:30"`, `hours = "03:00 - 03:20"`}},
			want: `[secret.backup-token] hours: must look like "03:00-03:20"`},
		{name: "hours that start and end at one time", edits: []edit{{`hours = "23:30-00:30"`, `hours = "03:00-03:00"`}},
			want: "[secret.backup-token] hours: the start and the end must differ"},

		// [key.*]
		{name: "key name with a slash", edits: []edit{{"[key.deploy]", `[key."deploy/1"]`}},
			want: "[key.*]: the name of a section must be", notWant: "deploy/1"},
		{name: "key file missing", edits: []edit{{"file = \"${CREDENTIALS_DIRECTORY}/ssh-deploy\"\n", ""}},
			want: "[key.deploy] file: is missing"},
		{name: "key file relative", edits: []edit{{"${CREDENTIALS_DIRECTORY}/ssh-deploy", "ssh-deploy"}},
			want: "[key.deploy] file: must be an absolute path"},
		{name: "key clients missing", edits: []edit{{"clients = [\"laptop\"]\nask = \"window\"\nwindow = \"15m\"\nhosts", "ask = \"window\"\nwindow = \"15m\"\nhosts"}},
			want: "[key.deploy] clients: is missing or empty"},
		{name: "key client unknown", edits: []edit{{"clients = [\"laptop\"]\nask = \"window\"\nwindow = \"15m\"\nhosts", "clients = [\"desktop\"]\nask = \"window\"\nwindow = \"15m\"\nhosts"}},
			want: "[key.deploy] clients: item 1 is not a [client.*] section"},
		{name: "key host unknown", edits: []edit{{`hosts = ["web-1", "web-2"]`, `hosts = ["web-1", "web-3"]`}},
			want: "[key.deploy] hosts: item 2 is not a host in known_hosts", notWant: "web-3"},
		{name: "key host twice", edits: []edit{{`hosts = ["web-1", "web-2"]`, `hosts = ["web-1", "web-1"]`}},
			want: "[key.deploy] hosts: item 2 is listed twice"},
		{name: "key rule out of range", edits: []edit{{"window = \"15m\"\nhosts", "window = \"9h\"\nhosts"}},
			want: "[key.deploy] window: must be at least 1m and at most 8h"},
		{name: "never key without hosts", edits: []edit{{"hosts = [\"db-1\"]\n", ""}},
			want: `[key.backup] hosts: is missing; ask = "never" needs a list of hosts`},
		{name: "never key with empty hosts", edits: []edit{{`hosts = ["db-1"]`, `hosts = []`}},
			want: `[key.backup] hosts: is missing; ask = "never" needs a list of hosts`},
		{name: "never key with two clients", edits: []edit{{"clients = [\"backup-box\"]\nask = \"never\"\nhosts", "clients = [\"backup-box\", \"laptop\"]\nask = \"never\"\nhosts"}},
			want: `[key.backup] clients: ask = "never" needs exactly one client`},
		{name: "two keys with one file", edits: []edit{{"[key.backup]",
			"[key.deploy-2]\nfile = \"${CREDENTIALS_DIRECTORY}/./ssh-deploy\"\nclients = [\"backup-box\"]\nask = \"always\"\n\n[key.backup]"}},
			want: "[key.deploy-2] file: [key.deploy] uses the same file"},

		// known_hosts
		{name: "known_hosts file missing", edits: []edit{{"{{dir}}/known_hosts", "{{dir}}/no-such-file"}},
			want: "known_hosts: lstat "},
		{name: "known_hosts file not valid", knownHosts: "web-1 ssh-ed25519 AAAA\n",
			want: "/known_hosts: line 1: the key is not a valid SSH public key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			if tt.knownHosts != "" {
				writeFile(t, e.dir, "known_hosts", tt.knownHosts, 0o644)
			}
			if tt.knownHostsMode != 0 {
				if err := os.Chmod(filepath.Join(e.dir, "known_hosts"), tt.knownHostsMode); err != nil {
					t.Fatal(err)
				}
			}
			if tt.unsetCreds {
				if err := os.Unsetenv("CREDENTIALS_DIRECTORY"); err != nil {
					t.Fatal(err)
				}
			}
			if tt.setup != nil {
				tt.setup(t, e)
			}
			path := e.write(t, tt.edits...)
			if tt.configMode != 0 {
				if err := os.Chmod(path, tt.configMode); err != nil {
					t.Fatal(err)
				}
			}
			b, err := LoadBroker(path)
			if b != nil {
				t.Errorf("LoadBroker returned a config with the error")
			}
			checkError(t, err, tt.want, tt.notWant)
			checkError(t, err, path, "")
		})
	}
}

// TestLoadBrokerHidesPastedText pastes a made-up token where a mistake
// could put one: as a key, as a section name, and as each kind of value.
// No error shows it.
func TestLoadBrokerHidesPastedText(t *testing.T) {
	// tok has characters that no name or key may have.
	const tok = "ghpMadeUp+Tok/en:0123456789Zz=="
	// noColon is tok without ":", so that it can stand where listen has a
	// host or a zone.
	noColon := strings.ReplaceAll(tok, ":", "")
	// lower17 is lower case text of 17 characters that starts with a
	// letter: one more than an error shows as a part of a key name.
	const lower17 = "a3f9c0d1e2b4a5968"
	// nameTok follows the name rule, but has upper case letters, so it is
	// not shown as a key name.
	const nameTok = "Made_up_token_for_tests_0123456789_ABCDEF"
	const listen = `listen = "192.0.2.10:7743"`
	const userID = "user_id = 123456789"
	tests := []struct {
		name  string
		edits []edit
		hide  string // the text that no error may show
	}{
		// keys and section names
		{"a quoted key at the top", []edit{{listen, listen + "\n\"" + tok + "\" = 1"}}, tok},
		{"a quoted key in [telegram]", []edit{{userID, userID + "\n\"" + tok + "\" = 1"}}, tok},
		{"a section name", []edit{{"[secret.db-password]", "[secret.\"" + tok + "\"]"}}, tok},
		{"a section kind", []edit{{"[secret.db-password]", "[\"" + tok + "\".x]"}}, tok},
		{"a section name in a dotted key", []edit{{listen, listen + "\nsecret.\"" + tok + "\".ask = \"never\""}}, tok},
		{"a section name, and a value of the wrong type", []edit{
			{"[secret.db-password]", "[secret.\"" + tok + "\"]"}, {`ask = "always"`, "ask = 1"}}, tok},
		{"a subtable of a valid section", []edit{
			{"[secret.db-password]", "[secret.db-password.\"" + tok + "\"]\nx = 1\n[secret.db-password]"}}, tok},
		{"an array of tables", []edit{{"hosts = [\"db-1\"]\n", "hosts = [\"db-1\"]\n\n[[\"" + tok + "\"]]\nx = 1\n"}}, tok},
		{"a key in an inline table", []edit{{listen, listen + "\nx = { \"" + tok + "\" = 1 }"}}, tok},
		{"a key in an inline table in hosts", []edit{{`hosts = ["db-1"]`, `hosts = [{ "` + tok + `" = 1 }]`}}, tok},
		{"a quoted key with an escaped newline", []edit{{userID, userID + "\n\"" + tok + "\\nX\" = 1"}}, tok},
		{"a key twice", []edit{{userID, userID + "\n\"" + tok + "\" = 1\n\"" + tok + "\" = 2"}}, tok},
		{"a key after a date as listen", []edit{{listen, "listen = 1979-05-27T07:32:00Z\n\"" + tok + "\" = 1"}}, tok},
		{"the name of an embedded Go field", []edit{{`ask = "always"`, "ask = \"always\"\nruleKeys = \"" + tok + "\""}}, tok},
		{"the name of an embedded Go field in lower case", []edit{
			{`ask = "always"`, "ask = \"always\"\nrulekeys = { ask = \"" + tok + "\" }"}}, tok},
		{"lower case text of 17 characters as a key", []edit{{listen, listen + "\n" + lower17 + " = 1"}}, lower17},
		{"a name with upper case letters as a key", []edit{{userID, userID + "\n" + nameTok + " = 1"}}, nameTok},

		// values
		{"listen", []edit{{listen, `listen = "` + tok + `"`}}, tok},
		{"the host in listen", []edit{{listen, `listen = "` + noColon + `:7743"`}}, "MadeUp"},
		{"the zone in listen", []edit{{listen, `listen = "[fe80::1%` + noColon + `]:7743"`}}, "MadeUp"},
		{"ask", []edit{{`ask = "always"`, `ask = "` + tok + `"`}}, tok},
		{"window", []edit{{`window = "15m"`, `window = "` + tok + `"`}}, tok},
		{"hours", []edit{{`hours = "23:30-00:30"`, `hours = "` + tok + `"`}}, tok},
		{"pin", []edit{{"pin = \"{{pin laptop}}\"", `pin = "` + tok + `"`}}, tok},
		{"id", []edit{{`id = "00000000-0000-0000-0000-00000000000A"`, `id = "` + tok + `"`}}, tok},
		{"store", []edit{{`store = "vault"`, `store = "` + tok + `"`}}, tok},
		{"type", []edit{{`type = "bw"`, `type = "` + tok + `"`}}, tok},
		{"an item of clients", []edit{{`clients = ["laptop", "backup-box"]`, `clients = ["laptop", "` + tok + `"]`}}, tok},
		{"an item of hosts", []edit{{`hosts = ["db-1"]`, `hosts = ["` + tok + `"]`}}, tok},
		{"user_id as a string", []edit{{userID, `user_id = "` + tok + `"`}}, tok},
		{"notify as a string", []edit{{"notify = false", `notify = "` + tok + `"`}}, tok},
		{"max_per_day as a string", []edit{{"max_per_day = 2", `max_per_day = "` + tok + `"`}}, tok},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			path := e.write(t, tt.edits...)
			b, err := LoadBroker(path)
			if b != nil {
				t.Error("LoadBroker returned a config with the error")
			}
			checkError(t, err, "config "+path+": ", tt.hide)
		})
	}
}

// TestLoadBrokerShowsNormalNames shows where the hiding stops (DESIGN.md
// section 14). An error shows a key name whose parts have up to 16 lower
// case letters, digits and "_", so that a typo is easy to find. It shows a
// section name that follows the name rule, because approval messages show
// that name anyway. So text pasted there by mistake is shown too.
func TestLoadBrokerShowsNormalNames(t *testing.T) {
	const lower16 = "a3f9c0d1e2b4a596" // made up, 16 characters
	const nameTok = "Made_up_token_for_tests_0123456789_ABCDEF"
	const listen = `listen = "192.0.2.10:7743"`
	tests := []struct {
		name  string
		edits []edit
		want  string
	}{
		{"lower case text of 16 characters as a key", []edit{{listen, listen + "\n" + lower16 + " = 1"}},
			`unknown key "` + lower16 + `"`},
		{"a section name that follows the name rule", []edit{{"[secret.db-password]", "[secret." + nameTok + "]\naks = 1"}},
			`unknown key "secret.` + nameTok + `.aks"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			_, err := LoadBroker(e.write(t, tt.edits...))
			checkError(t, err, tt.want, "")
		})
	}
}

func TestLoadBrokerTableExpected(t *testing.T) {
	for _, data := range []string{
		"client = \"laptop\"\n",
		"store = 1\n",
		"secret = [\"github-token\"]\n",
		"[[key]]\nfile = \"/tmp/x\"\n",
	} {
		path := writeFile(t, privateTempDir(t), "broker.toml", data, 0o644)
		_, err := LoadBroker(path)
		checkError(t, err, "must be a table", "")
	}
}

func TestLoadBrokerMissingFile(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "broker.toml")
	_, err := LoadBroker(path)
	checkError(t, err, "config "+path+": lstat "+path+": no such file or directory", "")
}

func TestCheckFiles(t *testing.T) {
	e := newBrokerEnv(t)
	path := e.write(t)
	b, err := LoadBroker(path)
	if err != nil {
		t.Fatalf("LoadBroker: %v", err)
	}
	if err := b.CheckFiles(); err != nil {
		t.Fatalf("CheckFiles on private files: %v", err)
	}

	// Each private file, one at a time, with a mode that is too open.
	private := []struct {
		file string
		mode os.FileMode
		want string
	}{
		{"broker-tls-key", 0o604, "tls_key: "},
		{"telegram-token", 0o640, "[telegram] token_file: "},
		{"bws-token", 0o644, "[store.main] token_file: "},
		{"bw-master-password", 0o660, "[store.vault] password_file: "},
		{"ssh-deploy", 0o640, "[key.deploy] file: "},
		{"ssh-backup", 0o602, "[key.backup] file: "},
	}
	for _, tt := range private {
		t.Run(tt.file, func(t *testing.T) {
			p := filepath.Join(e.creds, tt.file)
			chmod(t, p, tt.mode)
			checkError(t, b.CheckFiles(), "config "+path+": "+tt.want+p+": ", "made-up")
		})
	}

	t.Run("private file is missing", func(t *testing.T) {
		p := filepath.Join(e.creds, "ssh-backup")
		if err := os.Rename(p, p+".away"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Rename(p+".away", p); err != nil {
				t.Fatal(err)
			}
		}()
		checkError(t, b.CheckFiles(), "[key.backup] file: lstat "+p, "")
	})

	t.Run("private file is a symbolic link", func(t *testing.T) {
		p := filepath.Join(e.creds, "telegram-token")
		if err := os.Rename(p, p+".real"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p+".real", p); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(p+".real", p); err != nil {
				t.Fatal(err)
			}
		}()
		checkError(t, b.CheckFiles(), "[telegram] token_file: "+p+": is a symbolic link", "")
	})

	t.Run("credentials directory writable by group", func(t *testing.T) {
		chmod(t, e.creds, 0o770)
		checkError(t, b.CheckFiles(), "tls_key: "+e.creds+": group or others can write to this directory (mode 0770)", "")
	})

	t.Run("directory above the credentials directory writable by others", func(t *testing.T) {
		chmod(t, filepath.Dir(e.creds), 0o707)
		checkError(t, b.CheckFiles(), "tls_key: "+filepath.Dir(e.creds)+": group or others can write to this directory (mode 0707)", "")
	})

	bws := filepath.Join(e.dir, "bin", "bws")
	t.Run("program writable by group", func(t *testing.T) {
		chmod(t, bws, 0o775)
		checkError(t, b.CheckFiles(), "[store.main] program: "+bws+": group or others can write to it (mode 0775)", "")
	})

	t.Run("program directory writable by others", func(t *testing.T) {
		chmod(t, filepath.Join(e.dir, "bin"), 0o757)
		checkError(t, b.CheckFiles(), "[store.main] program: "+filepath.Join(e.dir, "bin")+": group or others can write to this directory", "")
	})

	t.Run("program is missing", func(t *testing.T) {
		if err := os.Rename(bws, bws+".away"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Rename(bws+".away", bws); err != nil {
				t.Fatal(err)
			}
		}()
		checkError(t, b.CheckFiles(), "[store.main] program: lstat "+bws, "")
	})

	t.Run("program is a link to a safe program", func(t *testing.T) {
		// The target is in a directory that is not above the link.
		elsewhere := mkdir(t, filepath.Dir(e.dir), "elsewhere", 0o755)
		target := filepath.Join(elsewhere, "bws-real")
		if err := os.Rename(bws, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, bws); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Remove(bws); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(target, bws); err != nil {
				t.Fatal(err)
			}
		}()
		if err := b.CheckFiles(); err != nil {
			t.Fatalf("CheckFiles: %v", err)
		}
		// The directory of the target counts too, and so does the target.
		for _, c := range []struct {
			path       string
			mode, back os.FileMode
			want       string
		}{
			{elsewhere, 0o770, 0o755, elsewhere + ": group or others can write to this directory"},
			{target, 0o757, 0o755, target + ": group or others can write to it (mode 0757)"},
		} {
			if err := os.Chmod(c.path, c.mode); err != nil {
				t.Fatal(err)
			}
			checkError(t, b.CheckFiles(), "[store.main] program: "+c.want, "")
			if err := os.Chmod(c.path, c.back); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("program through a link in a directory writable by others", func(t *testing.T) {
		// bin/bws -> hop/bws -> real/bws-real. The program and the
		// directories of the first link and of the program are safe, but
		// anyone can change where hop/bws points.
		real := mkdir(t, filepath.Dir(e.dir), "real", 0o755)
		hop := mkdir(t, filepath.Dir(e.dir), "hop", 0o777)
		target := filepath.Join(real, "bws-real")
		if err := os.Rename(bws, target); err != nil {
			t.Fatal(err)
		}
		symlink(t, symlink(t, target, filepath.Join(hop, "bws")), bws)
		defer func() {
			if err := os.Remove(bws); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(target, bws); err != nil {
				t.Fatal(err)
			}
		}()
		checkError(t, b.CheckFiles(), "[store.main] program: "+hop+": group or others can write to this directory (mode 0777)", "")
	})
}

// TestCheckFilesSameKeyFile names one key file in two [key.*] sections
// through two paths. The parse sees two paths; CheckFiles, which LoadBroker
// runs, sees one file.
func TestCheckFilesSameKeyFile(t *testing.T) {
	tests := []struct {
		name string
		file func(t *testing.T, e *brokerEnv) string // the second path to ssh-deploy
	}{
		{"through a hard link", func(t *testing.T, e *brokerEnv) string {
			p := filepath.Join(e.creds, "ssh-deploy-2")
			if err := os.Link(filepath.Join(e.creds, "ssh-deploy"), p); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"through a linked directory", func(t *testing.T, e *brokerEnv) string {
			return filepath.Join(symlink(t, e.creds, filepath.Join(e.dir, "creds-link")), "ssh-deploy")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			path := e.write(t, edit{"[key.backup]",
				"[key.deploy-2]\nfile = \"" + tt.file(t, e) + "\"\nclients = [\"laptop\"]\nask = \"always\"\n\n[key.backup]"})
			if _, err := loadBroker(path); err != nil {
				t.Fatalf("loadBroker: %v", err)
			}
			b, err := LoadBroker(path)
			if b != nil {
				t.Error("LoadBroker returned a config with the error")
			}
			checkError(t, err, "config "+path+": [key.deploy-2] file: is the same file as [key.deploy] file", "")
		})
	}
}

// TestLoadBrokerRunsCheckFiles checks that LoadBroker refuses a config
// whose files fail CheckFiles, so that no caller can skip the checks. The
// parse alone (loadBroker) passes.
func TestLoadBrokerRunsCheckFiles(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, e *brokerEnv)
		want  string // the error text after "config PATH: "
	}{
		{"TLS key readable by others", func(t *testing.T, e *brokerEnv) {
			chmod(t, filepath.Join(e.creds, "broker-tls-key"), 0o644)
		}, "tls_key: "},
		{"key file readable by group", func(t *testing.T, e *brokerEnv) {
			chmod(t, filepath.Join(e.creds, "ssh-deploy"), 0o640)
		}, "[key.deploy] file: "},
		{"store program writable by group", func(t *testing.T, e *brokerEnv) {
			chmod(t, filepath.Join(e.dir, "bin", "bw"), 0o775)
		}, "[store.vault] program: "},
		{"audit log readable by others", func(t *testing.T, e *brokerEnv) {
			writeFile(t, e.dir, "audit.jsonl", "", 0o644)
		}, "audit_log: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			path := e.write(t)
			tt.setup(t, e)
			if _, err := loadBroker(path); err != nil {
				t.Fatalf("loadBroker: %v", err)
			}
			b, err := LoadBroker(path)
			if b != nil {
				t.Error("LoadBroker returned a config with the error")
			}
			checkError(t, err, "config "+path+": "+tt.want, "made-up")
		})
	}
}

// TestLoadBrokerListen checks the forms of listen that are allowed.
func TestLoadBrokerListen(t *testing.T) {
	e := newBrokerEnv(t)
	for in, want := range map[string]string{
		"192.0.2.10:7743":          "192.0.2.10:7743",
		"127.0.0.1:1":              "127.0.0.1:1",
		"[2001:db8::10]:65535":     "[2001:db8::10]:65535",
		"[::1]:7743":               "[::1]:7743",
		"169.254.10.20:7743":       "169.254.10.20:7743", // IPv4 link-local may stay
		"[::ffff:192.0.2.10]:7743": "192.0.2.10:7743",    // taken as the IPv4 address
	} {
		b, err := LoadBroker(e.write(t, edit{`listen = "192.0.2.10:7743"`, `listen = "` + in + `"`}))
		if err != nil {
			t.Errorf("listen = %q: %v", in, err)
			continue
		}
		if got := b.Listen.String(); got != want {
			t.Errorf("listen = %q: Listen = %s, want %s", in, got, want)
		}
	}
}

// TestParseListen checks many forms of listen on parseListen itself. An
// error never repeats the value.
func TestParseListen(t *testing.T) {
	const (
		every     = "listen: 0.0.0.0 and :: are not allowed"
		multicast = "listen: a multicast or broadcast address is not allowed"
		zone      = "listen: an IPv6 zone (the part after %) is not allowed"
		linkLocal = "listen: an IPv6 link-local address (fe80::/10) is not allowed"
		form      = "listen: must be an IP address and a port"
		port      = "listen: the port must be a number from 1 to 65535"
	)
	tests := []struct {
		in   string
		want string // the address when it is allowed, or the start of the error
		hide string // text the error must not hold; "" means all of in
	}{
		// Allowed. An IPv4 address in IPv6 form is the IPv4 address. IPv4
		// link-local (169.254.0.0/16) may stay.
		{in: "192.0.2.10:7743", want: "192.0.2.10:7743"},
		{in: "[192.0.2.10]:7743", want: "192.0.2.10:7743"},
		{in: "192.0.2.10:07743", want: "192.0.2.10:7743"},
		{in: "127.0.0.1:7743", want: "127.0.0.1:7743"},
		{in: "[::1]:7743", want: "[::1]:7743"},
		{in: "[2001:db8::10]:7743", want: "[2001:db8::10]:7743"},
		{in: "[::ffff:127.0.0.1]:1", want: "127.0.0.1:1"},
		{in: "169.254.10.20:7743", want: "169.254.10.20:7743"},
		{in: "[::ffff:169.254.10.20]:7743", want: "169.254.10.20:7743"},

		// Any IPv6 zone, also on an IPv4 address in IPv6 form, and any IPv6
		// link-local address, with or without a zone.
		{in: "[fe80::1%eth0]:7743", want: zone, hide: "eth0"},
		{in: "[fe80::1%a made-up zone/with\nSECRET]:7743", want: zone, hide: "made-up"},
		{in: "[2001:db8::10%eth0]:7743", want: zone, hide: "eth0"},
		{in: "[::1%lo]:7743", want: zone, hide: "%lo"},
		{in: "[::ffff:192.0.2.10%eth0]:1", want: zone, hide: "eth0"},
		{in: "[fe80::1%1]:7743", want: zone, hide: "%1"},
		{in: "[fe80::1]:7743", want: linkLocal, hide: "fe80::1"},
		{in: "[febf:ffff::1]:7743", want: linkLocal, hide: "febf"},

		// Every network.
		{in: "0.0.0.0:7743", want: every},
		{in: "[::]:7743", want: every},
		{in: "[0::]:7743", want: every},
		{in: "[0:0:0:0:0:0:0:0]:7743", want: every},
		{in: "[::0.0.0.0]:7743", want: every},
		{in: "[::ffff:0:0]:7743", want: every},
		{in: "[::ffff:0.0.0.0%eth0]:7743", want: every, hide: "eth0"},
		{in: "[::%25eth0]:7743", want: every, hide: "eth0"},

		// Multicast, also link-local and interface-local, and broadcast.
		{in: "224.0.0.1:7743", want: multicast, hide: "224."},
		{in: "239.0.0.1:7743", want: multicast, hide: "239."},
		{in: "[::ffff:224.0.0.1]:7743", want: multicast, hide: "224."},
		{in: "[ff02::1]:7743", want: multicast, hide: "ff02"},
		{in: "[ff02::1%eth0]:7743", want: zone, hide: "eth0"},
		{in: "[ff01::1]:7743", want: multicast, hide: "ff01"},
		{in: "[ff0e::1]:7743", want: multicast, hide: "ff0e"},
		{in: "255.255.255.255:7743", want: multicast, hide: "255."},
		{in: "[::ffff:255.255.255.255]:7743", want: multicast, hide: "255."},

		// Not an IP address and a port.
		{in: "", want: "listen: is missing"},
		{in: ":7743", want: "listen: the IP address is missing"},
		{in: "192.0.2.10:+7743", want: port},
		{in: "192.0.2.10:7743 ", want: port},
		{in: "192.0.2.10:7743\n", want: port},
		{in: "192.0.2.10:0", want: port},
		{in: "192.0.2.10:65536", want: port},
		{in: " 192.0.2.10:7743", want: form},
		{in: "192.0.2.10%eth0:7743", want: form, hide: "eth0"},
		{in: "192.0.2.10:7743:1", want: form},
		{in: "192.0.2.10::7743", want: form},
		{in: "192.0.2:7743", want: form},
		{in: "0x7f.0.0.1:7743", want: form, hide: "0x7f"},
		{in: "web-1.example.com:7743", want: form, hide: "web-1"},
	}
	for _, tt := range tests {
		ap, err := parseListen(tt.in)
		if !strings.HasPrefix(tt.want, "listen:") {
			if err != nil || ap.String() != tt.want {
				t.Errorf("parseListen(%q) = %v, %v; want %s", tt.in, ap, err, tt.want)
			}
			continue
		}
		if ap.IsValid() {
			t.Errorf("parseListen(%q) returned %v with the error", tt.in, ap)
		}
		hide := tt.hide
		if hide == "" && tt.in != "" {
			hide = tt.in
		}
		checkError(t, err, tt.want, hide)
	}
}

// listenMarks stand for text pasted into listen by mistake. pasteMark
// holds ":", so it can never be a whole host or port. The others can: a
// word can be a host name or a zone, and a number can be a port.
var listenMarks = []string{pasteMark, "SECRETword", "86420975"}

// FuzzParseListenDoesNotRepeatText checks that an error from parseListen
// never shows one of listenMarks, and that an address it allows is the
// address of one machine, with no zone and a port.
func FuzzParseListenDoesNotRepeatText(f *testing.F) {
	for _, s := range []string{
		"SEC+RET:7743", "[SEC+RET:]:1", "192.0.2.10:SEC+RET:", "[fe80::1%SEC+RET:]:1",
		"[ff02::1%SEC+RET:]:7743", "224.0.0.1:7743", "255.255.255.255:7743", "[::ffff:0.0.0.0]:7743",
		"SECRETword:7743", "[SECRETword]:7743", "192.0.2.10:SECRETword", "[fe80::1%SECRETword]:7743",
		"192.0.2.10%SECRETword:7743", "[::ffff:192.0.2.10%SECRETword]:7743", "[2001:db8::10%SECRETword]:1",
		"86420975:7743", "192.0.2.10:86420975", "[fe80::1%86420975]:7743", "[fe80::1]:7743",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ap, err := parseListen(s)
		if err != nil {
			for _, mark := range listenMarks {
				if strings.Contains(err.Error(), mark) {
					t.Fatalf("the error shows the mark %q: %v", mark, err)
				}
			}
			return
		}
		// "%" can only start a zone, and a zone is refused, also when the
		// address would drop it.
		a := ap.Addr()
		if strings.Contains(s, "%") || !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() ||
			a == ipv4Broadcast || (a.Is6() && a.IsLinkLocalUnicast()) || a.Is4In6() || ap.Port() == 0 {
			t.Fatalf("parseListen(%q) = %v; want an error", s, ap)
		}
	})
}

// TestLoadBrokerAuditLog checks audit_log: the directories on the way, and
// the file when it is there. When it is missing, the broker makes it.
func TestLoadBrokerAuditLog(t *testing.T) {
	tests := []struct {
		name string
		path func(t *testing.T, e *brokerEnv) string // makes the setup; returns audit_log
		want string                                  // "" means no error
	}{
		{name: "missing", path: func(_ *testing.T, e *brokerEnv) string {
			return filepath.Join(e.dir, "audit.jsonl")
		}},
		{name: "private", path: func(t *testing.T, e *brokerEnv) string {
			return writeFile(t, e.dir, "audit.jsonl", "{}\n", 0o600)
		}},
		{name: "readable by group", path: func(t *testing.T, e *brokerEnv) string {
			return writeFile(t, e.dir, "audit.jsonl", "", 0o640)
		}, want: "/audit.jsonl: group or others have access (mode 0640); it must be private to its owner"},
		{name: "writable by others", path: func(t *testing.T, e *brokerEnv) string {
			return writeFile(t, e.dir, "audit.jsonl", "", 0o602)
		}, want: "/audit.jsonl: group or others have access (mode 0602)"},
		{name: "runnable by its owner", path: func(t *testing.T, e *brokerEnv) string {
			return writeFile(t, e.dir, "audit.jsonl", "", 0o700)
		}, want: "/audit.jsonl: its owner may run it as a program (mode 0700)"},
		{name: "a symbolic link to a private file", path: func(t *testing.T, e *brokerEnv) string {
			target := writeFile(t, e.dir, "real.jsonl", "", 0o600)
			return symlink(t, target, filepath.Join(e.dir, "audit.jsonl"))
		}, want: "/audit.jsonl: is a symbolic link"},
		{name: "a directory", path: func(t *testing.T, e *brokerEnv) string {
			return mkdir(t, e.dir, "audit.jsonl", 0o700)
		}, want: "/audit.jsonl: is not a regular file"},
		{name: "in a directory writable by others", path: func(t *testing.T, e *brokerEnv) string {
			return writeFile(t, mkdir(t, e.dir, "open", 0o777), "audit.jsonl", "", 0o666)
		}, want: "/open: group or others can write to this directory (mode 0777)"},
		{name: "missing, in a directory writable by group", path: func(t *testing.T, e *brokerEnv) string {
			return filepath.Join(mkdir(t, e.dir, "shared", 0o770), "audit.jsonl")
		}, want: "/shared: group or others can write to this directory (mode 0770)"},
		{name: "through a link that is in a directory writable by others", path: func(t *testing.T, e *brokerEnv) string {
			logs := mkdir(t, e.dir, "logs", 0o700)
			return filepath.Join(symlink(t, logs, filepath.Join(mkdir(t, e.dir, "open-links", 0o777), "logs")), "audit.jsonl")
		}, want: "/open-links: group or others can write to this directory (mode 0777)"},
		{name: "in a missing directory", path: func(_ *testing.T, e *brokerEnv) string {
			return filepath.Join(e.dir, "no-such-dir", "audit.jsonl")
		}, want: "/no-such-dir: no such file or directory"},
		{name: "a path that ends in a slash", path: func(_ *testing.T, e *brokerEnv) string {
			return e.dir + "/"
		}, want: ": is a directory, not a file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			audit := tt.path(t, e)
			path := e.write(t, edit{"{{dir}}/audit.jsonl", audit})
			b, err := LoadBroker(path)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("LoadBroker: %v", err)
				}
				if b.AuditLog != audit {
					t.Errorf("AuditLog = %q, want %q", b.AuditLog, audit)
				}
				return
			}
			if b != nil {
				t.Error("LoadBroker returned a config with the error")
			}
			checkError(t, err, "config "+path+": audit_log: ", "")
			checkError(t, err, tt.want, "")
		})
	}
}

// TestCheckFilesAuditLogIsAnotherFile names another file that the broker
// reads or runs as the audit log: a key, token or password file (by its own
// path, through a hard link, and through a linked directory), a store's
// program, the config file and known_hosts. The broker would add its lines
// to that file, and a copy of the log would hold what the file holds.
// CheckFiles, which LoadBroker runs, refuses it: by its mode when the mode
// gives more than read and write to the owner, and else because it is the
// same file. The parse alone (loadBroker) passes.
func TestCheckFilesAuditLogIsAnotherFile(t *testing.T) {
	creds := func(name string) func(*testing.T, *brokerEnv) string {
		return func(_ *testing.T, e *brokerEnv) string { return filepath.Join(e.creds, name) }
	}
	inDir := func(name string) func(*testing.T, *brokerEnv) string {
		return func(_ *testing.T, e *brokerEnv) string { return filepath.Join(e.dir, name) }
	}
	const own = "; the audit log must be a file of its own"
	tests := []struct {
		name  string
		audit func(t *testing.T, e *brokerEnv) string // returns audit_log
		mode  os.FileMode                             // when not 0, the mode audit_log gets after the config is written
		want  string                                  // the error after "audit_log: "
	}{
		{"the TLS key", creds("broker-tls-key"), 0, "is the same file as tls_key" + own},
		{"the Telegram token", creds("telegram-token"), 0, "is the same file as [telegram] token_file" + own},
		{"the bws token", creds("bws-token"), 0, "is the same file as [store.main] token_file" + own},
		{"the bw master password", creds("bw-master-password"), 0, "is the same file as [store.vault] password_file" + own},
		{"an SSH key", creds("ssh-deploy"), 0, "is the same file as [key.deploy] file" + own},
		{"a hard link to an SSH key", func(t *testing.T, e *brokerEnv) string {
			p := filepath.Join(e.dir, "audit.jsonl")
			if err := os.Link(filepath.Join(e.creds, "ssh-backup"), p); err != nil {
				t.Fatal(err)
			}
			return p
		}, 0, "is the same file as [key.backup] file" + own},
		{"an SSH key through a linked directory", func(t *testing.T, e *brokerEnv) string {
			return filepath.Join(symlink(t, e.creds, filepath.Join(e.dir, "creds-link")), "ssh-deploy")
		}, 0, "is the same file as [key.deploy] file" + own},

		// With mode 0600, the other files pass the audit log's own check,
		// but they are the same file.
		{"a store program", inDir("bin/bws"), 0o600, "is the same file as [store.main] program" + own},
		{"the config file", inDir("broker.toml"), 0o600, "is the same file as the config file" + own},
		{"known_hosts", inDir("known_hosts"), 0o600, "is the same file as known_hosts" + own},

		// With their usual modes, the audit log's own check refuses them.
		{"a store program that only its owner may run", inDir("bin/bws"), 0o700,
			"/bin/bws: its owner may run it as a program (mode 0700)"},
		{"a store program that anyone may run", inDir("bin/bw"), 0, "/bin/bw: group or others have access (mode 0755)"},
		{"the config file, readable by anyone", inDir("broker.toml"), 0, "/broker.toml: group or others have access (mode 0644)"},
		{"known_hosts, readable by anyone", inDir("known_hosts"), 0, "/known_hosts: group or others have access (mode 0644)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			audit := tt.audit(t, e)
			path := e.write(t, edit{"{{dir}}/audit.jsonl", audit})
			if tt.mode != 0 {
				chmod(t, audit, tt.mode)
			}
			if _, err := loadBroker(path); err != nil {
				t.Fatalf("loadBroker: %v", err)
			}
			b, err := LoadBroker(path)
			if b != nil {
				t.Error("LoadBroker returned a config with the error")
			}
			checkError(t, err, "config "+path+": audit_log: ", "made-up")
			checkError(t, err, tt.want, "")
		})
	}
}

// TestLoadBrokerHostWithSeveralKeys gives web-1 an ed25519 key and an
// ECDSA key. A second key of a type that web-1 already has is refused.
func TestLoadBrokerHostWithSeveralKeys(t *testing.T) {
	e := newBrokerEnv(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		knownHostsLine("web-1", e.hosts["web-1"]),
		knownHostsLine("web-2", e.hosts["web-2"]),
		knownHostsLine("db-1", e.hosts["db-1"]),
		knownHostsLine("web-1", ec),
	}
	writeFile(t, e.dir, "known_hosts", strings.Join(lines, "\n")+"\n", 0o644)
	b, err := LoadBroker(e.write(t))
	if err != nil {
		t.Fatalf("LoadBroker: %v", err)
	}
	if keys := b.KnownHosts.KeysFor("web-1"); len(keys) != 2 {
		t.Errorf("KeysFor(web-1) has %d keys, want 2", len(keys))
	}
	for _, key := range []ssh.PublicKey{e.hosts["web-1"], ec} {
		if name, ok := b.KnownHosts.NameFor(key); !ok || name != "web-1" {
			t.Errorf("NameFor(%s key) = %q, %v; want web-1, true", key.Type(), name, ok)
		}
	}

	lines[3] = knownHostsLine("web-1", newHostKey(t))
	writeFile(t, e.dir, "known_hosts", strings.Join(lines, "\n")+"\n", 0o644)
	_, err = LoadBroker(e.write(t))
	checkError(t, err, "/known_hosts: line 4: this host name already has a key of this type on line 1", "")
}

func TestCheckFilesWithoutLoad(t *testing.T) {
	// A config that LoadBroker did not make has no path to check. That
	// is an error, not a pass.
	b := &Broker{Stores: map[string]Store{}, Keys: map[string]Key{}}
	if err := b.CheckFiles(); err == nil {
		t.Fatal("CheckFiles on an empty config: got no error")
	}
	b = &Broker{Stores: map[string]Store{"x": {Name: "x", Type: "other"}}}
	checkError(t, b.CheckFiles(), "unknown store type", "")
}
