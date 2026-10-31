package config

import (
	"os"
	"strings"
	"testing"
)

// infStore is a [store.inf] section of type "infisical", with a secret.
const infStore = `
[store.inf]
type = "infisical"
server = "https://app.infisical.com/"
client_id = "11111111-2222-3333-4444-555555555555"
client_secret_file = "${CREDENTIALS_DIRECTORY}/infisical-secret"

[secret.inf-token]
store = "inf"
project = "66666666-7777-8888-9999-000000000000"
environment = "prod"
path = "/"
name = "GITHUB_TOKEN"
clients = ["laptop"]
ask = "always"
`

// infEdits adds infStore to the valid config, with the edits applied to it.
func infEdits(edits ...edit) []edit {
	s := infStore
	for _, ed := range edits {
		s = strings.Replace(s, ed.old, ed.new, 1)
	}
	return []edit{{"[key.deploy]", s + "\n[key.deploy]"}}
}

func newInfEnv(t *testing.T) *brokerEnv {
	t.Helper()
	e := newBrokerEnv(t)
	writeFile(t, e.creds, "infisical-secret", "made-up test content\n", 0o600)
	return e
}

func TestLoadBrokerInfisical(t *testing.T) {
	e := newInfEnv(t)
	b, err := LoadBroker(e.write(t, infEdits()...))
	if err != nil {
		t.Fatal(err)
	}
	st := b.Stores["inf"]
	if st.Type != StoreInfisical || st.Server != "https://app.infisical.com" ||
		st.ClientID != "11111111-2222-3333-4444-555555555555" ||
		st.ClientSecretFile != e.creds+"/infisical-secret" || st.Program != "" || st.TokenFile != "" {
		t.Errorf("store = %+v", st)
	}
	sec := b.Secrets["inf-token"]
	if sec.ID != "" || sec.Field != "" || sec.Project != "66666666-7777-8888-9999-000000000000" ||
		sec.Environment != "prod" || sec.Path != "/" || sec.SecretName != "GITHUB_TOKEN" {
		t.Errorf("secret = %+v", sec)
	}

	// A self-hosted server with a path, a folder, and a name with dots.
	b, err = LoadBroker(e.write(t, infEdits(
		edit{`"https://app.infisical.com/"`, `"https://secrets.example.com:8443/infisical"`},
		edit{`path = "/"`, `path = "/ci/deploy_keys"`},
		edit{`"GITHUB_TOKEN"`, `"github.token-2"`},
		edit{`environment = "prod"`, `environment = "staging-eu"`},
		edit{`"66666666-7777-8888-9999-000000000000"`, `"0123456789abcdef01234567"`},
	)...))
	if err != nil {
		t.Fatal(err)
	}
	if s := b.Stores["inf"].Server; s != "https://secrets.example.com:8443/infisical" {
		t.Errorf("server = %q", s)
	}
	if sec := b.Secrets["inf-token"]; sec.Path != "/ci/deploy_keys" || sec.SecretName != "github.token-2" {
		t.Errorf("secret = %+v", sec)
	}
}

func TestLoadBrokerInfisicalErrors(t *testing.T) {
	const (
		typeLine = `type = "infisical"`
		server   = `server = "https://app.infisical.com/"`
		project  = `project = "66666666-7777-8888-9999-000000000000"`
	)
	with := func(line string) edit { return edit{typeLine, typeLine + "\n" + line} }
	secretWith := func(line string) edit { return edit{`ask = "always"`, "ask = \"always\"\n" + line} }
	tests := []struct {
		name  string
		edits []edit
		want  string
	}{
		{"with a program", infEdits(with(`program = "/usr/bin/infisical"`)),
			`[store.inf] program: is not allowed with type = "infisical"`},
		{"with token_file", infEdits(with(`token_file = "${CREDENTIALS_DIRECTORY}/infisical-secret"`)),
			`[store.inf] token_file: is not allowed with type = "infisical"`},
		{"with password_file", infEdits(with(`password_file = "${CREDENTIALS_DIRECTORY}/infisical-secret"`)),
			`[store.inf] password_file: is not allowed with type = "infisical"`},
		{"with a vault", infEdits(with(`vault = "abcdefghijklmnopqrstuvwxyz"`)),
			`[store.inf] vault: is not allowed with type = "infisical"`},
		{"without client_secret_file", infEdits(edit{"client_secret_file = \"${CREDENTIALS_DIRECTORY}/infisical-secret\"\n", ""}),
			`[store.inf] client_secret_file: is missing; type = "infisical" needs it`},
		{"relative client_secret_file", infEdits(edit{`"${CREDENTIALS_DIRECTORY}/infisical-secret"`, `"infisical-secret"`}),
			`[store.inf] client_secret_file`},
		{"without a server", infEdits(edit{server + "\n", ""}),
			`[store.inf] server: is missing; type = "infisical" needs it`},
		{"http server", infEdits(edit{server, `server = "http://app.infisical.com"`}), "[store.inf] server: must be an https URL"},
		{"server with a user", infEdits(edit{server, `server = "https://me:pw@app.infisical.com"`}), "[store.inf] server: must be an https URL"},
		{"server with a query", infEdits(edit{server, `server = "https://app.infisical.com/?a=b"`}), "[store.inf] server: must be an https URL"},
		{"server with a fragment", infEdits(edit{server, `server = "https://app.infisical.com/#a"`}), "[store.inf] server: must be an https URL"},
		{"server with ..", infEdits(edit{server, `server = "https://example.com/a/../b"`}), "[store.inf] server: must be an https URL"},
		{"server without a host", infEdits(edit{server, `server = "https:///api"`}), "[store.inf] server: must be an https URL"},
		{"server with a space", infEdits(edit{server, `server = "https://example.com/a b"`}), "[store.inf] server: must be an https URL"},
		{"server is a name", infEdits(edit{server, `server = "app.infisical.com"`}), "[store.inf] server: must be an https URL"},
		{"server too long", infEdits(edit{server, `server = "https://example.com/` + strings.Repeat("a", maxServerLen) + `"`}),
			"[store.inf] server: must be an https URL"},
		{"without client_id", infEdits(edit{"client_id = \"11111111-2222-3333-4444-555555555555\"\n", ""}),
			`[store.inf] client_id: is missing; type = "infisical" needs it`},
		{"client_id is not a UUID", infEdits(edit{`"11111111-2222-3333-4444-555555555555"`, `"nodkey"`}),
			"[store.inf] client_id: must be the client ID"},
		{"server on bws", []edit{{`type = "bws"`, "type = \"bws\"\nserver = \"https://app.infisical.com\""}},
			`[store.main] server: is not allowed with type = "bws"`},
		{"client_id on 1password", []edit{{"[key.deploy]", "[store.op]\ntype = \"1password\"\nvault = \"abcdefghijklmnopqrstuvwxyz\"\n" +
			"token_file = \"${CREDENTIALS_DIRECTORY}/infisical-secret\"\nclient_id = \"11111111-2222-3333-4444-555555555555\"\n\n[key.deploy]"}},
			`[store.op] client_id: is not allowed with type = "1password"`},
		{"client_secret_file on bw", []edit{{`type = "bw"`, "type = \"bw\"\nclient_secret_file = \"/x\""}},
			`[store.vault] client_secret_file: is not allowed with type = "bw"`},

		{"secret with an id", infEdits(secretWith(`id = "00000000-0000-0000-0000-000000000009"`)),
			`[secret.inf-token] id: is not allowed with a store of type = "infisical"`},
		{"secret with a field", infEdits(secretWith(`field = "password"`)),
			`[secret.inf-token] field: is allowed only with a store of type = "1password"`},
		{"without a project", infEdits(edit{project + "\n", ""}), `[secret.inf-token] project: is missing`},
		{"without an environment", infEdits(edit{"environment = \"prod\"\n", ""}), `[secret.inf-token] environment: is missing`},
		{"without a path", infEdits(edit{"path = \"/\"\n", ""}), `[secret.inf-token] path: is missing`},
		{"without a name", infEdits(edit{"name = \"GITHUB_TOKEN\"\n", ""}), `[secret.inf-token] name: is missing`},
		{"project is a slug", infEdits(edit{project, `project = "my-project"`}), "[secret.inf-token] project: must be the project's ID"},
		{"project empty", infEdits(edit{project, `project = ""`}), "[secret.inf-token] project: must be the project's ID"},
		{"environment empty", infEdits(edit{`environment = "prod"`, `environment = ""`}), "[secret.inf-token] environment: must be"},
		{"environment with a slash", infEdits(edit{`environment = "prod"`, `environment = "prod/x"`}), "[secret.inf-token] environment: must be"},
		{"environment with a space", infEdits(edit{`environment = "prod"`, `environment = "pr od"`}), "[secret.inf-token] environment: must be"},
		{"environment too long", infEdits(edit{`environment = "prod"`, `environment = "` + strings.Repeat("e", 65) + `"`}),
			"[secret.inf-token] environment: must be"},
		{"path empty", infEdits(edit{`path = "/"`, `path = ""`}), "[secret.inf-token] path: must be a folder"},
		{"path without /", infEdits(edit{`path = "/"`, `path = "ci"`}), "[secret.inf-token] path: must be a folder"},
		{"path with ..", infEdits(edit{`path = "/"`, `path = "/ci/../prod"`}), "[secret.inf-token] path: must be a folder"},
		{"path with .", infEdits(edit{`path = "/"`, `path = "/./ci"`}), "[secret.inf-token] path: must be a folder"},
		{"path with //", infEdits(edit{`path = "/"`, `path = "//ci"`}), "[secret.inf-token] path: must be a folder"},
		{"path with / at the end", infEdits(edit{`path = "/"`, `path = "/ci/"`}), "[secret.inf-token] path: must be a folder"},
		{"path with a control character", infEdits(edit{`path = "/"`, `path = "/c\ni"`}), "[secret.inf-token] path: must be a folder"},
		{"path with ?", infEdits(edit{`path = "/"`, `path = "/ci?x"`}), "[secret.inf-token] path: must be a folder"},
		{"path too long", infEdits(edit{`path = "/"`, `path = "` + strings.Repeat("/abcdefgh", 30) + `"`}),
			"[secret.inf-token] path: must be a folder"},
		{"name empty", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = ""`}), "[secret.inf-token] name: must be the secret's name"},
		{"name ..", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = ".."`}), "[secret.inf-token] name: must be the secret's name"},
		{"name with a slash", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = "A/B"`}), "[secret.inf-token] name: must be the secret's name"},
		{"name with %", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = "A%2FB"`}), "[secret.inf-token] name: must be the secret's name"},
		{"name with ?", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = "A?B"`}), "[secret.inf-token] name: must be the secret's name"},
		{"name with a space", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = "A B"`}), "[secret.inf-token] name: must be the secret's name"},
		{"name with a control character", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = "A\tB"`}),
			"[secret.inf-token] name: must be the secret's name"},
		{"name too long", infEdits(edit{`name = "GITHUB_TOKEN"`, `name = "` + strings.Repeat("N", maxInfisicalNameLen+1) + `"`}),
			"[secret.inf-token] name: must be the secret's name"},
		{"project on bws", []edit{{`window = "15m"`, "window = \"15m\"\nproject = \"66666666-7777-8888-9999-000000000000\""}},
			`[secret.github-token] project: is allowed only with a store of type = "infisical"`},
		{"name on bws", []edit{{`window = "15m"`, "window = \"15m\"\nname = \"GITHUB_TOKEN\""}},
			`[secret.github-token] name: is allowed only with a store of type = "infisical"`},
		{"two never secrets for one Infisical secret", infEdits(
			edit{`ask = "always"`, `ask = "never"`},
			edit{"[secret.inf-token]", "[secret.inf-token-2]\nstore = \"inf\"\n" + project + "\nenvironment = \"prod\"\n" +
				"path = \"/\"\nname = \"GITHUB_TOKEN\"\nclients = [\"backup-box\"]\nask = \"never\"\n\n[secret.inf-token]"}),
			`also has ask = "never" for this secret in Infisical`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newInfEnv(t)
			b, err := LoadBroker(e.write(t, tt.edits...))
			if b != nil {
				t.Errorf("LoadBroker returned a config with the error")
			}
			checkError(t, err, tt.want, "")
		})
	}
}

// TestCheckFilesInfisical checks the client secret file of an infisical
// store, and no program.
func TestCheckFilesInfisical(t *testing.T) {
	e := newInfEnv(t)
	path := e.write(t, infEdits()...)
	if err := os.Chmod(e.creds+"/infisical-secret", 0o644); err != nil { //nolint:gosec // G302: the test makes the file readable by others on purpose.
		t.Fatal(err)
	}
	b, err := LoadBroker(path)
	if b != nil {
		t.Errorf("LoadBroker returned a config with a client secret file that others can read")
	}
	checkError(t, err, "[store.inf] client_secret_file", "")
}

func TestValidInfisical(t *testing.T) {
	for _, s := range []string{"/", "/a", "/a/b-c/d_e", "/A1"} {
		if !ValidInfisicalPath(s) {
			t.Errorf("path %q refused", s)
		}
	}
	for _, s := range []string{"", "a", "/a/", "//", "/.", "/..", "/a/./b", "/-a", "/a b", "/a\x00"} {
		if ValidInfisicalPath(s) {
			t.Errorf("path %q taken", s)
		}
	}
	for _, s := range []string{"A", "_A", "a.b", "A-1"} {
		if !ValidInfisicalName(s) {
			t.Errorf("name %q refused", s)
		}
	}
	for _, s := range []string{"", ".", "..", ".a", "-a", "a/b", "a%b", "a?b", "a#b", "é"} {
		if ValidInfisicalName(s) {
			t.Errorf("name %q taken", s)
		}
	}
	for _, tt := range []struct{ in, want string }{
		{"https://app.infisical.com", "https://app.infisical.com"},
		{"https://eu.infisical.com/", "https://eu.infisical.com"},
		{"https://192.0.2.1:8443/x/y/", "https://192.0.2.1:8443/x/y"},
	} {
		if got, ok := InfisicalServer(tt.in); !ok || got != tt.want {
			t.Errorf("InfisicalServer(%q) = %q, %v; want %q", tt.in, got, ok, tt.want)
		}
	}
	for _, s := range []string{"", "http://x", "https://", "https://x/a//b", "https://x/%2e%2e", "ftp://x", "https://x?", "https://x/a/."} {
		if got, ok := InfisicalServer(s); ok {
			t.Errorf("InfisicalServer(%q) = %q, taken", s, got)
		}
	}
}
