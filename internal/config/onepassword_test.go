package config

import (
	"os"
	"strings"
	"testing"
)

// opStore is a [store.op] section of type "1password", with a secret.
const opStore = `
[store.op]
type = "1password"
vault = "abcdefghijklmnopqrstuvwxyz"
token_file = "${CREDENTIALS_DIRECTORY}/op-token"

[secret.op-token]
store = "op"
id = "0123456789abcdefghijklmnop"
clients = ["laptop"]
ask = "always"
`

// opEdits adds opStore to the valid config, with the edits applied to it.
func opEdits(edits ...edit) []edit {
	s := opStore
	for _, ed := range edits {
		s = strings.Replace(s, ed.old, ed.new, 1)
	}
	return []edit{{"[key.deploy]", s + "\n[key.deploy]"}}
}

func newOPEnv(t *testing.T) *brokerEnv {
	t.Helper()
	e := newBrokerEnv(t)
	writeFile(t, e.creds, "op-token", "made-up test content\n", 0o600)
	return e
}

func TestLoadBrokerOnePassword(t *testing.T) {
	e := newOPEnv(t)
	b, err := LoadBroker(e.write(t, opEdits()...))
	if err != nil {
		t.Fatal(err)
	}
	st := b.Stores["op"]
	if st.Type != StoreOnePassword || st.Vault != "abcdefghijklmnopqrstuvwxyz" || st.Program != "" ||
		st.TokenFile != e.creds+"/op-token" || st.PasswordFile != "" {
		t.Errorf("store = %+v", st)
	}
	sec := b.Secrets["op-token"]
	if sec.ID != "0123456789abcdefghijklmnop" || sec.Field != "password" {
		t.Errorf("secret = %+v, want the default field \"password\"", sec)
	}
	if f := b.Secrets["github-token"].Field; f != "" {
		t.Errorf("a bws secret has the field %q", f)
	}

	b, err = LoadBroker(e.write(t, opEdits(edit{`ask = "always"`, "ask = \"always\"\nfield = \"API key\""})...))
	if err != nil {
		t.Fatal(err)
	}
	if f := b.Secrets["op-token"].Field; f != "API key" {
		t.Errorf("field = %q, want \"API key\"", f)
	}
}

func TestLoadBrokerOnePasswordErrors(t *testing.T) {
	tests := []struct {
		name  string
		edits []edit
		want  string
	}{
		{"with a program", opEdits(edit{`type = "1password"`, "type = \"1password\"\nprogram = \"/usr/bin/op\""}),
			`[store.op] program: is not allowed with type = "1password"`},
		{"without a vault", opEdits(edit{"vault = \"abcdefghijklmnopqrstuvwxyz\"\n", ""}),
			`[store.op] vault: is missing; type = "1password" needs it`},
		{"vault is a name", opEdits(edit{`vault = "abcdefghijklmnopqrstuvwxyz"`, `vault = "nodkey"`}),
			"[store.op] vault: must be the vault's ID"},
		{"vault in capitals", opEdits(edit{`vault = "abcdefghijklmnopqrstuvwxyz"`, `vault = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"`}),
			"[store.op] vault: must be the vault's ID"},
		{"without token_file", opEdits(edit{"token_file = \"${CREDENTIALS_DIRECTORY}/op-token\"\n", ""}),
			`[store.op] token_file: is missing; type = "1password" needs it`},
		{"with password_file", opEdits(edit{`type = "1password"`, "type = \"1password\"\npassword_file = \"${CREDENTIALS_DIRECTORY}/op-token\""}),
			`[store.op] password_file: is not allowed with type = "1password"`},
		{"vault on bws", []edit{{`type = "bws"`, "type = \"bws\"\nvault = \"abcdefghijklmnopqrstuvwxyz\""}},
			`[store.main] vault: is not allowed with type = "bws"`},
		{"item is a UUID", opEdits(edit{`id = "0123456789abcdefghijklmnop"`, `id = "00000000-0000-0000-0000-000000000009"`}),
			"[secret.op-token] id: must be the item's ID in 1Password"},
		{"item is a name", opEdits(edit{`id = "0123456789abcdefghijklmnop"`, `id = "GitHub token"`}),
			"[secret.op-token] id: must be the item's ID in 1Password"},
		{"field is empty", opEdits(edit{`ask = "always"`, "ask = \"always\"\nfield = \"\""}),
			"[secret.op-token] field: must be a field's ID or title"},
		{"field with a control character", opEdits(edit{`ask = "always"`, "ask = \"always\"\nfield = \"a\\nb\""}),
			"[secret.op-token] field: must be a field's ID or title"},
		{"field too long", opEdits(edit{`ask = "always"`, "ask = \"always\"\nfield = \"" + strings.Repeat("f", maxFieldLen+1) + "\""}),
			"[secret.op-token] field: must be a field's ID or title"},
		{"field on bws", []edit{{`window = "15m"`, "window = \"15m\"\nfield = \"password\""}},
			`[secret.github-token] field: is allowed only with a store of type = "1password"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newOPEnv(t)
			b, err := LoadBroker(e.write(t, tt.edits...))
			if b != nil {
				t.Errorf("LoadBroker returned a config with the error")
			}
			checkError(t, err, tt.want, "")
		})
	}
}

// TestCheckFilesOnePassword checks the token file of a 1password store,
// and no program.
func TestCheckFilesOnePassword(t *testing.T) {
	e := newOPEnv(t)
	path := e.write(t, opEdits()...)
	if err := os.Chmod(e.creds+"/op-token", 0o644); err != nil { //nolint:gosec // G302: the test makes the file readable by others on purpose.
		t.Fatal(err)
	}
	b, err := LoadBroker(path)
	if b != nil {
		t.Errorf("LoadBroker returned a config with a token file that others can read")
	}
	checkError(t, err, "[store.op] token_file", "")
}
