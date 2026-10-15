package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/transport"
)

// allTypes are the types of the protocol: every request, answer, and type
// inside them.
var allTypes = []any{
	KeysRequest{}, KeysAnswer{}, Key{},
	SecretsRequest{}, SecretRef{}, SecretsAnswer{}, SecretValue{},
	SignRequest{}, SignAnswer{},
	GrantRequest{}, GrantAnswer{},
	ErrorAnswer{},
}

// tagPattern is the form of a JSON field name: lower case, as the broker's
// JSON reader requires (transport.ReadJSON).
var tagPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// TestFieldNamesAreLowerCase walks every field of every type, also inside
// lists, and checks that it has a JSON name in lower case, without
// options such as omitempty: every field is always written.
func TestFieldNamesAreLowerCase(t *testing.T) {
	seen := make(map[reflect.Type]bool)
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Slice || typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := range typ.NumField() {
			f := typ.Field(i)
			tag, ok := f.Tag.Lookup("json")
			if !ok || !tagPattern.MatchString(tag) {
				t.Errorf("%s.%s: json tag %q; want a lower-case name and nothing else", typ.Name(), f.Name, tag)
			}
			if !f.IsExported() {
				t.Errorf("%s.%s: the field is not exported, so JSON skips it", typ.Name(), f.Name)
			}
			walk(f.Type)
		}
	}
	for _, v := range allTypes {
		walk(reflect.TypeOf(v))
	}
	if len(seen) != len(allTypes) {
		t.Errorf("walked %d types, want %d: a type is missing from allTypes", len(seen), len(allTypes))
	}
}

// fullValues returns a value of each type with every field set, so that a
// round trip uses every field name.
func fullValues() []any {
	return []any{
		&KeysRequest{},
		&KeysAnswer{Keys: []Key{{Name: "deploy", PublicKey: []byte{1, 2}}, {Name: "web", PublicKey: []byte{3}}}},
		&Key{Name: "deploy", PublicKey: []byte{1, 2, 3}},
		&SecretsRequest{
			Secrets: []SecretRef{{Var: "GH_TOKEN", Name: "github-token"}, {Var: "NPM_TOKEN", Name: "npm-token"}},
			Command: []string{"gh", "release", "create", "v1.2.0"}, Dir: "/home/dev/src/app", Reason: "publish",
		},
		&SecretRef{Var: "GH_TOKEN", Name: "github-token"},
		&SecretsAnswer{Secrets: []SecretValue{{Var: "GH_TOKEN", Value: []byte("made-up value")}}},
		&SecretValue{Var: "GH_TOKEN", Value: []byte("made-up value")},
		&SignRequest{
			PublicKey: []byte{1}, Data: []byte{2}, Flags: 4, Binds: [][]byte{{3}, {4}},
			Commands: [][]string{{"ssh", "web-1"}, {"ansible-playbook", "site.yml"}}, Reason: "apply the fix",
		},
		&SignAnswer{Format: "ssh-ed25519", Blob: []byte{5, 6}},
		&GrantRequest{Key: "deploy", User: "deploy", Hosts: []string{"web-1", "web-2"}, Seconds: 900, Reason: "r"},
		&GrantAnswer{Minutes: 15},
		&ErrorAnswer{Error: "Forbidden"},
	}
}

// decodeInto decodes data into a new value of the type of v, with the
// type's own strict decoder.
func decodeInto(v any, data []byte) (any, error) {
	n := reflect.New(reflect.TypeOf(v).Elem()).Interface()
	err := json.Unmarshal(data, n)
	return n, err
}

func TestRoundTrip(t *testing.T) {
	for _, v := range fullValues() {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%T: Marshal: %v", v, err)
		}
		got, err := decodeInto(v, data)
		if err != nil {
			t.Errorf("%T: Unmarshal(%s): %v", v, data, err)
			continue
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("%T: round trip gave %#v, want %#v", v, got, v)
		}
	}
}

// TestZeroValuesRoundTrip: a nil list is written as an empty list, not as
// null, so the other side takes it.
func TestZeroValuesRoundTrip(t *testing.T) {
	for _, v := range []any{
		&KeysAnswer{}, &SecretsRequest{}, &SecretsAnswer{Secrets: []SecretValue{{Var: "A", Value: []byte{}}}},
		&SignRequest{Binds: [][]byte{nil}, Commands: [][]string{nil}}, &SignAnswer{}, &GrantRequest{},
		&KeysAnswer{Keys: []Key{{Name: "deploy"}}},
	} {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%T: Marshal: %v", v, err)
		}
		if bytes.Contains(data, []byte("null")) {
			t.Errorf("%T: %s holds null", v, data)
		}
		if _, err := decodeInto(v, data); err != nil {
			t.Errorf("%T: Unmarshal(%s): %v", v, data, err)
		}
	}
}

// TestStrictDecoding shows that a missing or null field, a null list item,
// an unknown or repeated field, a name in another case, a value of the
// wrong type, or more after the object is refused. The errors never hold
// the data.
func TestStrictDecoding(t *testing.T) {
	const marker = "Zq9marker"
	tests := []struct {
		name string
		v    any
		data string
	}{
		{"missing field", &SecretsRequest{}, `{"secrets":[],"command":[],"dir":"` + marker + `"}`},
		{"null field", &SecretsRequest{}, `{"secrets":[],"command":[],"dir":"` + marker + `","reason":null}`},
		{"null list", &SecretsRequest{}, `{"secrets":null,"command":[],"dir":"` + marker + `","reason":""}`},
		{"null in a text list", &SecretsRequest{}, `{"secrets":[],"command":["` + marker + `",null],"dir":"","reason":""}`},
		{"null in an object list", &SecretsRequest{}, `{"secrets":[null],"command":[],"dir":"","reason":""}`},
		{"field of an item missing", &SecretsRequest{}, `{"secrets":[{"var":"` + marker + `"}],"command":[],"dir":"","reason":""}`},
		{"null field of an item", &SecretsRequest{}, `{"secrets":[{"var":"A","name":null}],"command":[],"dir":"","reason":""}`},
		{"unknown field", &SecretsRequest{}, `{"secrets":[],"command":[],"dir":"","reason":"","user":"` + marker + `"}`},
		{"unknown field of an item", &SecretsRequest{}, `{"secrets":[{"var":"A","name":"b","x":1}],"command":[],"dir":"","reason":""}`},
		{"repeated field", &SecretsRequest{}, `{"secrets":[],"command":[],"dir":"","reason":"","reason":"` + marker + `"}`},
		{"name in upper case", &SecretsRequest{}, `{"Secrets":[],"command":[],"dir":"","reason":""}`},
		{"name with a long s", &SecretsRequest{}, `{"ſecrets":[],"command":[],"dir":"","reason":""}`},
		{"wrong type", &SecretsRequest{}, `{"secrets":[],"command":"` + marker + `","dir":"","reason":""}`},
		{"number for text", &SecretsRequest{}, `{"secrets":[],"command":[],"dir":1,"reason":""}`},
		{"more after the object", &SecretsRequest{}, `{"secrets":[],"command":[],"dir":"","reason":""} {}`},
		{"not an object", &SecretsRequest{}, `["` + marker + `"]`},
		{"null", &SecretsRequest{}, `null`},
		{"bytes as numbers", &SignRequest{}, `{"public_key":[1,2],"data":"","flags":0,"binds":[],"commands":[],"reason":""}`},
		{"bytes not base64", &SignRequest{}, `{"public_key":"` + marker + `!","data":"","flags":0,"binds":[],"commands":[],"reason":""}`},
		{"negative flags", &SignRequest{}, `{"public_key":"","data":"","flags":-1,"binds":[],"commands":[],"reason":""}`},
		{"flags with a fraction", &SignRequest{}, `{"public_key":"","data":"","flags":1.5,"binds":[],"commands":[],"reason":""}`},
		{"flags as text", &SignRequest{}, `{"public_key":"","data":"","flags":"1","binds":[],"commands":[],"reason":""}`},
		{"null bind", &SignRequest{}, `{"public_key":"","data":"","flags":0,"binds":[null],"commands":[],"reason":""}`},
		{"null command line", &SignRequest{}, `{"public_key":"","data":"","flags":0,"binds":[],"commands":[null],"reason":""}`},
		{"seconds with an exponent", &GrantRequest{}, `{"key":"","user":"","hosts":[],"seconds":9e2,"reason":""}`},
		{"a field in KeysRequest", &KeysRequest{}, `{"keys":[]}`},
		{"null value", &SecretsAnswer{}, `{"secrets":[{"var":"A","value":null}]}`},
	}
	for _, tt := range tests {
		_, err := decodeInto(tt.v, []byte(tt.data))
		if err == nil {
			t.Errorf("%s: no error", tt.name)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the error holds the data: %v", tt.name, err)
		}
	}
}

// TestCaps shows that each cap of the request budget (DESIGN.md section
// 10) is enforced, and that one item less is taken.
func TestCaps(t *testing.T) {
	long := strings.Repeat("a", MaxName+1)
	tests := []struct {
		name     string
		ok, over any
	}{
		{"secrets", &SecretsRequest{Secrets: make([]SecretRef, MaxSecrets)},
			&SecretsRequest{Secrets: make([]SecretRef, MaxSecrets+1)}},
		{"variable name", &SecretsRequest{Secrets: []SecretRef{{Var: long[1:]}}},
			&SecretsRequest{Secrets: []SecretRef{{Var: long}}}},
		{"secret name", &SecretsRequest{Secrets: []SecretRef{{Name: long[1:]}}},
			&SecretsRequest{Secrets: []SecretRef{{Name: long}}}},
		{"arguments", &SecretsRequest{Command: make([]string, MaxArgs)},
			&SecretsRequest{Command: make([]string, MaxArgs+1)}},
		{"command lines", &SignRequest{Commands: make([][]string, MaxCommands)},
			&SignRequest{Commands: make([][]string, MaxCommands+1)}},
		{"arguments of an SSH command line", &SignRequest{Commands: [][]string{make([]string, MaxArgs)}},
			&SignRequest{Commands: [][]string{make([]string, MaxArgs+1)}}},
		{"binds", &SignRequest{Binds: make([][]byte, MaxBinds)}, &SignRequest{Binds: make([][]byte, MaxBinds+1)}},
		{"bind length", &SignRequest{Binds: [][]byte{make([]byte, MaxBind)}},
			&SignRequest{Binds: [][]byte{make([]byte, MaxBind+1)}}},
		{"data", &SignRequest{Data: make([]byte, MaxData)}, &SignRequest{Data: make([]byte, MaxData+1)}},
		{"public key", &SignRequest{PublicKey: make([]byte, MaxKey)}, &SignRequest{PublicKey: make([]byte, MaxKey+1)}},
		{"hosts", &GrantRequest{Hosts: make([]string, MaxGrantHosts)},
			&GrantRequest{Hosts: make([]string, MaxGrantHosts+1)}},
		{"host name", &GrantRequest{Hosts: []string{long[1:]}}, &GrantRequest{Hosts: []string{long}}},
		{"key name", &GrantRequest{Key: long[1:]}, &GrantRequest{Key: long}},
		{"remote user", &GrantRequest{User: long[1:]}, &GrantRequest{User: long}},
		{"values", &SecretsAnswer{Secrets: emptyValues(MaxSecrets)}, &SecretsAnswer{Secrets: emptyValues(MaxSecrets + 1)}},
		{"value", &SecretsAnswer{Secrets: []SecretValue{{Value: make([]byte, MaxValue)}}},
			&SecretsAnswer{Secrets: []SecretValue{{Value: make([]byte, MaxValue+1)}}}},
		{"keys", &KeysAnswer{Keys: make([]Key, MaxKeys)}, &KeysAnswer{Keys: make([]Key, MaxKeys+1)}},
	}
	for _, tt := range tests {
		data, err := json.Marshal(tt.ok)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeInto(tt.ok, data); err != nil {
			t.Errorf("%s: at the cap: %v", tt.name, err)
		}
		data, err = json.Marshal(tt.over)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeInto(tt.over, data); err == nil {
			t.Errorf("%s: over the cap: no error", tt.name)
		}
	}
	// All the values of one answer together.
	many := SecretsAnswer{}
	for range MaxValues/MaxValue + 1 {
		many.Secrets = append(many.Secrets, SecretValue{Var: "A", Value: make([]byte, MaxValue)})
	}
	if err := many.Check(); err == nil {
		t.Error("values of more than MaxValues bytes together: no error")
	}
}

// emptyValues returns n values that are empty, not nil.
func emptyValues(n int) []SecretValue {
	v := make([]SecretValue, n)
	for i := range v {
		v[i].Value = []byte{}
	}
	return v
}

// TestCapsMatchThePackages: the caps are those of the packages that check
// the data.
func TestCapsMatchThePackages(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"MaxText", MaxText, claim.MaxInput},
		{"MaxData", MaxData, sshauth.MaxDataLen},
		{"MaxBind", MaxBind, sshauth.MaxBindLen},
		{"MaxGrantHosts", MaxGrantHosts, approval.MaxGrantHosts},
		{"MaxAnswer", MaxAnswer, transport.MaxRequestBody},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// worstText returns n bytes of text that JSON writes with 6 bytes each.
func worstText(n int) string { return strings.Repeat("\x01", n) }

// worstCommand returns a command line at the caps: MaxArgs arguments with
// MaxText bytes in all, of the worst characters for JSON.
func worstCommand() []string {
	argv := make([]string, MaxArgs)
	for i := range argv {
		argv[i] = worstText(MaxText / MaxArgs)
	}
	return argv
}

// TestLargestRequestsFit: the largest valid request of each kind fits in
// the body that the broker reads, and decodes. The other fields of a
// request, such as names, keys and the data to sign, fit in 64 KiB.
func TestLargestRequestsFit(t *testing.T) {
	name := worstText(MaxName)
	refs := make([]SecretRef, MaxSecrets)
	for i := range refs {
		refs[i] = SecretRef{Var: name, Name: name}
	}
	commands := make([][]string, MaxCommands)
	for i := range commands {
		commands[i] = worstCommand()
	}
	hosts := make([]string, MaxGrantHosts)
	for i := range hosts {
		hosts[i] = name
	}
	sign := &SignRequest{
		PublicKey: make([]byte, MaxKey), Data: make([]byte, MaxData), Flags: 1<<32 - 1,
		Binds: [][]byte{make([]byte, MaxBind), make([]byte, MaxBind)}, Commands: commands, Reason: worstText(MaxText),
	}
	for _, r := range []any{
		&SecretsRequest{Secrets: refs, Command: worstCommand(), Dir: worstText(MaxText), Reason: worstText(MaxText)},
		sign,
		&GrantRequest{Key: name, User: name, Hosts: hosts, Seconds: -1 << 63, Reason: worstText(MaxText)},
	} {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > transport.MaxRequestBody {
			t.Errorf("%T: %d bytes, more than %d", r, len(data), transport.MaxRequestBody)
		}
		if _, err := decodeInto(r, data); err != nil {
			t.Errorf("%T: the largest request does not decode: %v", r, err)
		}
	}
	// The other fields: everything but the claimed text.
	others := []any{
		&SecretsRequest{Secrets: refs},
		&SignRequest{PublicKey: sign.PublicKey, Data: sign.Data, Flags: sign.Flags, Binds: sign.Binds},
		&GrantRequest{Key: name, User: name, Hosts: hosts, Seconds: -1 << 63},
	}
	for _, r := range others {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 64<<10 {
			t.Errorf("%T: the fields that are not claimed text take %d bytes, more than 64 KiB", r, len(data))
		}
	}
}

// TestLargestAnswerFits: the largest valid answer fits in MaxAnswer.
func TestLargestAnswerFits(t *testing.T) {
	var a SecretsAnswer
	for left := MaxValues; left > 0; left -= MaxValue {
		a.Secrets = append(a.Secrets, SecretValue{Var: worstText(MaxName), Value: make([]byte, min(left, MaxValue))})
	}
	for len(a.Secrets) < MaxSecrets {
		a.Secrets = append(a.Secrets, SecretValue{Var: worstText(MaxName), Value: []byte{}})
	}
	keys := KeysAnswer{Keys: make([]Key, MaxKeys)}
	for i := range keys.Keys {
		keys.Keys[i] = Key{Name: worstText(MaxName), PublicKey: make([]byte, 2200)} // RSA 16384
	}
	for _, v := range []any{&a, &keys} {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > MaxAnswer {
			t.Errorf("%T: %d bytes, more than MaxAnswer", v, len(data))
		}
		if _, err := readAnswerOf(v, data); err != nil {
			t.Errorf("%T: %v", v, err)
		}
	}
}

// readAnswerOf calls ReadAnswer for the type of v.
func readAnswerOf(v any, data []byte) (any, error) {
	switch v.(type) {
	case *SecretsAnswer:
		return ReadAnswer[SecretsAnswer](bytes.NewReader(data))
	case *KeysAnswer:
		return ReadAnswer[KeysAnswer](bytes.NewReader(data))
	}
	return nil, fmt.Errorf("no ReadAnswer for %T", v)
}

func TestReadAnswer(t *testing.T) {
	a, err := ReadAnswer[GrantAnswer](strings.NewReader(` {"minutes":15}` + "\n"))
	if err != nil || a.Minutes != 15 {
		t.Errorf("ReadAnswer = %+v, %v", a, err)
	}
	for _, body := range []string{
		`{"minutes":15} {"minutes":16}`,
		`{"minutes":15,"minutes":16}`,
		`{"MINUTES":15}`,
		`{}`,
		``,
		`{"minutes":15}` + strings.Repeat(" ", MaxAnswer),
	} {
		if _, err := ReadAnswer[GrantAnswer](strings.NewReader(body)); err == nil {
			t.Errorf("ReadAnswer(%.40q): no error", body)
		}
	}
}

// TestSecretValueHidesItself prints and logs the answer with the values in
// every way we know.
func TestSecretValueHidesItself(t *testing.T) {
	secret := "made-up-" + strings.Repeat("v", 20)
	v := SecretValue{Var: "GH_TOKEN", Value: []byte(secret)}
	a := SecretsAnswer{Secrets: []SecretValue{v}}
	var texts []string
	for _, x := range []any{v, &v, a, &a, []SecretValue{v}, struct{ A SecretsAnswer }{a}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			texts = append(texts, fmt.Sprintf(verb, x))
		}
	}
	var logs bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&logs, nil), slog.NewJSONHandler(&logs, nil)} {
		slog.New(h).Info("answer", "value", v, "answer", a, "pointer", &a)
	}
	texts = append(texts, logs.String())
	hexSecret := fmt.Sprintf("%x", secret)
	for _, text := range texts {
		if strings.Contains(text, secret) || strings.Contains(text, hexSecret) || strings.Contains(text, "GH_TOKEN") {
			t.Errorf("a text shows the value or the variable: %q", text)
		}
	}
	a.Clear()
	if !bytes.Equal(a.Secrets[0].Value, make([]byte, len(secret))) {
		t.Error("Clear did not overwrite the value")
	}
}

func TestValidVar(t *testing.T) {
	for _, ok := range []string{"GH_TOKEN", "_", "A", "A1", "_9", strings.Repeat("A", 64)} {
		if !ValidVar(ok) {
			t.Errorf("ValidVar(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "gh_token", "1A", "A-B", "A B", "A=B", "Ä", strings.Repeat("A", 65), "A\n"} {
		if ValidVar(bad) {
			t.Errorf("ValidVar(%q) = true", bad)
		}
	}
}

// TestDeniedVar: every name on the deny list is refused, and every name
// that starts with a prefix on it. Names that hold secrets on purpose, and
// names that only look like an entry, pass: a prefix matches only at the
// start and with its "_", and a name only as a whole.
func TestDeniedVar(t *testing.T) {
	names, prefixes := DenyList()
	if len(names) == 0 || len(prefixes) == 0 {
		t.Fatal("the deny list is empty")
	}
	for _, name := range names {
		if prefix, denied := DeniedVar(name); !denied || prefix != "" {
			t.Errorf("DeniedVar(%q) = %q, %v; want \"\", true", name, prefix, denied)
		}
	}
	for _, p := range prefixes {
		for _, name := range []string{p, p + "X", p + "PRELOAD_2", p + strings.Repeat("A", 64-len(p))} {
			if prefix, denied := DeniedVar(name); !denied || prefix != p {
				t.Errorf("DeniedVar(%q) = %q, %v; want %q, true", name, prefix, denied, p)
			}
		}
	}
	// Some names on the list, and the prefix that refuses them, if any.
	// TF_CLI_ARGS is a name on the list. terraform reads its forms for one
	// command, such as TF_CLI_ARGS_plan, only in lower case, which
	// ValidVar refuses.
	for _, tt := range []struct{ name, prefix string }{
		{"LD_PRELOAD", "LD_"}, {"LC_ALL", "LC_"}, {"GIT_SSH_COMMAND", "GIT_"},
		{"NPM_CONFIG_SCRIPT_SHELL", "NPM_CONFIG_"}, {"TF_CLI_ARGS", ""}, {"JAVA_OPTS", ""}, {"PATH", ""},
		{"MAKEFLAGS", ""}, {"GOFLAGS", ""}, {"GH_HOST", ""}, {"DOCKER_HOST", ""}, {"SUDO_ASKPASS", ""},
		{"MANPAGER", ""},
	} {
		if prefix, denied := DeniedVar(tt.name); !denied || prefix != tt.prefix {
			t.Errorf("DeniedVar(%q) = %q, %v; want %q, true", tt.name, prefix, denied, tt.prefix)
		}
	}
	for _, ok := range []string{
		"GH_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN", "AWS_SECRET_ACCESS_KEY", "LDAP_PASSWORD", "NODE_AUTH_TOKEN",
		"NPM_TOKEN", "HOMEBREW_GITHUB_API_TOKEN", "PGPASSWORD", "SSH_PRIVATE_KEY", "DB_PASSWORD",
		"DOCKER_PASSWORD", "CARGO_REGISTRY_TOKEN", "EMAIL_PASSWORD", "TF_TOKEN_EXAMPLE_COM", "TF_VAR_DB_PASSWORD",
		"GOPROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
		"LD", "LDX_PRELOAD", "XLD_PRELOAD", "LC", "GIT", "MY_GIT_TOKEN", "DYLD", "GCONV", "RESOLV",
		"PATHS", "HOME_DIR", "TERM_TOKEN", "PS", "PS5", "ENVIRONMENT", "LANGFUSE_SECRET_KEY", "CC_TOKEN",
		"NPM_CONFIG", "MY_NPM_CONFIG_X", "TF_CLI_ARG", "TF_LOG", "TF_IN_AUTOMATION", "DOCKER_CONFIG_TOKEN",
		"NODE_PATH", "PYTHONPATH", "RUBYLIB", "IFS", "LESSOPEN",
		// Lower case is not on the list; ValidVar refuses it anyway, also
		// Terraform's own forms of TF_TOKEN_ and TF_VAR_.
		"ld_preload", "path", "TF_TOKEN_example_com", "TF_VAR_db_password",
	} {
		if prefix, denied := DeniedVar(ok); denied {
			t.Errorf("DeniedVar(%q) = %q, true; want false", ok, prefix)
		}
	}
}

// TestDenyListIsClean: each entry is a valid name, each prefix ends with
// "_", no entry is there twice, and no name or prefix is covered by
// another prefix. DenyList returns copies, so a caller cannot change the
// list.
func TestDenyListIsClean(t *testing.T) {
	names, prefixes := DenyList()
	seen := make(map[string]bool)
	for _, e := range slices.Concat(names, prefixes) {
		if !ValidVar(e) || seen[e] {
			t.Errorf("the entry %q is not a valid name, or is there twice", e)
		}
		seen[e] = true
	}
	for _, p := range prefixes {
		if !strings.HasSuffix(p, "_") {
			t.Errorf("the prefix %q does not end with _", p)
		}
		for _, q := range prefixes {
			if p != q && strings.HasPrefix(p, q) {
				t.Errorf("the prefix %q covers the prefix %q", q, p)
			}
		}
	}
	for _, name := range names {
		if prefix, _ := DeniedVar(name); prefix != "" {
			t.Errorf("the prefix %q covers the name %q", prefix, name)
		}
	}
	names[0], prefixes[0] = "GH_TOKEN", "NPM_"
	if _, denied := DeniedVar("GH_TOKEN"); denied {
		t.Error("DenyList shares its names with the list")
	}
	if _, denied := DeniedVar("NPM_TOKEN"); denied {
		t.Error("DenyList shares its prefixes with the list")
	}
}

// TestDenyListAsInDesign: the table of DESIGN.md section 5 lists exactly
// the names and the prefixes of the deny list, in its first column. A
// prefix is written as LD_*.
func TestDenyListAsInDesign(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "\n### Variable names that the broker refuses\n")
	if !ok {
		t.Fatal("DESIGN.md section 5 has no list of the variable names that the broker refuses")
	}
	section, _, _ = strings.Cut(section, "\n#")
	var inDoc []string
	for line := range strings.Lines(section) {
		cell, ok := strings.CutPrefix(line, "| ")
		if !ok {
			continue
		}
		cell, _, _ = strings.Cut(cell, " |")
		for i, part := range strings.Split(cell, "`") {
			if i%2 == 1 {
				inDoc = append(inDoc, part)
			}
		}
	}
	names, prefixes := DenyList()
	for _, p := range prefixes {
		names = append(names, p+"*")
	}
	slices.Sort(names)
	slices.Sort(inDoc)
	if !slices.Equal(inDoc, names) {
		t.Errorf("DESIGN.md lists %q;\nthe deny list has %q", inDoc, names)
	}
}

func TestShortCode(t *testing.T) {
	h := func(values ...string) textproto.MIMEHeader {
		return textproto.MIMEHeader{textproto.CanonicalMIMEHeaderKey(ShortCodeHeader): values}
	}
	if code, ok := ShortCode(http.StatusProcessing, h("7qd2")); !ok || code != "7qd2" {
		t.Errorf("ShortCode = %q, %v", code, ok)
	}
	for _, tt := range []struct {
		status int
		h      textproto.MIMEHeader
	}{
		{http.StatusEarlyHints, h("7qd2")},
		{http.StatusProcessing, h()},
		{http.StatusProcessing, h("7qd2", "k3f9")},
		{http.StatusProcessing, h("7QD2")},
		{http.StatusProcessing, h("7qd")},
		{http.StatusProcessing, h("7qd1")}, // 1 is not in the alphabet
		{http.StatusProcessing, h("7qd2\n")},
	} {
		if code, ok := ShortCode(tt.status, tt.h); ok {
			t.Errorf("ShortCode(%d, %v) = %q", tt.status, tt.h, code)
		}
	}
}

// TestSecretsAnswerEncode: Encode writes the same bytes as json.Marshal,
// into a buffer of exactly that size, and ReadAnswer takes them. It
// refuses a variable name that is not valid, as such a name could need
// escaping, and an answer over the caps.
func TestSecretsAnswerEncode(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for _, a := range []SecretsAnswer{
		{Secrets: []SecretValue{}},
		{Secrets: []SecretValue{{Var: "GH_TOKEN", Value: []byte("made-up value")}}},
		{Secrets: []SecretValue{{Var: "A", Value: all}, {Var: "_", Value: []byte{}}, {Var: "B_9", Value: []byte("x")}}},
	} {
		got, err := a.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		want, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Encode = %s, want %s", got, want)
		}
		if cap(got) != len(got) {
			t.Errorf("the buffer has room for %d bytes, the answer %d", cap(got), len(got))
		}
		back, err := ReadAnswer[SecretsAnswer](bytes.NewReader(got))
		if err != nil {
			t.Fatalf("ReadAnswer: %v", err)
		}
		if !reflect.DeepEqual(*back, a) {
			t.Errorf("the answer decodes to %#v", back)
		}
	}
	for _, bad := range []SecretsAnswer{
		{Secrets: []SecretValue{{Var: "gh_token", Value: []byte("v")}}},
		{Secrets: []SecretValue{{Var: "A<B", Value: []byte("v")}}},
		{Secrets: []SecretValue{{Var: `A"`, Value: []byte("v")}}},
		{Secrets: []SecretValue{{Var: "", Value: []byte("v")}}},
		{Secrets: []SecretValue{{Var: "A", Value: make([]byte, MaxValue+1)}}},
		{Secrets: emptyValues(MaxSecrets + 1)},
	} {
		if b, err := bad.Encode(); err == nil {
			t.Errorf("Encode(%.60s): no error", b)
		}
	}
}
