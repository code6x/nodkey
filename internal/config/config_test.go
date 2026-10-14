package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// writeFile writes content to dir/name with mode and returns the path.
func writeFile(t testing.TB, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the umask; set the exact mode.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// newHostKey makes a new ed25519 public key. It belongs to no real host.
func newHostKey(t testing.TB) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// knownHostsLine returns a known_hosts line for name and key.
func knownHostsLine(name string, key ssh.PublicKey) string {
	return name + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// testPin makes a pin from a word. It is not the pin of any real key.
func testPin(word string) Pin {
	return Pin(sha256.Sum256([]byte(word)))
}

// trustDir makes the check of the directories on the way to a file start
// at dir for this test: the directories above dir are not checked. The
// system temporary directory (/tmp) is writable by everyone, so the check
// would refuse every test file.
func trustDir(t testing.TB, dir string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := trustedDir
	trustedDir = dir
	t.Cleanup(func() { trustedDir = old })
}

// privateTempDir returns a new temporary directory with mode 0700, and
// makes the check of the directories on the way to a file start at the
// test's own temporary root (also 0700). The testing package makes each
// temporary directory with mode 0777 minus the umask, which can leave it
// writable by the group.
func privateTempDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	chmod(t, dir, 0o700)
	trustDir(t, filepath.Dir(dir))
	return dir
}

// chmod sets the exact mode of path, without the umask, and puts the old
// mode back at the end of the test.
func chmod(t testing.TB, path string, mode os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, fi.Mode().Perm()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Error(err)
		}
	})
}

// mkdir makes the directory dir/name with exactly mode, and returns its
// path.
func mkdir(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	// Mkdir applies the umask; set the exact mode.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// openFile opens a file that the test made, with flags, and closes it at
// the end of the test.
func openFile(t *testing.T, path string, flags int) (*os.File, error) {
	t.Helper()
	f, err := os.OpenFile(path, flags, 0) //nolint:gosec // G304: tests open only files that they made in their own temporary directory.
	if err == nil {
		t.Cleanup(func() { _ = f.Close() }) // the test may have closed it already
	}
	return f, err
}

// symlink makes a symbolic link at link that points to target.
func symlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

// checkError fails the test unless err is not nil, its text holds want,
// and its text does not hold notWant (when notWant is not empty).
func checkError(t *testing.T, err error, want, notWant string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want one with %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to hold %q", err, want)
	}
	if notWant != "" && strings.Contains(err.Error(), notWant) {
		t.Errorf("error = %q, want it not to hold %q", err, notWant)
	}
}

func TestParsePin(t *testing.T) {
	p := testPin("laptop")
	s := p.String()
	if !strings.HasPrefix(s, "sha256:") || len(s) != len("sha256:")+43 {
		t.Fatalf("String() = %q, want sha256: and 43 characters", s)
	}
	got, err := ParsePin(s)
	if err != nil {
		t.Fatalf("ParsePin(%q): %v", s, err)
	}
	if got != p {
		t.Errorf("ParsePin(String()) = %v, want %v", got, p)
	}

	zero := strings.Repeat("A", 43) // 32 zero bytes
	bad := []struct{ name, pin string }{
		{"empty", ""},
		{"no prefix", strings.TrimPrefix(s, "sha256:")},
		{"other prefix", "sha512:" + strings.TrimPrefix(s, "sha256:")},
		{"upper case prefix", "SHA256:" + strings.TrimPrefix(s, "sha256:")},
		{"31 bytes", "sha256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 31))},
		{"33 bytes", "sha256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 33))},
		{"padding", s + "="},
		{"unused bits set", "sha256:" + zero[:42] + "B"},
		{"newline inside", s[:20] + "\n" + s[20:]},
		{"URL alphabet", "sha256:" + strings.Repeat("_", 42) + "w"},
		{"space after", s + " "},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePin(tt.pin); err == nil {
				t.Errorf("ParsePin(%q): got no error", tt.pin)
			}
		})
	}
}

// TestDecodeStrict checks the strict decoding on its own, with a small
// type that has a named section, like the broker config.
func TestDecodeStrict(t *testing.T) {
	type entry struct {
		Ask string `toml:"ask"`
	}
	type file struct {
		Name  string           `toml:"name"`
		Entry map[string]entry `toml:"entry"`
	}
	tests := []struct {
		name    string
		data    string
		want    string // "" means no error
		notWant string
	}{
		{name: "valid", data: "name = \"a\"\n[entry.Web-1]\nask = \"never\"\n"},
		{name: "valid with an empty parent header", data: "[entry]\n[entry.web-1]\nask = \"never\"\n"},
		{name: "braces and quotes in strings and comments", data: "name = \"{ \\\" #\" # { '\n[entry.web-1]\nask = '''{\n'' }'''''\n"},
		{name: "unknown key", data: "nick = \"a\"\n", want: `unknown key "nick"`},
		{name: "unknown key in a named section", data: "[entry.web-1]\naks = \"never\"\n", want: `unknown key "entry.web-1.aks"`},
		{name: "unknown subtable", data: "[entry.web-1.more]\nask = \"x\"\n", want: `"entry.web-1.more"`},
		{name: "two unknown keys", data: "a = 1\nb = 2\n", want: `unknown keys "a", "b"`},
		{name: "key in upper case", data: "NAME = \"a\"\n", want: "1 unknown key;", notWant: "NAME"},
		{name: "key in mixed case beside the real one", data: "[entry.web-1]\nask = \"always\"\nAsk = \"never\"\n",
			want: "1 unknown key;", notWant: "Ask"},
		{name: "section in upper case", data: "[Entry.web-1]\nask = \"never\"\n", want: "2 unknown keys;", notWant: "Entry"},
		{name: "quoted key that folds to a known key", data: "[entry.web-1]\n\"aſk\" = \"never\"\n", want: "1 unknown key;", notWant: "ſ"},
		{name: "named section as a string", data: "entry = \"x\"\n", want: "entry: must be a table"},
		{name: "named section as an array", data: "entry = [\"x\"]\n", want: "entry: must be a table"},
		{name: "named section as an array of tables", data: "[[entry]]\nask = \"x\"\n", want: "entry: must be a table"},
		{name: "named entry as a string", data: "entry.web-1 = \"x\"\n",
			want: "line 1: type mismatch for config.entry: expected table but found string", notWant: "web-1"},
		{name: "inline table", data: "name = \"a\"\nentry = { web-1 = { ask = \"never\" } }\n",
			want: "line 2: inline tables ({ ... }) are not allowed"},
		{name: "inline table after a multi-line string", data: "name = \"\"\"\nx\n\"\"\"\nentry.web-1 = { ask = \"never\" }\n",
			want: "line 4: inline tables"},
		{name: "inline table in a section", data: "[entry]\nweb-1 = { ask = \"never\" }\n", want: "line 2: inline tables"},
		{name: "dotted key at the top", data: "entry.web-1.ask = \"never\"\n",
			want: `key "entry.web-1.ask": write it as ask = ... below its own [entry.web-1] header`},
		{name: "dotted key at the top, then the header", data: "entry.web-1.ask = \"never\"\n[entry.web-1]\n",
			want: `key "entry.web-1.ask": write it as ask = ... below its own [entry.web-1] header`},
		{name: "dotted key below the parent header", data: "[entry.web-1]\n[entry]\nweb-1.ask = \"never\"\n",
			want: `key "entry.web-1.ask": write it as ask`},
		{name: "parent header after the section", data: "[entry.web-1]\nask = \"never\"\n[entry]\n", want: ""},
		{name: "key in another case in an inline table", data: "entry = { web-1 = { ASK = \"never\" } }\n",
			want: "1 unknown key;", notWant: "ASK"},
		{name: "key in another case beside the real one in an inline table", data: "entry.web-1 = { ask = \"always\", ASK = \"never\" }\n",
			want: "1 unknown key;", notWant: "ASK"},
		{name: "section in another case in an inline table", data: "Entry = { web-1 = { ask = \"never\" } }\n",
			want: "3 unknown keys;", notWant: "Entry"},
		{name: "key in another case as a dotted key", data: "entry.web-1.Ask = \"never\"\n",
			want: "1 unknown key;", notWant: "Ask"},
		{name: "section in another case as a dotted key", data: "ENTRY.web-1.ask = \"never\"\n",
			want: "1 unknown key;", notWant: "ENTRY"},
		{name: "key in another case as a dotted key below the parent header", data: "[entry]\nweb-1.ASK = \"never\"\n",
			want: "1 unknown key;", notWant: "ASK"},
		{name: "quoted key in another case", data: "[entry.web-1]\n'Ask' = \"never\"\n", want: "1 unknown key;", notWant: "Ask"},
		{name: "wrong value type", data: "name = 5\n",
			want: "line 1: incompatible types: TOML value has type int64; destination has type string"},
		{name: "wrong value type in a section with pasted text as its name", data: "[entry.\"SECRET token\"]\nask = 5\n",
			want: "line 2: incompatible types", notWant: "SECRET"},

		// An error shows a key name only if each part looks like a config
		// key, or like a name for a named section. Anything else may be
		// pasted text, such as a token.
		{name: "pasted text as a key", data: "[entry.web-1]\nSECRETpass-word_1 = 1\n", want: "1 unknown key; " +
			"an error shows a key name only if it looks like a config key, such as tls_key", notWant: "SECRET"},
		{name: "pasted token as a key", data: "ghp_madeUpSECRETtokenForTests = 1\n", want: "1 unknown key;", notWant: "SECRET"},
		{name: "pasted lower case token as a key", data: "tok_madeupsecret0000000000000000000 = 1\n", want: "1 unknown key;", notWant: "secret"},
		{name: "key of 16 characters", data: "abcdefghijklm_no = 1\n", want: `unknown key "abcdefghijklm_no"`},
		{name: "key of 17 characters", data: "abcdefghijklm_nop = 1\n", want: "1 unknown key;", notWant: "abcdef"},
		{name: "section part of 17 characters", data: "[abcdefghijklm_nop]\nask = 1\n", want: "2 unknown keys;", notWant: "abcdef"},
		{name: "lower case token of 32 characters", data: "a3f9c0d1e2b4a5968778695a4b3c2d1e = 1\n", want: "1 unknown key;", notWant: "a3f9"},
		{name: "key with a dash", data: "tls-key = 1\n", want: "1 unknown key;", notWant: "tls-key"},
		{name: "key that starts with a digit", data: "1key = 1\n", want: "1 unknown key;", notWant: "1key"},
		{name: "pasted text as a section name", data: "[entry.\"SECRET token\"]\naks = 1\n", want: "1 unknown key;", notWant: "SECRET"},
		{name: "pasted text as a section name in a dotted key", data: "entry.\"SECRET token\".ask = \"never\"\n",
			want: "a key is not below the header of its own section", notWant: "SECRET"},
		{name: "names shown and not shown", data: "nick = 1\nNICK = 2\nnme = 3\nSECRETx = 4\n",
			want: `unknown keys "nick", "nme", and 2 more unknown keys; an error shows a key name only if`, notWant: "SECRET"},
		{name: "one name shown and one not", data: "nick = 1\nNICK = 2\n", want: `unknown key "nick", and 1 more unknown key;`},
		{name: "syntax error does not repeat the text", data: "name = s3cretVALUE\n", want: `line 1, column 8: not valid TOML`, notWant: "s3cretVALUE"},
		{name: "syntax error does not repeat a pasted key", data: "[entry.web-1]\nc2VjcmV0s3cretVALUE\n", want: "line 2", notWant: "s3cret"},
		{name: "bad number does not repeat the text", data: "name = 12345s3cret\n", want: "line 1", notWant: "s3cret"},
		{name: "same table twice", data: "[entry.a]\nask = \"x\"\n[entry.a]\nask = \"y\"\n", want: "line 3"},
		{name: "array of tables for a name", data: "[[entry.web-1]]\nask = \"never\"\n",
			want: "line 1: type mismatch for config.entry: expected table but found []map[string]any", notWant: "web-1"},
		{name: "inline table in an array", data: "[entry.web-1]\nask = [{ x = 1 }]\n", want: "line 2: incompatible types"},
		{name: "empty key", data: "\"\" = 1\n", want: "1 unknown key;"},
		{name: "empty key in a section", data: "[entry.web-1]\n\"\" = 1\n", want: "1 unknown key;"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f file
			err := decode([]byte(tt.data), &f, "entry")
			if tt.want == "" {
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
				return
			}
			checkError(t, err, tt.want, tt.notWant)
		})
	}
}

// TestDecodeRefusesSplitSections tries more ways to put a key into a named
// section without writing it below the section's header: other spellings
// of a dotted key, and an inline table after strings and comments that can
// hide the "{" from inlineTableLine.
func TestDecodeRefusesSplitSections(t *testing.T) {
	type entry struct {
		Ask string `toml:"ask"`
	}
	type file struct {
		Name  string           `toml:"name"`
		Entry map[string]entry `toml:"entry"`
	}
	const dotted = `key "entry.web-1.ask": write it as ask = ... below its own [entry.web-1] header, not as a dotted key`
	const inline = "line 2: inline tables ({ ... }) are not allowed"
	for name, tt := range map[string]struct{ data, want string }{
		"quoted dotted key at the top":            {"\"entry\".\"web-1\".ask = \"never\"\n", dotted},
		"dotted key with spaces":                  {"entry . web-1 . ask = \"never\"\n", dotted},
		"quoted dotted key below the parent":      {"[entry]\n\"web-1\".ask = \"never\"\n", dotted},
		"inline table after an escaped backslash": {"name = \"a\\\\\"\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table after a literal backslash":  {"name = 'a\\'\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table after 4 closing quotes":     {"name = '''a''''\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table after 5 closing quotes":     {"name = \"\"\"a\"\"\"\"\"\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table after an escaped quote":     {"name = \"\"\"a\\\"\"\"b\"\"\"\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table after a quote in a comment": {"# it's\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table after an empty string":      {"name = \"\"\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table after an empty ml string":   {"name = \"\"\"\"\"\"\nentry = { web-1 = { ask = \"never\" } }\n", inline},
		"inline table with CRLF":                  {"name = \"a\"\r\nentry = { web-1 = { ask = \"never\" } }\r\n", inline},
	} {
		t.Run(name, func(t *testing.T) {
			var f file
			checkError(t, decode([]byte(tt.data), &f, "entry"), tt.want, "")
		})
	}
}

// TestDecodeRefusesTelegramNotATable gives [telegram] other shapes.
func TestDecodeRefusesTelegramNotATable(t *testing.T) {
	for data, want := range map[string]string{
		"telegram = \"x\"\n":            "line 1: type mismatch for config.telegramSection: expected table but found string",
		"telegram = 5\n":                "line 1: type mismatch for config.telegramSection: expected table but found int64",
		"[[telegram]]\nuser_id = 1\n":   "line 1: type mismatch for config.telegramSection: expected table but found []map[string]any",
		"[telegram.sub]\nuser_id = 1\n": `unknown keys "telegram.sub", "telegram.sub.user_id"`,
	} {
		var f brokerFile
		checkError(t, decode([]byte(data), &f, "client", "store", "secret", "key"), want, "")
	}
}

func TestKeyText(t *testing.T) {
	names := []string{"secret", "key"}
	tests := []struct {
		key  toml.Key
		want string // "" means not shown
	}{
		{toml.Key{"tls_key"}, `"tls_key"`},
		{toml.Key{"telegram", "user_id"}, `"telegram.user_id"`},
		{toml.Key{"secret", "github-token", "windw"}, `"secret.github-token.windw"`},
		{toml.Key{"key", "Deploy.2", "ask"}, `"key.\"Deploy.2\".ask"`}, // a valid name
		{toml.Key{"notice_chat_id"}, `"notice_chat_id"`},               // the longest key nodkey defines
		{toml.Key{"a234567890123456"}, `"a234567890123456"`},
		{toml.Key{"a2345678901234567"}, ""}, // 17 characters
		{toml.Key{"telegram", "a2345678901234567"}, ""},
		{toml.Key{"a2345678901234567", "ask"}, ""},
		{toml.Key{}, ""},
		{toml.Key{""}, ""},
		{toml.Key{"ASK"}, ""},
		{toml.Key{"Ask"}, ""},
		{toml.Key{"aſk"}, ""},
		{toml.Key{"_ask"}, ""},
		{toml.Key{"1ask"}, ""},
		{toml.Key{"tls-key"}, ""},
		{toml.Key{"tls.key"}, ""},
		{toml.Key{"telegram", "github-token"}, ""}, // telegram has no names
		{toml.Key{"Secret", "github-token"}, ""},
		{toml.Key{"secret", "SECRET token", "ask"}, ""},
		{toml.Key{"secret", "-x"}, ""},
		{toml.Key{"secret", strings.Repeat("a", 65)}, ""},
		{toml.Key{"secret", "github-token", "ASK"}, ""},
		{toml.Key{"secret", "github-token", "x", "Y"}, ""},
	}
	for _, tt := range tests {
		got, ok := keyText(tt.key, names)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("keyText(%q) = %q, %v; want %q", []string(tt.key), got, ok, tt.want)
		}
	}
}

// TestTOMLErrorsDoNotRepeatText pastes made-up tokens into a broker config,
// in the forms a mistake can give: alone on a line, after a key, or with
// "=" at the end. The error gives only the line and the column.
func TestTOMLErrorsDoNotRepeatText(t *testing.T) {
	for _, line := range []string{
		"c2VjcmV0LXRva2VuLVNFQ1JFVA==", // base64 of "secret-token-SECRET"
		"ghp_madeUpSECRETtokenForTestsOnly0000000",
		"123456789:AAmadeUpSECRETtelegramToken",
		"0.00000000-0000-0000-0000-000000000000.madeUpSECRET:AAAAAAAAAAAAAAAAAAAAAA==",
		"token_file = 0.00000000.SECRET:AAAAAAAAAAAAAAAAAAAAAA==",
		"SECRETpass-word_1=",
		"SECRET.part.two=",
		"user_id = 99999999999999999999999SECRET",
		`"SECRET quoted" =`,
	} {
		t.Run(line, func(t *testing.T) {
			var f brokerFile
			err := decode([]byte("[telegram]\nuser_id = 1\n"+line+"\n"), &f, "client", "store", "secret", "key")
			checkError(t, err, "line 3, column ", "SECRET")
			checkError(t, err, "not valid TOML", "")
		})
	}
}

func TestTOMLError(t *testing.T) {
	pe := toml.ParseError{Message: "near SECRET", LastKey: "telegram.SECRET", Position: toml.Position{Line: 3, Col: 7}}
	for name, err := range map[string]error{
		"value":           pe,
		"pointer":         &pe,
		"wrapped value":   fmt.Errorf("wrapped: %w", pe),
		"wrapped pointer": fmt.Errorf("wrapped: %w", &pe),
	} {
		checkError(t, tomlError(err), "line 3, column 7: not valid TOML", "SECRET")
		if t.Failed() {
			t.Fatalf("for a %s", name)
		}
	}
	var nilPointer *toml.ParseError
	checkError(t, tomlError(fmt.Errorf("wrapped: %w", nilPointer)), "not valid TOML", "")
	// Other errors of the library name the last key and two types. Only the
	// line and the types are kept: the key can hold a section name that is
	// pasted text. An error of any other form is not shown.
	tests := []struct{ in, want string }{
		{`toml: line 2 (last key "telegram.user_id"): incompatible types: TOML value has type string; destination has type integer`,
			"line 2: incompatible types: TOML value has type string; destination has type integer"},
		{`toml: line 7 (last key "secret.\"SECRET \\\" token\".ask"): incompatible types`, "line 7: incompatible types"},
		{`toml: (last key "secret.SECRET"): type mismatch for config.secretSection: expected table but found string`,
			"type mismatch for config.secretSection: expected table but found string"},
		{`toml: line 2 (last key "a"): two` + "\nlines SECRET", "not a valid config file"},
		{`toml: line 2 (last key "a SECRET): incompatible types`, "not a valid config file"},
		{"toml: SECRET in a form nodkey does not know", "not a valid config file"},
		{"SECRET", "not a valid config file"},
	}
	for _, tt := range tests {
		if got := tomlError(errors.New(tt.in)); got.Error() != tt.want {
			t.Errorf("tomlError(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestDecodeRecoversFromAPanic makes the TOML library panic, through the
// seam that decodeWith gives. No input is known that makes the library
// panic, but its panic messages can repeat text from the file, such as a
// pasted token. The error must not, and decode must not panic.
func TestDecodeRecoversFromAPanic(t *testing.T) {
	const pasted = "SECRET-made-up-token"
	data := []byte("[telegram]\nuser_id = 1\n" + pasted + "\n")
	tests := map[string]tomlDecoder{
		"with a message that repeats the file": func(s string, _ any) (toml.MetaData, error) {
			panic("toml: BUG: Expected key type but found '" + s + "'.")
		},
		"with an error": func(s string, _ any) (toml.MetaData, error) {
			panic(errors.New(s))
		},
		"with a parse error": func(s string, _ any) (toml.MetaData, error) {
			panic(toml.ParseError{Message: s, LastKey: s, Position: toml.Position{Line: 3, Col: 1}})
		},
		"with a runtime error": func(s string, _ any) (toml.MetaData, error) {
			lines := strings.Split(s, "\n")
			return toml.MetaData{}, errors.New(lines[len(lines)]) // index out of range
		},
		"with nil": func(string, any) (toml.MetaData, error) {
			panic(nil)
		},
		"after it filled in a value": func(s string, v any) (toml.MetaData, error) {
			v.(*brokerFile).Listen = s
			panic(s)
		},
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			var f brokerFile
			err := decodeWith(fn, data, &f, "client", "store", "secret", "key")
			if !errors.Is(err, errNotConfig) {
				t.Errorf("decodeWith = %v, want %v", err, errNotConfig)
			}
			checkError(t, err, "not a valid config file", "SECRET")
		})
	}
	// The real library, for comparison: the same text is a syntax error.
	var f brokerFile
	checkError(t, decode(data, &f, "client", "store", "secret", "key"), "line 3, column ", "SECRET")

	// With GODEBUG=panicnil=1, recover returns nil for panic(nil). Run this
	// test again in a child process with that setting.
	if os.Getenv("GODEBUG") != "panicnil=1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDecodeRecoversFromAPanic$") //nolint:gosec // G204: the test runs its own binary again.
		cmd.Env = append(os.Environ(), "GODEBUG=panicnil=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("with GODEBUG=panicnil=1: %v\n%s", err, out)
		}
	}
}

// pasteMark stands for a token that was pasted into a config file by
// mistake. It cannot be a name, a key or the start of a path, because it
// holds "+" and ":". So no error may show it.
const pasteMark = "SEC+RET:"

// FuzzDecodeDoesNotRepeatText decodes and checks fuzzed config files, as
// LoadBroker and LoadClient do, and fails if an error shows pasteMark. The
// seeds put the mark in keys, in section names and in values.
func FuzzDecodeDoesNotRepeatText(f *testing.F) {
	// A broker config that passes newBroker, for seeds that reach its
	// checks. Its paths are not read.
	pin := testPin("laptop").String()
	valid := "listen = \"192.0.2.10:7743\"\ntls_key = \"/etc/nodkey/tls\"\naudit_log = \"/var/lib/nodkey/audit.jsonl\"\n" +
		"known_hosts = \"/etc/nodkey/known_hosts\"\n[telegram]\ntoken_file = \"/etc/nodkey/telegram\"\nuser_id = 1\n" +
		"[client.laptop]\npin = \"" + pin + "\"\n[store.main]\ntype = \"bws\"\nprogram = \"/usr/bin/bws\"\n" +
		"token_file = \"/etc/nodkey/bws\"\n[secret.github-token]\nstore = \"main\"\n" +
		"id = \"00000000-0000-0000-0000-000000000001\"\nclients = [\"laptop\"]\nask = \"window\"\nwindow = \"15m\"\n" +
		"[key.deploy]\nfile = \"/etc/nodkey/ssh\"\nclients = [\"laptop\"]\nask = \"never\"\nhosts = [\"web-1\"]\n"
	for _, s := range []string{
		"\"SEC+RET:\" = 1\n",
		"[secret.\"SEC+RET:\"]\nask = 1\n",
		"[secret.\"SEC+RET:\"]\naks = 1\n",
		"secret.\"SEC+RET:\".ask = \"never\"\n",
		"[telegram]\n\"SEC+RET:\" = 1\n",
		"[\"SEC+RET:\".x]\nask = 1\n",
		"x = { \"SEC+RET:\" = 1 }\n",
		"[key.k]\nhosts = [{ \"SEC+RET:\" = 1 }]\n",
		"[[secret.\"SEC+RET:\"]]\nask = 1\n",
		"[secret.a]\nclients = [\"SEC+RET:\", 1]\n",
		"listen = \"SEC+RET:\"\n",
		"[telegram]\nuser_id = \"SEC+RET:\"\n",
		"[secret.a.\"SEC+RET:\"]\nx = 1\n",
		"\"SEC+RET:\" = 1\n\"SEC+RET:\" = 2\n",
		"[secret.\"SEC+RET:\"]\n[secret.\"SEC+RET:\"]\n",
		"[secret.\"SEC+RET:\"]\nask = 1979-05-27T07:32:00Z\n",
		"[secret.\"SEC+RET:\"]\nmax_per_day = 99999999999999999999\n",
		"[secret.\"SEC+RET:\"]\nmax_per_day = 1.5\n",
		"[secret.\"SEC+RET:\"]\nnotify = [1]\n",
		"broker = \"192.0.2.10:7743\"\nbroker_pin = \"SEC+RET:\"\ntls_key = \"~/SEC+RET:\"\n",
		valid,
		strings.Replace(valid, pin, pasteMark, 1),
		strings.Replace(valid, "192.0.2.10:7743", pasteMark, 1),
		strings.Replace(valid, "00000000-0000-0000-0000-000000000001", pasteMark, 1),
		strings.Replace(valid, `ask = "window"`, `ask = "SEC+RET:"`, 1),
		strings.Replace(valid, "15m", pasteMark, 1),
		strings.Replace(valid, `hosts = ["web-1"]`, `hosts = ["SEC+RET:"]`, 1),
		strings.Replace(valid, `store = "main"`, `store = "SEC+RET:"`, 1),
		strings.Replace(valid, `type = "bws"`, `type = "SEC+RET:"`, 1),
		strings.Replace(valid, "[client.laptop]", `[client."SEC+RET:"]`, 1),
		strings.Replace(valid, `user_id = 1`, "user_id = 1\nhours = \"SEC+RET:\"", 1),
		strings.Replace(valid, `/etc/nodkey/tls`, "SEC+RET:", 1),
	} {
		f.Add(s)
	}
	// newBroker reads known_hosts. It gets a file that this test made, so
	// no other file is read. The other paths are only parsed.
	dir := privateTempDir(f)
	var lines []string
	for _, name := range []string{"web-1", "web-2", "db-1"} {
		lines = append(lines, knownHostsLine(name, newHostKey(f)))
	}
	knownHosts := writeFile(f, dir, "known_hosts", strings.Join(lines, "\n")+"\n", 0o644)
	f.Fuzz(func(t *testing.T, data string) {
		var b brokerFile
		err := decode([]byte(data), &b, "client", "store", "secret", "key")
		if err == nil {
			b.KnownHosts = knownHosts
			_, err = newBroker(&b)
		}
		if err != nil && strings.Contains(err.Error(), pasteMark) {
			t.Fatalf("broker config: the error shows the mark: %v", err)
		}
		var c clientFile
		err = decode([]byte(data), &c)
		if err == nil {
			_, err = newClientConfig(&c)
		}
		if err != nil && strings.Contains(err.Error(), pasteMark) {
			t.Fatalf("client config: the error shows the mark: %v", err)
		}
	})
}

func TestFormatDuration(t *testing.T) {
	tests := map[string]string{"15s": "15s", "10m": "10m", "110s": "1m50s", "8h": "8h", "90m": "1h30m", "2h0m1s": "2h0m1s"}
	for in, want := range tests {
		d, err := parseDuration("", "x", in)
		if err != nil {
			t.Fatal(err)
		}
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%s) = %q, want %q", in, got, want)
		}
	}
}
