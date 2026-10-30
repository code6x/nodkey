package doctor

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/client"
)

// canaryValue returns a made-up token, made at run time.
func canaryValue() string { return "made-up-canary-" + rand.Text() }

// snapshot returns the name, mode, size and time of change of every file
// under dir.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		b.WriteString(p + " " + fi.Mode().String() + " " + strconv.FormatInt(fi.Size(), 10) + " " + fi.ModTime().String() + "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func write(t *testing.T, path, data string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

// both returns the report as text and as JSON.
func both(t *testing.T, r Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestClientCanary runs the config check of the client on a TLS key file
// that holds a made-up token.
func TestClientCanary(t *testing.T) {
	dir := t.TempDir()
	c := canaryValue()
	write(t, filepath.Join(dir, "client.key"), c, 0o600)
	pin := "sha256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	cfg := filepath.Join(dir, "client.toml")
	write(t, cfg, `broker = "192.0.2.10:7743"
broker_pin = "`+pin+`"
tls_key = "`+dir+`/client.key"
`, 0o600)
	before := snapshot(t, dir)
	env := goodClient(t)
	env.ConfigPath = cfg
	env.Load = func(path string) (Prober, error) {
		b, err := client.Load(path)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	r := Run(ClientChecks(t.Context(), env))
	if res := result(t, r, "config"); res.Status != Fail {
		t.Errorf("config: %+v, want a FAIL", res)
	}
	if out := both(t, r); strings.Contains(out, c) || strings.Contains(out, c[len("made-up-canary-"):][:8]) {
		t.Errorf("the output holds a made-up token: %s", out)
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("a check changed a file:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestNoSecretCalls checks the code of nodkey doctor: it does not import
// the parts that talk to Telegram, run a store or load a key, and it
// names no call that decrypts a credential or polls Telegram.
func TestNoSecretCalls(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join("..", "..", "cmd", "nodkey", "doctor.go"))
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"getUpdates", `"systemd-creds"`, "ReadPrivateFile", "LoadKeyFile", "os.WriteFile",
			"os.Create", "os.OpenFile", "os.Remove", "os.Mkdir", "os.Chmod", "os.Chown", "os.Rename"} {
			if bytes.Contains(src, []byte(bad)) {
				t.Errorf("%s names %s", f, bad)
			}
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range []string{"/internal/telegram", "/internal/store", "/internal/transport", "/internal/broker", "/internal/approval"} {
				if strings.HasSuffix(p, bad) {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
	if n < 4 {
		t.Errorf("checked %d files, want the files of nodkey doctor", n)
	}
}
