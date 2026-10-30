package config_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/doctor"
)

// The test of nodkey doctor broker on real files is here, because only
// the tests of package config can trust a temporary directory.

func result(t *testing.T, r doctor.Report, name string) doctor.Result {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q", name)
	return doctor.Result{}
}

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
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func both(t *testing.T, r doctor.Report) string {
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

func canaryValue() string { return "made-up-canary-" + rand.Text() }

// TestBrokerReadOnlyCanary runs the broker checks on real files that hold
// made-up tokens, as the config and the file checks of the broker read
// them. No check may change a file, and no token may show in the output,
// also not a part of one (issue #124).
func TestBrokerReadOnlyCanary(t *testing.T) {
	dir := config.PrivateTempDir(t)
	creds := filepath.Join(dir, "creds")
	canaries := []string{canaryValue(), canaryValue(), canaryValue(), canaryValue()}
	write(t, filepath.Join(dir, "telegram-token"), canaries[0], 0o600)
	write(t, filepath.Join(dir, "bws-token"), canaries[1], 0o644) // too open: a FAIL
	write(t, filepath.Join(creds, "broker-tls-key"), canaries[2], 0o600)
	write(t, filepath.Join(dir, "known_hosts"), "", 0o644)
	write(t, filepath.Join(dir, "broker-tls-key.cred"), canaryValue(), 0o600)
	write(t, filepath.Join(dir, "bin", "bws"), "#!/bin/sh\necho "+canaries[3]+"\n", 0o755)
	pin := "sha256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	cfgPath := filepath.Join(dir, "broker.toml")
	write(t, cfgPath, `listen = "192.0.2.10:7743"
tls_key = "${CREDENTIALS_DIRECTORY}/broker-tls-key"
audit_log = "`+dir+`/audit.jsonl"
known_hosts = "`+dir+`/known_hosts"
[telegram]
token_file = "`+dir+`/telegram-token"
user_id = 123456789
[client.laptop]
pin = "`+pin+`"
[store.main]
type = "bws"
program = "`+dir+`/bin/bws"
token_file = "`+dir+`/bws-token"
[secret.github-token]
store = "main"
id = "00000000-0000-0000-0000-000000000001"
clients = ["laptop"]
ask = "always"
`, 0o644)
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	before := snapshot(t, dir)

	env := doctor.BrokerEnv{
		LookupUser:     func(string) (uint32, error) { return uint32(os.Geteuid()), nil },
		Stat:           os.Stat,
		ReadFile:       func(string) ([]byte, error) { return nil, fs.ErrNotExist },
		ReadDir:        func(string) ([]string, error) { return nil, fs.ErrNotExist },
		SystemdVersion: func() (string, error) { return "systemd 255", nil },
		Service:        func() (string, []string, error) { return "active", nil, nil },
	}
	env.ConfigPath, env.CredDir = cfgPath, creds
	env.ReadConfig = config.ReadBroker
	env.CheckFiles = func(b *config.Broker, self uint32, skip func(string) bool) error {
		return b.CheckFilesAs(self, skip)
	}
	env.UnitText = func() (string, error) {
		return "User=nodkey\nLoadCredentialEncrypted=broker-tls-key:" + dir + "/broker-tls-key.cred\n", nil
	}
	r := doctor.Run(doctor.BrokerChecks(env))
	if res := result(t, r, "config"); res.Status != doctor.OK {
		t.Fatalf("config: %+v", res)
	}
	if res := result(t, r, "files"); res.Status != doctor.Fail {
		t.Errorf("files: %+v, want a FAIL", res)
	}
	out := both(t, r)
	for _, c := range canaries {
		for _, part := range []string{c, c[len("made-up-canary-"):][:8]} {
			if strings.Contains(out, part) {
				t.Errorf("the output holds a made-up token: %s", out)
			}
		}
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("a check changed a file:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
