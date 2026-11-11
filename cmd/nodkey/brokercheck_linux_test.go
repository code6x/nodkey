package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests of nodkey broker check run it in this process. It sets
// CREDENTIALS_DIRECTORY for the process, so these tests are not parallel,
// and each one gives the variable back with t.Setenv.

func runCheck(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runBroker(append([]string{"check"}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestBrokerCheckRefusesWhatTheStartRefuses: for each config that the
// start of nodkey broker refuses, nodkey broker check exits 1 with the
// same reason. A good config passes both.
func TestBrokerCheckRefusesWhatTheStartRefuses(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	cases := []struct {
		name   string
		change func(t *testing.T, e *brokerEnv)
		reason string // in the log of the start and in the check's error
	}{
		{"a bad pin", func(t *testing.T, e *brokerEnv) {
			appendConfig(t, e, "\n[client.bad]\npin = \"not-a-pin\"\n")
		}, "[client.bad] pin"},
		{"a host that known_hosts does not have", func(t *testing.T, e *brokerEnv) {
			replaceConfig(t, e, `hosts = ["web-1"]`, `hosts = ["web-9"]`)
		}, "[key.deploy] hosts: item 1 is not a host in known_hosts"},
		{"a store program that others can change", func(t *testing.T, e *brokerEnv) {
			if err := os.Chmod(filepath.Join(e.dir, "bin", "bws"), 0o722); err != nil { //nolint:gosec // G302: the test makes a bad mode.
				t.Fatal(err)
			}
		}, "[store.main] program"},
		{"a known_hosts that others can change", func(t *testing.T, e *brokerEnv) {
			if err := os.Chmod(filepath.Join(e.dir, "etc", "known_hosts"), 0o622); err != nil { //nolint:gosec // G302: the test makes a bad mode.
				t.Fatal(err)
			}
		}, "known_hosts"},
		{"an audit log that is a key file", func(t *testing.T, e *brokerEnv) {
			replaceConfig(t, e, "audit_log = \""+e.auditPath+"\"",
				"audit_log = \""+filepath.Join(e.dir, "bin", "bws-vault")+"\"")
		}, "audit_log"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newBrokerEnv(t, brokerOptions{})
			c.change(t, e)
			e.start()
			e.mustExit(exitFailure)
			if !e.stderr.has(c.reason) {
				t.Fatalf("the start does not say %q; its log:\n%s", c.reason, e.stderr.text())
			}
			code, out, errOut := runCheck(t, "--config", e.cfgPath, "--credentials", filepath.Join(e.dir, "creds"))
			if code != exitFailure || out != "" || !strings.Contains(errOut, c.reason) ||
				strings.Count(errOut, "\n") != 1 || !strings.Contains(errOut, "docs/setup.md section 7") {
				t.Fatalf("check: exit %d, stdout %q, stderr %q; want exit 1 with %q", code, out, errOut, c.reason)
			}
		})
	}
	t.Run("a good config", func(t *testing.T) {
		e := newBrokerEnv(t, brokerOptions{})
		code, out, errOut := runCheck(t, "--config", e.cfgPath, "--credentials", filepath.Join(e.dir, "creds"))
		if code != exitOK || errOut != "" || strings.Contains(out, "skipped") ||
			!strings.Contains(out, "passed the checks of a start") {
			t.Fatalf("check: exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})
}

// TestBrokerCheckFiles: with --files DIR, known_hosts comes from DIR, and
// the file at the path in the config is not read.
func TestBrokerCheckFiles(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	e := newBrokerEnv(t, brokerOptions{})
	files := filepath.Join(e.dir, "new")
	if err := os.Mkdir(files, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(e.dir, "etc", "known_hosts")
	good, err := os.ReadFile(knownHosts) //nolint:gosec // G304: the test's own file.
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(files, "broker.toml"), cfg, 0o600)
	writeTestFile(t, filepath.Join(files, "known_hosts"), good, 0o600)
	// The file at the path in the config is gone: the check passes, so it
	// did not read it.
	if err := os.Remove(knownHosts); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCheck(t, "--files", files)
	if code != exitOK || errOut != "" || !strings.Contains(out, filepath.Join(files, "broker.toml")+" passed") {
		t.Fatalf("check --files: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	for _, want := range []string{"needs the credential \"telegram-token\"", "the store programs and audit_log"} {
		if !strings.Contains(out, "skipped: ") || !strings.Contains(out, want) {
			t.Errorf("stdout %q does not say %q", out, want)
		}
	}
	// A good known_hosts at the path, and one in DIR without web-1: the
	// check uses the one in DIR, and refuses the config.
	writeTestFile(t, knownHosts, good, 0o600)
	var noWeb []string
	for line := range strings.Lines(string(good)) {
		if !strings.HasPrefix(line, "web-1 ") {
			noWeb = append(noWeb, line)
		}
	}
	writeTestFile(t, filepath.Join(files, "known_hosts"), []byte(strings.Join(noWeb, "")), 0o600)
	code, out, errOut = runCheck(t, "--files", files)
	if code != exitFailure || !strings.Contains(errOut, "[key.deploy] hosts: item 1 is not a host") {
		t.Fatalf("check --files with a known_hosts without web-1: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// --config with --files: the config from --config, known_hosts from DIR.
	code, _, errOut = runCheck(t, "--config", e.cfgPath, "--files", files)
	if code != exitFailure || !strings.Contains(errOut, "[key.deploy] hosts: item 1 is not a host") {
		t.Fatalf("check --config --files: exit %d, stderr %q", code, errOut)
	}
}

// TestBrokerCheckNeedsNoCredentials: the check runs as a user that is not
// root, does not read the credentials, and opens no port.
func TestBrokerCheckNeedsNoCredentials(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if os.Getuid() == 0 {
		t.Skip("runs as root; this test is for a user that is not root")
	}
	e := newBrokerEnv(t, brokerOptions{})
	// The test holds the listen address: a start would fail there.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// No --credentials: each credential is skipped, and the check passes.
	code, out, errOut := runCheck(t, "--config", e.cfgPath)
	if code != exitOK || errOut != "" {
		t.Fatalf("check: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	for _, name := range []string{"broker-tls-key", "telegram-token", "bws-token", "bws-token-vault", "ssh-deploy"} {
		if !strings.Contains(out, "needs the credential \""+name+"\";") {
			t.Errorf("stdout %q does not skip %s", out, name)
		}
	}

	// --credentials with files that nobody may read: they are found, not
	// read. NAME.cred counts too.
	creds := filepath.Join(e.dir, "sealed")
	if err := os.Mkdir(creds, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"broker-tls-key", "telegram-token", "bws-token.cred", "bws-token-vault", "ssh-deploy.cred"} {
		writeTestFile(t, filepath.Join(creds, name), []byte("sealed"), 0)
	}
	code, out, errOut = runCheck(t, "--config", e.cfgPath, "--credentials", creds)
	if code != exitOK || errOut != "" || strings.Contains(out, "skipped") {
		t.Fatalf("check --credentials: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	// A missing credential: exit 1, and the error names it and its place.
	if err := os.Remove(filepath.Join(creds, "ssh-deploy.cred")); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runCheck(t, "--config", e.cfgPath, "--credentials", creds)
	if code != exitFailure || out != "" || !strings.Contains(errOut, "[key.deploy] file: the credential \"ssh-deploy\" is not in") {
		t.Fatalf("check without ssh-deploy: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// A directory is not a credential.
	if err := os.Mkdir(filepath.Join(creds, "ssh-deploy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut = runCheck(t, "--config", e.cfgPath, "--credentials", creds); code != exitFailure ||
		!strings.Contains(errOut, "is not a regular file") {
		t.Fatalf("check with a directory for ssh-deploy: exit %d, stderr %q", code, errOut)
	}
	// A directory that this user cannot enter: the error says so, and
	// does not say that the credential is missing.
	if err := os.Chmod(creds, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(creds, 0o700) }) //nolint:gosec // G302: the test's own directory.
	code, _, errOut = runCheck(t, "--config", e.cfgPath, "--credentials", creds)
	if code != exitFailure || !strings.Contains(errOut, "cannot look for the credential") ||
		strings.Contains(errOut, "is not in") {
		t.Fatalf("check with a closed credentials directory: exit %d, stderr %q", code, errOut)
	}
	// A credential path with "..": refused, with a clear reason.
	if err := os.Chmod(creds, 0o700); err != nil { //nolint:gosec // G302: the test's own directory.
		t.Fatal(err)
	}
	replaceConfig(t, e, "${CREDENTIALS_DIRECTORY}/ssh-deploy", "${CREDENTIALS_DIRECTORY}/../ssh-deploy")
	for _, args := range [][]string{{}, {"--credentials", creds}} {
		code, _, errOut = runCheck(t, append([]string{"--config", e.cfgPath}, args...)...)
		if code != exitFailure || !strings.Contains(errOut, "[key.deploy] file: the path leaves ${CREDENTIALS_DIRECTORY}") {
			t.Fatalf("check %q with ../ssh-deploy: exit %d, stderr %q", args, code, errOut)
		}
	}
}

// TestBrokerCheckCleansConfigText: text from the config, such as a line
// break in a path, cannot add a line to the output.
func TestBrokerCheckCleansConfigText(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	e := newBrokerEnv(t, brokerOptions{})
	replaceConfig(t, e, "known_hosts = \"", "known_hosts = \"/etc/a\\n::error::fake\\u001b[31m")
	for _, args := range [][]string{{"--config", e.cfgPath}, {"--config", e.cfgPath, "--files", e.dir}} {
		code, out, errOut := runCheck(t, args...)
		if code != exitFailure || out != "" || strings.Count(errOut, "\n") != 1 || strings.ContainsRune(errOut, 0x1b) {
			t.Errorf("check %q: exit %d, stdout %q, stderr %q; want exit 1 and one clean line", args, code, out, errOut)
		}
	}
	// The same in a skipped line.
	e = newBrokerEnv(t, brokerOptions{})
	replaceConfig(t, e, "${CREDENTIALS_DIRECTORY}/ssh-deploy", "${CREDENTIALS_DIRECTORY}/ssh\\n::error::x")
	code, out, errOut := runCheck(t, "--config", e.cfgPath)
	if code != exitOK || strings.Contains(out, "\n::error") {
		t.Errorf("check: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// TestBrokerCheckUsage: wrong usage exits 64 with one line.
func TestBrokerCheckUsage(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	missing := filepath.Join(t.TempDir(), "missing")
	for _, args := range [][]string{
		{"--nope"},
		{"extra"},
		{"--files", missing},
		{"--credentials", missing},
		{"--config"},
	} {
		code, out, errOut := runCheck(t, args...)
		if code != exitUsage || out != "" || strings.Count(errOut, "\n") != 1 ||
			!strings.HasPrefix(errOut, "nodkey broker check: ") {
			t.Errorf("check %q: exit %d, stdout %q, stderr %q; want exit 64 and one line", args, code, out, errOut)
		}
	}
	code, out, _ := runCheck(t, "--help")
	if code != exitOK || !strings.HasPrefix(out, "Usage: nodkey broker check") {
		t.Errorf("check --help: exit %d, stdout %q", code, out)
	}
	// A config that is not there: exit 1, with the path.
	code, _, errOut := runCheck(t, "--config", missing)
	if code != exitFailure || !strings.Contains(errOut, missing) {
		t.Errorf("check of a missing config: exit %d, stderr %q", code, errOut)
	}
}

func appendConfig(t *testing.T, e *brokerEnv, extra string) {
	t.Helper()
	data, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, e.cfgPath, append(data, extra...), 0o600)
}

func replaceConfig(t *testing.T, e *brokerEnv, old, repl string) {
	t.Helper()
	data, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(old)) {
		t.Fatalf("the config has no %q", old)
	}
	writeTestFile(t, e.cfgPath, bytes.Replace(data, []byte(old), []byte(repl), 1), 0o600)
}
