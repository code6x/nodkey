package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/transport"
)

// runReload runs nodkey broker reload for the config of e.
func runReload(e *brokerEnv, extra ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	args := append([]string{"broker", "reload", "--config", e.cfgPath, "--timeout", "30s"}, extra...)
	code = run(args, strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

// listKeys asks the broker for the keys of the client, with c.
func listKeys(t *testing.T, e *brokerEnv, c *http.Client) []api.Key {
	t.Helper()
	a := e.post(c, api.PathKeys, api.KeysRequest{})
	mustStatus(t, a, http.StatusOK)
	ans, err := api.ReadAnswer[api.KeysAnswer](bytes.NewReader(a.body))
	if err != nil {
		t.Fatal(err)
	}
	return ans.Keys
}

// TestBrokerReload: nodkey broker reload sends SIGHUP and exits 0 only
// when the broker loaded the config that is in the file. An invalid config
// and a change that needs a restart are refused: the command exits 1 with
// the reason, the broker logs why and goes on with the old config. A new
// config takes effect at once; a client with a new pin cannot use its open
// connection; each reload that the broker took has a config_reloaded entry.
func TestBrokerReload(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()
	orig, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	write := func(cfg string) { writeTestFile(t, e.cfgPath, []byte(cfg), 0o600) }
	if n := len(listKeys(t, e, c)); n != 1 {
		t.Fatalf("%d keys at the start, want 1", n)
	}

	// The same config: loaded.
	code, out, errOut := runReload(e)
	if code != exitOK || !strings.Contains(out, "the broker loaded the new config") || errOut != "" {
		t.Fatalf("reload: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	// A config that does not parse: the command says why, and sends no
	// signal. SIGHUP by hand: the broker refuses it, logs why, and goes on
	// with the old config.
	write(string(orig) + "\n[client.bad]\npin = \"not-a-pin\"\n")
	code, out, errOut = runReload(e)
	if code != exitFailure || out != "" || !strings.Contains(errOut, "[client.bad] pin") ||
		strings.Count(errOut, "\n") != 1 {
		t.Fatalf("reload of an invalid config: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	e.signal(syscall.SIGHUP)
	e.stderr.wait(t, "nodkey broker: refused the new config; the broker goes on with the config it has")
	if !e.running() {
		t.Fatal("SIGHUP stopped the broker")
	}
	if n := len(listKeys(t, e, c)); n != 1 {
		t.Fatalf("%d keys after a refused reload, want 1", n)
	}

	// A config that parses, but names a key file that is not there: the
	// broker refuses it, and the command exits 1 with the reason.
	write(strings.Replace(string(orig), "/ssh-deploy\"", "/ssh-missing\"", 1))
	code, out, errOut = runReload(e)
	if code != exitFailure || out != "" || !strings.Contains(errOut, "the broker refused the new config") ||
		!strings.Contains(errOut, "[key.deploy]") || strings.Count(errOut, "\n") != 1 {
		t.Fatalf("reload of a missing key file: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if n := len(listKeys(t, e, c)); n != 1 {
		t.Fatalf("%d keys after a refused reload, want 1", n)
	}

	// A change that needs a restart: refused.
	write(strings.Replace(string(orig), "listen = ", "listen = \"192.0.2.1:7000\"\n# ", 1))
	code, _, errOut = runReload(e)
	if code != exitFailure || !strings.Contains(errOut, "listen: is changed, and a reload cannot change it") {
		t.Fatalf("reload of a new listen address: exit %d, stderr %q", code, errOut)
	}

	// The key is removed: the client sees it at once.
	cut := strings.Index(string(orig), "[key.deploy]")
	write(string(orig[:cut]))
	if code, out, errOut = runReload(e); code != exitOK {
		t.Fatalf("reload without the key: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if n := len(listKeys(t, e, c)); n != 0 {
		t.Fatalf("%d keys after the key was removed, want 0", n)
	}

	// The client gets a new pin: its open connection is refused.
	pin, err := transport.GenerateKeyFile(filepath.Join(e.dir, "client2.key"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^(\[client\.laptop\]\npin = )"[^"]*"`)
	write(re.ReplaceAllString(string(orig), `${1}"`+pin.String()+`"`))
	if code, out, errOut = runReload(e); code != exitOK {
		t.Fatalf("reload with a new pin: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if a := e.post(c, api.PathKeys, api.KeysRequest{}); a.err == nil && a.status != http.StatusForbidden {
		t.Fatalf("the old key of the client got status %d after its pin changed", a.status)
	}
	if a := e.post(e.httpClient(), api.PathKeys, api.KeysRequest{}); a.err == nil {
		t.Fatalf("a new connection with the old key got status %d", a.status)
	}

	e.signal(syscall.SIGINT)
	e.mustExit(exitOK)
	got := eventNames(e.auditEntries())
	if n := countOf(got, "config_reloaded"); n != 3 {
		t.Errorf("%d config_reloaded entries, want 3: %q", n, got)
	}
}

// countOf counts s in list.
func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

// TestBrokerReloadNoBroker: without a running broker, nodkey broker reload
// sends no signal and exits 1 with the reason: when the status file is
// missing, and when the process in it is not the broker that wrote it.
func TestBrokerReloadNoBroker(t *testing.T) {
	t.Parallel()
	e := newBrokerEnv(t, brokerOptions{})
	code, out, errOut := runReload(e)
	if code != exitFailure || out != "" || !strings.Contains(errOut, "is missing: the broker does not run") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	// A status file of this test process, with another start time: the
	// signal would go to the wrong process.
	start, err := procStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(reloadStatus{PID: os.Getpid(), Start: start + 1, Result: reloadStarted,
		ConfigSHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	status := filepath.Join(filepath.Dir(e.auditPath), reloadStatusName)
	writeTestFile(t, status, data, 0o600)
	code, _, errOut = runReload(e)
	if code != exitFailure || !strings.Contains(errOut, "does not run any more") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	// A symbolic link is refused.
	if err := os.Rename(status, status+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(status+".real", status); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut = runReload(e); code != exitFailure || !strings.Contains(errOut, "cannot read") {
		t.Fatalf("a link: exit %d, stderr %q", code, errOut)
	}
}

// TestBrokerReloadUsage: wrong usage is one line and exit 64.
func TestBrokerReloadUsage(t *testing.T) {
	for _, args := range [][]string{{"extra"}, {"--timeout", "0s"}, {"--timeout", "2h"}, {"--nope"}} {
		var out, errOut bytes.Buffer
		code := run(append([]string{"broker", "reload"}, args...), strings.NewReader(""), &out, &errOut)
		if code != exitUsage || strings.Count(errOut.String(), "\n") != 1 || out.Len() != 0 {
			t.Errorf("%q: exit %d, stderr %q", args, code, errOut.String())
		}
	}
	var out bytes.Buffer
	if code := run([]string{"broker", "reload", "--help"}, strings.NewReader(""), &out, &bytes.Buffer{}); code != exitOK ||
		!strings.HasPrefix(out.String(), "Usage: nodkey broker reload") {
		t.Errorf("--help: exit %d, %q", code, out.String())
	}
}

// TestBrokerReloadDuringTap: a request that waits for a tap while a reload
// gives its secret another store item is denied after the tap: no value
// is fetched, and the audit log records the deny.
func TestBrokerReloadDuringTap(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()
	orig, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	res := make(chan brokerAnswer, 1)
	go func() { res <- e.post(c, api.PathSecrets, secretsRequest("TOKEN", "github-token")) }()
	msgID, requestID := e.tg.waitAsk(1)
	other := "00000000-0000-4000-8000-000000000001"
	writeTestFile(t, e.cfgPath, []byte(strings.Replace(string(orig), idGitHub, other, 1)), 0o600)
	if code, out, errOut := runReload(e); code != exitOK {
		t.Fatalf("reload: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	for try := 1; ; try++ {
		answer := e.tg.waitTapAnswer(e.tg.tap(msgID, "o:"+requestID))
		if !strings.Contains(answer, "Not ready yet") {
			break
		}
		if try == 100 {
			t.Fatal("every tap came too early")
		}
	}
	a := <-res
	mustStatus(t, a, http.StatusForbidden)
	e.stderr.wait(t, "broker: a reload of the config took away what an approved request uses; the request is denied")
	e.signal(syscall.SIGINT)
	e.mustExit(exitOK)
	got := eventNames(e.auditEntries())
	// The request entry is written with its decision, after the tap.
	want := []string{"broker_started", "config_reloaded", "request", "decision:approve_once", "denied:not_allowed",
		"broker_stopped"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("audit entries:\n%q\nwant:\n%q", got, want)
	}
}
