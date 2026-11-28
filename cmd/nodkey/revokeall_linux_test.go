package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
)

// runRevokeAll runs nodkey revoke --all for the config of e.
func runRevokeAll(e *brokerEnv) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run([]string{"revoke", "--all", "--config", e.cfgPath, "--timeout", "30s"}, strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestBrokerRevokeAll: nodkey revoke --all sends SIGUSR1 to the broker in
// a child process, which ends a scheduled grant with a grant_ended entry
// (cause revoked) and sends one alert. The command prints the count and
// exits 0; the broker goes on, and the next request is asked for again.
// After a restart the grant stays ended.
func TestBrokerRevokeAll(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{preapprove: true})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()
	grant := api.PreapproveRequest{
		Secrets: []string{"github-token"}, Uses: 2, Reason: "job nightly-backup",
		From:  time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
		Until: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	mustStatus(t, e.approve(c, api.PathPreapprove, grant), http.StatusOK)

	code, out, errOut := runRevokeAll(e)
	if code != exitOK || out != "nodkey revoke: the broker ended every grant: 1 grant(s)\n" || errOut != "" {
		t.Fatalf("revoke --all: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	if !e.running() {
		t.Fatal("SIGUSR1 stopped the broker")
	}
	e.mustAskAndDeny(c)
	// A second one finds nothing.
	if code, out, _ = runRevokeAll(e); code != exitOK || !strings.Contains(out, ": 0 grant(s)") {
		t.Fatalf("second revoke --all: exit %d, stdout %q", code, out)
	}
	e.restart()
	c = e.httpClient()
	e.mustAskAndDeny(c)

	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	ended := 0
	for _, ev := range e.auditEntries() {
		if ev["event"] == "grant_ended" {
			if ev["cause"] != "revoked" {
				t.Errorf("grant_ended entry %v, want cause revoked", ev)
			}
			ended++
		}
	}
	if ended != 1 {
		t.Errorf("%d grant_ended entries, want 1", ended)
	}
	if n := e.tg.alertCount("Every grant ended (nodkey revoke --all on the broker host): 1 grant(s)"); n != 1 {
		t.Errorf("%d alerts about the revoke, want 1", n)
	}
}

// TestRevokeAllOldBroker: a status file without revoke_all is of a broker
// from before nodkey revoke --all, which SIGUSR1 would stop. The command
// sends no signal, exits 1 and says how to fix it.
func TestRevokeAllOldBroker(t *testing.T) {
	t.Parallel()
	e := newBrokerEnv(t, brokerOptions{})
	// Another start time too, so that even a wrong check could not signal
	// this test process.
	start, err := procStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"pid": os.Getpid(), "start": start + 1, "result": reloadStarted})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(filepath.Dir(e.auditPath), reloadStatusName), data, 0o600)
	code, out, errOut := runRevokeAll(e)
	if code != exitFailure || out != "" || !strings.Contains(errOut, "older than nodkey revoke --all") ||
		strings.Count(errOut, "\n") != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// TestRevokeAllNoBroker: with no status file the command sends no signal
// and exits 1.
func TestRevokeAllNoBroker(t *testing.T) {
	t.Parallel()
	e := newBrokerEnv(t, brokerOptions{})
	code, out, errOut := runRevokeAll(e)
	if code != exitFailure || out != "" || !strings.Contains(errOut, "is missing: the broker does not run") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}
