package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
)

// The log lines of nodkey broker that the tests look for.
const (
	lineStarting      = "nodkey broker: starting"
	lineConfigChecked = "nodkey broker: the config and the files it names passed their checks"
	lineNoCoreDumps   = "nodkey broker: core dumps are off"
	lineTLSKey        = "nodkey broker: the TLS key is loaded"
	lineSSHKey        = "nodkey broker: an SSH key is loaded and can sign"
	lineSSHKeys       = "nodkey broker: the SSH keys are loaded"
	lineAuditOpen     = "nodkey broker: the audit log is open"
	lineStoreStarted  = "nodkey broker: a store started"
	lineStoreFailed   = "nodkey broker: a store could not start"
	lineProxy         = "calls to Telegram go through a proxy from the environment"
	lineListenOpen    = "nodkey broker: the listen address is open"
	lineApproverRuns  = "nodkey broker: the approver runs"
	lineListening     = "nodkey broker: listening; the broker is ready"
	lineStopSignal    = "nodkey broker: stopping, as a signal asked"
	lineStopApprover  = "nodkey broker: stopping, because the approver stopped"
	lineRunStopped    = "nodkey broker: the approver stopped; no answer counts any more"
	lineSvcStopped    = "nodkey broker: the service stopped"
	lineServerClosed  = "nodkey broker: the server is closed"
	lineStoresClosed  = "nodkey broker: the stores are closed"
	lineAuditClosed   = "nodkey broker: the audit log is closed"
	lineStopped       = "nodkey broker: stopped"
)

// secretsRequest returns a request of one variable for the secret name.
func secretsRequest(variable, name string) api.SecretsRequest {
	return api.SecretsRequest{
		Secrets: []api.SecretRef{{Var: variable, Name: name}},
		Command: []string{"gh", "release", "create", "v1.2.0"},
		Dir:     "/home/dev/src/app",
		Reason:  "publish the release the user asked for",
	}
}

// secretValues decodes the answer to a request for secrets.
func secretValues(t *testing.T, a brokerAnswer) map[string]string {
	t.Helper()
	mustStatus(t, a, http.StatusOK)
	ans, err := api.ReadAnswer[api.SecretsAnswer](bytes.NewReader(a.body))
	if err != nil {
		t.Fatalf("the answer: %v", err)
	}
	m := make(map[string]string, len(ans.Secrets))
	for _, s := range ans.Secrets {
		m[s.Var] = string(s.Value)
	}
	return m
}

// checkCoreDumpsOff checks from outside that the process pid has a soft
// and a hard limit of core dumps of 1, and is not dumpable: the files of a
// process that is not dumpable are owned by root in /proc, and other
// processes of its user cannot read its environment.
func checkCoreDumpsOff(t *testing.T, pid int) {
	t.Helper()
	limits, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for line := range strings.SplitSeq(string(limits), "\n") {
		rest, ok := strings.CutPrefix(line, "Max core file size")
		if !ok {
			continue
		}
		found = true
		if f := strings.Fields(rest); len(f) < 2 || f[0] != "1" || f[1] != "1" {
			t.Errorf("the soft and hard limits of core dumps of the broker are not 1: %q", line)
		}
	}
	if !found {
		t.Errorf("/proc/%d/limits has no limit of core dumps", pid)
	}
	if os.Geteuid() == 0 {
		t.Log("the test runs as root, so it cannot see whether the broker is dumpable")
		return
	}
	environ := fmt.Sprintf("/proc/%d/environ", pid)
	fi, err := os.Stat(environ)
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		t.Errorf("the broker is dumpable: %s is not owned by root (%v)", environ, fi.Sys())
	}
	if _, err := os.ReadFile(environ); !errors.Is(err, fs.ErrPermission) { //nolint:gosec // G304: a file of /proc.
		t.Errorf("another process of the user reads the environment of the broker: %v", err)
	}
}

// TestBrokerStartsAndStops runs nodkey broker with a store whose start
// fails, and stops it with SIGTERM. It checks the order of the start, that
// core dumps are off, that the broken store does not stop the broker (one
// alert; its secrets are denied; the other store works), that the stop
// closes the connection of the waiting getUpdates call while the broker
// still runs, the order of the stop, exit code 0, and the audit log: from
// broker_started to broker_stopped, every entry with its anchor in the
// journal.
func TestBrokerStartsAndStops(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{holdAlerts: true}, seamStoreStartFails)
	e.stderr.wait(t, lineListening)
	e.stderr.inOrder(t, lineStarting, lineConfigChecked, lineNoCoreDumps, lineTLSKey, lineSSHKey, lineSSHKeys,
		lineAuditOpen, lineStoreStarted, lineStoreFailed, lineProxy, "variable=SSL_CERT_FILE", lineListenOpen,
		"audit anchor 1:", lineApproverRuns, lineListening)
	checkCoreDumpsOff(t, e.cmd.Process.Pid)

	// One alert for the broken store; it waits at the fake Telegram until
	// the test releases it.
	if alert := e.tg.waitAlert("could not start"); !strings.Contains(alert, "vault") {
		t.Errorf("the alert does not name the store: %s", alert)
	}
	c := e.httpClient()
	// A secret of the broken store is denied: its fetch fails too.
	mustStatus(t, e.post(c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password")),
		http.StatusServiceUnavailable)
	// A secret of the other store is handed out after the tap.
	if got := secretValues(t, e.approve(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))); got["GH_TOKEN"] != e.values["github-token"] {
		t.Error("the variable did not get its value")
	}

	// SIGTERM while a getUpdates call waits. The stop waits for the held
	// alert after the server is closed, so the broker still runs when the
	// test looks at the polling.
	e.tg.waitPolling()
	e.signal(syscall.SIGTERM)
	e.stderr.wait(t, lineServerClosed)
	e.tg.waitPollsGone()
	if !e.running() {
		t.Fatal("the broker ended before the test released the alert")
	}
	polls := e.tg.pollCount()
	e.tg.release()
	e.mustExit(exitOK)
	if n := e.tg.pollCount(); n != polls {
		t.Errorf("%d getUpdates calls after the approver stopped", n-polls)
	}
	if n := e.tg.alertCount("could not start"); n != 1 {
		t.Errorf("%d alerts about the store, want 1", n)
	}
	e.stderr.inOrder(t, lineStopSignal, lineRunStopped, lineSvcStopped, lineServerClosed, lineStoresClosed,
		lineAuditClosed, lineStopped+`" exit_code=0`)

	// The audit log, from broker_started to broker_stopped.
	got := eventNames(e.auditEntries())
	want := []string{
		"broker_started",
		"request", "grant_used:never_rule", "error:store_failed", "denied:error", // db-password
		"request", "decision:approve_once", "secret_sent", // github-token
		"broker_stopped",
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit entries:\n%q\nwant:\n%q", got, want)
	}
	if v, _ := e.auditEntries()[0]["version"].(string); v != version {
		t.Errorf("broker_started has version %q, want %q", v, version)
	}
	f, err := os.Open(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	anchors, err := audit.ReadAnchors(strings.NewReader(e.stderr.text()))
	if err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(f, anchors...)
	if err != nil || res.Entries != uint64(len(want)) || res.Anchors != res.Entries {
		t.Errorf("audit verify: %+v, %v; want every entry with its anchor", res, err)
	}
}

// TestBrokerPollConflict: when Telegram reports a polling conflict, the
// broker sends an alert, writes an error entry with poll_conflict, stops
// in order, and exits with exitPollConflict, which the example unit lists
// in RestartPreventExitStatus=.
func TestBrokerPollConflict(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{refusePolls: http.StatusConflict})
	e.mustExit(exitPollConflict)
	e.tg.waitAlert("conflict")
	e.stderr.inOrder(t, lineAuditOpen, "audit anchor 1:", lineApproverRuns,
		"another program polls with the bot token", lineStopApprover, lineRunStopped, lineAuditClosed,
		fmt.Sprintf("exit_code=%d", exitPollConflict))
	got := eventNames(e.auditEntries())
	if want := []string{"broker_started", "error:poll_conflict", "broker_stopped"}; !slices.Equal(got, want) {
		t.Errorf("audit entries %q, want %q", got, want)
	}
}

// TestBrokerRefusesTheSameKeyTwice: two [key.*] sections whose files hold
// one key stop the start, before the audit log is opened and before
// anything listens or calls Telegram.
func TestBrokerRefusesTheSameKeyTwice(t *testing.T) {
	t.Parallel()
	e := startBroker(t, brokerOptions{sameKeyTwice: true})
	e.mustExit(exitFailure)
	if !e.stderr.has("[key.copy] and [key.deploy] hold the same public key") {
		t.Errorf("the log does not say why; its log:\n%s", e.stderr.text())
	}
	for _, line := range []string{lineAuditOpen, lineListening} {
		if e.stderr.has(line) {
			t.Errorf("the log has %q", line)
		}
	}
	if _, err := os.Lstat(e.auditPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the broker made the audit log: %v", err)
	}
	if p := e.tg.proxied(); len(p) != 0 {
		t.Errorf("the broker called Telegram: %q", p)
	}
}

// TestBrokerNoListenBeforeTheAuditLog: when the audit log cannot be
// opened, because another process holds its lock as a second broker
// would, the broker stops, and never listens or polls.
func TestBrokerNoListenBeforeTheAuditLog(t *testing.T) {
	t.Parallel()
	e := newBrokerEnv(t, brokerOptions{})
	f, err := os.OpenFile(e.auditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var lockErr error
	if err := rc.Control(func(fd uintptr) { lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB) }); err != nil {
		t.Fatal(err)
	}
	if lockErr != nil {
		t.Fatal(lockErr)
	}

	// Try to connect to the listen address all the time the broker runs.
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	var connected bool
	wg.Go(func() {
		d := net.Dialer{Timeout: 100 * time.Millisecond}
		for ctx.Err() == nil {
			if c, err := d.DialContext(ctx, "tcp", e.addr); err == nil {
				_ = c.Close()
				connected = true
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	})
	e.start()
	e.mustExit(exitFailure)
	cancel()
	wg.Wait()
	if connected {
		t.Error("the broker listened, though it could not open its audit log")
	}
	if !e.stderr.has("only one broker may write to one audit log") {
		t.Errorf("the log does not say why; its log:\n%s", e.stderr.text())
	}
	for _, line := range []string{lineAuditOpen, lineListenOpen, lineApproverRuns, lineListening} {
		if e.stderr.has(line) {
			t.Errorf("the log has %q", line)
		}
	}
	if p := e.tg.proxied(); len(p) != 0 {
		t.Errorf("the broker called Telegram: %q", p)
	}
}

// TestBrokerListenAddressInUse: when the broker cannot open its listen
// address, the start stops before the broker_started entry, before any
// call to Telegram and before any alert. So when systemd starts it again
// and again, such as at boot before the private network is up, no alert
// goes out each time, and the audit log does not grow.
func TestBrokerListenAddressInUse(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	e := newBrokerEnv(t, brokerOptions{listen: ln.Addr().String()})
	e.start(seamStoreStartFails) // a store alert waits
	e.mustExit(exitFailure)
	e.stderr.inOrder(t, lineAuditOpen, lineStoreFailed, "cannot listen on "+e.addr, lineStoresClosed,
		lineAuditClosed, lineStopped+`" exit_code=1`)
	for _, line := range []string{lineListenOpen, lineApproverRuns, lineListening} {
		if e.stderr.has(line) {
			t.Errorf("the log has %q", line)
		}
	}
	if data, err := os.ReadFile(e.auditPath); err != nil || len(data) != 0 {
		t.Errorf("the audit log: %d bytes, %v; want it empty", len(data), err)
	}
	if p := e.tg.proxied(); len(p) != 0 {
		t.Errorf("the broker called Telegram: %q", p)
	}
}

// TestBrokerNeedsCoreDumpsOff: when the soft limit of core dumps cannot
// be set to 1, because the hard limit is 0, the broker does not start. It
// stops before it loads a key or opens the audit log.
func TestBrokerNeedsCoreDumpsOff(t *testing.T) {
	t.Parallel()
	e := startBroker(t, brokerOptions{}, seamNoCoreDumps)
	e.mustExit(exitFailure)
	if !e.stderr.has("the hard limit of core dumps is 0") {
		t.Errorf("the log does not say why; its log:\n%s", e.stderr.text())
	}
	for _, line := range []string{lineNoCoreDumps, lineTLSKey, lineAuditOpen, lineListening} {
		if e.stderr.has(line) {
			t.Errorf("the log has %q", line)
		}
	}
	if _, err := os.Lstat(e.auditPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the broker made the audit log: %v", err)
	}
}

// TestBrokerCanaryThroughTelegram is the canary test of issue #11, end to
// end: the real broker, the real Telegram approver and the fake Telegram
// server, with the person's taps. A made-up secret X in the reason, the
// directory, the variable name, the command and the parent commands, as
// -pX, --token=X, password=X, "Authorization: X" and a long random word,
// never reaches the messages to Telegram, the audit log or the journal.
// Neither does a secret value or the bot token.
func TestBrokerCanaryThroughTelegram(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	c := e.httpClient()
	x := canarySecret()
	forms := []string{"-p" + x, "--token=" + x, "password=" + x, "Authorization: " + x, x}
	reason := strings.Join(forms, " ")

	// Secrets, approved on the phone.
	req := api.SecretsRequest{
		Secrets: []api.SecretRef{{Var: x, Name: "github-token"}},
		Command: append([]string{"mysql"}, forms...),
		Dir:     "/home/dev/" + x,
		Reason:  reason,
	}
	if got := secretValues(t, e.approve(c, api.PathSecrets, req)); got[x] != e.values["github-token"] {
		t.Error("the variable did not get its value")
	}
	// An SSH login, approved on the phone.
	sign, data := e.signRequest("web-1", "deploy")
	sign.Commands = [][]string{
		{"ssh", "-p" + x, "deploy@web-1"}, {"bash", "-c", "deploy --token " + x}, append([]string{"make"}, forms...),
	}
	sign.Reason = reason
	a := e.approve(c, api.PathSign, sign)
	mustStatus(t, a, http.StatusOK)
	ans, err := api.ReadAnswer[api.SignAnswer](bytes.NewReader(a.body))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.userKey.PublicKey().Verify(data, &ssh.Signature{Format: ans.Format, Blob: ans.Blob}); err != nil {
		t.Errorf("the signature: %v", err)
	}
	// Denied by the broker's checks, before any message: an unknown
	// secret named after the canary, and a login to a host that the key
	// may not use.
	req.Secrets = []api.SecretRef{{Var: "A", Name: x}}
	mustStatus(t, e.post(c, api.PathSecrets, req), http.StatusForbidden)
	other, _ := e.signRequest("db-1", "deploy")
	other.Commands, other.Reason = sign.Commands, reason
	mustStatus(t, e.post(c, api.PathSign, other), http.StatusForbidden)

	e.signal(syscall.SIGINT)
	e.mustExit(exitOK)
	auditLog, err := os.ReadFile(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	texts := map[string]string{
		"the calls to Telegram": e.tg.bodies(),
		"the audit log":         string(auditLog),
		"the journal":           e.stderr.text(),
	}
	if !strings.Contains(texts["the calls to Telegram"], "***") {
		t.Error("nothing was masked; the test does not test")
	}
	_, tokenSecret, _ := strings.Cut(e.tg.token, ":")
	for where, text := range texts {
		if strings.Contains(text, x) || strings.Contains(text, strings.ToLower(x)) {
			t.Errorf("%s holds the canary", where)
		}
		if strings.Contains(text, e.values["github-token"]) {
			t.Errorf("%s holds the secret value", where)
		}
		if strings.Contains(text, tokenSecret) {
			t.Errorf("%s holds the bot token", where)
		}
	}
	if e.tg.asked() != 2 {
		t.Errorf("%d messages with buttons, want 2", e.tg.asked())
	}
	for _, p := range e.tg.proxied() {
		if p != "CONNECT "+telegramHost+":443" {
			t.Errorf("the proxy was asked for %q", p)
		}
	}
	got := eventNames(e.auditEntries())
	want := []string{
		"broker_started",
		"request", "decision:approve_once", "secret_sent",
		"request", "decision:approve_once", "signed",
		"request", "denied:not_allowed",
		"request", "denied:not_allowed",
		"broker_stopped",
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit entries:\n%q\nwant:\n%q", got, want)
	}
}

// TestBrokerSignalDuringStart: a SIGTERM while the stores start ends the
// start. The broker closes what it opened, writes no broker_started
// entry, never listens or polls, and exits with 0.
func TestBrokerSignalDuringStart(t *testing.T) {
	t.Parallel()
	e := startBroker(t, brokerOptions{}, seamStoreStartWaits)
	e.stderr.wait(t, lineAuditOpen)
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	e.stderr.inOrder(t, lineAuditOpen, "a signal asked to stop during the start", lineStoresClosed, lineAuditClosed,
		lineStopped+`" exit_code=0`)
	for _, line := range []string{lineApproverRuns, lineListening} {
		if e.stderr.has(line) {
			t.Errorf("the log has %q", line)
		}
	}
	if data, err := os.ReadFile(e.auditPath); err != nil || len(data) != 0 {
		t.Errorf("the audit log: %d bytes, %v; want it empty", len(data), err)
	}
	if p := e.tg.proxied(); len(p) != 0 {
		t.Errorf("the broker called Telegram: %q", p)
	}
}

// tearAuditLog stops the broker of e with SIGTERM, and adds a torn last
// line to its audit log, as a power cut during a write would.
func tearAuditLog(t *testing.T, e *brokerEnv) {
	t.Helper()
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	appendTornLine(t, e)
}

// appendTornLine adds a torn last line to the audit log of e, as a power
// cut during a write would. The broker must have stopped.
func appendTornLine(t *testing.T, e *brokerEnv) {
	t.Helper()
	f, err := os.OpenFile(e.auditPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"seq":3,"time":"2026-10-15T00:00:00Z","event":"req`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// tornLineEntries are the audit entries of two broker runs with a torn
// line between them.
var tornLineEntries = []string{
	"broker_started", "broker_stopped", "(torn line)", "log_recovered", "broker_started", "broker_stopped",
}

// TestBrokerTornLineAlert: after a torn last line, the next start records
// it with a log_recovered entry, and the approver gets one alert.
func TestBrokerTornLineAlert(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	tearAuditLog(t, e)
	e.start()
	e.stderr.wait(t, lineListening)
	e.signal(syscall.SIGTERM) // the stop waits for the alerts of the start
	e.mustExit(exitOK)
	if n := e.tg.alertCount("torn line"); n != 1 {
		t.Errorf("%d alerts about the torn line, want 1", n)
	}
	if got := eventNames(e.auditEntries()); !slices.Equal(got, tornLineEntries) {
		t.Errorf("audit entries %q, want %q", got, tornLineEntries)
	}
}

// TestBrokerTornLineAlertAfterAFailedStart: a power cut leaves a torn last
// line. At the next boot the listen address is not there yet, so the start
// fails at the listen step, after audit.Open recorded the torn line and
// queued the alert. systemd starts the broker again; this time the log
// ends in the log_recovered entry, with no broker_started after it, so the
// broker sends the alert then. The approver gets it once.
func TestBrokerTornLineAlertAfterAFailedStart(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	tearAuditLog(t, e)

	// The boot: the listen address is not there yet (here: taken).
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	e.start()
	e.mustExit(exitFailure)
	if !e.stderr.has("ALERT: the audit log ended in a torn line") || !e.stderr.has("cannot listen on") {
		t.Fatalf("the first start did not record the torn line and fail at listen; its log:\n%s", e.stderr.text())
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if n := e.tg.alertCount("torn line"); n != 0 {
		t.Errorf("the failed start sent %d alerts", n)
	}

	// systemd starts it again, and the address is there now.
	e.start()
	e.stderr.wait(t, lineListening)
	if !e.stderr.has("the start that recorded it stopped before it could send the alert") {
		t.Errorf("the log does not say why the alert goes out again; its log:\n%s", e.stderr.text())
	}
	e.signal(syscall.SIGTERM) // the stop waits for the alerts of the start
	e.mustExit(exitOK)
	if n := e.tg.alertCount("torn line"); n != 1 {
		t.Errorf("%d alerts about the torn line reached the approver, want 1", n)
	}
	if got := eventNames(e.auditEntries()); !slices.Equal(got, tornLineEntries) {
		t.Errorf("audit entries %q, want %q", got, tornLineEntries)
	}

	// A third start sends no alert: broker_started follows the
	// log_recovered entry now.
	e.start()
	e.stderr.wait(t, lineListening)
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	if n := e.tg.alertCount("torn line"); n != 1 {
		t.Errorf("%d alerts about the torn line after a third start, want 1", n)
	}
}

// TestBrokerRefusedToken: when Telegram does not accept the bot token, the
// broker stops with exit code 77: 401 for a revoked token, 404 for a bot
// that is gone. The example unit lists 77 in RestartPreventExitStatus=,
// because a start with the same token would fail again: it would only call
// Telegram, and write broker_started and broker_stopped, every few
// seconds. Another refusal of getUpdates, such as 403, ends with 1.
func TestBrokerRefusedToken(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		opts brokerOptions
		code int
	}{
		{"a revoked token (401)", brokerOptions{unknownToken: true}, exitTokenRefused},
		{"a bot that is gone (404)", brokerOptions{refusePolls: http.StatusNotFound}, exitTokenRefused},
		{"another refusal (403)", brokerOptions{refusePolls: http.StatusForbidden}, exitFailure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := startListening(t, tt.opts)
			e.mustExit(tt.code)
			if want := fmt.Sprintf(`" exit_code=%d`, tt.code); !e.stderr.has(want) {
				t.Errorf("the log has no %q; its log:\n%s", want, e.stderr.text())
			}
			got := eventNames(e.auditEntries())
			if want := []string{"broker_started", "broker_stopped"}; !slices.Equal(got, want) {
				t.Errorf("audit entries %q, want %q", got, want)
			}
		})
	}
}

// TestPortsOutside: the ports for the brokers of the tests are outside the
// kernel's own range of ports, below it or above it, or none.
func TestPortsOutside(t *testing.T) {
	for _, tt := range []struct{ lo, hi, low, high int64 }{
		{32768, 60999, 10000, 32768}, // the default of Linux
		{1024, 60999, 61000, 65536},  // a range from low ports
		{10000, 65535, 0, 0},         // no room
		{1024, 65535, 0, 0},
		{40000, 40999, 10000, 40000}, // more room below
		{11000, 50000, 50001, 65536}, // more room above
	} {
		if low, high := portsOutside(tt.lo, tt.hi); low != tt.low || high != tt.high {
			t.Errorf("portsOutside(%d, %d) = %d, %d; want %d, %d", tt.lo, tt.hi, low, high, tt.low, tt.high)
		}
	}
}

// lineAlertAgain is the log line of a failed try of an alert message of
// the start.
const lineAlertAgain = "an alert message did not go out; the broker tries again"

// TestBrokerAlertTriesAgain: after a power cut, the broker host can be up
// before Telegram can be reached. The broker writes broker_started, so the
// next start would not send the alert about the torn line again. So it
// tries again, with a growing wait, until Telegram can be reached, and the
// approver gets the alert once.
func TestBrokerAlertTriesAgain(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	tearAuditLog(t, e)
	e.tg.setOffline(true)
	e.start(seamFastAlertTries)
	e.stderr.wait(t, lineListening)
	e.stderr.waitCount(t, lineAlertAgain, 2)
	if n := e.tg.alertCount("torn line"); n != 0 {
		t.Fatalf("%d alerts while Telegram cannot be reached", n)
	}
	e.tg.setOffline(false)
	e.tg.waitAlert("torn line")
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	if n := e.tg.alertCount("torn line"); n != 1 {
		t.Errorf("%d alerts about the torn line, want 1", n)
	}
	if e.stderr.has("they are lost") {
		t.Errorf("the log says an alert is lost; its log:\n%s", e.stderr.text())
	}
}

// TestBrokerAlertTriesEndAtTheStop: while Telegram cannot be reached, the
// tries go on until the stop begins. Then the broker stops in time and
// cleanly, and its log says that the alert is lost.
func TestBrokerAlertTriesEndAtTheStop(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	tearAuditLog(t, e)
	e.tg.setOffline(true)
	e.start(seamFastAlertTries)
	e.stderr.wait(t, lineListening)
	e.stderr.waitCount(t, lineAlertAgain, 2)
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	if !e.stderr.has("they are lost") {
		t.Errorf("the log does not say that the alert is lost; its log:\n%s", e.stderr.text())
	}
	if n := e.tg.alertCount("torn line"); n != 0 {
		t.Errorf("%d alerts, want none: Telegram could not be reached", n)
	}
}

// threeAlertsAtTheNextStart makes the next start of the broker of e, with
// seamStoreStartFails, queue three alerts: it appends a log_recovered
// entry, as from a start that recorded a torn line and stopped before its
// broker_started entry, and then a torn line. It returns a part of the
// text of each alert: about the old torn line, the new torn line and the
// store. The broker must have stopped.
func threeAlertsAtTheNextStart(t *testing.T, e *brokerEnv) []string {
	t.Helper()
	appendForgedRecovery(t, e, 10, strings.Repeat("ab", 32))
	entries := e.auditEntries()
	seq, ok := entries[len(entries)-1]["seq"].(float64)
	if !ok {
		t.Fatal("the log_recovered entry has no seq")
	}
	appendTornLine(t, e)
	return []string{
		fmt.Sprintf("Entry %d (log_recovered)", int(seq)),
		fmt.Sprintf("Entry %d (log_recovered)", int(seq)+1),
		"could not start",
	}
}

// TestBrokerStopWithThreeAlertsAndNoAnswer: three alerts wait at the start,
// and Telegram takes each alert message but never answers, as in a long
// outage, so each try runs into its time limit. The first tries of the
// three alerts run at the same time. A SIGTERM right after the start: the
// stop waits for these tries, as long as one of them takes, then stops
// cleanly within its limit and writes broker_stopped. Each alert got at
// least one try, and the log says that all three are lost. Tried one after
// the other, the three tries took longer than the stop limit (issue #59);
// TestStartAlertsAtTheSameTime checks the times of the real limits.
func TestBrokerStopWithThreeAlertsAndNoAnswer(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{holdAlerts: true})
	e.stderr.wait(t, lineListening)
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	alerts := threeAlertsAtTheNextStart(t, e)
	e.start(seamStoreStartFails, seamFastAlertTries)
	e.stderr.wait(t, lineListening)
	e.tg.waitHeld(len(alerts)) // the first tries, at the same time
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK) // a clean stop, in time
	for _, alert := range alerts {
		if e.tg.alertCount(alert) == 0 {
			t.Errorf("the alert with %q got no try", alert)
		}
	}
	if !e.stderr.has(`they are lost" lost=3`) {
		t.Errorf("the log does not say that the three alerts are lost; its log:\n%s", e.stderr.text())
	}
	got := eventNames(e.auditEntries())
	want := []string{
		"broker_started", "broker_stopped", "log_recovered", "(torn line)", "log_recovered", "broker_started",
		"broker_stopped",
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit entries %q, want %q", got, want)
	}
}

// TestBrokerThreeAlertsGoOutOnce: three alerts wait at the start, and
// Telegram cannot be reached. Each alert tries again on its own. Once
// Telegram can be reached, the approver gets each alert exactly once, and
// none is lost.
func TestBrokerThreeAlertsGoOutOnce(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	alerts := threeAlertsAtTheNextStart(t, e)
	e.tg.setOffline(true)
	e.start(seamStoreStartFails, seamFastAlertTries)
	e.stderr.wait(t, lineListening)
	for n := range len(alerts) {
		e.stderr.waitCount(t, fmt.Sprintf(`%s" alert=%d `, lineAlertAgain, n+1), 2)
	}
	if n := e.tg.alertCount(""); n != 0 {
		t.Fatalf("%d alerts while Telegram cannot be reached", n)
	}
	e.tg.setOffline(false)
	for _, alert := range alerts {
		e.tg.waitAlert(alert)
	}
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	for _, alert := range alerts {
		if n := e.tg.alertCount(alert); n != 1 {
			t.Errorf("%d alerts with %q, want 1", n, alert)
		}
	}
	if n := e.tg.alertCount(""); n != len(alerts) {
		t.Errorf("%d alerts, want %d", n, len(alerts))
	}
	if e.stderr.has("they are lost") {
		t.Errorf("the log says that alerts are lost; its log:\n%s", e.stderr.text())
	}
}

// appendForgedRecovery appends a log_recovered entry that chains right
// onto the last entry of the audit log of e, as someone with write access
// to the log could: it names a torn line that never was.
func appendForgedRecovery(t *testing.T, e *brokerEnv, tornLength int, tornHash string) {
	t.Helper()
	data, err := os.ReadFile(e.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
	last := lines[len(lines)-1]
	var m struct {
		Seq uint64 `json:"seq"`
	}
	if err := json.Unmarshal(last, &m); err != nil {
		t.Fatal(err)
	}
	prev := sha256.Sum256(last)
	line := fmt.Sprintf(`{"seq":%d,"time":"2026-10-15T00:00:00.000Z","event":"log_recovered","prev":"%s",`+
		`"torn_length":%d,"torn_sha256":"%s"}`+"\n", m.Seq+1, hex.EncodeToString(prev[:]), tornLength, tornHash)
	f, err := os.OpenFile(e.auditPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestBrokerForgedRecoveryAlertsOnce: a forged log_recovered entry as the
// last entry brings one alert at the next start, and no alert at any later
// start: never an endless alert (DESIGN.md section 9).
func TestBrokerForgedRecoveryAlertsOnce(t *testing.T) {
	t.Parallel()
	e := startListening(t, brokerOptions{})
	e.stderr.wait(t, lineListening)
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
	appendForgedRecovery(t, e, 10, strings.Repeat("ab", 32))
	for round := 1; round <= 3; round++ {
		e.start()
		e.stderr.wait(t, lineListening)
		e.signal(syscall.SIGTERM) // the stop waits for the first try of each alert
		e.mustExit(exitOK)
		if n := e.tg.alertCount("torn line"); n != 1 {
			t.Errorf("after start %d: %d alerts about the torn line, want 1", round, n)
		}
	}
}

// TestBrokerBadRecoveryStopsTheStart: a log_recovered last entry with a
// torn_length out of range, or a hash that is not 64 lower-case hex
// digits, is not a valid entry: the broker does not start, writes nothing
// and calls no Telegram; a person must look (DESIGN.md section 9).
//
// Only the calls with the proxy user name of the second start count. The
// fake proxy can take a call of the first start after that broker ended
// (see brokerenv_linux_test.go), and a count of all calls then blamed the
// second start (issue #69). The first start polls before its stop, so the
// test also sees that the proxy tells the starts apart.
func TestBrokerBadRecoveryStopsTheStart(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		length int
		hash   string
	}{
		{"length 0", 0, strings.Repeat("ab", 32)},
		{"length over the line limit", 1 << 20, strings.Repeat("ab", 32)},
		{"a short hash", 10, "abcd"},
		{"upper-case hex", 10, strings.Repeat("AB", 32)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := startListening(t, brokerOptions{})
			e.stderr.wait(t, lineListening)
			e.tg.waitPolling()
			first := e.proxyUser
			e.signal(syscall.SIGTERM)
			e.mustExit(exitOK)
			if len(e.tg.proxiedBy(first)) == 0 {
				t.Fatalf("the proxy got no call with the user name of the first start; all calls: %q",
					e.tg.proxied())
			}
			appendForgedRecovery(t, e, tt.length, tt.hash)
			before, err := os.ReadFile(e.auditPath)
			if err != nil {
				t.Fatal(err)
			}
			e.start()
			e.mustExit(exitFailure)
			after, err := os.ReadFile(e.auditPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Error("the broker wrote to the audit log")
			}
			if p := e.tg.proxiedBy(e.proxyUser); len(p) != 0 {
				t.Errorf("the broker called Telegram: %q", p)
			}
			if !e.stderr.has("the last complete line is not a valid entry") {
				t.Errorf("the log does not say why; its log:\n%s", e.stderr.text())
			}
		})
	}
}
