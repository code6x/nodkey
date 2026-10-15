package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/telegram"
)

// fakeAnchor is a line that looks like an audit anchor (DESIGN.md section
// 9). No line of the broker may start with "audit anchor ".
var fakeAnchor = "audit anchor 1:" + strings.Repeat("ab", 32)

// noAnchorLine fails if a line of out starts like an audit anchor.
func noAnchorLine(t *testing.T, out string) {
	t.Helper()
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(line, "audit anchor ") {
			t.Errorf("a line looks like an audit anchor: %q", line)
		}
	}
}

func TestBrokerUsage(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		code int
		log  string // a part of the log line, if any
	}{
		{"an unknown flag", []string{"broker", "--bogus"}, exitUsage, "nodkey broker: wrong usage"},
		{"an argument", []string{"broker", "extra"}, exitUsage, "it takes no arguments"},
		{"a flag with a line break", []string{"broker", "--x\n" + fakeAnchor}, exitUsage, "nodkey broker: wrong usage"},
		{"-h", []string{"broker", "-h"}, exitOK, ""},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(tt.args, strings.NewReader(""), &stdout, &stderr); code != tt.code {
			t.Errorf("%s: exit code %d, want %d", tt.name, code, tt.code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: stdout = %q, want it empty", tt.name, stdout.String())
		}
		if !strings.Contains(stderr.String(), "Usage: nodkey broker [--config FILE]") {
			t.Errorf("%s: stderr = %q, want the usage", tt.name, stderr.String())
		}
		if tt.log != "" && (!strings.Contains(stderr.String(), "time=") || !strings.Contains(stderr.String(), tt.log)) {
			t.Errorf("%s: stderr = %q, want a log line with %q", tt.name, stderr.String(), tt.log)
		}
		noAnchorLine(t, stderr.String())
	}
	var stdout bytes.Buffer
	if run([]string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); !strings.Contains(stdout.String(), "broker") {
		t.Errorf("help does not list broker: %q", stdout.String())
	}
}

// TestBrokerConfigErrorIsOneLine: an error at the start goes through the
// broker's logger, which escapes a line break, also one in a path. The
// broker exits with 1.
func TestBrokerConfigErrorIsOneLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing\n"+fakeAnchor)
	var stderr bytes.Buffer
	if code := run([]string{"broker", "--config", path}, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != exitFailure {
		t.Errorf("exit code %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "nodkey broker: cannot start") {
		t.Errorf("stderr = %q", stderr.String())
	}
	noAnchorLine(t, stderr.String())
}

func TestBrokerExitCode(t *testing.T) {
	conflict := fmt.Errorf("telegram: %w", telegram.ErrPollConflict)
	refused := fmt.Errorf("telegram: polling stopped: %w", telegram.ErrTokenRefused)
	other := errors.New("made-up: the approver stopped")
	for _, tt := range []struct {
		bySignal, clean bool
		runErr          error
		want            int
	}{
		{bySignal: true, clean: true, want: exitOK},
		{bySignal: true, clean: true, runErr: other, want: exitOK}, // Run ends with the context error
		{bySignal: true, clean: false, want: exitFailure},
		{bySignal: false, clean: true, runErr: other, want: exitFailure},
		{bySignal: false, clean: true, want: exitFailure}, // a failed start, or the server stopped
		{bySignal: false, clean: true, runErr: conflict, want: exitPollConflict},
		{bySignal: true, clean: false, runErr: conflict, want: exitPollConflict},
		{bySignal: false, clean: false, runErr: conflict, want: exitPollConflict},
		{bySignal: false, clean: true, runErr: refused, want: exitTokenRefused},
		{bySignal: true, clean: true, runErr: refused, want: exitTokenRefused},
	} {
		if got := brokerExitCode(tt.bySignal, tt.runErr, tt.clean); got != tt.want {
			t.Errorf("signal %v, clean %v, Run %v: exit code %d, want %d", tt.bySignal, tt.clean, tt.runErr, got, tt.want)
		}
	}
}

// makeLogin returns what OpenSSH sends to its agent for a login as user
// with the key userKey to the host with the key hostKey: the content of
// the session-bind, with the host key's signature over a new session
// identifier, and the data to sign, a login request for that session (RFC
// 4252 section 7).
func makeLogin(t *testing.T, userKey ssh.PublicKey, hostKey ssh.Signer, user string) (bind, data []byte) {
	t.Helper()
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		t.Fatal(err)
	}
	sig, err := hostKey.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	bind = ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{hostKey.PublicKey().Marshal(), sessionID, ssh.Marshal(sig), false})
	const msgUserAuthRequest = 50
	data = ssh.Marshal(struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		HasSig    bool
		Algorithm string
		PublicKey []byte
	}{sessionID, msgUserAuthRequest, user, "ssh-connection", "publickey", true, userKey.Type(), userKey.Marshal()})
	return bind, data
}

// newHostSigner makes an Ed25519 SSH key.
func newHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestLoadSSHKeys loads keys as nodkey broker does at start: each key
// file of a [key.*] section, with its hosts. It refuses two sections with
// the same public key in two files, a key with a passphrase, a file that
// holds no key, and a key that sshauth.NewKey refuses. No error shows the
// content of a file.
func TestLoadSSHKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	read := func(path string) ([]byte, error) { return os.ReadFile(path) } //nolint:gosec // G304: the test's own files.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(block)
	deploy := write("deploy", keyPEM)
	userKey, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}

	// A key loads, with its hosts.
	known := make(map[string]ssh.Signer)
	var kh strings.Builder
	for _, host := range []string{"web-1", "db-1"} {
		known[host] = newHostSigner(t)
		kh.WriteString(host + " " + string(ssh.MarshalAuthorizedKey(known[host].PublicKey())))
	}
	knownHosts, err := config.ParseKnownHosts([]byte(kh.String()))
	if err != nil {
		t.Fatal(err)
	}
	key := func(file string, hosts ...string) config.Key {
		return config.Key{File: file, Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}, Hosts: hosts}
	}
	keys, err := loadSSHKeys(&config.Broker{Keys: map[string]config.Key{"deploy": key(deploy, "web-1")}}, read)
	if err != nil {
		t.Fatal(err)
	}
	k := keys["deploy"]
	if k.Name() != "deploy" || !bytes.Equal(k.PublicKey().Marshal(), userKey.PublicKey().Marshal()) {
		t.Fatalf("the key is %v", k)
	}
	for host, want := range map[string]error{"web-1": nil, "db-1": sshauth.ErrHostNotAllowed} {
		bind, data := makeLogin(t, userKey.PublicKey(), known[host], "deploy")
		_, err := k.Check(sshauth.Request{Key: userKey.PublicKey().Marshal(), Data: data, Binds: [][]byte{bind}}, knownHosts)
		if !errors.Is(err, want) {
			t.Errorf("a login to %s: %v, want %v", host, err, want)
		}
	}

	// Errors.
	canaryText := "made-up " + canaryWord()
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(canaryWord()))
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the test needs a key that is too small.
	if err != nil {
		t.Fatal(err)
	}
	smallPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)})
	for _, tt := range []struct {
		name string
		keys map[string]config.Key
		want string
	}{
		{"the same key in two files", map[string]config.Key{
			"deploy": key(deploy), "copy": key(write("copy", keyPEM), "db-1"),
		}, "[key.copy] and [key.deploy] hold the same public key"},
		{"a passphrase", map[string]config.Key{"deploy": key(write("encrypted", pem.EncodeToMemory(encrypted)))},
			"the key has a passphrase"},
		{"not a key", map[string]config.Key{"deploy": key(write("text", []byte(canaryText)))},
			"does not hold an SSH private key"},
		{"a PEM block that is not a key", map[string]config.Key{"deploy": key(write("block",
			pem.EncodeToMemory(&pem.Block{Type: canaryWord(), Bytes: []byte(canaryText)})))},
			"does not hold an SSH private key"},
		{"an RSA key that is too small", map[string]config.Key{"deploy": key(write("small", smallPEM))},
			"fewer than 2048 bits"},
		{"a file that cannot be read", map[string]config.Key{"deploy": key(filepath.Join(dir, "missing"))},
			"[key.deploy] file: open "},
	} {
		keys, err := loadSSHKeys(&config.Broker{Keys: tt.keys}, read)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want an error with %q", tt.name, err, tt.want)
		}
		if keys != nil {
			t.Errorf("%s: keys were returned with the error", tt.name)
		}
		if err != nil && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(canaryWord())) {
			t.Errorf("%s: the error shows the content of the file", tt.name)
		}
	}
}

// canaryWord returns a made-up word that the tests look for, made at run
// time.
func canaryWord() string {
	return "CANARY" + strings.Repeat("Q7", 8)
}

// TestStopStep: a step of the stop that panics is not clean, and its panic
// value is not logged; a step that takes too long is left behind, and the
// stop ends; a closed channel counts also after the deadline.
func TestStopStep(t *testing.T) {
	var logs bytes.Buffer
	b := &brokerParts{log: broker.NewLogger(&logs)}
	soon := time.Now().Add(time.Minute)
	if done, ok := b.step("a step", func() {}, soon); !done || !ok {
		t.Errorf("a step that returns: done %v, ok %v", done, ok)
	}
	if done, ok := b.step("a step that panics", func() { panic(canaryWord()) }, soon); !done || ok {
		t.Errorf("a step that panics: done %v, ok %v", done, ok)
	}
	block := make(chan struct{})
	defer close(block)
	if done, ok := b.step("a slow step", func() { <-block }, time.Now().Add(10*time.Millisecond)); done || ok {
		t.Errorf("a step that takes too long: done %v, ok %v", done, ok)
	}
	for _, want := range []string{"a step of the stop panicked", `step="a step that panics"`,
		"the stop takes too long", `waiting_for="a slow step"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log has no %q: %s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), canaryWord()) {
		t.Error("the log holds the panic value")
	}
	closed := make(chan struct{})
	close(closed)
	if !waitUntil(closed, time.Now().Add(-time.Second)) {
		t.Error("a closed channel did not count after the deadline")
	}
	if waitUntil(make(chan struct{}), time.Now().Add(-time.Second)) {
		t.Error("an open channel counted after the deadline")
	}
}

// startAlerts are the alert messages of the start in the tests of
// sendAlerts.
var startAlerts = []string{"alert one", "alert two", "alert three"}

// alertLines returns the lines of log whose message ends in msgEnd, about
// the alert with the number n.
func alertLines(log, msgEnd string, n int) []string {
	var lines []string
	for line := range strings.SplitSeq(log, "\n") {
		if strings.Contains(line+" ", fmt.Sprintf(`%s" alert=%d `, msgEnd, n)) {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestStartAlertsAtTheSameTime: three alerts of the start, and a Telegram
// that takes each alert message but never answers, so each try runs into
// its time limit. The stop begins right after the start. The first tries
// run at the same time, so the stop waits as long as one try takes, well
// within its limit, and is clean. Each alert gets exactly one try, and one
// log line for it; one more line says that the three are lost. Tried one
// after the other, the three tries took longer than the stop limit (issue
// #59). synctest runs the real times on a fake clock, and fails if a
// goroutine is left.
func TestStartAlertsAtTheSameTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		b := &brokerParts{log: broker.NewLogger(&logs), alerts: slices.Clone(startAlerts)}
		var mu sync.Mutex
		tries := make(map[string]int)
		inFlight, most := 0, 0
		b.sendAlerts(func(ctx context.Context, msg string) error {
			mu.Lock()
			tries[msg]++
			inFlight++
			most = max(most, inFlight)
			mu.Unlock()
			<-ctx.Done() // Telegram does not answer
			mu.Lock()
			inFlight--
			mu.Unlock()
			return errors.New("made-up: the call timed out")
		})
		start := time.Now()
		runErr, clean := b.stop(start.Add(stopTimeout))
		if took := time.Since(start); runErr != nil || !clean || took != alertTimeout {
			t.Errorf("the stop: error %v, clean %v, after %v; want a clean stop after one try, %v",
				runErr, clean, took, alertTimeout)
		}
		// After a stop that was not clean, the tries go on: the test waits
		// for them, so it fails without a panic of synctest.
		<-b.alertsDone
		mu.Lock()
		defer mu.Unlock()
		if most != len(startAlerts) {
			t.Errorf("%d tries at the same time, want %d", most, len(startAlerts))
		}
		log := logs.String()
		for i, msg := range startAlerts {
			if tries[msg] != 1 {
				t.Errorf("%d tries of %q, want 1", tries[msg], msg)
			}
			if n := len(alertLines(log, "an alert message did not go out", i+1)); n != 1 {
				t.Errorf("%d lines about the failed try of alert %d, want 1", n, i+1)
			}
		}
		if strings.Contains(log, "tries again") || !strings.Contains(log, `they are lost" lost=3`) {
			t.Errorf("want no try again, and a line that says that three alerts are lost; the log:\n%s", log)
		}
	})
}

// TestStartAlertsTryAgain: Telegram cannot be reached for the first 20
// minutes after the start. Each alert tries again on its own, with a wait
// that doubles from alertFirstWait up to alertMaxWait, and one log line
// for each failed try. Once Telegram can be reached, each alert goes out
// exactly once, and makes no try after that. The stop finds none lost.
func TestStartAlertsTryAgain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const outage = 20 * time.Minute
		var logs bytes.Buffer
		b := &brokerParts{log: broker.NewLogger(&logs), alerts: slices.Clone(startAlerts)}
		start := time.Now()
		var mu sync.Mutex
		tries := make(map[string][]bool) // for each alert: whether each try went out
		b.sendAlerts(func(_ context.Context, msg string) error {
			out := time.Since(start) >= outage
			mu.Lock()
			tries[msg] = append(tries[msg], out)
			mu.Unlock()
			if !out {
				return errors.New("made-up: cannot connect to the server")
			}
			return nil
		})
		time.Sleep(outage + alertMaxWait) // each alert has had its next try after the outage
		if runErr, clean := b.stop(time.Now().Add(stopTimeout)); runErr != nil || !clean {
			t.Errorf("the stop: error %v, clean %v; want a clean stop", runErr, clean)
		}
		// The wait after each failed try of one alert, in the outage.
		var waits []string
		for at, wait := time.Duration(0), alertFirstWait; at < outage; wait = min(2*wait, alertMaxWait) {
			waits = append(waits, "next_try_in="+wait.String())
			at += wait
		}
		log := logs.String()
		mu.Lock()
		defer mu.Unlock()
		for i, msg := range startAlerts {
			if want := append(slices.Repeat([]bool{false}, len(waits)), true); !slices.Equal(tries[msg], want) {
				t.Errorf("the tries of %q went out: %v; want %d that failed, then one that went out",
					msg, tries[msg], len(waits))
			}
			lines := alertLines(log, "the broker tries again", i+1)
			if len(lines) != len(waits) {
				t.Errorf("%d lines about failed tries of alert %d, want %d", len(lines), i+1, len(waits))
				continue
			}
			for j, line := range lines {
				if !strings.HasSuffix(line, " "+waits[j]) {
					t.Errorf("alert %d, failed try %d: the line %q does not end in %q", i+1, j+1, line, waits[j])
				}
			}
		}
		if strings.Contains(log, "they are lost") {
			t.Errorf("the log says that alerts are lost:\n%s", log)
		}
	})
}

// TestStartAlertPanics: a panic while one alert is sent ends only that
// alert. Its panic value is not logged, the other alerts still go out, and
// the stop counts the alert as lost.
func TestStartAlertPanics(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs bytes.Buffer
		b := &brokerParts{log: broker.NewLogger(&logs), alerts: slices.Clone(startAlerts)}
		var mu sync.Mutex
		var out []string
		b.sendAlerts(func(_ context.Context, msg string) error {
			if msg == startAlerts[1] {
				panic(canaryWord())
			}
			mu.Lock()
			defer mu.Unlock()
			out = append(out, msg)
			return nil
		})
		if runErr, clean := b.stop(time.Now().Add(stopTimeout)); runErr != nil || !clean {
			t.Errorf("the stop: error %v, clean %v; want a clean stop", runErr, clean)
		}
		mu.Lock()
		defer mu.Unlock()
		want := []string{startAlerts[0], startAlerts[2]}
		slices.Sort(out)
		slices.Sort(want)
		if !slices.Equal(out, want) {
			t.Errorf("these alerts went out: %q, want %q", out, want)
		}
		log := logs.String()
		if len(alertLines(log, "the panic value is not logged", 2)) != 1 {
			t.Errorf("no line about the panic of alert 2; the log:\n%s", log)
		}
		if !strings.Contains(log, `they are lost" lost=1`) {
			t.Errorf("the log does not say that one alert is lost:\n%s", log)
		}
		if strings.Contains(log, canaryWord()) {
			t.Error("the log holds the panic value")
		}
	})
}

// TestUnitPreventsRestarts: the example systemd unit does not start the
// broker again after the exit codes that only a person can fix: wrong
// usage, a polling conflict and a bot token that Telegram refuses.
func TestUnitPreventsRestarts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "contrib", "systemd", "nodkey.service"))
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("RestartPreventExitStatus=%d %d %d", exitUsage, exitPollConflict, exitTokenRefused)
	var found []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "RestartPreventExitStatus=") {
			found = append(found, line)
		}
	}
	if len(found) != 1 || found[0] != want {
		t.Errorf("the unit has %q, want %q", found, want)
	}
}

// TestUnitHasEachCredential: the example unit loads a credential for each
// ${CREDENTIALS_DIRECTORY}/NAME of the example config in DESIGN.md
// section 14, and no other.
func TestUnitHasEachCredential(t *testing.T) {
	design, err := os.ReadFile(filepath.Join("..", "..", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(filepath.Join("..", "..", "contrib", "systemd", "nodkey.service"))
	if err != nil {
		t.Fatal(err)
	}
	_, example, ok := strings.Cut(string(design), "Broker, `/etc/nodkey/broker.toml`:\n\n```toml\n")
	if !ok {
		t.Fatal("DESIGN.md has no example of the broker config")
	}
	example, _, _ = strings.Cut(example, "```")
	var inConfig, inUnit []string
	for _, part := range strings.Split(example, "${CREDENTIALS_DIRECTORY}/")[1:] {
		inConfig = append(inConfig, part[:strings.IndexByte(part, '"')])
	}
	for line := range strings.SplitSeq(string(unit), "\n") {
		if rest, ok := strings.CutPrefix(line, "LoadCredentialEncrypted="); ok {
			inUnit = append(inUnit, rest[:strings.IndexByte(rest, ':')])
		}
	}
	slices.Sort(inConfig)
	slices.Sort(inUnit)
	if len(inConfig) == 0 || !slices.Equal(inConfig, inUnit) {
		t.Errorf("the credentials of the example config %q and of the unit %q differ", inConfig, inUnit)
	}
}
