package broker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/telegram"
	"github.com/code6x/nodkey/internal/transport"
)

// setGate makes Append wait until gate is closed; nil lets it go on.
func (f *fakeAudit) setGate(gate chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate = gate
}

// waitLog waits until the log holds want, and returns the log.
func waitLog(t testing.TB, logs *syncBuffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		text := logs.String()
		if strings.Contains(text, want) {
			return text
		}
		if time.Now().After(deadline) {
			t.Fatalf("the log does not hold %q:\n%s", want, text)
			return text
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAuditFailureDenies: when an entry cannot be written, the request is
// denied. Without its decision entry nothing is fetched; without its
// secret_sent entry nothing is sent, and the value is cleared.
func TestAuditFailureDenies(t *testing.T) {
	for _, tt := range []struct {
		failing string // the entry that cannot be written
		entries string // the entries that are written
		fetches int
	}{
		{"request", "", 0},
		{"decision", "request", 0},
		{"secret_sent", "request decision:approve_once", 1},
	} {
		t.Run(tt.failing, func(t *testing.T) {
			e := newEnv(t, envOptions{})
			e.approver.Auto(audit.AnswerApproveOnce)
			e.audit.setFail(func(ev audit.Event) error {
				if strings.HasPrefix(eventName(ev), tt.failing) {
					return errors.New("made-up disk error")
				}
				return nil
			})
			res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
			mustStatus(t, res, http.StatusServiceUnavailable)
			if bytes.Contains(res.body, []byte(e.values["github-token"])) {
				t.Error("the answer holds the value")
			}
			mustEvents(t, e.audit.all(), tt.entries)
			if e.main.fetched() != tt.fetches {
				t.Errorf("the store ran %d times, want %d", e.main.fetched(), tt.fetches)
			}
			e.main.checkCleared(t)
			// A failed entry that is not a broken log denies only that
			// request.
			e.audit.setFail(nil)
			secretsOf(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")))
		})
	}
}

// TestNoGrantWithoutItsDecisionEntry: an "Approve 15 min" whose decision
// entry cannot be written starts no grant, so the next request asks again.
// A request that a "never ask" rule allows is not fetched when its
// grant_used entry cannot be written.
func TestNoGrantWithoutItsDecisionEntry(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	e.approver.Auto(audit.AnswerApproveWindow)
	e.audit.setFail(func(ev audit.Event) error {
		switch ev.(type) {
		case audit.Decision, audit.GrantUsed:
			return errors.New("made-up disk error")
		}
		return nil
	})
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")),
		http.StatusServiceUnavailable)
	mustStatus(t, e.post(t.Context(), e.httpClient("ci"), api.PathSecrets, secretsRequest("B", "backup-token")),
		http.StatusServiceUnavailable)
	e.audit.setFail(nil)
	e.approver.Auto(audit.AnswerDeny)
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")),
		http.StatusForbidden)
	if n := len(e.approver.Asked()); n != 2 {
		t.Errorf("%d messages, want 2: the grant must not start", n)
	}
	if e.main.fetched() != 0 {
		t.Errorf("the store ran %d times, want 0", e.main.fetched())
	}
}

// TestNoClientName: a request without a client name from the TLS layer is
// refused, also when it reaches the handler some other way.
func TestNoClientName(t *testing.T) {
	e := newEnv(t, envOptions{})
	for _, path := range []string{api.PathKeys, api.PathSecrets, "/v1/nope"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader("{}"))
		r.Header.Set("Content-Type", api.ContentType)
		e.svc.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != `{"error":"Forbidden"}` {
			t.Errorf("%s: %d %s, want 403", path, w.Code, w.Body.String())
		}
	}
	if len(e.audit.all()) != 0 {
		t.Error("a request without a client name was recorded")
	}
}

// TestBrokenAuditLog: after a failed write (audit.ErrBroken), every
// request is denied at once, also one that a grant would allow, and the
// broker sends one alert.
func TestBrokenAuditLog(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	e.approver.Auto(audit.AnswerApproveWindow)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))) // a grant
	e.approver.Auto(audit.AnswerApproveOnce)
	e.audit.setFail(func(ev audit.Event) error {
		if _, ok := ev.(audit.Decision); ok {
			return fmt.Errorf("%w (made-up: no space left on the disk)", audit.ErrBroken)
		}
		return nil
	})
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password")),
		http.StatusServiceUnavailable)
	asked := len(e.approver.Asked())
	for _, req := range []api.SecretsRequest{
		secretsRequest("GH_TOKEN", "github-token"), // the grant would allow it
		secretsRequest("DB_PASSWORD", "db-password"),
	} {
		mustStatus(t, e.post(t.Context(), c, api.PathSecrets, req), http.StatusServiceUnavailable)
	}
	if len(e.approver.Asked()) != asked || e.vault.fetched() != 0 || e.main.fetched() != 1 {
		t.Error("a request after the broken write was shown or fetched")
	}
	waitLog(t, e.alerts, "audit log")
	time.Sleep(50 * time.Millisecond) // a second alert would come now
	if got := e.alerts.String(); got != brokenAlert+"\n" {
		t.Errorf("alerts:\n%s\nwant one", got)
	}
	if n := strings.Count(e.logs.String(), "ALERT: the audit log cannot be written"); n != 1 {
		t.Errorf("the log has %d alerts, want 1:\n%s", n, e.logs.String())
	}
}

// TestCanaryNeverLeaks: a made-up secret in every claimed field, in the
// forms that masking knows, never reaches a message, the audit log or the
// log: in the reason, the working directory, the variable names, the
// command, the parent commands of ssh, and the name of a secret that does
// not exist.
func TestCanaryNeverLeaks(t *testing.T) {
	e := newEnv(t, envOptions{})
	x := canary()
	forms := []string{"-p" + x, "--token=" + x, "password=" + x, "Authorization: " + x, x}
	reason := strings.Join(forms, " ")
	laptop, ci := e.httpClient("laptop"), e.httpClient("ci")
	e.approver.Auto(audit.AnswerApproveOnce)

	// Secrets, approved.
	req := api.SecretsRequest{
		Secrets: []api.SecretRef{{Var: x, Name: "github-token"}, {Var: "DB_PASSWORD", Name: "db-password"}},
		Command: append([]string{"mysql"}, forms...),
		Dir:     "/home/dev/" + x,
		Reason:  reason,
	}
	if got := secretsOf(t, e.post(t.Context(), laptop, api.PathSecrets, req)); got[x] != e.values["github-token"] {
		t.Error("the variable did not get its value")
	}
	// Secrets, denied by the broker's checks: an unknown secret named
	// after the canary, and a bad variable.
	req.Secrets = []api.SecretRef{{Var: "A", Name: x}, {Var: "B", Name: strings.ToLower(x)}}
	mustStatus(t, e.post(t.Context(), laptop, api.PathSecrets, req), http.StatusForbidden)
	req.Secrets = []api.SecretRef{{Var: x + "=1", Name: "github-token"}}
	mustStatus(t, e.post(t.Context(), laptop, api.PathSecrets, req), http.StatusForbidden)
	// Secrets by a "never ask" rule, with a notice.
	req.Secrets = []api.SecretRef{{Var: x, Name: "backup-token"}}
	mustStatus(t, e.post(t.Context(), ci, api.PathSecrets, req), http.StatusOK)
	// An SSH login with the canary in the parent commands and the reason.
	sign := e.signRequest(t, "deploy", "web-1", "deploy")
	sign.Commands = [][]string{{"ssh", "-p" + x, "deploy@web-1"}, {"bash", "-c", "deploy --token " + x}, append([]string{"make"}, forms...)}
	sign.Reason = reason
	mustStatus(t, e.post(t.Context(), laptop, api.PathSign, sign), http.StatusOK)
	// An SSH grant with the canary in the reason, denied.
	e.approver.Auto(audit.AnswerDeny)
	grant := api.GrantRequest{Key: "deploy", User: "deploy", Hosts: []string{"web-1"}, Seconds: 600, Reason: reason}
	mustStatus(t, e.post(t.Context(), laptop, api.PathSSHGrant, grant), http.StatusForbidden)

	texts := map[string]string{
		"the messages":     e.approverTexts(),
		"the audit log":    encodeEvents(t, e.audit.all()),
		"the log":          e.logs.String(),
		"the server's log": e.srvLogs.String(),
	}
	if !strings.Contains(texts["the messages"], "***") {
		t.Error("nothing was masked; the test does not test")
	}
	for where, text := range texts {
		if strings.Contains(text, x) || strings.Contains(text, strings.ToLower(x)) {
			t.Errorf("%s holds the canary", where)
		}
	}
}

// emoji takes 4 bytes in UTF-8, the most for one character after the
// cleaning of package claim.
const emoji = "\U0001F600"

// worstText returns n bytes of claimed text with the worst characters.
func worstText(n int) string { return strings.Repeat(emoji, n/len(emoji)) }

// worstCommand returns a command line at the caps (DESIGN.md section 10):
// 4096 arguments with 64 KiB in all, of which the 9 shown are long.
func worstCommand() []string {
	argv := make([]string, api.MaxArgs)
	for i := range 9 {
		argv[i] = worstText((api.MaxText - 1024) / 9)
	}
	return argv
}

// TestAuditEntriesFit: with every claimed field at its cap and the worst
// characters, and the longest names, every entry fits in a line of the
// audit log (audit.CheckEvent, which the fake log runs), so a deny is
// always recorded. The fake approver puts every claimed field into its
// message without cutting it, so its message is longer than a Telegram
// message can be.
func TestAuditEntriesFit(t *testing.T) {
	long := func(prefix string, i int) string { return fmt.Sprintf("%s%02d-", prefix, i) + strings.Repeat("x", 60) }
	var hostNames []string
	e := newEnv(t, envOptions{config: func(cfg *config.Broker) {
		for i := range api.MaxSecrets {
			name := long("s", i)
			cfg.Secrets[name] = config.Secret{Name: name, Store: "main", ID: idGitHub, Clients: []string{"laptop"},
				Rule: config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute}}
		}
		var kh strings.Builder
		for i := range api.MaxGrantHosts {
			name := long("h", i)
			hostNames = append(hostNames, name)
			kh.WriteString(name + " " + string(ssh.MarshalAuthorizedKey(newHostKey(t).PublicKey())))
		}
		for _, name := range []string{"web-1", "web-2", "db-1"} {
			for _, k := range cfg.KnownHosts.KeysFor(name) {
				kh.WriteString(name + " " + string(ssh.MarshalAuthorizedKey(k)))
			}
		}
		known, err := config.ParseKnownHosts([]byte(kh.String()))
		if err != nil {
			t.Fatal(err)
		}
		cfg.KnownHosts = known
	}})
	c := e.httpClient("laptop")
	var refs []api.SecretRef
	for i := range api.MaxSecrets {
		refs = append(refs, api.SecretRef{Var: fmt.Sprintf("V%02d", i) + strings.Repeat("_", 61), Name: long("s", i)})
	}
	big := api.SecretsRequest{Secrets: refs, Command: worstCommand(), Dir: worstText(api.MaxText),
		Reason: worstText(api.MaxText)}
	user := "u" + strings.Repeat("x", 31)

	// Approved, denied by the person, and denied by the broker.
	e.approver.Auto(audit.AnswerApproveOnce)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, big))
	e.approver.Auto(audit.AnswerDeny)
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, big), http.StatusForbidden)
	bad := big
	bad.Secrets = append([]api.SecretRef{{Var: worstText(api.MaxName), Name: "github-token"}}, refs[1:]...)
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, bad), http.StatusForbidden)

	sign := e.signRequest(t, "deploy", "web-1", "deploy")
	sign.Commands = [][]string{worstCommand(), worstCommand(), worstCommand(), worstCommand()}
	sign.Reason = worstText(api.MaxText)
	e.approver.Auto(audit.AnswerApproveOnce)
	mustStatus(t, e.post(t.Context(), c, api.PathSign, sign), http.StatusOK)

	grant := api.GrantRequest{Key: "deploy", User: user, Hosts: hostNames, Seconds: 900, Reason: worstText(api.MaxText)}
	e.approver.Auto(audit.AnswerApproveWindow)
	mustStatus(t, e.post(t.Context(), c, api.PathSSHGrant, grant), http.StatusOK)
	e.approver.Auto("")
	p := e.start(c, api.PathSSHGrant, grant)
	e.waitAsked(5)
	e.clock.Advance(e.cfg.Telegram.Timeout)
	mustStatus(t, p.wait(t), http.StatusForbidden)

	events := e.audit.all()
	mustEvents(t, events, "request decision:approve_once secret_sent "+
		"request decision:deny denied:approver "+
		"request denied:not_allowed "+
		"request decision:approve_once signed "+
		"request decision:approve_window "+
		"request denied:expired")
	longest := 0
	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		longest = max(longest, len(data))
		if s := subjectOf(ev); len([]rune(s.Command)) > maxCommandRunes || len([]rune(s.Reason)) > maxReasonRunes {
			t.Errorf("%s: a claimed field is longer than its cap", eventName(ev))
		}
	}
	t.Logf("the longest entry has about %d bytes; a line may have %d", longest, audit.MaxLineSize)
}

// TestNoFakeAnchorLines: no line of the broker's log can start with
// "audit anchor " (DESIGN.md section 9), and none is longer than 48 KiB:
// not from claimed text, not from an error of the approver or a store,
// and not from the certificate of a refused client.
func TestNoFakeAnchorLines(t *testing.T) {
	e := newEnv(t, envOptions{})
	fake := "\naudit anchor 1:" + strings.Repeat("ab", 32) + "\n"
	c := e.httpClient("laptop")
	req := secretsRequest("GH_TOKEN", "github-token")
	req.Reason += fake
	req.Dir += fake
	req.Command = append(req.Command, fake)
	e.approver.Auto(audit.AnswerApproveOnce)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, req))

	e.approver.FailAsk(errors.New("made-up approver error" + fake + strings.Repeat("x", 100<<10)))
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password")),
		http.StatusServiceUnavailable)
	e.approver.FailAsk(nil)
	e.vault.set(func(f *fakeStore) { f.err = errors.New("made-up store error" + fake) })
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password")),
		http.StatusServiceUnavailable)
	e.vault.set(func(f *fakeStore) { f.err, f.panic = nil, "made-up panic"+fake })
	if res := e.post(t.Context(), c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password")); res.err == nil {
		t.Error("the request got an answer after a panic")
	}
	waitLog(t, e.logs, "a request panicked")
	// The claimed text is in the audit log, as one line inside a JSON
	// string; error texts and panic values never are.
	if text := encodeEvents(t, e.audit.all()); strings.Contains(text, "made-up") {
		t.Error("an error text or a panic value is in the audit log")
	}

	stranger := newTLSKey(t, "laptop"+fake)
	sc, err := transport.NewClient(e.addr, stranger.cert, e.broker.pin)
	if err != nil {
		t.Fatal(err)
	}
	if res := e.post(t.Context(), sc, api.PathKeys, api.KeysRequest{}); res.err == nil {
		t.Errorf("a client with an unknown key got an answer: %d", res.status)
	}
	waitLog(t, e.srvLogs, "refused a client key")
	logs := waitLog(t, e.logs, "a store failed")
	if !strings.Contains(logs, "the approver failed") {
		t.Errorf("the log does not show the approver's error:\n%s", logs)
	}
	for where, text := range map[string]string{"the log": logs, "the server's log": e.srvLogs.String()} {
		for line := range strings.Lines(text) {
			if strings.HasPrefix(line, audit.JournalPrefix) {
				t.Errorf("%s has a line that looks like an anchor: %q", where, line)
			}
			if len(line) > 48<<10 {
				t.Errorf("%s has a line of %d bytes", where, len(line))
			}
		}
	}
}

// TestPanicDenies: a panic while a request is handled denies it: the
// connection is dropped, the audit log records the deny, the value that
// was fetched is cleared, and the log says where, never the panic value.
// The broker goes on.
func TestPanicDenies(t *testing.T) {
	e := newEnv(t, envOptions{})
	x := canary()
	e.vault.set(func(f *fakeStore) { f.panic = "made-up panic " + x })
	e.approver.Auto(audit.AnswerApproveOnce)
	c := e.httpClient("laptop")
	req := secretsRequest("GH_TOKEN", "github-token")
	req.Secrets = append(req.Secrets, api.SecretRef{Var: "DB_PASSWORD", Name: "db-password"})
	if res := e.post(t.Context(), c, api.PathSecrets, req); res.err == nil {
		t.Fatalf("the request got an answer after a panic: %d", res.status)
	}
	events := e.audit.waitFor(t, 4)
	mustEvents(t, events, "request decision:approve_once error:store_failed denied:error")
	e.main.checkCleared(t)
	logs := waitLog(t, e.logs, "a request panicked")
	if strings.Contains(logs, x) || strings.Contains(e.srvLogs.String(), x) {
		t.Error("the log holds the panic value")
	}
	if !strings.Contains(logs, "fakeStore") {
		t.Errorf("the log does not say where the panic happened:\n%s", logs)
	}
	e.vault.set(func(f *fakeStore) { f.panic = "" })
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, req))
}

// takeRunErr waits for the end of Run, and gives the error back for the
// cleanup of the test.
func (e *env) takeRunErr(t testing.TB) error {
	t.Helper()
	select {
	case err := <-e.runErr:
		e.runErr <- err
		return err
	case <-time.After(waitLimit):
		t.Fatal("Run did not return")
		return nil
	}
}

// TestApproverStopDeniesEverything: when the approval core's Run returns,
// every request is denied, also one that a grant would allow.
func TestApproverStopDeniesEverything(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	e.approver.Auto(audit.AnswerApproveWindow)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")))
	stop := errors.New("made-up: the approver cannot get answers")
	e.approver.Stop(stop)
	if err := e.takeRunErr(t); !errors.Is(err, stop) {
		t.Errorf("Run returned %v, want the approver's error", err)
	}
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")),
		http.StatusServiceUnavailable)
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request error:approver_failed denied:error")
	if e.main.fetched() != 1 {
		t.Error("a request after the stop was fetched")
	}
	waitLog(t, e.logs, "the approver stopped")
	mustStatus(t, e.post(t.Context(), c, api.PathKeys, api.KeysRequest{}), http.StatusServiceUnavailable)
}

// TestPollConflict: when Telegram reports a polling conflict, Run writes
// an error entry with code poll_conflict, and returns the error.
func TestPollConflict(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.approver.Stop(fmt.Errorf("telegram: %w", telegram.ErrPollConflict))
	if err := e.takeRunErr(t); !errors.Is(err, telegram.ErrPollConflict) {
		t.Errorf("Run returned %v, want ErrPollConflict", err)
	}
	events := e.audit.all()
	if len(events) != 1 {
		t.Fatalf("audit entries: %s", eventNames(events))
	}
	if f, ok := events[0].(audit.Failure); !ok || f.Code != audit.CodePollConflict || f.RequestID != "" {
		t.Errorf("the entry is %+v, want an error entry with poll_conflict", events[0])
	}
	waitLog(t, e.logs, "another program polls with the bot token")
}

// TestForeignTap: ForeignTap writes a foreign_tap entry. It only queues
// the entry, so a slow audit log never holds up the Telegram polling;
// when the queue is full, it drops entries and the log counts them. It
// never panics, also after Close.
func TestForeignTap(t *testing.T) {
	e := newEnv(t, envOptions{})
	tap := audit.ForeignTap{UserID: 987654321, ChatID: 987654321, MessageID: 42, Data: "o:" + strings.Repeat("A", 22),
		Cause: audit.TapUnknownRequest}
	e.svc.ForeignTap(tap)
	if got := e.audit.waitFor(t, 1); got[0] != audit.Event(tap) {
		t.Errorf("the entry is %+v", got[0])
	}
	gate := make(chan struct{})
	e.audit.setGate(gate)
	start := time.Now()
	for range 3 * tapQueue {
		e.svc.ForeignTap(tap)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("ForeignTap waited %v for a slow audit log", d)
	}
	e.audit.setGate(nil)
	close(gate)
	waitLog(t, e.logs, "dropped foreign_tap entries")
	if n := len(e.audit.all()); n < 2 || n > 2+tapQueue {
		t.Errorf("%d entries, want at most the queue", n)
	}
	e.svc.Close()
	e.svc.ForeignTap(tap) // no panic, no wait
}

// TestRouting: only POST on the exact paths of the API reaches a handler.
// "PRI *", "OPTIONS *", other methods and other spellings of a path get
// 404 or 405, without an audit entry or a message.
func TestRouting(t *testing.T) {
	e := newEnv(t, envOptions{})
	post := func(target string) string {
		return "POST " + target + " HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n" +
			"Content-Length: 2\r\n\r\n{}"
	}
	for _, tt := range []struct {
		text   string
		status int
	}{
		{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", http.StatusNotFound},
		{"OPTIONS * HTTP/1.1\r\nHost: broker\r\n\r\n", http.StatusNotFound},
		{"GET /v1/secrets HTTP/1.1\r\nHost: broker\r\n\r\n", http.StatusMethodNotAllowed},
		{"OPTIONS /v1/sign HTTP/1.1\r\nHost: broker\r\n\r\n", http.StatusMethodNotAllowed},
		{post("/v1/nope"), http.StatusNotFound},
		{post("/v1/secrets?x=1"), http.StatusNotFound},
		{post("//v1/secrets"), http.StatusNotFound},
		{post("/v1/secrets/"), http.StatusNotFound},
		{post("/v1/./secrets"), http.StatusNotFound},
		{post("/v1/%73ecrets"), http.StatusNotFound},
		{post("/V1/SECRETS"), http.StatusNotFound},
		{post("https://broker/v1/secrets"), http.StatusNotFound},
	} {
		if got := e.rawRequest("laptop", tt.text); got != tt.status {
			t.Errorf("%q: %d, want %d", strings.SplitN(tt.text, "\r\n", 2)[0], got, tt.status)
		}
	}
	if len(e.audit.all()) != 0 || len(e.approver.Asked()) != 0 {
		t.Error("a request on a wrong path or with a wrong method was handled")
	}
}

// TestNotReady: before Run and after Close, every request is denied with
// 503, without an audit entry.
func TestNotReady(t *testing.T) {
	e := newEnv(t, envOptions{noRun: true})
	c := e.httpClient("laptop")
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")),
		http.StatusServiceUnavailable)
	e.svc.Close()
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")),
		http.StatusServiceUnavailable)
	if err := e.svc.Run(t.Context(), e.core, nil); !errors.Is(err, errClosed) {
		t.Errorf("Run after Close: %v", err)
	}
	if n := len(e.audit.all()); n != 0 {
		t.Errorf("%d audit entries", n)
	}
}

// TestCloseCancelsRequests: Close ends the requests in progress: they are
// cancelled, and their clients get 503, not a deny, so nodkey run exits
// with 69 when the broker restarts.
func TestCloseCancelsRequests(t *testing.T) {
	e := newEnv(t, envOptions{})
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.svc.Close()
	mustStatus(t, p.wait(t), http.StatusServiceUnavailable)
	mustEvents(t, requestEvents(e.audit.all(), id), "request denied:cancelled")
}

// TestNewChecksTheParts: New refuses parts that do not fit the config.
// Two [key.*] sections with the same public key are refused, as the
// config check finds only the same file, not a copy of a key.
func TestNewChecksTheParts(t *testing.T) {
	e := newEnv(t, envOptions{noRun: true})
	newKey := func(name string, hosts []string) sshauth.Key {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k, err := sshauth.NewKey(name, priv, hosts)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	parts := func() Parts {
		keys := make(map[string]sshauth.Key)
		for name, k := range e.cfg.Keys {
			keys[name] = newKey(name, k.Hosts)
		}
		return Parts{Config: e.cfg, Audit: e.audit, Keys: keys,
			Stores: map[string]store.Store{"main": e.main, "vault": e.vault}}
	}
	if _, err := New(parts()); err != nil {
		t.Fatalf("New with good parts: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	same := func(name string) sshauth.Key {
		k, err := sshauth.NewKey(name, priv, nil)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	for _, tt := range []struct {
		name string
		edit func(*Parts)
		want string
	}{
		{"no config", func(p *Parts) { p.Config = nil }, "required"},
		{"no audit log", func(p *Parts) { p.Audit = nil }, "required"},
		{"a store is missing", func(p *Parts) { delete(p.Stores, "vault") }, "[store.vault]"},
		{"a store too many", func(p *Parts) { p.Stores["other"] = e.main }, "no [store.*] section"},
		{"a key is missing", func(p *Parts) { delete(p.Keys, "web") }, "[key.web]"},
		{"a key too many", func(p *Parts) { p.Keys["other"] = newKey("other", nil) }, "no [key.*] section"},
		{"a key of another section", func(p *Parts) { p.Keys["web"] = newKey("admin", nil) }, "[key.web]"},
		{"two sections with the same key", func(p *Parts) {
			p.Keys["web"], p.Keys["admin"] = same("web"), same("admin")
		}, "[key.admin] and [key.web] hold the same public key"},
	} {
		p := parts()
		tt.edit(&p)
		_, err := New(p)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v; want an error with %q", tt.name, err, tt.want)
		}
	}
}

// TestRunTwice: Run runs once.
func TestRunTwice(t *testing.T) {
	e := newEnv(t, envOptions{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := e.svc.Run(ctx, e.core, nil); err == nil {
		t.Error("a second Run: no error")
	}
	if err := e.svc.Run(ctx, nil, nil); err == nil {
		t.Error("Run without a core: no error")
	}
}

// TestStopDuringDecide: when the approver stops while the core decides a
// request, the broker denies it, also after an approval, and fetches
// nothing.
func TestStopDuringDecide(t *testing.T) {
	e := newEnv(t, envOptions{})
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.svc.coreStopped.Store(true) // as when Run returns now
	e.tap(id, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusServiceUnavailable)
	mustEvents(t, requestEvents(e.audit.all(), id),
		"request decision:approve_once error:approver_failed denied:error")
	if e.main.fetched() != 0 {
		t.Error("the broker fetched a value after the approver stopped")
	}
}
