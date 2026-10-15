package broker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// TestSecretsApproveOnce: a request waits for the person, the client gets
// the short code while it waits, the person taps "Approve once", and the
// client gets the value. The audit log has request, decision and
// secret_sent, in this order. The value is cleared after the answer.
func TestSecretsApproveOnce(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	asked := e.waitAsked(1)
	prompt := asked[0].Prompt
	if prompt.Client != "laptop" || len(prompt.Secrets) != 1 || prompt.Secrets[0] != "github-token" {
		t.Errorf("the message shows %+v", prompt)
	}
	want := approval.Claim{Vars: "GH_TOKEN", Command: "gh release create v1.2.0", Dir: "/home/dev/src/app",
		Reason: "publish the release the user asked for"}
	if prompt.Claim != want {
		t.Errorf("the claimed part is %+v, want %+v", prompt.Claim, want)
	}
	if e.main.fetched() != 0 {
		t.Error("the broker fetched the value before the approval")
	}
	e.tap(prompt.RequestID, audit.AnswerApproveOnce)
	res := p.wait(t)
	if got := secretsOf(t, res); got["GH_TOKEN"] != e.values["github-token"] || len(got) != 1 {
		t.Error("the answer does not hold the value of github-token as GH_TOKEN")
	}
	want64 := base64.StdEncoding.EncodeToString([]byte(e.values["github-token"]))
	if string(res.body) != `{"secrets":[{"var":"GH_TOKEN","value":"`+want64+`"}]}` {
		t.Error("the answer is not the JSON of DESIGN.md section 10")
	}
	if res.code != prompt.ShortCode {
		t.Errorf("the client got the short code %q, the message has %q", res.code, prompt.ShortCode)
	}
	events := requestEvents(e.audit.all(), prompt.RequestID)
	mustEvents(t, events, "request decision:approve_once secret_sent")
	req, ok := events[0].(audit.Request)
	if !ok || req.Message != asked[0].Text || req.Client != "laptop" || req.Kind != audit.KindSecrets ||
		req.Command != want.Command || req.Reason != want.Reason {
		t.Errorf("the request entry is %+v", events[0])
	}
	if d, ok := events[1].(audit.Decision); !ok || d.UserID != approverID {
		t.Errorf("the decision entry is %+v", events[1])
	}
	if e.main.fetched() != 1 {
		t.Errorf("the store ran %d times, want 1", e.main.fetched())
	}
	e.main.checkCleared(t)
	// "Approve once" makes no grant: the next request asks again.
	p = e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	e.waitAsked(2)
	e.tap(e.approver.Asked()[1].Prompt.RequestID, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
}

// TestSecretsTwoVariablesOneSecret: one secret for two variables is
// fetched once, and both variables get it.
func TestSecretsTwoVariablesOneSecret(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.approver.Auto(audit.AnswerApproveOnce)
	req := secretsRequest("GH_TOKEN", "github-token")
	req.Secrets = append(req.Secrets, api.SecretRef{Var: "GITHUB_TOKEN", Name: "github-token"},
		api.SecretRef{Var: "DB_PASSWORD", Name: "db-password"})
	got := secretsOf(t, e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, req))
	if got["GH_TOKEN"] != e.values["github-token"] || got["GITHUB_TOKEN"] != e.values["github-token"] ||
		got["DB_PASSWORD"] != e.values["db-password"] {
		t.Error("the answer does not hold the values")
	}
	if e.main.fetched() != 1 || e.vault.fetched() != 1 {
		t.Errorf("fetches: main %d, vault %d; want 1 each", e.main.fetched(), e.vault.fetched())
	}
	asked := e.approver.Asked()
	if len(asked) != 1 || asked[0].Prompt.Claim.Vars != "GH_TOKEN, GITHUB_TOKEN, DB_PASSWORD" ||
		strings.Join(asked[0].Prompt.Secrets, ",") != "github-token,db-password" {
		t.Errorf("one message for the request, with every name; got %+v", asked)
	}
	e.main.checkCleared(t)
	e.vault.checkCleared(t)
}

// TestSecretsDeny: the person taps Deny. The client gets 403, nothing is
// fetched, and new requests for the secret are denied for a minute
// without a message (the pause after a Deny), with 429.
func TestSecretsDeny(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
	mustEvents(t, requestEvents(e.audit.all(), id), "request decision:deny denied:approver")
	if e.main.fetched() != 0 {
		t.Error("the broker fetched a value after a Deny")
	}
	res := e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	mustStatus(t, res, http.StatusTooManyRequests)
	if res.code != "" || len(e.approver.Asked()) != 1 {
		t.Error("a request in the pause after a Deny waited for the person")
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request denied:limit")
}

// TestSecretsExpire: the person does not answer in time.
func TestSecretsExpire(t *testing.T) {
	e := newEnv(t, envOptions{})
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.clock.Advance(e.cfg.Telegram.Timeout)
	mustStatus(t, p.wait(t), http.StatusForbidden)
	mustEvents(t, requestEvents(e.audit.all(), id), "request denied:expired")
	ended, err := e.approver.WaitEnded(1, waitLimit)
	if err != nil || ended[0].Ending.Cause != audit.CauseExpired {
		t.Errorf("the message was not updated as expired: %+v, %v", ended, err)
	}
	if e.main.fetched() != 0 {
		t.Error("the broker fetched a value after the request expired")
	}
}

// TestSecretsCancel: the client hangs up while it waits. The request is
// cancelled, and a late tap changes nothing.
func TestSecretsCancel(t *testing.T) {
	e := newEnv(t, envOptions{})
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	p.cancel()
	// The broker answers a cancelled request with 403 at once. The client
	// may still read that answer while its connection closes, so either a
	// dropped connection or 403 is right; never a value.
	if res := p.wait(t); res.err == nil && res.status != http.StatusForbidden {
		t.Errorf("the request got the answer %d after the client hung up", res.status)
	}
	ended, err := e.approver.WaitEnded(1, waitLimit)
	if err != nil || ended[0].Ending.Cause != audit.CauseCancelled {
		t.Fatalf("the request did not end as cancelled: %+v, %v", ended, err)
	}
	mustEvents(t, requestEvents(e.audit.waitFor(t, 2), id), "request denied:cancelled")
	if err := e.approver.Tap(id, audit.AnswerApproveOnce); !errors.Is(err, approval.ErrUnknownRequest) {
		t.Errorf("a tap after the cancel: %v, want ErrUnknownRequest", err)
	}
	if e.main.fetched() != 0 {
		t.Error("the broker fetched a value for a cancelled request")
	}
}

// TestSecretsCancelAfterApproval: a request whose client hung up after
// the approval is not fetched.
func TestSecretsCancelAfterApproval(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.main.set(func(f *fakeStore) { f.block = true }) // the fetch waits for the end of the request
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerApproveOnce)
	select {
	case <-e.main.started:
	case <-time.After(waitLimit):
		t.Fatal("no fetch")
	}
	p.cancel()
	p.wait(t)
	mustEvents(t, requestEvents(e.audit.waitFor(t, 3), id), "request decision:approve_once denied:cancelled")
}

// TestSecretsGrant: "Approve N min" makes a grant. The next request of the
// same client for the same secret gets the value without a message, as
// grant_used. A grant covers only that client and secret.
func TestSecretsGrant(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	p := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	asked := e.waitAsked(1)
	if asked[0].Prompt.WindowMinutes != 15 {
		t.Fatalf("the message has no Approve 15 min: %+v", asked[0].Prompt)
	}
	id := asked[0].Prompt.RequestID
	e.tap(id, audit.AnswerApproveWindow)
	secretsOf(t, p.wait(t))
	mustEvents(t, requestEvents(e.audit.all(), id), "request decision:approve_window secret_sent")

	res := e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	if got := secretsOf(t, res); got["GH_TOKEN"] != e.values["github-token"] {
		t.Error("the grant did not hand out the value")
	}
	if res.code != "" || len(e.approver.Asked()) != 1 {
		t.Error("a request covered by a grant waited for the person")
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request grant_used:grant secret_sent")
	// Another secret still asks.
	p = e.start(c, api.PathSecrets, secretsRequest("NPM_TOKEN", "npm-token"))
	e.waitAsked(2)
	p.cancel()
	p.wait(t)
	// The grant ends after its window.
	e.clock.Advance(15 * time.Minute)
	p = e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	e.waitAsked(3)
	p.cancel()
	p.wait(t)
}

// TestSecretsNeverAsk: a "never ask" rule hands out the value without a
// tap, with a notice; another client cannot use it.
func TestSecretsNeverAsk(t *testing.T) {
	e := newEnv(t, envOptions{})
	res := e.post(t.Context(), e.httpClient("ci"), api.PathSecrets, secretsRequest("BACKUP_TOKEN", "backup-token"))
	if got := secretsOf(t, res); got["BACKUP_TOKEN"] != e.values["backup-token"] {
		t.Error("the never-ask rule did not hand out the value")
	}
	if len(e.approver.Asked()) != 0 || len(e.approver.Notices()) != 1 {
		t.Errorf("messages %d, notices %d; want 0 and 1", len(e.approver.Asked()), len(e.approver.Notices()))
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request grant_used:never_rule secret_sent")
	// The rule is for ci only.
	res = e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("BACKUP_TOKEN", "backup-token"))
	mustStatus(t, res, http.StatusForbidden)
	events = e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request denied:not_allowed")
	// A notice that cannot be sent denies the use.
	e.approver.FailNotify(errors.New("telegram is down"))
	res = e.post(t.Context(), e.httpClient("ci"), api.PathSecrets, secretsRequest("BACKUP_TOKEN", "backup-token"))
	mustStatus(t, res, http.StatusServiceUnavailable)
	events = e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request error:approver_failed denied:error")
	if e.main.fetched() != 1 {
		t.Errorf("the store ran %d times, want 1", e.main.fetched())
	}
}

// TestSecretsLimits: at most 5 messages wait for one client and 10
// requests wait in its queue; the next request is denied at once, with
// 429. Queued requests get the short code too.
func TestSecretsLimits(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	var waiting []*pendingResult
	codes := make(map[string]bool)
	for range approval.MaxOpenMessages + approval.MaxQueued {
		p := e.start(c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password"))
		waiting = append(waiting, p)
		// The request waits: it has a message, or a place in the queue.
		codes[p.waitCode(t)] = true
	}
	if len(codes) != len(waiting) {
		t.Errorf("%d different short codes for %d waiting requests", len(codes), len(waiting))
	}
	res := e.post(t.Context(), c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password"))
	mustStatus(t, res, http.StatusTooManyRequests)
	if res.code != "" {
		t.Error("a request over the limit got a short code")
	}
	if n := len(e.waitAsked(approval.MaxOpenMessages)); n != approval.MaxOpenMessages {
		t.Errorf("%d messages, want %d", n, approval.MaxOpenMessages)
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request denied:limit")
	for _, p := range waiting {
		p.cancel()
	}
	for _, p := range waiting {
		p.wait(t)
	}
}

// TestRequestsPerClient: a client with too many requests in progress gets
// 429 at once; another client does not.
func TestRequestsPerClient(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.svc.setMaxPerClient(2)
	c := e.httpClient("laptop")
	p1 := e.start(c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password"))
	p2 := e.start(c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password"))
	e.waitAsked(2)
	res := e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	mustStatus(t, res, http.StatusTooManyRequests)
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)), "request denied:limit")
	if len(e.approver.Asked()) != 2 {
		t.Error("a request over the cap was shown")
	}
	// The keys of the other client.
	res = e.post(t.Context(), e.httpClient("ci"), api.PathSecrets, secretsRequest("BACKUP_TOKEN", "backup-token"))
	mustStatus(t, res, http.StatusOK)
	p1.cancel()
	p2.cancel()
	p1.wait(t)
	p2.wait(t)
	e.svc.waitIdle(t, "laptop") // the broker sees the hang-ups after the client
	// The places are free again.
	e.approver.Auto(audit.AnswerApproveOnce)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")))
}

// TestSecretsBrokerChecks: the broker checks the variables and the names
// itself, and denies without a message. The audit log never holds a name
// that failed a check.
func TestSecretsBrokerChecks(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	unknown := "github-" + strings.ToLower(canary())
	tests := []struct {
		name   string
		refs   []api.SecretRef
		passed []string
	}{
		{"no secrets", []api.SecretRef{}, nil},
		{"an unknown secret", []api.SecretRef{{Var: "A", Name: unknown}}, nil},
		{"a secret of another client", []api.SecretRef{{Var: "A", Name: "backup-token"}}, nil},
		{"a known and an unknown secret", []api.SecretRef{{Var: "A", Name: "github-token"}, {Var: "B", Name: unknown}},
			[]string{"github-token"}},
		{"a variable in lower case", []api.SecretRef{{Var: "gh_token", Name: "github-token"}}, []string{"github-token"}},
		{"a variable with =", []api.SecretRef{{Var: "A=B", Name: "github-token"}}, []string{"github-token"}},
		{"a variable with a line break", []api.SecretRef{{Var: "A\nB", Name: "github-token"}}, []string{"github-token"}},
		{"a variable that starts with a digit", []api.SecretRef{{Var: "1A", Name: "github-token"}}, []string{"github-token"}},
		// Over the cap of api.MaxName: refused when the body is read (400).
		{"a variable of 65 characters", []api.SecretRef{{Var: strings.Repeat("A", 65), Name: "github-token"}}, nil},
		{"one variable twice", []api.SecretRef{{Var: "A", Name: "github-token"}, {Var: "A", Name: "npm-token"}},
			[]string{"github-token", "npm-token"}},
	}
	for _, tt := range tests {
		req := secretsRequest("A", "github-token")
		req.Secrets = tt.refs
		before := len(e.audit.all())
		res := e.post(t.Context(), c, api.PathSecrets, req)
		if res.err != nil || res.status == http.StatusOK || res.code != "" {
			t.Errorf("%s: status %d, %v; want a deny without a wait", tt.name, res.status, res.err)
			continue
		}
		got := e.audit.waitFor(t, before+2)[before:]
		mustEvents(t, got, "request denied:not_allowed")
		if s := subjectOf(got[0]); strings.Join(s.Secrets, ",") != strings.Join(tt.passed, ",") {
			t.Errorf("%s: the audit log names %q, want %q", tt.name, s.Secrets, tt.passed)
		}
	}
	if len(e.approver.Asked()) != 0 || e.main.fetched() != 0 {
		t.Error("a request that failed a check was shown or fetched")
	}
	if all := encodeEvents(t, e.audit.all()) + e.logs.String(); strings.Contains(strings.ToLower(all), strings.ToLower(canary())) {
		t.Error("the name of an unknown secret is in the audit log or the log")
	}
}

// TestBadBodies: a body that is not a valid request is refused with 400
// and recorded as denied, without a message.
func TestBadBodies(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	tooMany := secretsRequest("A", "github-token")
	for i := range api.MaxSecrets {
		tooMany.Secrets = append(tooMany.Secrets, api.SecretRef{Var: "V" + strings.Repeat("A", i), Name: "github-token"})
	}
	many, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{
		`{}`,
		`{"secrets":[],"command":[],"dir":""}`,
		`{"secrets":[],"command":[],"dir":"","reason":null}`,
		`{"secrets":[{"var":"A","name":"github-token"}],"command":[null],"dir":"","reason":""}`,
		`{"secrets":[],"command":[],"dir":"","reason":"","local_user":"dev"}`,
		`{"secrets":[],"command":[],"dir":"","reason":"","reason":""}`,
		`{"SECRETS":[],"command":[],"dir":"","reason":""}`,
		`[]`,
		string(many),
	}
	for _, body := range bodies {
		res := e.postRaw(t.Context(), c, api.PathSecrets, []byte(body))
		mustStatus(t, res, http.StatusBadRequest)
	}
	// Each body is recorded as denied. ReadJSON answers first, so the
	// entries may come after the answer.
	events := e.audit.waitFor(t, 2*len(bodies))
	mustEvents(t, events, strings.Repeat("request denied:not_allowed ", len(bodies)-1)+"request denied:not_allowed")
	if len(e.approver.Asked()) != 0 {
		t.Error("a bad body was shown")
	}
}

// TestValueTooLong: a value over api.MaxValue is not handed out.
func TestValueTooLong(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.main.set(func(f *fakeStore) { f.items[idGitHub] = strings.Repeat("v", api.MaxValue+1) })
	e.approver.Auto(audit.AnswerApproveOnce)
	res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	mustStatus(t, res, http.StatusServiceUnavailable)
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)),
		"request decision:approve_once error:store_failed denied:error")
	e.main.checkCleared(t)
}

// TestStoreFailure: a store error denies the whole request. The log gets
// the store's fixed text; the client gets only the status.
func TestStoreFailure(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.vault.set(func(f *fakeStore) { f.err = errors.New(`store "vault": bw sync: the program failed (exit code 1)`) })
	e.approver.Auto(audit.AnswerApproveOnce)
	req := secretsRequest("GH_TOKEN", "github-token")
	req.Secrets = append(req.Secrets, api.SecretRef{Var: "DB_PASSWORD", Name: "db-password"})
	res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, req)
	mustStatus(t, res, http.StatusServiceUnavailable)
	if bytes.Contains(res.body, []byte("vault")) || bytes.Contains(res.body, []byte(e.values["github-token"])) {
		t.Errorf("the answer says more than the status: %s", res.body)
	}
	events := e.audit.all()
	mustEvents(t, requestEvents(events, lastRequestID(t, events)),
		"request decision:approve_once error:store_failed denied:error")
	if !strings.Contains(e.logs.String(), "bw sync: the program failed") {
		t.Errorf("the log does not say which store failed:\n%s", e.logs.String())
	}
	e.main.checkCleared(t) // github-token was fetched first, then cleared
}
