package broker

// Regression tests from the security review of issue #11 (part A): two
// requests of one client at once, a grant that covers fewer secrets than
// the request, a client that hangs up between the decision and the fetch
// or the signature, and two sign requests whose logins differ.

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
)

// TestTwoRequestsAtOnce: two requests of one client wait at the same
// time. The person approves one and denies the other. Each gets only what
// its own message showed.
func TestTwoRequestsAtOnce(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	pa := e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	pb := e.start(c, api.PathSecrets, secretsRequest("DB_PASSWORD", "db-password"))
	asked := e.waitAsked(2)
	var idA, idB string
	for _, a := range asked {
		switch a.Prompt.Secrets[0] {
		case "github-token":
			idA = a.Prompt.RequestID
		case "db-password":
			idB = a.Prompt.RequestID
		}
	}
	if idA == "" || idB == "" || idA == idB {
		t.Fatalf("prompts: %+v", asked)
	}
	e.tap(idB, audit.AnswerDeny)
	e.tap(idA, audit.AnswerApproveOnce)
	ra, rb := pa.wait(t), pb.wait(t)
	got := secretsOf(t, ra)
	if len(got) != 1 || got["GH_TOKEN"] != e.values["github-token"] {
		t.Errorf("request A got %d values; want only GH_TOKEN", len(got))
	}
	mustStatus(t, rb, http.StatusForbidden)
	if bytes.Contains(rb.body, []byte(e.values["db-password"])) || bytes.Contains(ra.body, []byte(e.values["db-password"])) {
		t.Error("the denied value is in an answer")
	}
	if e.vault.fetched() != 0 || e.main.fetched() != 1 {
		t.Errorf("fetches: main %d, vault %d; want 1 and 0", e.main.fetched(), e.vault.fetched())
	}
	mustEvents(t, requestEvents(e.audit.all(), idA), "request decision:approve_once secret_sent")
	mustEvents(t, requestEvents(e.audit.all(), idB), "request decision:deny denied:approver")
}

// TestGrantCoversFewerSecrets: a grant for github-token does not
// allow a request for github-token and npm-token: that request asks, and
// nothing is fetched for it before the tap.
func TestGrantCoversFewerSecrets(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	e.approver.Auto(audit.AnswerApproveWindow)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")))
	e.approver.Auto("")
	req := secretsRequest("GH_TOKEN", "github-token")
	req.Secrets = append(req.Secrets, api.SecretRef{Var: "NPM_TOKEN", Name: "npm-token"})
	p := e.start(c, api.PathSecrets, req)
	asked := e.waitAsked(2)
	if code := p.waitCode(t); code != asked[1].Prompt.ShortCode {
		t.Errorf("short code %q, message %q", code, asked[1].Prompt.ShortCode)
	}
	if e.main.fetched() != 1 {
		t.Fatalf("the store ran %d times before the tap; want 1 (the first request)", e.main.fetched())
	}
	e.tap(asked[1].Prompt.RequestID, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
	// The Deny also ends the grant for github-token.
	p = e.start(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	res := p.wait(t)
	mustStatus(t, res, http.StatusTooManyRequests) // the pause after the Deny
	if e.main.fetched() != 1 {
		t.Errorf("the store ran %d times; want 1", e.main.fetched())
	}
}

// TestHangUpBetweenDecisionAndFetch: the client hangs up while the
// decision entry is being written. Nothing is fetched or sent, and the
// request ends as cancelled. The test waits until the server has seen the
// hang-up before the entry is on disk.
func TestHangUpBetweenDecisionAndFetch(t *testing.T) {
	wrap, contexts := requestContexts()
	e := newEnv(t, envOptions{wrap: wrap})
	gate := make(chan struct{})
	e.audit.setFail(func(ev audit.Event) error {
		if _, ok := ev.(audit.Decision); ok {
			<-gate // the disk is slow
		}
		return nil
	})
	// If the broker saw the hang-up only after the fetch began, the fetch
	// waits for the end of the request, so the outcome is the same.
	e.main.set(func(f *fakeStore) { f.block = true })
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	ctx := <-contexts
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerApproveOnce)
	time.Sleep(100 * time.Millisecond) // the handler now waits in Append
	p.cancel()
	p.wait(t)
	waitDone(t, ctx) // the server has seen the hang-up
	close(gate)
	events := requestEvents(e.audit.waitFor(t, 3), id)
	mustEvents(t, events, "request decision:approve_once denied:cancelled")
	if n := e.main.fetched(); n != 0 {
		t.Errorf("the store ran %d times after the client hung up; want 0", n)
	}
}

// TestHangUpBeforeSign: the same for an SSH login: no signature.
func TestHangUpBeforeSign(t *testing.T) {
	wrap, contexts := requestContexts()
	e := newEnv(t, envOptions{wrap: wrap})
	gate := make(chan struct{})
	e.audit.setFail(func(ev audit.Event) error {
		if _, ok := ev.(audit.Decision); ok {
			<-gate
		}
		return nil
	})
	p := e.start(e.httpClient("laptop"), api.PathSign, e.signRequest(t, "admin", "web-1", "deploy"))
	ctx := <-contexts
	id := e.waitAsked(1)[0].Prompt.RequestID
	e.tap(id, audit.AnswerApproveOnce)
	time.Sleep(100 * time.Millisecond)
	p.cancel()
	p.wait(t)
	waitDone(t, ctx)
	close(gate)
	mustEvents(t, requestEvents(e.audit.waitFor(t, 3), id), "request decision:approve_once denied:cancelled")
}

// TestTwoLoginsAtOnce: two sign requests of one client wait at the
// same time, for two remote users. The person approves the one for root
// only. Its signature is over its own data, and the other gets 403.
func TestTwoLoginsAtOnce(t *testing.T) {
	e := newEnv(t, envOptions{})
	c := e.httpClient("laptop")
	reqDeploy := e.signRequest(t, "admin", "web-1", "deploy")
	reqRoot := e.signRequest(t, "admin", "web-1", "root")
	pd := e.start(c, api.PathSign, reqDeploy)
	pr := e.start(c, api.PathSign, reqRoot)
	asked := e.waitAsked(2)
	for _, a := range asked {
		if a.Prompt.RemoteUser == "root" {
			e.tap(a.Prompt.RequestID, audit.AnswerApproveOnce)
		} else {
			e.tap(a.Prompt.RequestID, audit.AnswerDeny)
		}
	}
	rr, rd := pr.wait(t), pd.wait(t)
	mustStatus(t, rd, http.StatusForbidden)
	mustStatus(t, rr, http.StatusOK)
	ans, err := api.ReadAnswer[api.SignAnswer](bytes.NewReader(rr.body))
	if err != nil {
		t.Fatal(err)
	}
	sig := &ssh.Signature{Format: ans.Format, Blob: ans.Blob}
	pub := e.userKeys["admin"].PublicKey()
	if err := pub.Verify(reqRoot.Data, sig); err != nil {
		t.Errorf("the signature is not over the approved data: %v", err)
	}
	if err := pub.Verify(reqDeploy.Data, sig); err == nil {
		t.Error("the signature is valid for the denied login too")
	}
}

// waitDone waits until ctx has ended.
func waitDone(t testing.TB, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(waitLimit):
		t.Fatal("the server did not see the client hang up")
	}
}
