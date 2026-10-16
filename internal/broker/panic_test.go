package broker

// Regression tests from the security review of issue #11 (part A): panics
// in the approver, in the request's goroutine and in Run.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
)

// panicApprover is the fake approver, but Ask panics when askPanics is
// set, and Run panics when panicRun is closed.
type panicApprover struct {
	*approvaltest.Approver
	askPanics atomic.Bool
	panicRun  chan struct{}
}

func (p *panicApprover) Ask(ctx context.Context, pr approval.Prompt) (approval.Shown, error) {
	if p.askPanics.Load() {
		panic("made-up panic in Ask")
	}
	return p.Approver.Ask(ctx, pr)
}

func (p *panicApprover) Run(ctx context.Context, answer func(approval.Answer) error) error {
	done := make(chan error, 1)
	go func() { done <- p.Approver.Run(ctx, answer) }()
	select {
	case <-p.panicRun:
		panic("made-up panic in the approver's Run")
	case err := <-done:
		return err
	}
}

// runWithPanicApprover runs e.svc with a core whose approver is a
// panicApprover. It returns the approver, and a channel that gets the
// panic value of Run (nil if Run returned).
func runWithPanicApprover(t *testing.T, e *env) (*panicApprover, chan any) {
	t.Helper()
	pa := &panicApprover{Approver: e.approver, panicRun: make(chan struct{})}
	core, err := approval.New(e.cfg, pa, approval.Options{Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }() // as nodkey broker might
		_ = e.svc.Run(ctx, core, nil, nil)
	}()
	if err := e.approver.WaitRunning(waitLimit); err != nil {
		t.Fatal(err)
	}
	return pa, recovered
}

// TestPanicInAsk: the approver panics in the request's goroutine, inside
// Decide. The request is denied (the connection drops), the audit log
// records it under an ID of the broker, with the names that passed the
// checks, and the broker goes on.
func TestPanicInAsk(t *testing.T) {
	e := newEnv(t, envOptions{noRun: true})
	pa, _ := runWithPanicApprover(t, e)
	pa.askPanics.Store(true)
	c := e.httpClient("laptop")
	res := e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	if res.err == nil {
		t.Errorf("an answer after a panic: %d", res.status)
	}
	waitLog(t, e.logs, "a request panicked")
	events := e.audit.waitFor(t, 3)
	mustEvents(t, events, "request error:approver_failed denied:error")
	if s := subjectOf(events[0]); s.Kind != audit.KindSecrets || strings.Join(s.Secrets, ",") != "github-token" ||
		s.Reason != "publish the release the user asked for" {
		t.Errorf("the entry names %+v", s)
	}
	// The same for an SSH login: the record names what sshauth checked.
	res = e.post(t.Context(), c, api.PathSign, e.signRequest(t, "deploy", "web-1", "deploy"))
	if res.err == nil {
		t.Errorf("an answer after a panic: %d", res.status)
	}
	events = e.audit.waitFor(t, 6)
	mustEvents(t, events[3:], "request error:approver_failed denied:error")
	if s := subjectOf(events[3]); s.Key != "deploy" || strings.Join(s.Hosts, ",") != "web-1" || s.RemoteUser != "deploy" ||
		s.HostKey == "" {
		t.Errorf("the entry names %+v", s)
	}
	pa.askPanics.Store(false)
	e.approver.Auto(audit.AnswerApproveOnce)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")))
}

// TestApproverRunPanics: the approver's Run panics. The core stops.
// If nodkey broker recovers that panic, does the Service still deny every
// request, also one that a grant allows?
func TestApproverRunPanics(t *testing.T) {
	e := newEnv(t, envOptions{noRun: true})
	pa, recovered := runWithPanicApprover(t, e)
	c := e.httpClient("laptop")
	e.approver.Auto(audit.AnswerApproveWindow)
	secretsOf(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))) // a grant
	e.approver.Auto("")
	close(pa.panicRun)
	select {
	case v := <-recovered:
		if v == nil {
			t.Fatal("Run returned without a panic")
		}
	case <-time.After(waitLimit):
		t.Fatal("Run did not panic")
	}
	// Every request is denied, also one that the grant would allow.
	for _, req := range []api.SecretsRequest{
		secretsRequest("GH_TOKEN", "github-token"), secretsRequest("DB_PASSWORD", "db-password"),
	} {
		mustStatus(t, e.post(t.Context(), c, api.PathSecrets, req), http.StatusServiceUnavailable)
	}
	if e.main.fetched() != 1 {
		t.Errorf("the store ran %d times, want 1", e.main.fetched())
	}
}

// TestPanicBeforeTheCore: a panic before the core gives the request an ID,
// such as in the decoding or the claim code, is recorded under an ID of
// the broker, with the names that passed so far. With a broken audit log,
// the panic path writes nothing and does not wait.
func TestPanicBeforeTheCore(t *testing.T) {
	e := newEnv(t, envOptions{})
	panicIn := func(rq *request) {
		defer func() { _ = recover() }() // the http.ErrAbortHandler of recoverPanic
		defer rq.recoverPanic()
		panic("made-up panic in the checks")
	}
	rq := &request{s: e.svc, w: httptest.NewRecorder(), client: "laptop", kind: audit.KindSecrets,
		pre: audit.Subject{Secrets: []string{"github-token"}, Reason: "checked text"}}
	panicIn(rq)
	events := e.audit.waitFor(t, 2)
	mustEvents(t, events, "request denied:not_allowed")
	if s := subjectOf(events[0]); s.Client != "laptop" || strings.Join(s.Secrets, ",") != "github-token" ||
		s.Reason != "checked text" || len(s.RequestID) != 22 {
		t.Errorf("the entry names %+v", s)
	}

	// A broken log: nothing is written, and the panic path does not wait.
	e.svc.broken.Store(true)
	gate := make(chan struct{})
	e.audit.setGate(gate) // an Append would wait for ever
	defer close(gate)
	done := make(chan struct{})
	go func() {
		defer close(done)
		panicIn(&request{s: e.svc, w: httptest.NewRecorder(), client: "laptop", kind: audit.KindSecrets})
	}()
	select {
	case <-done:
	case <-time.After(waitLimit):
		t.Fatal("the panic path waits for a broken audit log")
	}
	if n := len(e.audit.all()); n != 2 {
		t.Errorf("%d entries, want 2", n)
	}
}
