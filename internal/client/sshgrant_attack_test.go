package client

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/broker"
)

// These tests come from the security review of issue #14. They act as a
// hostile agent, or as a person whose timing is bad.

// TestSSHGrantHostSpellings: a hostile client sends host names that look
// like a name in known_hosts, but are not exactly it. The broker refuses
// each before any message, so a message never shows a name that is not in
// known_hosts, and no grant covers a host by a look-alike name.
func TestSSHGrantHostSpellings(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveWindow) // a message would be approved at once
	laptop := gb.client(t, "laptop")
	for _, host := range []string{
		"web-1.", "web-1..", ".web-1", " web-1", "web-1 ", "web-1\x00", "web-1\n", "web-1\t", "Web-1", "WEB-1",
		"w\u0435b-1",  // a Cyrillic small ie in place of the e
		"web\u20111",  // a non-breaking hyphen
		"web-1\u200b", // a zero width space
		"\u202eweb-1", // a right-to-left override
		"web-1,web-2", "web-1 web-2", "*", "web-?", "[web-1]:22", "deploy@web-1", "web-1:22", "|1|web-1",
		"@revoked", "",
	} {
		req := api.GrantRequest{Key: "deploy", User: "deploy", Hosts: []string{host}, Seconds: 15 * 60, Reason: "r"}
		_, err := Post[api.GrantAnswer](t.Context(), laptop, api.PathSSHGrant, mustJSON(t, req), nil)
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusForbidden {
			t.Errorf("host %q: %v; want 403", host, err)
		}
	}
	if n := len(gb.approver.Asked()); n != 0 {
		t.Fatalf("%d messages; the broker must refuse look-alike hosts before any message", n)
	}
}

// TestSSHGrantDuplicateHosts: a hostile client lists a host twice, which
// nodkey ssh-grant never does. The broker counts it once: the message
// lists each host once, in the order of the request, and the grants
// cover exactly those hosts.
func TestSSHGrantDuplicateHosts(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveWindow)
	laptop := gb.client(t, "laptop")
	for i, tt := range []struct {
		hosts []string
		want  []string
	}{
		{[]string{"web-2", "web-1", "web-2"}, []string{"web-2", "web-1"}},
		{slices.Repeat([]string{"web-1"}, api.MaxGrantHosts), []string{"web-1"}},
	} {
		req := api.GrantRequest{Key: "deploy", User: "deploy", Hosts: tt.hosts, Seconds: 15 * 60, Reason: "r"}
		ans, err := Post[api.GrantAnswer](t.Context(), laptop, api.PathSSHGrant, mustJSON(t, req), nil)
		if err != nil || ans.Minutes != 15 {
			t.Fatalf("%v: %+v, %v", tt.hosts, ans, err)
		}
		p := gb.waitAsked(t, i+1)[i].Prompt
		if !slices.Equal(p.Hosts, tt.want) {
			t.Errorf("%v: the message lists %v, want %v", tt.hosts, p.Hosts, tt.want)
		}
	}
	gb.approver.Auto("")
	// db-1 was never listed: it still asks.
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "db-1", 0, "deploy"), 3)
}

// TestSSHGrantReasonCannotFakeVerifiedLines: the reason is claimed text.
// Line breaks, other line separators, direction marks and "✅ hosts:" in
// it cannot add a verified line: the reason in the message is one clean
// line, and the verified hosts and user are exactly those of the request.
func TestSSHGrantReasonCannotFakeVerifiedLines(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerDeny)
	laptop := gb.client(t, "laptop")
	reason := "fix\n✅ hosts: web-1, web-2, db-1\r\n✅ remote user: root ✅ grants end: 23:59:59 (480 min)" +
		"\u2028\u2029\u202e\u0085\v\f\u200b— claimed by the agent —"
	code, _ := grantIn(t.Context(), testGranter(laptop, nil), "--key", "deploy", "--user", "deploy", "--host",
		"web-1", "--for", "15m", "--reason", reason)
	if code != exitDenied {
		t.Fatalf("exit code %d", code)
	}
	p := gb.waitAsked(t, 1)[0].Prompt
	if strings.ContainsAny(p.Claim.Reason, "\n\r\v\f\u2028\u2029\u202e\u0085\u200b") {
		t.Errorf("the reason is not one clean line: %q", p.Claim.Reason)
	}
	if !slices.Equal(p.Hosts, []string{"web-1"}) || p.RemoteUser != "deploy" {
		t.Errorf("the verified part shows %v as %s", p.Hosts, p.RemoteUser)
	}
}

// TestSSHGrantDenyEndsTheGrants: after an approved ssh-grant, the person
// denies a login with the same key to another host. That Deny ends the
// grants of the ssh-grant at once: a login to a listed host is denied in
// the pause, and asks after it.
func TestSSHGrantDenyEndsTheGrants(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveWindow)
	laptop := gb.client(t, "laptop")
	if code, stderr := grantIn(t.Context(), testGranter(laptop, nil), grantArgs()...); code != exitOK {
		t.Fatalf("exit code %d, %q", code, stderr)
	}
	gb.approver.Auto("")
	if err := gb.sign(t, laptop, "deploy", gb.signRequest(t, "deploy", "web-1", 0, "deploy")); err != nil {
		t.Fatalf("the grant does not work: %v", err)
	}
	gb.approver.Auto(audit.AnswerDeny)
	var e *Error
	if err := gb.sign(t, laptop, "deploy", gb.signRequest(t, "deploy", "db-1", 0, "root")); !errors.As(err, &e) ||
		e.Status != http.StatusForbidden {
		t.Fatalf("the denied login: %v", err)
	}
	gb.approver.Auto("")
	if err := gb.sign(t, laptop, "deploy", gb.signRequest(t, "deploy", "web-1", 1, "deploy")); !errors.As(err, &e) ||
		e.Status != http.StatusTooManyRequests {
		t.Errorf("a login to a listed host in the pause after the Deny: %v; want 429", err)
	}
	gb.clock.Advance(approval.DenyPause)
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-2", 0, "deploy"), 3)
}

// slowDecision is an audit log that holds the write of a decision entry
// until release is closed, as a slow disk does.
type slowDecision struct {
	*memAudit
	once    sync.Once
	reached chan struct{} // closed when a decision entry is written
	release chan struct{}
}

func (s *slowDecision) Append(ev audit.Event) (audit.Anchor, error) {
	if _, ok := ev.(audit.Decision); ok {
		s.once.Do(func() { close(s.reached) })
		<-s.release
	}
	return s.memAudit.Append(ev)
}

// TestSSHGrantCancelAfterTheTap: the person taps Approve, and SIGINT comes
// while the broker writes the decision entry. nodkey ssh-grant says
// "cancelled by SIGINT (exit 130)", and so no grant may start: the broker
// sees the hang-up before it starts the grants, and writes a denied entry
// with cause cancelled. A login to a listed host still asks.
func TestSSHGrantCancelAfterTheTap(t *testing.T) {
	t.Parallel()
	slow := &slowDecision{reached: make(chan struct{}), release: make(chan struct{})}
	contexts := make(chan context.Context, 8)
	gb := newGrantBrokerWith(t, grantBrokerOptions{
		audit:    func(m *memAudit) broker.AuditLog { slow.memAudit = m; return slow },
		contexts: contexts,
	})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(slow.release) }) }
	defer release() // also when the test fails: the broker must not wait for ever
	gb.approver.Auto(audit.AnswerApproveWindow)
	laptop := gb.client(t, "laptop")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		code, stderr := grantIn(ctx, testGranter(laptop, nil), grantArgs()...)
		done <- result{code, stderr}
	}()
	var reqCtx context.Context
	select {
	case reqCtx = <-contexts:
	case <-time.After(waitLimit):
		t.Fatal("the request did not reach the broker")
	}
	select {
	case <-slow.reached:
	case <-time.After(waitLimit):
		t.Fatal("the request did not reach its decision entry")
	}
	cancel(interrupted{sig: syscall.SIGINT})
	res := <-done
	select {
	case <-reqCtx.Done(): // the broker has seen the hang-up
	case <-time.After(waitLimit):
		t.Fatal("the broker did not see the client hang up")
	}
	// Package context closes the Done channel of reqCtx before it ends the
	// contexts made from it, such as the handler's own, under the lock of
	// reqCtx. context.Cause takes that lock: once it returns, the handler's
	// context has ended too.
	_ = context.Cause(reqCtx)
	release()
	if res.code != 130 || lastLine(res.stderr) != "nodkey: cancelled by SIGINT (exit 130)" {
		t.Errorf("exit code %d, stderr %q; want 130", res.code, res.stderr)
	}
	p := gb.waitAsked(t, 1)[0].Prompt
	gb.waitEvents(t, p.RequestID, "request decision:approve_window denied:cancelled")
	gb.approver.Auto("")
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
}
