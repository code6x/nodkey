package approval_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// TestEventsOfEachEnd checks the audit entries of each way a request
// ends, with their fields (DESIGN.md section 9).
func TestEventsOfEachEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()

		// Approve N min: a request entry with the message, then the
		// decision with the user and the minutes.
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.tap(1, audit.AnswerApproveWindow)
		r := mustResult(t, ch)
		evs := r.Events()
		want := []audit.Event{
			audit.Request{Subject: r.Subject, Message: e.fake.Asked()[0].Text},
			audit.Decision{Subject: r.Subject, UserID: approverID, Answer: audit.AnswerApproveWindow, WindowMinutes: 15},
		}
		if !reflect.DeepEqual(evs, want) {
			t.Errorf("events\n%#v\nwant\n%#v", evs, want)
		}
		if r.Subject.RequestID != r.RequestID || r.Subject.Client != "laptop" || r.Subject.Kind != audit.KindSecrets {
			t.Errorf("subject %+v", r.Subject)
		}

		// The JSON form has the fields of DESIGN.md section 9.
		data, err := json.Marshal(evs[1])
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"request_id", "client", "kind", "secrets", "command", "reason", "user_id", "answer", "window_minutes"} {
			if _, ok := fields[name]; !ok {
				t.Errorf("the decision entry has no %q: %s", name, data)
			}
		}

		// An SSH grant names its hosts, and no single host key.
		ch = e.decide(grantReq("laptop", "web", "deploy", 10*time.Minute, "web-2", "web-1"))
		mustWait(t, ch)
		e.tap(2, audit.AnswerDeny)
		r = mustResult(t, ch)
		checkEvents(t, r, "request", "decision:deny", "denied:approver")
		s := r.Subject
		if s.Kind != audit.KindSSHGrant || s.Key != "web" || !reflect.DeepEqual(s.Hosts, []string{"web-2", "web-1"}) ||
			s.HostKey != "" || s.RemoteUser != "deploy" || len(s.Secrets) != 0 || s.Reason == "" {
			t.Errorf("subject of an SSH grant %+v", s)
		}
	})
}

// TestEventsOfGrantAndNever checks a request that a grant and a "never
// ask" rule allow together: one grant_used entry for each, with the
// secrets each one covered.
func TestEventsOfGrantAndNever(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, func(cfg *config.Broker) {
			s := cfg.Secrets["npm-token"]
			s.Rule = config.Rule{Ask: config.AskNever, Notify: true}
			cfg.Secrets["npm-token"] = s
		})
		defer e.stop()
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		r := e.now(secretsReq("laptop", "npm-token", "github-token"))
		checkAllowed(t, r)
		checkEvents(t, r, "request", "grant_used:grant", "grant_used:never_rule")
		evs := r.Events()
		if got := evs[1].(audit.GrantUsed).Secrets; !reflect.DeepEqual(got, []string{"github-token"}) {
			t.Errorf("the grant covered %v, want github-token", got)
		}
		if got := evs[2].(audit.GrantUsed).Secrets; !reflect.DeepEqual(got, []string{"npm-token"}) {
			t.Errorf("the never rule covered %v, want npm-token", got)
		}
		if got := evs[0].(audit.Request).Secrets; !reflect.DeepEqual(got, []string{"npm-token", "github-token"}) {
			t.Errorf("the request entry names %v, want both secrets", got)
		}
		if len(e.fake.Notices()) != 1 {
			t.Errorf("%d notices, want 1", len(e.fake.Notices()))
		}
	})
}

// TestEventsWhenNoIDCouldBeMade checks the result when the random source
// fails: a deny, with no request ID.
func TestEventsWhenNoIDCouldBeMade(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.core.SetRandom(&chunks{})
		r := e.core.Decide(context.Background(), secretsReq("laptop", "github-token"))
		checkDenied(t, r, audit.CauseError)
		checkEvents(t, r, "request", "denied:error")
	})
}

// TestResultIsACopy checks that the result does not share slices with the
// request, so the caller cannot change what the core keeps.
func TestResultIsACopy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		req := secretsReq("laptop", "github-token", "npm-token")
		ch := e.decide(req)
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		p.Secrets[0] = "changed"
		req.Secrets[0] = "changed"
		e.tap(1, audit.AnswerApproveWindow)
		r := mustResult(t, ch)
		if !reflect.DeepEqual(r.Subject.Secrets, []string{"github-token", "npm-token"}) {
			t.Errorf("the subject names %v", r.Subject.Secrets)
		}
		r.Subject.Secrets[0] = "changed"
		r.StartGrants()
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		checkEvents(t, e.now(secretsReq("laptop", "github-token")), "request", "grant_used:grant")
	})
}
