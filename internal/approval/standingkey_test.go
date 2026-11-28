package approval_test

// Tests of standing grants for an SSH key (DESIGN.md section 8, "An SSH
// key"): each signature is one use and rotates the token. The fake clock
// starts at noon; the window is 03:00-05:00 each day.

import (
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/grantkey"
)

// keyStandEnv is standEnv with standing = true on the key web too.
func keyStandEnv(t *testing.T) *env {
	t.Helper()
	return standEnv(t, func(cfg *config.Broker) {
		k := cfg.Keys["web"]
		k.Rule.Standing = true
		cfg.Keys["web"] = k
	})
}

// keyStandReq asks for a standing grant of the key web, as deploy, on
// web-1, 2 uses in each window.
func keyStandReq(tok grantkey.Token) *approval.Request {
	r := standReq("laptop", tok)
	r.Key, r.RemoteUser, r.Hosts = "web", "deploy", []string{"web-1"}
	return r
}

// sign asks for one signature with the token tok.
func (e *env) sign(tok grantkey.Token, hostKey ssh.PublicKey, user string) *approval.Result {
	e.t.Helper()
	h := grantkey.Hash(tok)
	return e.core.UseStanding(approval.StandingRequest{
		Client: "laptop", Key: "web", HostKey: hostKey, RemoteUser: user, Token: &h,
	})
}

func TestStandingKeyGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := keyStandEnv(t)
		defer e.stop()
		e.grant(keyStandReq(newToken(t)), 1)
		p := e.fake.Asked()[0].Prompt
		if p.Kind != audit.KindStanding || p.Key != "web" || p.RemoteUser != "deploy" ||
			len(p.Hosts) != 1 || p.Hosts[0] != "web-1" || len(p.Secrets) != 0 || p.Uses != 2 {
			t.Errorf("the prompt is %+v", p)
		}
		list := e.core.ListStanding()
		if len(list) != 1 || list[0].Key != "web" || list[0].RemoteUser != "deploy" || len(list[0].Hosts) != 1 || len(list[0].Secrets) != 0 {
			t.Errorf("the list is %+v", list)
		}
	})
}

func TestStandingKeyRefused(t *testing.T) {
	tests := []struct {
		name string
		edit func(*approval.Request)
	}{
		{"a key without standing", func(r *approval.Request) { r.Key = "deploy" }},
		{"a host outside the key's hosts", func(r *approval.Request) { r.Hosts = []string{"web-3"} }},
		{"no hosts", func(r *approval.Request) { r.Hosts = nil }},
		{"a bad user", func(r *approval.Request) { r.RemoteUser = "-oProxy" }},
		{"an unknown key", func(r *approval.Request) { r.Key = "nope" }},
		{"another client", func(r *approval.Request) { r.Client = "build" }},
		{"no token hash", func(r *approval.Request) { r.TokenHash = [32]byte{} }},
		{"no windows", func(r *approval.Request) { r.Windows = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := keyStandEnv(t)
				defer e.stop()
				r := keyStandReq(newToken(t))
				tt.edit(r)
				e.refuses(r, audit.CauseNotAllowed)
			})
		})
	}
}

// TestStandingKeyUse: each signature takes one use and rotates the token.
// A login the grant does not cover is denied without an alarm; a third
// signature in a window of 2 uses ends the grant with an alarm.
func TestStandingKeyUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := keyStandEnv(t)
		defer e.stop()
		tok := newToken(t)
		e.grant(keyStandReq(tok), 1)
		e.pass(15*time.Hour + 30*time.Minute) // 03:30

		for _, c := range []struct {
			name    string
			hostKey ssh.PublicKey
			user    string
		}{{"another host", e.hosts.web2, "deploy"}, {"another user", e.hosts.web1, "root"}} {
			res := e.sign(tok, c.hostKey, c.user)
			checkDenied(t, res, audit.CauseNotAllowed)
			if _, ok := res.NewToken(); ok {
				t.Errorf("%s: a new token", c.name)
			}
		}
		if n := len(e.fake.Alarms()); n != 0 {
			t.Fatalf("%d alarms for logins outside the grant, want 0", n)
		}

		// Any host key of web-1 is covered.
		res := e.sign(tok, e.hosts.web1, "deploy")
		checkAllowed(t, res)
		next, ok := res.NewToken()
		if !ok || next == tok {
			t.Fatal("no new token after a signature")
		}
		if err := res.SendNotice(t.Context()); err != nil {
			t.Fatal(err)
		}
		res = e.sign(next, e.hosts.web1ecdsa, "deploy")
		checkAllowed(t, res)
		third, _ := res.NewToken()
		if err := res.SendNotice(t.Context()); err != nil {
			t.Fatal(err)
		}
		res = e.sign(third, e.hosts.web1, "deploy")
		checkDenied(t, res, audit.CauseNotAllowed)
		res.SendAlarm(t.Context())
		al := e.fake.Alarms()
		if len(al) != 1 || al[0].Cause != audit.AlarmOverUses || !al[0].Ended || al[0].Key != "web" || len(al[0].Secrets) != 0 {
			t.Fatalf("the alarms are %+v", al)
		}
		if len(e.core.ListStanding()) != 0 {
			t.Error("the grant lives after over_uses")
		}
	})
}

// TestStandingKeyOldToken: a signature with an old token ends the grant
// with an alarm that names the key.
func TestStandingKeyOldToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := keyStandEnv(t)
		defer e.stop()
		tok := newToken(t)
		e.grant(keyStandReq(tok), 1)
		e.pass(15*time.Hour + 30*time.Minute)
		res := e.sign(tok, e.hosts.web1, "deploy")
		checkAllowed(t, res)
		if err := res.SendNotice(t.Context()); err != nil {
			t.Fatal(err)
		}
		res = e.sign(tok, e.hosts.web1, "deploy")
		checkDenied(t, res, audit.CauseNotAllowed)
		res.SendAlarm(t.Context())
		al := e.fake.Alarms()
		if len(al) != 1 || al[0].Cause != audit.AlarmOldToken || !al[0].Ended || al[0].Key != "web" {
			t.Fatalf("the alarms are %+v", al)
		}
	})
}

// TestStandingKeyOutsideWindow: a valid token outside the windows is
// denied with an alarm, and the grant stays.
func TestStandingKeyOutsideWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := keyStandEnv(t)
		defer e.stop()
		tok := newToken(t)
		e.grant(keyStandReq(tok), 1)
		res := e.sign(tok, e.hosts.web1, "deploy")
		checkDenied(t, res, audit.CauseNotAllowed)
		res.SendAlarm(t.Context())
		al := e.fake.Alarms()
		if len(al) != 1 || al[0].Cause != audit.AlarmOutsideWindow || al[0].Ended || al[0].Key != "web" {
			t.Fatalf("the alarms are %+v", al)
		}
		if len(e.core.ListStanding()) != 1 {
			t.Error("the grant ended")
		}
	})
}
