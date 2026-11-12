package audit

import (
	"strings"
	"testing"
)

const testItem = "11111111-1111-1111-1111-111111111111"

func webLoginSubject() Subject {
	return Subject{
		RequestID: testRequestID(1), Client: "laptop", Kind: KindWebLogin,
		Logins: "web", Item: testItem, Origin: "https://example.com",
	}
}

func TestWebLoginSubjectValidate(t *testing.T) {
	pre := webLoginSubject()
	pre.Kind, pre.Uses = KindPreapprove, 1
	good := []Subject{webLoginSubject(), pre}
	for i, s := range good {
		if _, _, err := encodeEvent(Request{Subject: s}); err != nil {
			t.Errorf("good subject %d: %v", i, err)
		}
	}
	edit := func(base Subject, f func(s *Subject)) Subject { f(&base); return base }
	bad := map[string]Subject{
		"no logins":               edit(webLoginSubject(), func(s *Subject) { s.Logins = "" }),
		"no item":                 edit(webLoginSubject(), func(s *Subject) { s.Item = "" }),
		"no origin":               edit(webLoginSubject(), func(s *Subject) { s.Origin = "" }),
		"http origin":             edit(webLoginSubject(), func(s *Subject) { s.Origin = "http://example.com" }),
		"origin with path":        edit(webLoginSubject(), func(s *Subject) { s.Origin = "https://example.com/a" }),
		"origin with user":        edit(webLoginSubject(), func(s *Subject) { s.Origin = "https://u:p@example.com" }),
		"item not a UUID":         edit(webLoginSubject(), func(s *Subject) { s.Item = "CANARY" }),
		"secrets":                 edit(webLoginSubject(), func(s *Subject) { s.Secrets = []string{"a"} }),
		"key":                     edit(webLoginSubject(), func(s *Subject) { s.Key = "k" }),
		"hosts":                   edit(webLoginSubject(), func(s *Subject) { s.Hosts = []string{"h"} }),
		"host key":                edit(webLoginSubject(), func(s *Subject) { s.HostKey = testHostKey() }),
		"remote user":             edit(webLoginSubject(), func(s *Subject) { s.RemoteUser = "root" }),
		"login in secrets":        edit(secretsSubject(), func(s *Subject) { s.Origin = "https://example.com" }),
		"item in ssh login":       edit(loginSubject(), func(s *Subject) { s.Item = testItem }),
		"preapprove with secrets": edit(pre, func(s *Subject) { s.Secrets = []string{"a"} }),
		"preapprove with key":     edit(pre, func(s *Subject) { s.Key = "k" }),
		"preapprove no origin":    edit(pre, func(s *Subject) { s.Origin = "" }),
	}
	for name, s := range bad {
		t.Run(name, func(t *testing.T) {
			_, _, err := encodeEvent(Request{Subject: s})
			if err == nil {
				t.Fatal("no error")
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Errorf("the error shows the value: %v", err)
			}
		})
	}
}

func TestLoginEventsValidate(t *testing.T) {
	good := []Event{
		LoginList{Client: "laptop", Logins: "web", Origin: "https://example.com:8443", Count: 2},
		LoginTOTP{Client: "laptop", Logins: "web", Item: testItem, Origin: "https://example.com", Allowed: true},
		LoginTOTP{Client: "laptop", Logins: "web", Item: testItem, Origin: "https://example.com", Cause: TOTPNoGrant},
		LoginTOTP{Client: "laptop", Cause: TOTPBadItem},
	}
	for i, ev := range good {
		if _, _, err := encodeEvent(ev); err != nil {
			t.Errorf("good event %d: %v", i, err)
		}
	}
	bad := []Event{
		LoginList{Client: "laptop", Logins: "web", Origin: "http://example.com"},
		LoginList{Client: "", Logins: "web", Origin: "https://example.com"},
		LoginList{Client: "laptop", Logins: "web", Origin: "https://example.com", Count: -1},
		LoginTOTP{Client: "laptop", Allowed: true, Cause: TOTPNoSeed},
		LoginTOTP{Client: "laptop"},
		LoginTOTP{Client: "laptop", Cause: "CANARY"},
		LoginTOTP{Client: "laptop", Item: "CANARY", Cause: TOTPNoSeed},
	}
	for i, ev := range bad {
		if _, _, err := encodeEvent(ev); err == nil {
			t.Errorf("bad event %d: no error", i)
		}
	}
}
