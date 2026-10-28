package audit

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestEventNames: the events are the ones in DESIGN.md section 9.
func TestEventNames(t *testing.T) {
	want := []string{"broker_started", "request", "decision", "grant_used", "grant_ended", "secret_sent", "signed", "denied",
		"foreign_tap", "error", "log_recovered", "broker_stopped"}
	var got []string
	for _, ev := range append(sampleEvents(), logRecovered{}, GrantEnded{}) {
		if name := ev.eventName(); !slices.Contains(got, name) {
			got = append(got, name)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("events = %q, want %q", got, want)
	}
}

// TestEventFields: the fields of an event never take the place of seq,
// time, event or prev, and they come back as they went in.
func TestEventFields(t *testing.T) {
	for _, ev := range sampleEvents() {
		name, body, err := encodeEvent(ev)
		if err != nil {
			t.Fatalf("encodeEvent(%T): %v", ev, err)
		}
		if !eventPattern.MatchString(name) {
			t.Errorf("event name %q does not match %v", name, eventPattern)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, key := range []string{"seq", "time", "event", "prev", "torn_length", "torn_sha256"} {
			if _, ok := fields[key]; ok {
				t.Errorf("%s has a field %q", name, key)
			}
		}
		back := reflect.New(reflect.TypeOf(ev))
		if err := json.Unmarshal(body, back.Interface()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := back.Elem().Interface(); !reflect.DeepEqual(got, ev) {
			t.Errorf("%s came back as %+v, want %+v", name, got, ev)
		}
	}
}

// embedsAnEvent has the Event methods of SecretSent, and a field of its
// own that must never reach the log.
type embedsAnEvent struct {
	SecretSent
	Values map[string]string
}

func TestEncodeEventRefusesBadFields(t *testing.T) {
	edit := func(f func(s *Subject)) Subject {
		s := loginSubject()
		f(&s)
		return s
	}
	secrets := func(f func(s *Subject)) Subject {
		s := secretsSubject()
		f(&s)
		return s
	}
	tests := []struct {
		name string
		ev   Event
	}{
		{"nil", nil},
		{"pointer", &Signed{Subject: loginSubject()}},
		{"nil pointer", (*Denied)(nil)},
		{"a type that embeds an event", embedsAnEvent{SecretSent: SecretSent{Subject: secretsSubject()},
			Values: map[string]string{"GH_TOKEN": canary}}},
		{"no request ID", Signed{Subject: edit(func(s *Subject) { s.RequestID = "" })}},
		{"request ID too short", Signed{Subject: edit(func(s *Subject) { s.RequestID = s.RequestID[1:] })}},
		{"request ID with text", Signed{Subject: edit(func(s *Subject) { s.RequestID = "CANARY made-up text 22" })}},
		{"no client", Signed{Subject: edit(func(s *Subject) { s.Client = "" })}},
		{"client that is not a name", Signed{Subject: edit(func(s *Subject) { s.Client = "laptop " + canary })}},
		{"no kind", Signed{Subject: edit(func(s *Subject) { s.Kind = "" })}},
		{"unknown kind", Signed{Subject: edit(func(s *Subject) { s.Kind = "other" })}},
		{"secret names in an SSH login", Signed{Subject: edit(func(s *Subject) { s.Secrets = []string{"github-token"} })}},
		{"two hosts in an SSH login", Signed{Subject: edit(func(s *Subject) { s.Hosts = []string{"web-1", "web-2"} })}},
		{"host key in an SSH grant", Request{Subject: func() Subject { s := grantSubject(); s.HostKey = testHostKey(); return s }()}},
		{"key in a secrets request", SecretSent{Subject: secrets(func(s *Subject) { s.Key = "deploy" })}},
		{"host in a secrets request", SecretSent{Subject: secrets(func(s *Subject) { s.Hosts = []string{"web-1"} })}},
		{"secret that is not a name", SecretSent{Subject: secrets(func(s *Subject) { s.Secrets = []string{canary + "="} })}},
		{"key that is not a name", Signed{Subject: edit(func(s *Subject) { s.Key = "-" + canary })}},
		{"host that is not a name", Signed{Subject: edit(func(s *Subject) { s.Hosts = []string{"web-1;" + canary} })}},
		{"host key that is not a fingerprint", Signed{Subject: edit(func(s *Subject) { s.HostKey = "SHA256:" + canary })}},
		{"remote user that breaks the rule", Signed{Subject: edit(func(s *Subject) { s.RemoteUser = "-" + canary })}},
		{"version that is not a version", BrokerStarted{Version: "1.0 " + canary}},
		{"no version", BrokerStarted{}},
		{"decision without a user", Decision{Subject: loginSubject(), Answer: AnswerApproveOnce}},
		{"unknown answer", Decision{Subject: loginSubject(), UserID: 1, Answer: canary}},
		{"window without minutes", Decision{Subject: loginSubject(), UserID: 1, Answer: AnswerApproveWindow}},
		{"window too long", Decision{Subject: loginSubject(), UserID: 1, Answer: AnswerApproveWindow, WindowMinutes: 481}},
		{"minutes for once", Decision{Subject: loginSubject(), UserID: 1, Answer: AnswerApproveOnce, WindowMinutes: 15}},
		{"unknown via", GrantUsed{Subject: loginSubject(), Via: canary}},
		{"unknown cause", Denied{Subject: loginSubject(), Cause: canary}},
		{"unknown code", Failure{Code: canary}},
		{"failure with half a subject", Failure{Subject: Subject{Client: "laptop"}, Code: CodeSignFailed}},
		{"tap data too long", ForeignTap{UserID: 1, Data: strings.Repeat("d", 65)}},
		{"unknown tap cause", ForeignTap{UserID: 1, Cause: canary}},
		{"torn length 0", logRecovered{TornSHA256: zeros}},
		{"torn hash in capitals", logRecovered{TornLength: 1, TornSHA256: strings.Repeat("A", 64)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := encodeEvent(tt.ev)
			if err == nil {
				t.Fatal("no error")
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Errorf("the error shows the value: %v", err)
			}
		})
	}
}

// TestEncodeEventAllowsWhatABrokerKnows: a request that the broker denied
// may lack names that failed its checks.
func TestEncodeEventAllowsWhatABrokerKnows(t *testing.T) {
	for _, ev := range []Event{
		Denied{Subject: Subject{RequestID: testRequestID(4), Client: "laptop", Kind: KindSecrets}, Cause: CauseNotAllowed},
		Denied{Subject: Subject{RequestID: testRequestID(5), Client: "laptop", Kind: KindSSHLogin, HostKey: testHostKey()},
			Cause: CauseNotAllowed},
		Request{Subject: Subject{RequestID: testRequestID(6), Client: "laptop", Kind: KindSSHGrant, Key: "deploy"}},
		Decision{Subject: loginSubject(), UserID: 1, Answer: AnswerApproveWindow, WindowMinutes: 480},
		ForeignTap{},
		Failure{Code: CodeApproverFailed},
		BrokerStarted{Version: "v1.2.0-rc.1+abc"},
	} {
		if _, _, err := encodeEvent(ev); err != nil {
			t.Errorf("encodeEvent(%+v): %v", ev, err)
		}
	}
}

// TestPreapproveEvents: the fields of a scheduled grant are checked, and
// only a preapprove request may hold uses and a time span.
func TestPreapproveEvents(t *testing.T) {
	bad := func(name string, ev Event) {
		t.Helper()
		if _, _, err := encodeEvent(ev); err == nil {
			t.Errorf("%s: the event was accepted", name)
		}
	}
	ok := preapproveSubject()
	if _, _, err := encodeEvent(GrantEnded{Subject: ok, Cause: EndEnded, UsesLeft: 1}); err != nil {
		t.Fatalf("a valid grant_ended: %v", err)
	}
	bad("unknown cause", GrantEnded{Subject: ok, Cause: "gone"})
	bad("no cause", GrantEnded{Subject: ok})
	bad("negative uses left", GrantEnded{Subject: ok, Cause: EndEnded, UsesLeft: -1})
	noID := ok
	noID.GrantID = ""
	bad("no grant_id", GrantEnded{Subject: noID, Cause: EndEnded})
	other := secretsSubject()
	other.GrantID = testRequestID(5)
	bad("grant_ended of another kind", GrantEnded{Subject: other, Cause: EndEnded})
	uses := secretsSubject()
	uses.Uses = 2
	bad("uses in a secrets request", Request{Subject: uses})
	span := secretsSubject()
	span.NotAfter = "2026-10-28T02:00:00Z"
	bad("a time span in a secrets request", Request{Subject: span})
	badTime := ok
	badTime.NotBefore = "tomorrow"
	bad("a time that is not RFC 3339", Request{Subject: badTime})
	badID := ok
	badID.GrantID = "short"
	bad("a grant_id that is not an ID", Request{Subject: badID})
	both := ok
	both.Key = "deploy"
	bad("secrets and a key", Request{Subject: both})
	bad("via that is not known", GrantUsed{Subject: secretsSubject(), Via: "scheduled2"})
}
