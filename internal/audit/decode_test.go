package audit

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// allEvents returns valid events of every type, with many fields set.
func allEvents() []Event {
	standing := preapproveSubject()
	standing.Kind = KindStanding
	standing.Windows = []string{"daily 03:00-05:00", "mon,thu 10:30-11:00"}
	project := secretsSubject()
	project.Secrets = []string{"github-token", "infra/db-password"}
	project.ProjectSecrets = []ProjectSecret{{Name: "infra/db-password", ID: "0a1b2c3d-0000-4000-8000-00000000abcd"}}
	evs := append(sampleEvents(),
		GrantsReset{Cause: ResetChain},
		GrantsReset{Cause: ResetHead},
		GrantsReset{Cause: ResetClock},
		GrantsReset{Cause: ResetFormat},
		ConfigReloaded{ConfigSHA256: strings.Repeat("ab", 32), GrantsEnded: 2},
		Request{Subject: standing, Message: "<b>standing</b>"},
		Decision{Subject: standing, Channel: "ntfy:ans-1", Answer: AnswerApproveOnce, MessageID: "Ab12Cd34Ef56"},
		Decision{Subject: standing, UserID: 1, Answer: AnswerApproveOnce, MessageID: "-1001234567890:42", TokenHash: strings.Repeat("01", 32)},
		Decision{Subject: standing, UserID: 1, Answer: AnswerRenew, RenewOf: testRequestID(9)},
		GrantUsed{Subject: standing, Via: ViaStanding, NewTokenHash: strings.Repeat("cd", 32)},
		GrantUsed{Subject: preapproveSubject(), Via: ViaScheduled},
		GrantEnded{Subject: preapproveSubject(), Cause: EndUsedUp},
		GrantEnded{Subject: standing, Cause: EndRevoked, UsesLeft: 1},
		GrantAlarm{Subject: standing, Cause: AlarmMissedWindow},
		SecretSent{Subject: project},
		logRecovered{TornLength: 10, TornSHA256: strings.Repeat("ef", 32)},
		LoginList{Client: "laptop", Logins: "web", Origin: "https://example.com:8443", Count: 2},
		LoginList{Client: "laptop", Cause: ListLimited},
		LoginTOTP{Client: "laptop", Logins: "web", Item: testItem, Origin: "https://example.com", Allowed: true},
		LoginTOTP{Client: "laptop", Cause: TOTPBadItem},
	)
	return evs
}

// TestDecodeEventRoundTrip: every event that Append writes decodes to the
// same event.
func TestDecodeEventRoundTrip(t *testing.T) {
	seen := map[string]bool{}
	for _, ev := range allEvents() {
		name, body, err := encodeEvent(ev)
		if err != nil {
			t.Fatalf("encodeEvent(%T): %v", ev, err)
		}
		seen[name] = true
		got, err := DecodeEvent(name, body)
		if err != nil {
			t.Errorf("DecodeEvent(%s, %s): %v", name, body, err)
			continue
		}
		if !reflect.DeepEqual(got, ev) {
			t.Errorf("%s came back as %#v, want %#v", name, got, ev)
		}
	}
	for name := range decoders {
		if !seen[name] {
			t.Errorf("no round trip test for the event %s", name)
		}
	}
}

// TestDecodersMatchTheirNames: each decoder makes an event of its name, so
// an entry can never decode as another event.
func TestDecodersMatchTheirNames(t *testing.T) {
	for name := range decoders {
		_, body, err := encodeEvent(eventOf(t, name))
		if err != nil {
			t.Fatal(err)
		}
		ev, err := DecodeEvent(name, body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ev.eventName() != name {
			t.Errorf("the decoder of %s makes %s", name, ev.eventName())
		}
	}
}

func eventOf(t *testing.T, name string) Event {
	t.Helper()
	for _, ev := range allEvents() {
		if ev.eventName() == name {
			return ev
		}
	}
	t.Fatalf("no sample event %s", name)
	return nil
}

// TestDecodeEventRefuses: an unknown event, an unknown field, a field of
// the wrong type, a bad value, and every way encoding/json is looser than
// Append are errors. No error shows a value or a field name of the body.
func TestDecodeEventRefuses(t *testing.T) {
	_, decision, err := encodeEvent(Decision{Subject: secretsSubject(), UserID: 123456789, Answer: AnswerApproveOnce})
	if err != nil {
		t.Fatal(err)
	}
	// with returns the decision body with extra fields at its end.
	with := func(extra string) string {
		return string(bytes.TrimSuffix(decision, []byte("}"))) + "," + extra + "}"
	}
	project := `{"request_id":"` + testRequestID(1) + `","client":"laptop","kind":"secrets","secrets":["infra/db"],"project_secrets":[{"name":"infra/db","id":"0a1b2c3d-0000-4000-8000-00000000abcd"%s}]}`
	tests := []struct {
		name  string
		event string
		body  string
	}{
		{"unknown event", "made_up_CANARY", `{}`},
		{"empty event name", "", `{}`},
		{"event name in another case", "Decision", string(decision)},
		{"unknown field", "decision", with(`"CANARY_field":1`)},
		{"unknown field in an empty event", "broker_stopped", `{"CANARY":1}`},
		{"a header field in the body", "decision", with(`"seq":1`)},
		{"wrong type", "decision", strings.Replace(string(decision), `"user_id":123456789`, `"user_id":"CANARY"`, 1)},
		{"a list where a string is", "grants_reset", `{"cause":["chain"]}`},
		{"bad value", "decision", strings.Replace(string(decision), `"approve_once"`, `"CANARY"`, 1)},
		{"bad reset cause", "grants_reset", `{"cause":"CANARY"}`},
		{"no reset cause", "grants_reset", `{}`},
		{"missing field that Append writes", "decision", strings.Replace(string(decision), `"user_id":123456789,`, ``, 1)},
		{"a zero value that Append leaves out", "decision", with(`"window_minutes":0`)},
		{"a null", "decision", with(`"renew_of":null`)},
		{"a null list", "decision", with(`"hosts":null`)},
		{"a field in another case", "grants_reset", `{"Cause":"chain"}`},
		{"a field with a long s", "denied", `{"requeſt_id":"` + testRequestID(1) + `","client":"laptop","kind":"secrets","cause":"approver"}`},
		{"a field twice", "grants_reset", `{"cause":"chain","cause":"head"}`},
		{"a field twice, the last one good", "grants_reset", `{"cause":"CANARY","cause":"head"}`},
		{"a nested field twice", "secret_sent", strings.Replace(project, "%s", `,"id":"0a1b2c3d-0000-4000-8000-00000000abcd"`, 1)},
		{"a nested unknown field", "secret_sent", strings.Replace(project, "%s", `,"CANARY":1`, 1)},
		{"a number in another form", "decision", strings.Replace(string(decision), `123456789`, `1.23456789e8`, 1)},
		{"more after the object", "grants_reset", `{"cause":"chain"}{}`},
		{"not an object", "grants_reset", `["chain"]`},
		{"not JSON", "grants_reset", `{"cause":"chain"`},
		{"empty body", "broker_stopped", ``},
		{"null body", "broker_stopped", `null`},
		{"too deep", "broker_started", `{"version":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`},
		{"too long", "request", `{"message":"` + strings.Repeat("a", MaxLineSize) + `"}`},
		{"an escaped key twice", "grants_reset", `{"cause":"chain","c\u0061use":"head"}`},
		{"event that fails the checks of Append", "grant_used", `{"request_id":"` + testRequestID(1) + `","client":"laptop","kind":"secrets","via":"standing"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := DecodeEvent(tt.event, []byte(tt.body))
			if err == nil {
				t.Fatalf("no error; got %#v", ev)
			}
			if ev != nil {
				t.Errorf("an event with the error: %#v", ev)
			}
			if strings.Contains(strings.ToUpper(err.Error()), "CANARY") {
				t.Errorf("the error shows text of the body: %v", err)
			}
			if !strings.Contains(err.Error(), "DESIGN.md section 8") {
				t.Errorf("the error does not say where to read on: %v", err)
			}
		})
	}
}

// TestDecodeEventSaysWhy: the checks that another check could hide give
// their own error.
func TestDecodeEventSaysWhy(t *testing.T) {
	for _, tt := range []struct{ event, body, want string }{
		{"broker_started", `{"version":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`, "too deep"},
		{"request", `{"message":"` + strings.Repeat("a", MaxLineSize) + `"}`, "too long"},
		{"grants_reset", `{"cause":"chain","c\u0061use":"chain"}`, "twice"},
		{"grants_reset", `{"Cause":"chain"}`, "not as Append writes them"},
		{"grants_reset", `{"cause":"chain"} 1`, "more data"},
	} {
		_, err := DecodeEvent(tt.event, []byte(tt.body))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("DecodeEvent(%s, %.40s): %v, want an error with %q", tt.event, tt.body, err, tt.want)
		}
	}
}

// TestEveryEventHasADecoder: each event name of this package has a
// decoder, so no entry that Append writes stops a rebuild.
func TestEveryEventHasADecoder(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "event.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, id := range spec.Names {
			if !strings.HasPrefix(id.Name, "event") || i >= len(spec.Values) {
				continue
			}
			lit, ok := spec.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			n++
			if _, ok := decoders[name]; !ok {
				t.Errorf("the event %s (%s) has no decoder", name, id.Name)
			}
		}
		return true
	})
	if n != len(decoders) {
		t.Errorf("%d event names, %d decoders", n, len(decoders))
	}
}

// TestForeignTapDataIsUTF8: data that is not UTF-8 is refused, because
// it would not decode the same.
func TestForeignTapDataIsUTF8(t *testing.T) {
	if _, _, err := encodeEvent(ForeignTap{UserID: 1, Data: strings.Repeat("\xff", 64)}); err == nil {
		t.Error("data that is not UTF-8 was accepted")
	}
}

// TestDecisionMessageAndTokenHash: message_id names a message, and
// token_hash is only on an approved standing request, as 64 hex digits.
func TestDecisionMessageAndTokenHash(t *testing.T) {
	standing := preapproveSubject()
	standing.Kind = KindStanding
	standing.Windows = []string{"daily 03:00-05:00"}
	h := strings.Repeat("ab", 32)
	for _, ev := range []Decision{
		{Subject: standing, UserID: 1, Answer: AnswerApproveOnce, MessageID: "987654321:42", TokenHash: h},
		{Subject: standing, UserID: 1, Answer: AnswerDeny, MessageID: "987654321:42"},
		{Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce, MessageID: "message-1"},
		{Subject: standing, UserID: 1, Answer: AnswerRenew, RenewOf: testRequestID(9), MessageID: "987654321:43"},
	} {
		if _, _, err := encodeEvent(ev); err != nil {
			t.Errorf("encodeEvent(%+v): %v", ev, err)
		}
	}
	for name, ev := range map[string]Decision{
		"a message with a space":       {Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce, MessageID: "987 42"},
		"a message with a newline":     {Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce, MessageID: "1:2\n" + canary},
		"a message too long":           {Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce, MessageID: strings.Repeat("1", 65)},
		"a token hash on secrets":      {Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce, TokenHash: h},
		"a token hash on a scheduled":  {Subject: preapproveSubject(), UserID: 1, Answer: AnswerApproveOnce, TokenHash: h},
		"a token hash on a deny":       {Subject: standing, UserID: 1, Answer: AnswerDeny, TokenHash: h},
		"a token hash on a renew":      {Subject: standing, UserID: 1, Answer: AnswerRenew, RenewOf: testRequestID(9), TokenHash: h},
		"a short token hash":           {Subject: standing, UserID: 1, Answer: AnswerApproveOnce, TokenHash: "ab"},
		"a token hash in capitals":     {Subject: standing, UserID: 1, Answer: AnswerApproveOnce, TokenHash: strings.ToUpper(h)},
		"a token in place of the hash": {Subject: standing, UserID: 1, Answer: AnswerApproveOnce, TokenHash: canary},
	} {
		_, _, err := encodeEvent(ev)
		if err == nil {
			t.Errorf("%s: the event was accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "CANARY") {
			t.Errorf("%s: the error shows the value: %v", name, err)
		}
	}
}

// TestUniqueKeysAllowsNesting: the same key in two objects is fine.
func TestUniqueKeysAllowsNesting(t *testing.T) {
	for _, body := range []string{`{}`, `{"a":[{"a":1},{"a":2}],"b":{"a":[]},"c":[[],[1,{"c":1}]]}`} {
		if err := uniqueKeys([]byte(body)); err != nil {
			t.Errorf("uniqueKeys(%s): %v", body, err)
		}
	}
	for _, body := range []string{`{"a":1,"a":1}`, `{"a":[{"b":1,"b":2}]}`, `[{"x":{},"x":{}}]`} {
		if err := uniqueKeys([]byte(body)); err == nil {
			t.Errorf("uniqueKeys(%s): no error", body)
		}
	}
}
