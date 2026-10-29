package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/grantkey"
)

// useEnv is an environment with one standing grant of laptop for
// github-token, daily 11:00-13:00 (the clock is at 12:00), 2 uses in each
// window. tok is its token.
func useEnv(t *testing.T, names ...string) (*env, string, string) {
	t.Helper()
	e := newEnv(t, envOptions{config: standingOn})
	if len(names) == 0 {
		names = []string{"github-token"}
	}
	r := standReq(names...)
	r.Windows = []api.Window{{Kind: api.WindowDaily, From: "11:00", To: "13:00"}}
	ans := e.preapprove(e.httpClient("laptop"), r, 1)
	return e, ans.GrantToken, ans.ID
}

// useToken sends a request for github-token with the header, as client.
func (e *env) useToken(client, token string, names ...string) (*result, *api.SecretsAnswer) {
	e.t.Helper()
	req := secretsRequest("GH_TOKEN", "github-token")
	if client == "ci" {
		req = secretsRequest("GH_TOKEN", "backup-token")
	}
	for i, n := range names {
		req.Secrets = append(req.Secrets, api.SecretRef{Var: "V" + string(rune('A'+i)), Name: n})
	}
	data, _ := json.Marshal(req)
	hr, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+e.addr+api.PathSecrets, bytes.NewReader(data))
	if err != nil {
		e.t.Fatal(err)
	}
	hr.Header.Set("Content-Type", api.ContentType)
	hr.Header.Set(api.GrantTokenHeader, token)
	resp, err := e.httpClient(client).Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	res := &result{status: resp.StatusCode}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	res.body = buf.Bytes()
	if resp.StatusCode != http.StatusOK {
		return res, nil
	}
	ans, err := api.ReadAnswer[api.SecretsAnswer](bytes.NewReader(res.body))
	if err != nil {
		e.t.Fatalf("the answer: %v", err)
	}
	return res, ans
}

func hashHex(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// noToken fails if the token is in any text the broker wrote or sent.
func (e *env) noToken(tokens ...string) {
	e.t.Helper()
	alarms := ""
	for _, a := range e.approver.Alarms() {
		alarms += a.Client + a.GrantID + string(a.Cause) + strings.Join(a.Secrets, ",")
	}
	for name, text := range map[string]string{
		"the audit log": encodeEvents(e.t, e.audit.all()), "the approver": e.approverTexts() + alarms,
		"the logs": e.logs.String(), "the notices": strings.Join(e.notices.wentOut(), "\n"),
	} {
		for _, tok := range tokens {
			if strings.Contains(text, tok) {
				e.t.Errorf("a token is in %s", name)
			}
		}
	}
}

func (e *env) alarmEntries() (out []audit.GrantAlarm) {
	for _, ev := range e.audit.all() {
		if a, ok := ev.(audit.GrantAlarm); ok {
			out = append(out, a)
		}
	}
	return out
}

// TestStandingUseRotates: the way of a good use, then the second use in the
// window, then the use over the limit that ends the grant.
func TestStandingUseRotates(t *testing.T) {
	e, tok0, id := useEnv(t)
	noticesBefore := len(e.approver.Notices())
	res, ans := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusOK)
	tok1 := ans.GrantToken
	if _, err := grantkey.Parse(tok1); err != nil || tok1 == tok0 || len(ans.Secrets) != 1 {
		t.Fatalf("the answer: token ok=%v, secrets %d", err == nil, len(ans.Secrets))
	}
	var used *audit.GrantUsed
	for _, ev := range e.audit.all() {
		if u, ok := ev.(audit.GrantUsed); ok {
			used = &u
		}
	}
	if used == nil || used.Via != audit.ViaStanding || used.GrantID != id || used.NewTokenHash != hashHex(tok1) {
		t.Fatalf("grant_used is %+v", used)
	}
	ns := e.approver.Notices()
	if len(ns) != noticesBefore+1 || ns[len(ns)-1].Via != audit.ViaStanding {
		t.Errorf("notices: %+v", ns)
	}
	if len(e.approver.Asked()) != 1 {
		t.Error("the person was asked for a use")
	}
	// The second use in the window, with the new token.
	res, ans = e.useToken("laptop", tok1)
	mustStatus(t, res, http.StatusOK)
	tok2 := ans.GrantToken
	// The third is over the 2 uses: a deny, an alarm, the end.
	res, _ = e.useToken("laptop", tok2)
	mustStatus(t, res, http.StatusForbidden)
	al := e.alarmEntries()
	if len(al) != 1 || al[0].Cause != audit.AlarmOverUses || al[0].GrantID != id {
		t.Fatalf("alarms: %+v", al)
	}
	if as := e.approver.Alarms(); len(as) != 1 || !as[0].Ended || as[0].Cause != audit.AlarmOverUses {
		t.Errorf("the alarm: %+v", as)
	}
	var ended bool
	for _, ev := range e.audit.all() {
		if g, ok := ev.(audit.GrantEnded); ok && g.GrantID == id && g.Cause == audit.EndAlarm {
			ended = true
		}
	}
	if !ended {
		t.Error("no grant_ended:alarm")
	}
	// The grant is gone: the token is now unknown.
	res, _ = e.useToken("laptop", tok2)
	mustStatus(t, res, http.StatusForbidden)
	if len(e.approver.Asked()) != 1 {
		t.Error("the person was asked after a token was sent")
	}
	e.noToken(tok0, tok1, tok2)
}

// TestStandingOldToken: an old token is denied and ends the grant.
func TestStandingOldToken(t *testing.T) {
	e, tok0, id := useEnv(t)
	_, ans := e.useToken("laptop", tok0)
	tok1 := ans.GrantToken
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusForbidden)
	al := e.alarmEntries()
	if len(al) != 1 || al[0].Cause != audit.AlarmOldToken || al[0].GrantID != id {
		t.Fatalf("alarms: %+v", al)
	}
	if as := e.approver.Alarms(); len(as) != 1 || !as[0].Ended {
		t.Errorf("the alarm: %+v", as)
	}
	// The new token does not work any more: the grant ended.
	res, _ = e.useToken("laptop", tok1)
	mustStatus(t, res, http.StatusForbidden)
	if len(e.approver.Asked()) != 1 {
		t.Error("the person was asked")
	}
	e.noToken(tok0, tok1)
}

// TestStandingOutsideWindow: a denied use, one alarm in the window, the
// grant stays and works in the next window.
func TestStandingOutsideWindow(t *testing.T) {
	e, tok0, id := useEnv(t)
	e.clock.Advance(3 * time.Hour) // 15:00
	for range 2 {
		res, _ := e.useToken("laptop", tok0)
		mustStatus(t, res, http.StatusForbidden)
	}
	al := e.alarmEntries()
	if len(al) != 1 || al[0].Cause != audit.AlarmOutsideWindow || al[0].GrantID != id {
		t.Fatalf("alarms: %+v", al)
	}
	if as := e.approver.Alarms(); len(as) != 1 || as[0].Ended {
		t.Errorf("the alarms: %+v", as)
	}
	e.clock.Advance(20 * time.Hour) // 11:00 the next day
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusOK)
	for _, ev := range e.audit.all() {
		if g, ok := ev.(audit.GrantEnded); ok && g.GrantID == id {
			t.Error("the grant ended")
		}
	}
}

// TestStandingUnknownToken: no grant, an alarm with sound, rate limited;
// a bad format is the same.
func TestStandingUnknownToken(t *testing.T) {
	e, tok0, _ := useEnv(t)
	other, err := grantkey.New()
	if err != nil {
		t.Fatal(err)
	}
	res, _ := e.useToken("laptop", other.Reveal())
	mustStatus(t, res, http.StatusForbidden)
	res, _ = e.useToken("laptop", "not a token")
	mustStatus(t, res, http.StatusForbidden)
	// A token that no grant has, sent by ci.
	res, _ = e.useToken("ci", other.Reveal())
	mustStatus(t, res, http.StatusForbidden)
	al := e.alarmEntries()
	if len(al) != 3 || al[2].Cause != audit.AlarmUnknownToken || al[2].Client != "ci" || al[0].Cause != audit.AlarmUnknownToken || al[0].GrantID != "" {
		t.Fatalf("alarms: %+v", al)
	}
	if len(e.approver.Alarms()) != 3 {
		t.Errorf("the alarms: %+v", e.approver.Alarms())
	}
	// Laptop's grant is not touched.
	res, _ = e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusOK)
	// More than 3 a minute for one client: no more alarms.
	for range 6 {
		_, _ = e.useToken("laptop", other.Reveal())
	}
	if n := len(e.approver.Alarms()); n > 1+MaxUnknownPerMinuteForTest {
		t.Errorf("%d alarms", n)
	}
	e.noToken(tok0, other.Reveal())
}

// MaxUnknownPerMinuteForTest is the limit of the core.
const MaxUnknownPerMinuteForTest = 3

// TestStandingNotAllSecrets: a token for a grant that does not cover the
// whole request is denied; it takes no use and raises no alarm.
func TestStandingNotAllSecrets(t *testing.T) {
	e, tok0, _ := useEnv(t)
	res, _ := e.useToken("laptop", tok0, "npm-token")
	mustStatus(t, res, http.StatusForbidden)
	if len(e.alarmEntries()) != 0 || len(e.approver.Alarms()) != 0 {
		t.Error("an alarm for a request that the grant does not cover")
	}
	if len(e.approver.Asked()) != 1 {
		t.Error("the person was asked")
	}
	for range 2 { // both uses are still there
		res, ans := e.useToken("laptop", tok0)
		mustStatus(t, res, http.StatusOK)
		tok0 = ans.GrantToken
	}
}

// TestStandingAuditFailure: if grant_used cannot be written, the request is
// denied, the use is given back, and the token is not replaced.
func TestStandingAuditFailure(t *testing.T) {
	e, tok0, _ := useEnv(t)
	e.audit.setFail(func(ev audit.Event) error {
		if u, ok := ev.(audit.GrantUsed); ok && u.Via == audit.ViaStanding {
			return errors.New("disk full")
		}
		return nil
	})
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusServiceUnavailable)
	if strings.Contains(string(res.body), "nkg_") {
		t.Error("a token in a failed answer")
	}
	e.audit.setFail(nil)
	for range 2 {
		res, ans := e.useToken("laptop", tok0)
		mustStatus(t, res, http.StatusOK)
		tok0 = ans.GrantToken
	}
	if len(e.alarmEntries()) != 0 {
		t.Error("an alarm after a failed write")
	}
}

// TestStandingNoticeFailure: if the notice cannot be sent, the request is
// denied and the old token stays valid.
func TestStandingNoticeFailure(t *testing.T) {
	e, tok0, _ := useEnv(t)
	e.approver.FailNotify(errors.New("telegram is down"))
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusServiceUnavailable)
	e.approver.FailNotify(nil)
	res, ans := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusOK)
	if ans.GrantToken == tok0 {
		t.Error("the token did not change")
	}
	if len(e.alarmEntries()) != 0 {
		t.Error("an alarm for a failed notice")
	}
	e.noToken(tok0, ans.GrantToken)
}

// TestStandingNoTokenAsksAsBefore: a request without the header is unchanged.
func TestStandingNoTokenAsksAsBefore(t *testing.T) {
	e, _, _ := useEnv(t)
	p := e.start(e.httpClient("laptop"), api.PathSecrets, secretsRequest("GH_TOKEN", "github-token"))
	pr := e.waitAsked(2)[1].Prompt
	if pr.Kind != audit.KindSecrets {
		t.Errorf("kind %q", pr.Kind)
	}
	e.tap(pr.RequestID, audit.AnswerDeny)
	_ = p.wait(t)
}

// TestStandingStoreFailure: if the secret cannot be fetched after the
// token was replaced, the client has no new token, so the old one must stay
// valid and no alarm comes.
func TestStandingStoreFailure(t *testing.T) {
	e, tok0, _ := useEnv(t)
	e.main.set(func(f *fakeStore) { f.err = errors.New("store down") })
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusServiceUnavailable)
	e.main.set(func(f *fakeStore) { f.err = nil })
	res, ans := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusOK)
	res, _ = e.useToken("laptop", ans.GrantToken)
	mustStatus(t, res, http.StatusOK) // the failed use did not count
	if len(e.alarmEntries()) != 0 {
		t.Error("an alarm after a failed fetch")
	}
}

// TestStandingSecretSentFailure: if secret_sent cannot be written, no value
// and no new token are sent, and the use is undone: the old token is valid
// again, with all its uses.
func TestStandingSecretSentFailure(t *testing.T) {
	e, tok0, _ := useEnv(t)
	e.audit.setFail(func(ev audit.Event) error {
		if _, ok := ev.(audit.SecretSent); ok {
			return errors.New("disk full")
		}
		return nil
	})
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusServiceUnavailable)
	if strings.Contains(string(res.body), "nkg_") || strings.Contains(string(res.body), e.values["github-token"]) {
		t.Error("a token or a value in a failed answer")
	}
	e.audit.setFail(nil)
	for range 2 { // both uses of the window are still there
		res, ans := e.useToken("laptop", tok0)
		mustStatus(t, res, http.StatusOK)
		tok0 = ans.GrantToken
	}
	if len(e.alarmEntries()) != 0 || len(e.approver.Alarms()) != 0 {
		t.Error("an alarm after a failed write")
	}
}

// TestStandingCancelAfterRotation: the client hangs up after the broker made
// the new token, so it never gets it. Nothing is sent, and the old token
// stays valid with all its uses (DESIGN.md section 8).
func TestStandingCancelAfterRotation(t *testing.T) {
	e, tok0, _ := useEnv(t)
	e.main.set(func(f *fakeStore) { f.block = true }) // the fetch comes after the rotation
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	data, _ := json.Marshal(secretsRequest("GH_TOKEN", "github-token"))
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+e.addr+api.PathSecrets, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	hr.Header.Set("Content-Type", api.ContentType)
	hr.Header.Set(api.GrantTokenHeader, tok0)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := e.httpClient("laptop").Do(hr); err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-e.main.started:
	case <-time.After(waitLimit):
		t.Fatal("no fetch")
	}
	cancel()
	<-done
	e.svc.waitIdle(t, "laptop")
	e.main.set(func(f *fakeStore) { f.block = false })
	for range 2 { // the cancelled use did not count
		res, ans := e.useToken("laptop", tok0)
		mustStatus(t, res, http.StatusOK)
		tok0 = ans.GrantToken
	}
	if len(e.alarmEntries()) != 0 || len(e.approver.Alarms()) != 0 {
		t.Error("an alarm after a cancel")
	}
}

// TestStandingForeignToken: the token of a grant of another client, current
// or old, has left its machine. The request is denied and the grant ends,
// with an alarm that names it.
func TestStandingForeignToken(t *testing.T) {
	for _, old := range []bool{false, true} {
		e, tok0, id := useEnv(t)
		tok := tok0
		if old {
			_, ans := e.useToken("laptop", tok0)
			tok = tok0
			tok0 = ans.GrantToken
		}
		res, _ := e.useToken("ci", tok)
		mustStatus(t, res, http.StatusForbidden)
		al := e.alarmEntries()
		if len(al) != 1 || al[0].Cause != audit.AlarmOldToken || al[0].GrantID != id {
			t.Fatalf("old=%v alarms: %+v", old, al)
		}
		if as := e.approver.Alarms(); len(as) != 1 || !as[0].Ended || as[0].GrantID != id {
			t.Errorf("old=%v the alarm: %+v", old, as)
		}
		var ended bool
		for _, ev := range e.audit.all() {
			if g, ok := ev.(audit.GrantEnded); ok && g.GrantID == id && g.Cause == audit.EndAlarm {
				ended = true
			}
		}
		if !ended {
			t.Errorf("old=%v: no grant_ended:alarm", old)
		}
		res, _ = e.useToken("laptop", tok0)
		mustStatus(t, res, http.StatusForbidden)
		e.noToken(tok, tok0)
	}
}

// TestStandingOutsideWindowAlarmFails: the daily mark is set only by an
// alarm that went out. After a failed send the next request tries again.
func TestStandingOutsideWindowAlarmFails(t *testing.T) {
	e, tok0, id := useEnv(t)
	e.clock.Advance(3 * time.Hour) // 15:00
	e.approver.FailAlarm(errors.New("made-up: the alarm cannot be sent"))
	res, _ := e.useToken("laptop", tok0)
	mustStatus(t, res, http.StatusForbidden)
	if n := len(e.approver.Alarms()); n != 0 {
		t.Fatalf("%d alarms went out", n)
	}
	e.approver.FailAlarm(nil)
	for range 2 {
		res, _ = e.useToken("laptop", tok0)
		mustStatus(t, res, http.StatusForbidden)
	}
	if as := e.approver.Alarms(); len(as) != 1 || as[0].Cause != audit.AlarmOutsideWindow || as[0].GrantID != id {
		t.Errorf("the alarms: %+v", as)
	}
}

// TestStandingBeforeStart: a valid token before the start of the grant is
// denied, with an outside_window alarm, and the grant stays.
func TestStandingBeforeStart(t *testing.T) {
	e := newEnv(t, envOptions{config: standingOn})
	r := standReq("github-token")
	r.From = "2026-10-14T20:00:00Z"
	r.Windows = []api.Window{{Kind: api.WindowDaily, From: "11:00", To: "13:00"}}
	ans := e.preapprove(e.httpClient("laptop"), r, 1)
	res, _ := e.useToken("laptop", ans.GrantToken)
	mustStatus(t, res, http.StatusForbidden)
	al := e.alarmEntries()
	if len(al) != 1 || al[0].Cause != audit.AlarmOutsideWindow || al[0].GrantID != ans.ID {
		t.Fatalf("alarms: %+v", al)
	}
	if as := e.approver.Alarms(); len(as) != 1 || as[0].Ended {
		t.Errorf("the alarms: %+v", as)
	}
}
