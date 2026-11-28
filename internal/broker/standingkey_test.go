package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// keyStandingOn is standingOn with standing = true on the key web too.
func keyStandingOn(cfg *config.Broker) {
	standingOn(cfg)
	k := cfg.Keys["web"]
	k.Rule.Standing = true
	cfg.Keys["web"] = k
}

// keyUseEnv is an environment with one standing grant of laptop for the
// key web, as deploy on web-1, daily 11:00-13:00 (the clock is at 12:00),
// 2 uses in each window. It returns the token.
func keyUseEnv(t *testing.T) (*env, string) {
	t.Helper()
	e := newEnv(t, envOptions{config: keyStandingOn})
	r := standReq()
	r.Key, r.User, r.Hosts = "web", "deploy", []string{"web-1"}
	r.Windows = []api.Window{{Kind: api.WindowDaily, From: "11:00", To: "13:00"}}
	ans := e.preapprove(e.httpClient("laptop"), r, 1)
	if pr := e.approver.Asked()[0].Prompt; pr.Kind != audit.KindStanding || pr.Key != "web" || len(pr.Secrets) != 0 {
		t.Fatalf("the message shows %+v", pr)
	}
	return e, ans.GrantToken
}

// signToken sends a signature request for the key web to host as user,
// with the token header.
func (e *env) signToken(token, host, user string) (*result, *api.SignAnswer) {
	e.t.Helper()
	data, _ := json.Marshal(e.signRequest(e.t, "web", host, user))
	hr, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+e.addr+api.PathSign, bytes.NewReader(data))
	if err != nil {
		e.t.Fatal(err)
	}
	hr.Header.Set("Content-Type", api.ContentType)
	hr.Header.Set(api.GrantTokenHeader, token)
	resp, err := e.httpClient("laptop").Do(hr)
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
	ans, err := api.ReadAnswer[api.SignAnswer](bytes.NewReader(res.body))
	if err != nil {
		e.t.Fatalf("the answer: %v", err)
	}
	return res, ans
}

// TestStandingKeySign: each signature with the token is one use and
// rotates it; a login the grant does not cover is denied without an
// alarm; a use over the limit ends the grant with an alarm. The person is
// asked only once, for the grant.
func TestStandingKeySign(t *testing.T) {
	e, tok0 := keyUseEnv(t)
	res, _ := e.signToken(tok0, "web-2", "deploy")
	mustStatus(t, res, http.StatusForbidden)
	res, _ = e.signToken(tok0, "web-1", "root")
	mustStatus(t, res, http.StatusForbidden)
	if len(e.alarmEntries()) != 0 || len(e.approver.Alarms()) != 0 {
		t.Fatal("an alarm for a login that the grant does not cover")
	}
	toks := []string{tok0}
	for i := range 2 {
		res, ans := e.signToken(toks[i], "web-1", "deploy")
		mustStatus(t, res, http.StatusOK)
		if len(ans.Blob) == 0 || ans.GrantToken == "" || string(ans.GrantToken) == toks[i] {
			t.Fatalf("use %d: no signature or no new token", i+1)
		}
		toks = append(toks, string(ans.GrantToken))
	}
	var used int
	for _, ev := range e.audit.all() {
		if gu, ok := ev.(audit.GrantUsed); ok && gu.Via == audit.ViaStanding && gu.Kind == audit.KindSSHLogin {
			used++
		}
	}
	if used != 2 {
		t.Errorf("%d grant_used entries of SSH logins, want 2", used)
	}
	res, _ = e.signToken(toks[2], "web-1", "deploy")
	mustStatus(t, res, http.StatusForbidden)
	al := e.approver.Alarms()
	if len(al) != 1 || al[0].Cause != audit.AlarmOverUses || al[0].Key != "web" || !al[0].Ended {
		t.Fatalf("the alarms are %+v", al)
	}
	if len(e.approver.Asked()) != 1 {
		t.Error("the person was asked for a signature")
	}
	e.noToken(toks...)
}

// TestStandingKeyOldToken: a signature with an old token is denied and
// ends the grant with an alarm.
func TestStandingKeyOldToken(t *testing.T) {
	e, tok0 := keyUseEnv(t)
	res, _ := e.signToken(tok0, "web-1", "deploy")
	mustStatus(t, res, http.StatusOK)
	res, _ = e.signToken(tok0, "web-1", "deploy")
	mustStatus(t, res, http.StatusForbidden)
	al := e.approver.Alarms()
	if len(al) != 1 || al[0].Cause != audit.AlarmOldToken || al[0].Key != "web" {
		t.Fatalf("the alarms are %+v", al)
	}
}
