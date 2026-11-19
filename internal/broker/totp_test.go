package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/totp"
)

// The TOTP item of the tests, and its seed: the base32 form of the SHA1
// seed of RFC 6238, appendix B.
const (
	idOTP   = "00000000-0000-0000-0000-000000000005"
	otpSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

// fakeTOTPStore is a bw-like store that hands out the TOTP seed of its
// items (store.TOTPStore). It keeps each seed it hands out, so a test can
// check that the broker cleared it.
type fakeTOTPStore struct {
	*fakeStore
	tmu     sync.Mutex
	seeds   map[string]string // by item ID; "" is an item with no seed
	seedErr error
	tgiven  [][]byte
	tcount  int
}

func newFakeTOTPStore() *fakeTOTPStore {
	return &fakeTOTPStore{fakeStore: newFakeStore(), seeds: map[string]string{idOTP: otpSeed}}
}

func (f *fakeTOTPStore) FetchTOTP(_ context.Context, id string) (store.Value, error) {
	f.tmu.Lock()
	defer f.tmu.Unlock()
	f.tcount++
	seed, ok := f.seeds[id]
	switch {
	case f.seedErr != nil:
		return store.Value{}, f.seedErr
	case !ok:
		return store.Value{}, store.ErrBadID
	case seed == "":
		return store.Value{}, store.ErrNoTOTP
	}
	b := []byte(seed)
	f.tgiven = append(f.tgiven, b)
	return store.NewValue(b), nil
}

func (f *fakeTOTPStore) checkSeedsCleared(t testing.TB) {
	t.Helper()
	f.tmu.Lock()
	defer f.tmu.Unlock()
	for _, b := range f.tgiven {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Error("a TOTP seed was not cleared")
		}
	}
}

// totpOn adds the store otp (type bw) and the secret npm-otp: the TOTP
// code of the item idOTP, ask always, for laptop, with preapprove.
func totpOn(cfg *config.Broker) {
	cfg.Stores["otp"] = config.Store{Name: "otp", Type: config.StoreBW}
	cfg.Secrets["npm-otp"] = config.Secret{Name: "npm-otp", Store: "otp", ID: idOTP, TOTP: true,
		Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways, Preapprove: true}}
}

// totpEnv starts a broker with totpOn and a fake TOTP store. The broker's
// clock for the codes is now.
func totpEnv(t *testing.T, more func(*config.Broker), now func() time.Time) (*env, *fakeTOTPStore) {
	t.Helper()
	ts := newFakeTOTPStore()
	e := newEnv(t, envOptions{
		config: func(cfg *config.Broker) {
			totpOn(cfg)
			if more != nil {
				more(cfg)
			}
		},
		stores: map[string]store.Store{"otp": ts},
	})
	e.svc.setNow(now)
	return e, ts
}

// wantCode is the code of otpSeed at t.
func wantCode(t testing.TB, at time.Time) string {
	t.Helper()
	k, err := totp.Parse([]byte(otpSeed))
	if err != nil {
		t.Fatal(err)
	}
	c, err := k.Code(at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func totpRequest(variable, name string) api.SecretsRequest {
	r := secretsRequest(variable, name)
	r.Secrets[0].Kind = api.KindTOTP
	r.Command = []string{"/usr/bin/npm", "publish", "pkg.tgz", "--otp"}
	return r
}

// TestTOTPCode: a --totp request asks for a tap; after it, the client gets
// the code of the broker's clock, and the seed is cleared. The message
// names the secret and the command; the entries hold no code and no seed.
func TestTOTPCode(t *testing.T) {
	at := time.Unix(1111111109, 0)
	e, ts := totpEnv(t, nil, func() time.Time { return at })
	c := e.httpClient("laptop")
	p := e.start(c, api.PathSecrets, totpRequest("NPM_OTP", "npm-otp"))
	pr := e.waitAsked(1)[0].Prompt
	if strings.Join(pr.Secrets, ",") != "npm-otp" || !strings.Contains(pr.Claim.Command, "npm publish pkg.tgz --otp") ||
		pr.WindowMinutes != 0 {
		t.Errorf("the message shows %+v", pr)
	}
	e.tap(pr.RequestID, audit.AnswerApproveOnce)
	got := secretsOf(t, p.wait(t))
	if got["NPM_OTP"] != wantCode(t, at) || got["NPM_OTP"] != "081804" {
		t.Errorf("the code is not the RFC 6238 code of the time (%d bytes)", len(got["NPM_OTP"]))
	}
	events := e.audit.waitFor(t, 3)
	mustEvents(t, requestEvents(events, pr.RequestID), "request decision:approve_once secret_sent")
	text := encodeEvents(t, events) + e.logs.String() + e.approverTexts()
	if strings.Contains(text, otpSeed[:8]) || strings.Contains(text, "081804") {
		t.Error("an entry, the log or the message holds the seed or the code")
	}
	ts.checkSeedsCleared(t)
}

// TestTOTPRefused: closed by default. Each request is refused before a
// message: a secret with totp = true asked for with --secret, --totp for a
// secret that is not a TOTP code, two codes in one request, a client that
// is not in the list, and a name that is not in the config.
func TestTOTPRefused(t *testing.T) {
	e, ts := totpEnv(t, func(cfg *config.Broker) {
		s := cfg.Secrets["npm-otp"]
		s.Clients = []string{"laptop", "ci"}
		cfg.Secrets["npm-otp"] = s
		cfg.Secrets["other-otp"] = config.Secret{Name: "other-otp", Store: "otp", ID: idOTP, TOTP: true,
			Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}}
		cfg.Secrets["only-laptop"] = config.Secret{Name: "only-laptop", Store: "otp", ID: idOTP, TOTP: true,
			Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}}
	}, time.Now)
	two := totpRequest("A", "npm-otp")
	two.Secrets = append(two.Secrets, api.SecretRef{Var: "B", Name: "other-otp", Kind: api.KindTOTP})
	cases := []struct {
		name   string
		client string
		req    api.SecretsRequest
	}{
		{"totp secret as a plain secret", "laptop", secretsRequest("NPM_OTP", "npm-otp")},
		{"a plain secret as totp", "laptop", totpRequest("DB", "db-password")},
		{"two codes", "laptop", two},
		{"another client", "ci", totpRequest("NPM_OTP", "only-laptop")},
		{"not in the config", "laptop", totpRequest("NPM_OTP", "no-such-otp")},
	}
	for i, tc := range cases {
		res := e.post(t.Context(), e.httpClient(tc.client), api.PathSecrets, tc.req)
		if res.err != nil || res.status != http.StatusForbidden {
			t.Errorf("%s: status %d, %v; want 403", tc.name, res.status, res.err)
		}
		events := e.audit.waitFor(t, 2*(i+1))
		mustEvents(t, events[2*i:], "request denied:not_allowed")
	}
	if n := len(e.approver.Asked()); n != 0 {
		t.Errorf("%d messages for refused requests", n)
	}
	if ts.tcount != 0 || e.vault.fetched() != 0 {
		t.Error("a refused request read a store")
	}
}

// TestTOTPNoSeed: an item with no seed, a seed that internal/totp does not
// read, and a store failure each deny the request after the tap, with a
// log line that says how to fix it and no code in the answer.
func TestTOTPNoSeed(t *testing.T) {
	cases := []struct {
		name, seed, log string
		err             error
	}{
		{"no seed", "", "put the seed into the item in Bitwarden, or remove totp = true from [secret.npm-otp]", nil},
		{"steam seed", "steam://ABCDEFGH", "the TOTP field is not a base32 secret", nil},
		{"bad base32", "!!!!", "the TOTP secret is not valid base32; copy the secret again", nil},
		{"store failure", otpSeed, "bw sync: the program failed",
			errors.New(`store "otp": bw sync: the program failed (exit code 1)`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, ts := totpEnv(t, nil, time.Now)
			ts.seeds[idOTP] = tc.seed
			ts.seedErr = tc.err
			e.approver.Auto(audit.AnswerApproveOnce)
			res := e.post(t.Context(), e.httpClient("laptop"), api.PathSecrets, totpRequest("NPM_OTP", "npm-otp"))
			mustStatus(t, res, http.StatusServiceUnavailable)
			events := e.audit.all()
			mustEvents(t, requestEvents(events, lastRequestID(t, events)),
				"request decision:approve_once error:store_failed denied:error")
			if !strings.Contains(e.logs.String(), tc.log) {
				t.Errorf("the log does not say how to fix it:\n%s", e.logs.String())
			}
			if tc.seed != "" && (strings.Contains(e.logs.String(), tc.seed) || strings.Contains(e.logs.String(), otpSeed[:8])) {
				t.Error("the log holds the seed")
			}
			ts.checkSeedsCleared(t)
		})
	}
}

// TestTOTPPreapprove: a scheduled grant with 2 uses gives 2 codes without
// a tap, each the code of the moment of its use; the third request asks
// again.
func TestTOTPPreapprove(t *testing.T) {
	var mu sync.Mutex
	at := noon
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return at
	}
	e, ts := totpEnv(t, func(cfg *config.Broker) { cfg.Preapprove = config.DefaultPreapprove() }, now)
	c := e.httpClient("laptop")
	e.preapprove(c, preReq(2, "npm-otp"), 1)
	e.clock.Advance(time.Hour)
	var codes []string
	for i := range 2 {
		mu.Lock()
		at = noon.Add(time.Hour + time.Duration(i)*30*time.Second)
		mu.Unlock()
		got := secretsOf(t, e.post(t.Context(), c, api.PathSecrets, totpRequest("NPM_OTP", "npm-otp")))
		if got["NPM_OTP"] != wantCode(t, now()) {
			t.Errorf("use %d: not the code of the moment of the use", i+1)
		}
		codes = append(codes, got["NPM_OTP"])
	}
	if codes[0] == codes[1] {
		t.Error("two uses in two time steps got the same code")
	}
	events := e.audit.waitFor(t, 8)[2:]
	mustEvents(t, events, "request grant_used:scheduled secret_sent "+
		"request grant_used:scheduled grant_ended:used_up secret_sent")
	if n := len(e.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
	// Used up: the next code needs a tap.
	again := e.start(c, api.PathSecrets, totpRequest("NPM_OTP", "npm-otp"))
	e.waitAsked(2)
	again.cancel()
	again.wait(t)
	ts.checkSeedsCleared(t)
}

// TestTOTPGrantToken: a request for a code with the header of a standing
// grant token is refused: a TOTP secret has no standing grants. Nobody is
// asked and no seed is read.
func TestTOTPGrantToken(t *testing.T) {
	e, ts := totpEnv(t, nil, time.Now)
	c := e.httpClient("laptop")
	data, err := json.Marshal(totpRequest("NPM_OTP", "npm-otp"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+e.addr+api.PathSecrets, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(api.GrantTokenHeader, "nodkey-grant-v1-"+strings.Repeat("A", 43))
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", res.StatusCode)
	}
	if n := len(e.approver.Asked()); n != 0 {
		t.Errorf("%d messages", n)
	}
	ts.tmu.Lock()
	defer ts.tmu.Unlock()
	if ts.tcount != 0 {
		t.Error("a seed was read")
	}
}

// TestTOTPReloadEndsGrant: a reload that turns a secret with an open
// window grant into a TOTP code (ask = "always") ends the grant: the next
// code needs a tap.
func TestTOTPReloadEndsGrant(t *testing.T) {
	e, ts := totpEnv(t, func(cfg *config.Broker) {
		s := cfg.Secrets["npm-otp"]
		s.TOTP, s.Rule = false, config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute}
		cfg.Secrets["npm-otp"] = s
	}, time.Now)
	ts.set(func(f *fakeStore) { f.items[idOTP] = madeUp("password") })
	c := e.httpClient("laptop")
	p := e.start(c, api.PathSecrets, secretsRequest("PW", "npm-otp"))
	e.tap(e.waitAsked(1)[0].Prompt.RequestID, audit.AnswerApproveWindow)
	secretsOf(t, p.wait(t))
	next := *e.svc.view().cfg
	next.Secrets = maps.Clone(next.Secrets)
	s := next.Secrets["npm-otp"]
	s.TOTP, s.Rule = true, config.Rule{Ask: config.AskAlways}
	next.Secrets["npm-otp"] = s
	if ended, err := e.svc.Reload(&next, e.svc.view().keys, strings.Repeat("a", 64)); err != nil || ended != 1 {
		t.Fatalf("Reload = %d, %v; want 1 grant ended", ended, err)
	}
	// The old kind is refused now, and a code needs a tap.
	mustStatus(t, e.post(t.Context(), c, api.PathSecrets, secretsRequest("PW", "npm-otp")), http.StatusForbidden)
	p = e.start(c, api.PathSecrets, totpRequest("NPM_OTP", "npm-otp"))
	e.waitAsked(2)
	p.cancel()
	p.wait(t)
}
