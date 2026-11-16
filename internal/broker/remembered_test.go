package broker

// Tests of the login that a login pre-approval keeps in memory (DESIGN.md
// section 21.3, issue #190).

import (
	"bytes"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
)

// rememberEnv is newLoginEnv with the clock of the broker on the test
// clock, and the shop item pre-approved for laptop on example.com.
func rememberEnv(t *testing.T, edit func(*config.Broker)) *loginTest {
	t.Helper()
	l := newLoginEnv(t, func(cfg *config.Broker) {
		s := cfg.Logins["web"]
		s.Clients = []string{"laptop", "ci"}
		cfg.Logins["web"] = s
		if edit != nil {
			edit(cfg)
		}
	})
	l.svc.setNow(l.clock.Now)
	mustStatus(t, l.loginPre(itemShop, pageShop), http.StatusOK)
	if n := l.svc.rememberedCount(); n != 1 {
		t.Fatalf("the broker keeps %d logins, want 1", n)
	}
	return l
}

// noTapLogin asks for a login as client c with the no-tap header, as the
// plugin does.
func (l *loginTest) noTapLogin(c *http.Client, item, url string) *result {
	l.t.Helper()
	keep := l.laptp
	l.laptp = c
	defer func() { l.laptp = keep }()
	return l.postHeader(api.PathLogin, l.loginReq(item, url), api.NoTapHeader, api.NoTapValue)
}

// noGrant checks that no grant covers the shop login: a login asks the
// person. The test hangs up before the tap.
func (l *loginTest) noGrant() {
	l.t.Helper()
	n := len(l.approver.Asked()) + 1
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	l.waitAsked(n)
	p.cancel()
}

// rememberedPassword returns the bytes of the password that the broker
// keeps for the one remembered login, to check later that they are
// cleared.
func (l *loginTest) rememberedPassword() []byte {
	l.t.Helper()
	l.svc.logins.mu.Lock()
	defer l.svc.logins.mu.Unlock()
	for _, r := range l.svc.logins.remembered {
		return r.login.Password.Bytes()
	}
	l.t.Fatal("no remembered login")
	return nil
}

func zeroed(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

// TestLoginRememberedRunsNoStore: after the pre-approval, the login is
// answered from memory: no fetch, no list and no sync. The pre-approval
// itself syncs twice: before and after the tap.
func TestLoginRememberedRunsNoStore(t *testing.T) {
	l := rememberEnv(t, nil)
	runs, syncs := l.vs.runs()
	if runs != 2 || syncs != 2 {
		t.Errorf("the pre-approval ran the store %d times with %d syncs; want 2 and 2", runs, syncs)
	}
	kept := l.rememberedPassword()
	res := l.noTapLogin(l.laptp, itemShop, pageShop)
	mustStatus(t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.LoginAnswer](bytes.NewReader(res.body))
	if err != nil || ans.Username != "alice@example.com" || string(ans.Password) != l.pw {
		t.Errorf("the answer is not the login of the shop item (%v)", err)
	}
	if again, _ := l.vs.runs(); again != runs {
		t.Errorf("the login ran the store %d times; want 0", again-runs)
	}
	if n := l.svc.rememberedCount(); n != 0 {
		t.Errorf("the broker still keeps %d logins after the use", n)
	}
	if !zeroed(kept) {
		t.Error("the remembered password is not cleared after the use")
	}
	if !strings.Contains(eventNames(l.audit.all()), "secret_sent") {
		t.Error("no secret_sent entry")
	}
	// One TOTP code follows, as after any login.
	if code := codeOf(t, l.totp(itemShop, pageShop)); len(code) != 6 {
		t.Errorf("code %q", code)
	}
	l.vs.checkCleared(t)
}

// TestLoginRememberedDenyPaths: a login that the remembered login does not
// cover is denied, with the no-tap header, before the store runs.
func TestLoginRememberedDenyPaths(t *testing.T) {
	type step func(l *loginTest) *result
	cases := map[string]step{
		"another client": func(l *loginTest) *result {
			return l.noTapLogin(l.httpClient("ci"), itemShop, pageShop)
		},
		"another origin": func(l *loginTest) *result {
			return l.noTapLogin(l.laptp, itemShop, "https://shop.example.com/sign-in")
		},
		"another item": func(l *loginTest) *result {
			return l.noTapLogin(l.laptp, itemMail, pageShop)
		},
		"second use": func(l *loginTest) *result {
			mustStatus(l.t, l.noTapLogin(l.laptp, itemShop, pageShop), http.StatusOK)
			return l.noTapLogin(l.laptp, itemShop, pageShop)
		},
		"after 60 s": func(l *loginTest) *result {
			l.clock.Advance(60 * time.Second)
			return l.noTapLogin(l.laptp, itemShop, pageShop)
		},
		"reload that changes [logins.*]": func(l *loginTest) *result {
			l.reloadLogins(func(m map[string]config.Logins) {
				o := m["other"]
				o.Rule.Window = 4 * time.Hour
				o.Rule.Ask = config.AskWindow
				m["other"] = o
			})
			return l.noTapLogin(l.laptp, itemShop, pageShop)
		},
		"reload that removes the item's section": func(l *loginTest) *result {
			l.reloadLogins(func(m map[string]config.Logins) { delete(m, "web") })
			return l.noTapLogin(l.laptp, itemShop, pageShop)
		},
		"cancelled pre-approval": func(l *loginTest) *result {
			id := l.preapprovalID()
			mustStatus(l.t, l.post(l.t.Context(), l.laptp, api.PathPreapproveCancel, api.PreapproveCancelRequest{ID: id}), http.StatusOK)
			return l.noTapLogin(l.laptp, itemShop, pageShop)
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			l := rememberEnv(t, nil)
			kept := l.rememberedPassword()
			before, _ := l.vs.runs()
			res := run(l)
			if res.status == http.StatusOK || bytes.Contains(res.body, []byte(l.pw)) {
				t.Fatalf("status %d: the login is not denied", res.status)
			}
			if res.status != http.StatusPreconditionRequired {
				t.Errorf("status %d, want 428", res.status)
			}
			// For "second use", this counts the first use too.
			if after, _ := l.vs.runs(); after != before {
				t.Errorf("the store ran %d times; want 0", after-before)
			}
			if n := len(l.approver.Asked()); n != 1 {
				t.Errorf("%d messages, want 1 (the pre-approval)", n)
			}
			if name != "another client" && name != "another origin" && name != "another item" {
				if n := l.svc.rememberedCount(); n != 0 {
					t.Errorf("the broker still keeps %d logins", n)
				}
				if !zeroed(kept) {
					t.Error("the remembered password is not cleared")
				}
			}
			l.vs.checkCleared(t)
		})
	}
}

// TestLoginRememberedStop: the stop clears the remembered login.
func TestLoginRememberedStop(t *testing.T) {
	l := rememberEnv(t, nil)
	kept := l.rememberedPassword()
	before, _ := l.vs.runs()
	l.svc.Close()
	if n := l.svc.rememberedCount(); n != 0 || !zeroed(kept) {
		t.Errorf("after the stop the broker keeps %d logins (cleared: %v)", n, zeroed(kept))
	}
	res := l.noTapLogin(l.laptp, itemShop, pageShop)
	if res.status == http.StatusOK || bytes.Contains(res.body, []byte(l.pw)) {
		t.Fatalf("status %d after the stop", res.status)
	}
	if after, _ := l.vs.runs(); after != before {
		t.Errorf("the store ran %d times; want 0", after-before)
	}
}

// TestLoginRememberedGoneButGrantLives: a reload that changes [logins.*]
// only for another item keeps the grant in the core, but the broker
// forgets the login. A login without the no-tap header still uses the
// pre-approval; it fetches the item with one sync.
func TestLoginRememberedGoneButGrantLives(t *testing.T) {
	l := rememberEnv(t, nil)
	l.reloadLogins(func(m map[string]config.Logins) {
		o := m["other"]
		o.Items = map[string]config.LoginItemRule{
			itemMail: {Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}},
		}
		m["other"] = o
	})
	if n := l.svc.rememberedCount(); n != 0 {
		t.Fatalf("the broker still keeps %d logins", n)
	}
	runs, syncs := l.vs.runs()
	mustStatus(t, l.noTapLogin(l.laptp, itemShop, pageShop), http.StatusPreconditionRequired)
	if again, _ := l.vs.runs(); again != runs {
		t.Errorf("the no-tap login ran the store")
	}
	res := l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	mustStatus(t, res, http.StatusOK)
	runs2, syncs2 := l.vs.runs()
	if syncs2-syncs != 1 || runs2-runs != 2 {
		t.Errorf("the login ran the store %d times with %d syncs; want 2 and 1", runs2-runs, syncs2-syncs)
	}
	if n := len(l.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1: the grant covers the login", n)
	}
	l.vs.checkCleared(t)
}

// TestLoginPreapproveItemChangesBeforeFetch: when the item changed during
// the tap, the pre-approval is denied, no grant starts, and nothing is
// kept.
func TestLoginPreapproveItemChangesBeforeFetch(t *testing.T) {
	l := newLoginEnv(t, nil)
	p := l.start(l.laptp, api.PathPreapprove, api.PreapproveRequest{Login: itemShop, URL: pageShop, Uses: 1})
	pr := l.waitAsked(1)[0].Prompt
	l.vs.lmu.Lock()
	l.shop.Username = "mallory@example.com"
	l.vs.lmu.Unlock()
	l.tap(pr.RequestID, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusForbidden)
	if n := l.svc.rememberedCount(); n != 0 {
		t.Errorf("the broker keeps %d logins", n)
	}
	l.noGrant()
	l.vs.checkCleared(t)
}

// TestLoginTapSyncsOnce: a login by tap runs "bw sync" once: the fetch
// before the tap syncs, the fetch after it does not.
func TestLoginTapSyncsOnce(t *testing.T) {
	l := newLoginEnv(t, nil)
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce), http.StatusOK)
	runs, syncs := l.vs.runs()
	if runs != 2 || syncs != 1 {
		t.Errorf("the login ran the store %d times with %d syncs; want 2 and 1", runs, syncs)
	}
	l.vs.checkCleared(t)
}

// TestRememberLimit: the broker keeps at most maxRememberedLogins logins;
// the next pre-approval is denied and starts no grant.
func TestRememberLimit(t *testing.T) {
	l := newLoginEnv(t, nil)
	l.svc.setNow(l.clock.Now)
	end := l.clock.Now().Add(time.Minute)
	for i := range maxRememberedLogins {
		id := strings.Repeat("x", 10) + string(rune('A'+i%26)) + string(rune('A'+i/26))
		pw := []byte(madeUp("pw"))
		if why := l.svc.remember(id, rememberedLogin{client: "ci", item: itemMail, origin: "https://example.net", end: end},
			store.Login{Password: store.NewValue(pw)}); why != "" {
			t.Fatalf("remember %d failed", i)
		}
	}
	res := l.loginPre(itemShop, pageShop)
	mustStatus(t, res, http.StatusTooManyRequests)
	l.noGrant()
	l.svc.forgetLogins()
	l.vs.checkCleared(t)
}

// reloadLogins reloads the config with [logins.*] changed by edit.
func (l *loginTest) reloadLogins(edit func(map[string]config.Logins)) {
	l.t.Helper()
	next := *l.svc.view().cfg
	next.Logins = maps.Clone(next.Logins)
	edit(next.Logins)
	if _, err := l.svc.Reload(&next, l.svc.view().keys, strings.Repeat("a", 64)); err != nil {
		l.t.Fatal(err)
	}
}

// preapprovalID returns the ID of the one remembered login's grant.
func (l *loginTest) preapprovalID() string {
	l.t.Helper()
	l.svc.logins.mu.Lock()
	defer l.svc.logins.mu.Unlock()
	for id := range l.svc.logins.remembered {
		return id
	}
	l.t.Fatal("no remembered login")
	return ""
}

// TestLoginPreapproveEndsAtTapWithSlowFetch: the fetch after the tap takes
// 30 s. The grant and the remembered login still end 60 s after the tap,
// not 60 s after the fetch.
func TestLoginPreapproveEndsAtTapWithSlowFetch(t *testing.T) {
	l := newLoginEnv(t, nil)
	l.svc.setNow(l.clock.Now)
	l.vs.lmu.Lock()
	l.vs.onFetch = func(n int) {
		if n == 2 { // the fetch after the tap
			l.clock.Advance(30 * time.Second)
		}
	}
	l.vs.lmu.Unlock()
	mustStatus(t, l.loginPre(itemShop, pageShop), http.StatusOK)
	l.vs.lmu.Lock()
	l.vs.onFetch = nil
	l.vs.lmu.Unlock()
	l.clock.Advance(31 * time.Second) // 61 s after the tap
	before, _ := l.vs.runs()
	mustStatus(t, l.noTapLogin(l.laptp, itemShop, pageShop), http.StatusPreconditionRequired)
	if after, _ := l.vs.runs(); after != before {
		t.Errorf("the store ran %d times; want 0", after-before)
	}
	if n := l.svc.rememberedCount(); n != 0 {
		t.Errorf("the broker keeps %d logins", n)
	}
	l.noGrant()
}

// TestLoginPreapproveFetchTooSlow: when the fetch after the tap takes the
// whole 60 s, nothing is kept and no grant starts.
func TestLoginPreapproveFetchTooSlow(t *testing.T) {
	l := newLoginEnv(t, nil)
	l.svc.setNow(l.clock.Now)
	l.vs.lmu.Lock()
	l.vs.onFetch = func(n int) {
		if n == 2 {
			l.clock.Advance(61 * time.Second)
		}
	}
	l.vs.lmu.Unlock()
	res := l.loginPre(itemShop, pageShop)
	if res.status == http.StatusOK {
		t.Fatal("the pre-approval is allowed")
	}
	if !strings.Contains(l.logs.String(), "A slow store") {
		t.Error("the journal does not point to the docs of a slow store")
	}
	if n := l.svc.rememberedCount(); n != 0 {
		t.Errorf("the broker keeps %d logins", n)
	}
	l.vs.lmu.Lock()
	l.vs.onFetch = nil
	l.vs.lmu.Unlock()
	l.noGrant()
	l.vs.checkCleared(t)
}

// TestStoreStepsInTheJournal: a slow run of a store program is logged at
// info level, with the store, the step and the time; a fast one is not
// (it is at debug level).
func TestStoreStepsInTheJournal(t *testing.T) {
	l := newLoginEnv(t, nil)
	timer := store.StepTimerOf(l.svc.timeSteps(t.Context(), "laptop"))
	if timer == nil {
		t.Fatal("no step timer")
	}
	timer("vault", "bw get item", 10*time.Millisecond, false)
	if strings.Contains(l.logs.String(), "bw get item") {
		t.Error("a fast step is logged at info level")
	}
	timer("vault", "bw sync", 6*time.Second, true)
	got := l.logs.String()
	for _, want := range []string{"a store step was slow", `step="bw sync"`, "took=6s", "store=vault", "client=laptop", "failed=true", "A slow store"} {
		if !strings.Contains(got, want) {
			t.Errorf("the journal has no %q:\n%s", want, got)
		}
	}
}
