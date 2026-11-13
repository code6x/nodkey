package broker

// Tests of website logins (DESIGN.md section 21) through the broker.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
)

const (
	collWeb   = "aaaaaaaa-0000-0000-0000-000000000001" // the collection of [logins.web]
	collOther = "aaaaaaaa-0000-0000-0000-000000000002" // the collection of [logins.other]
	collNone  = "aaaaaaaa-0000-0000-0000-000000000003" // a collection no section names
	itemShop  = "bbbbbbbb-0000-0000-0000-000000000001"
	itemMail  = "bbbbbbbb-0000-0000-0000-000000000002"
	pageShop  = "https://example.com/sign-in"
	// totpSeed is the base32 form of "12345678901234567890", the seed of
	// RFC 6238 appendix B. At 59 s after the epoch, the SHA1 code with 6
	// digits is 287082.
	totpSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

// fakeLogin is an item of the fake login store.
type fakeLogin struct {
	store.LoginItem
	password, totp string
	fetchErr       error // FetchLogin returns it
	hidden         bool  // ListLogins leaves it out
}

// fakeLoginStore is the store "vault" for the tests of logins.
type fakeLoginStore struct {
	*fakeStore
	lmu        sync.Mutex
	logins     map[string]*fakeLogin
	listErr    error
	listed     int
	fetchedIDs []string
	given      [][]byte
}

func newFakeLoginStore() *fakeLoginStore {
	return &fakeLoginStore{fakeStore: newFakeStore(), logins: make(map[string]*fakeLogin)}
}

func (f *fakeLoginStore) add(l *fakeLogin) {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	f.logins[l.ID] = l
}

func (f *fakeLoginStore) ListLogins(_ context.Context, collection string) ([]store.LoginItem, error) {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	f.listed++
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []store.LoginItem
	for _, id := range slices.Sorted(mapKeys(f.logins)) {
		l := f.logins[id]
		if !l.hidden && slices.Contains(l.Collections, collection) {
			out = append(out, l.LoginItem)
		}
	}
	return out, nil
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func (f *fakeLoginStore) FetchLogin(_ context.Context, id string) (store.Login, error) {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	f.fetchedIDs = append(f.fetchedIDs, id)
	l, ok := f.logins[id]
	if !ok {
		return store.Login{}, fmt.Errorf("fake bw: not found: %w", store.ErrFailed)
	}
	if l.fetchErr != nil {
		return store.Login{}, l.fetchErr
	}
	pw, seed := []byte(l.password), []byte(l.totp)
	f.given = append(f.given, pw, seed)
	out := store.Login{LoginItem: l.LoginItem, Password: store.NewValue(pw)}
	if l.totp != "" {
		out.TOTP = store.NewValue(seed)
	}
	return out, nil
}

// checkCleared fails unless every password and seed that the store gave
// out is cleared.
func (f *fakeLoginStore) checkCleared(t testing.TB) {
	t.Helper()
	f.lmu.Lock()
	defer f.lmu.Unlock()
	for i, b := range f.given {
		if len(b) > 0 && !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("value %d that the store gave out is not cleared", i)
		}
	}
}

func (f *fakeLoginStore) fetches() int {
	f.lmu.Lock()
	defer f.lmu.Unlock()
	return len(f.fetchedIDs)
}

// loginEnv starts a broker with [logins.web] (laptop; window 15m;
// preapprove) for the collection collWeb on the store "vault", and
// [logins.other] for collOther. The store holds the shop login and a mail
// login, both at example.com.
type loginTest struct {
	*env
	vs    *fakeLoginStore
	pw    string
	seed  string
	shop  *fakeLogin
	laptp *http.Client
}

func newLoginEnv(t *testing.T, edit func(*config.Broker)) *loginTest {
	t.Helper()
	vs := newFakeLoginStore()
	pw := madeUp("shop-password")
	shop := &fakeLogin{
		LoginItem: store.LoginItem{
			ID: itemShop, Name: "Example shop", Username: "alice@example.com",
			URIs: []store.LoginURI{{URI: "https://example.com"}}, Collections: []string{collWeb},
		},
		password: pw, totp: totpSeed,
	}
	vs.add(shop)
	vs.add(&fakeLogin{
		LoginItem: store.LoginItem{
			ID: itemMail, Name: "Example mail", Username: "bob@example.com",
			URIs: []store.LoginURI{{URI: "https://example.com"}}, Collections: []string{collWeb},
		},
		password: madeUp("mail-password"),
	})
	e := newEnv(t, envOptions{vault: vs, config: func(cfg *config.Broker) {
		cfg.Preapprove = config.DefaultPreapprove()
		cfg.Logins = map[string]config.Logins{
			"web": {Name: "web", Store: "vault", Collection: collWeb, Clients: []string{"laptop"},
				Rule: config.Rule{Ask: config.AskWindow, Window: 15 * time.Minute, Preapprove: true}},
			"other": {Name: "other", Store: "vault", Collection: collOther, Clients: []string{"laptop"},
				Rule: config.Rule{Ask: config.AskAlways}},
		}
		if edit != nil {
			edit(cfg)
		}
	}})
	return &loginTest{env: e, vs: vs, pw: pw, seed: totpSeed, shop: shop, laptp: e.httpClient("laptop")}
}

func (l *loginTest) loginReq(item, url string) api.LoginRequest {
	return api.LoginRequest{URL: url, Item: item}
}

// approveLogin asks for the login and approves it with action.
func (l *loginTest) approveLogin(item, url string, action audit.Answer) *result {
	l.t.Helper()
	n := len(l.approver.Asked()) + 1
	p := l.start(l.laptp, api.PathLogin, l.loginReq(item, url))
	pr := l.waitAsked(n)[n-1].Prompt
	l.tap(pr.RequestID, action)
	return p.wait(l.t)
}

func (l *loginTest) noMessage(res *result, status int) {
	l.t.Helper()
	mustStatus(l.t, res, status)
	if n := len(l.approver.Asked()); n != 0 {
		l.t.Errorf("the approver was asked %d times; want 0", n)
	}
}

func TestLoginByTap(t *testing.T) {
	l := newLoginEnv(t, nil)
	res := l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce)
	mustStatus(t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.LoginAnswer](bytes.NewReader(res.body))
	if err != nil || ans.Username != "alice@example.com" || string(ans.Password) != l.pw {
		t.Fatalf("answer: %v", err)
	}
	pr := l.approver.Asked()[0].Prompt
	if pr.Kind != audit.KindWebLogin || pr.Login == nil || pr.Login.Name != "Example shop" ||
		pr.Login.Username != "alice@example.com" || pr.Login.Origin != "https://example.com" {
		t.Errorf("prompt %+v", pr)
	}
	events := l.audit.all()
	mustEvents(t, events, "request decision:approve_once secret_sent")
	s := subjectOf(events[0])
	if s.Kind != audit.KindWebLogin || s.Logins != "web" || s.Item != itemShop || s.Origin != "https://example.com" {
		t.Errorf("subject %+v", s)
	}
	// The password was fetched twice: it is not held while the person decides.
	if n := l.vs.fetches(); n != 2 {
		t.Errorf("%d fetches, want 2", n)
	}
	l.vs.checkCleared(t)
	if all := encodeEvents(t, events); strings.Contains(all, l.pw) || strings.Contains(all, "alice@") ||
		strings.Contains(all, "Example shop") || strings.Contains(all, l.seed) {
		t.Errorf("the audit log holds vault text or a secret:\n%s", all)
	}
	if strings.Contains(l.logs.String(), l.pw) || strings.Contains(l.approverTexts(), l.pw) {
		t.Error("the password is in the log or in a message")
	}
}

func TestLoginDeny(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(l *loginTest)
		url    string
		item   string
		header string
	}{
		{name: "item outside the collection", edit: func(l *loginTest) { l.shop.Collections = []string{collNone} }},
		{name: "item in two configured collections", edit: func(l *loginTest) { l.shop.Collections = []string{collWeb, collOther} }},
		{name: "not a login", edit: func(l *loginTest) { l.shop.fetchErr = store.ErrNotLogin }},
		{name: "in the trash", edit: func(l *loginTest) { l.shop.fetchErr = store.ErrTrashed }},
		{name: "archived", edit: func(l *loginTest) { l.shop.fetchErr = store.ErrArchived }},
		{name: "no password", edit: func(l *loginTest) { l.shop.fetchErr = store.ErrNoValue }},
		{name: "origin matches no URI", url: "https://evil.test/sign-in"},
		{name: "sibling host with host match", edit: func(l *loginTest) {
			host := 1
			l.shop.URIs = []store.LoginURI{{URI: "https://example.com", Match: &host}}
		}, url: "https://www.example.com/"},
		{name: "http page", url: "http://example.com/sign-in"},
		{name: "page URL that is not a URL", url: "example"},
		{name: "page with a user name", url: "https://" + "u:p" + "@example.com/"},
		{name: "unknown item", item: "bbbbbbbb-0000-0000-0000-0000000000ff"},
		{name: "item that is not a UUID", item: "../etc"},
		{name: "grant token header", header: "tokentokentoken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLoginEnv(t, nil)
			if tt.edit != nil {
				tt.edit(l)
			}
			item, url := cmp(tt.item, itemShop), cmp(tt.url, pageShop)
			body := l.loginReq(item, url)
			var res *result
			if tt.header != "" {
				res = l.postHeader(api.PathLogin, body, api.GrantTokenHeader, tt.header)
			} else {
				res = l.post(t.Context(), l.laptp, api.PathLogin, body)
			}
			l.noMessage(res, http.StatusForbidden)
			if bytes.Contains(res.body, []byte(l.pw)) {
				t.Error("the answer holds the password")
			}
			events := l.audit.all()
			if got := eventNames(events); got != "request denied:not_allowed" {
				t.Errorf("entries %s", got)
			}
			l.vs.checkCleared(t)
		})
	}
}

func cmp(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// postHeader sends body with one header.
func (l *loginTest) postHeader(path string, body any, name, value string) *result {
	l.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		l.t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(l.t.Context(), http.MethodPost, "https://"+l.addr+path, bytes.NewReader(data))
	if err != nil {
		l.t.Fatal(err)
	}
	req.Header.Set("Content-Type", api.ContentType)
	req.Header.Set(name, value)
	resp, err := l.laptp.Do(req)
	if err != nil {
		return &result{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, api.MaxAnswer+1))
	return &result{status: resp.StatusCode, body: b, err: err}
}

func TestLoginItemRuleDecidesTheClient(t *testing.T) {
	// A stricter item rule: the collection names laptop, the item names ci.
	l := newLoginEnv(t, func(cfg *config.Broker) {
		s := cfg.Logins["web"]
		s.Items = map[string]config.LoginItemRule{itemShop: {ID: itemShop, Clients: []string{"ci"}, Rule: config.Rule{Ask: config.AskAlways}}}
		cfg.Logins["web"] = s
	})
	l.noMessage(l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop)), http.StatusForbidden)
	// The mail item still follows the collection's rule.
	res := l.approveLogin(itemMail, pageShop, audit.AnswerApproveOnce)
	mustStatus(t, res, http.StatusOK)
}

func TestLoginItemRuleLooser(t *testing.T) {
	// A looser item rule: ci is not in the collection's clients, but the
	// item's rule names it.
	l := newLoginEnv(t, func(cfg *config.Broker) {
		s := cfg.Logins["web"]
		s.Items = map[string]config.LoginItemRule{itemShop: {ID: itemShop, Clients: []string{"laptop", "ci"}, Rule: config.Rule{Ask: config.AskAlways}}}
		cfg.Logins["web"] = s
	})
	ci := l.httpClient("ci")
	p := l.start(ci, api.PathLogin, l.loginReq(itemShop, pageShop))
	pr := l.waitAsked(1)[0].Prompt
	if pr.WindowMinutes != 0 {
		t.Errorf("the item rule is always, but the message offers a window: %+v", pr)
	}
	l.tap(pr.RequestID, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusOK)
	// ci may not use the mail item: the collection does not name it.
	res := l.post(t.Context(), ci, api.PathLogin, l.loginReq(itemMail, pageShop))
	mustStatus(t, res, http.StatusForbidden)
}

func TestLoginReprompt(t *testing.T) {
	l := newLoginEnv(t, nil)
	l.shop.Reprompt = true
	n := 1
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	pr := l.waitAsked(n)[0].Prompt
	if pr.WindowMinutes != 0 {
		t.Errorf("an item with a re-prompt must offer no window: %+v", pr)
	}
	l.tap(pr.RequestID, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusOK)
}

func TestLoginWindowGrant(t *testing.T) {
	l := newLoginEnv(t, nil)
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveWindow), http.StatusOK)
	// The same item again: no message.
	res := l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	mustStatus(t, res, http.StatusOK)
	if n := len(l.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
	// Another item needs a tap.
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemMail, pageShop))
	pr := l.waitAsked(2)[1].Prompt
	l.tap(pr.RequestID, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
}

func (l *loginTest) listReq(url string) *result {
	return l.post(l.t.Context(), l.laptp, api.PathLoginList, api.ListLoginsRequest{URL: url})
}

func TestLoginList(t *testing.T) {
	l := newLoginEnv(t, nil)
	l.vs.add(&fakeLogin{LoginItem: store.LoginItem{ID: "bbbbbbbb-0000-0000-0000-000000000003", Name: "Other site",
		Username: "x", URIs: []store.LoginURI{{URI: "https://other.test"}}, Collections: []string{collWeb}}})
	l.vs.add(&fakeLogin{LoginItem: store.LoginItem{ID: "bbbbbbbb-0000-0000-0000-000000000004", Name: "In two",
		Username: "y", URIs: []store.LoginURI{{URI: "https://example.com"}}, Collections: []string{collWeb, collOther}}})
	l.vs.add(&fakeLogin{LoginItem: store.LoginItem{ID: "bbbbbbbb-0000-0000-0000-000000000005", Name: "Hidden",
		Username: "z", URIs: []store.LoginURI{{URI: "https://example.com"}}, Collections: []string{collWeb}}, hidden: true})
	res := l.listReq(pageShop)
	mustStatus(t, res, http.StatusOK)
	ans, err := api.ReadAnswer[api.ListLoginsAnswer](bytes.NewReader(res.body))
	if err != nil || len(ans.Logins) != 2 || ans.Logins[0].ID != itemShop || ans.Logins[1].ID != itemMail ||
		ans.Logins[0].Logins != "web" || ans.Logins[0].Username != "alice@example.com" || ans.Logins[0].Name != "Example shop" {
		t.Fatalf("answer %+v, %v", ans, err)
	}
	for _, secret := range []string{l.pw, l.seed, "password", "totp"} {
		if bytes.Contains(res.body, []byte(secret)) {
			t.Errorf("the raw answer holds %q:\n%s", secret, res.body)
		}
	}
	events := l.audit.all()
	mustEvents(t, events, "login_list login_list") // other: 0 matches, web: 2
	if got := encodeEvents(t, events); !strings.Contains(got, `"count":2`) || strings.Contains(got, "alice") ||
		strings.Contains(got, "Example") {
		t.Errorf("entry %s", got)
	}
	if n := len(l.approver.Asked()); n != 0 {
		t.Errorf("a list asked the person %d times", n)
	}
	// Other pages: no match is an empty list; a bad page is refused.
	res = l.listReq("https://nothing.test/")
	ans, err = api.ReadAnswer[api.ListLoginsAnswer](bytes.NewReader(res.body))
	if err != nil || len(ans.Logins) != 0 {
		t.Errorf("answer %s, %v", res.body, err)
	}
	mustStatus(t, l.listReq("http://example.com/"), http.StatusForbidden)
	// A store that fails makes a 503, not a list.
	l.vs.lmu.Lock()
	l.vs.listErr = errors.New("fake bw: down")
	l.vs.lmu.Unlock()
	mustStatus(t, l.listReq(pageShop), http.StatusServiceUnavailable)
}

func TestLoginListRate(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	l.svc.setNow(func() time.Time { return now })
	for i := range LoginListRate {
		if res := l.listReq(pageShop); res.status != http.StatusOK {
			t.Fatalf("list %d: status %d", i, res.status)
		}
	}
	mustStatus(t, l.listReq(pageShop), http.StatusTooManyRequests)
	now = now.Add(time.Minute)
	mustStatus(t, l.listReq(pageShop), http.StatusOK)
}

func (l *loginTest) totp(item, url string) *result {
	return l.post(l.t.Context(), l.laptp, api.PathLoginTOTP, api.TOTPRequest{URL: url, Item: item})
}

func codeOf(t *testing.T, res *result) string {
	t.Helper()
	mustStatus(t, res, http.StatusOK)
	a, err := api.ReadAnswer[api.TOTPAnswer](bytes.NewReader(res.body))
	if err != nil {
		t.Fatal(err)
	}
	return a.Code
}

func TestLoginTOTPTicket(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Unix(59, 0)
	l.svc.setNow(func() time.Time { return now })
	// No login first: no code, and the seed is not even read.
	mustStatus(t, l.totp(itemShop, pageShop), http.StatusForbidden)
	if n := l.vs.fetches(); n != 0 {
		t.Errorf("%d fetches without a ticket", n)
	}
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce), http.StatusOK)
	// Another origin, another item: no code.
	mustStatus(t, l.totp(itemShop, "https://shop.example.com/"), http.StatusForbidden)
	mustStatus(t, l.totp(itemMail, pageShop), http.StatusForbidden)
	// The RFC 6238 code for T = 59 s with SHA1 and 6 digits.
	res := l.totp(itemShop, pageShop+"?step=2")
	if code := codeOf(t, res); code != "287082" {
		t.Errorf("code %q, want 287082", code)
	}
	// One code only.
	mustStatus(t, l.totp(itemShop, pageShop), http.StatusForbidden)
	events := l.audit.all()
	var got []string
	for _, ev := range events {
		if _, ok := ev.(audit.LoginTOTP); ok {
			got = append(got, eventName(ev))
		}
	}
	want := "login_totp:false:no_login login_totp:false:no_login login_totp:false:no_login login_totp:true: login_totp:false:no_login"
	if strings.Join(got, " ") != want {
		t.Errorf("totp entries %v\nwant %s", got, want)
	}
	all := encodeEvents(t, events)
	for _, secret := range []string{l.seed, "287082", l.pw} {
		if strings.Contains(all, secret) || strings.Contains(l.logs.String(), secret) || strings.Contains(l.approverTexts(), secret) {
			t.Errorf("%q is in the audit log, the journal or a message", secret)
		}
	}
	l.vs.checkCleared(t)
}

func TestLoginTOTPTicketExpires(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Unix(59, 0)
	l.svc.setNow(func() time.Time { return now })
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce), http.StatusOK)
	now = now.Add(LoginTOTPTime)
	mustStatus(t, l.totp(itemShop, pageShop), http.StatusForbidden)
}

func TestLoginTOTPWithWindowGrant(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Unix(59, 0)
	l.svc.setNow(func() time.Time { return now })
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveWindow), http.StatusOK)
	for i := range 3 {
		if code := codeOf(t, l.totp(itemShop, pageShop)); code != "287082" {
			t.Errorf("code %d: %q", i, code)
		}
	}
	// The window grant is for the shop item only.
	mustStatus(t, l.totp(itemMail, pageShop), http.StatusForbidden)
}

func TestLoginTOTPNoSeedAndReprompt(t *testing.T) {
	l := newLoginEnv(t, nil)
	mustStatus(t, l.approveLogin(itemMail, pageShop, audit.AnswerApproveOnce), http.StatusOK)
	res := l.totp(itemMail, pageShop) // the mail item has no seed
	mustStatus(t, res, http.StatusForbidden)
	// A window grant does not cover a code of an item with a re-prompt.
	l.shop.Reprompt = true
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce), http.StatusOK) // gives a ticket
	l.shop.Reprompt = false
}

func TestLoginTOTPBadSeed(t *testing.T) {
	l := newLoginEnv(t, nil)
	l.shop.totp = "steam://" + madeUp("seed")
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce), http.StatusOK)
	res := l.totp(itemShop, pageShop)
	mustStatus(t, res, http.StatusForbidden)
	if strings.Contains(string(res.body), "steam") || strings.Contains(l.logs.String(), "steam://") {
		t.Error("the seed shows in an answer or the journal")
	}
	l.vs.checkCleared(t)
}

// loginPre asks for the pre-approval and approves it.
func (l *loginTest) loginPre(item, url string) *result {
	l.t.Helper()
	n := len(l.approver.Asked()) + 1
	p := l.start(l.laptp, api.PathPreapprove, api.PreapproveRequest{Login: item, URL: url, Uses: 1, Reason: "log in for the test"})
	pr := l.waitAsked(n)[n-1].Prompt
	if pr.Kind != audit.KindPreapprove || pr.Login == nil || pr.Login.For != 60*time.Second || pr.Uses != 1 {
		l.t.Errorf("prompt %+v", pr)
	}
	l.tap(pr.RequestID, audit.AnswerApproveOnce)
	return p.wait(l.t)
}

func TestLoginPreapprove(t *testing.T) {
	l := newLoginEnv(t, nil)
	res := l.loginPre(itemShop, pageShop)
	mustStatus(t, res, http.StatusOK)
	if got := l.approver.Asked(); len(got) != 1 {
		t.Fatalf("%d messages", len(got))
	}
	// Another item or origin does not use it: the person is asked. The
	// client hangs up, so nothing is denied.
	for i, tt := range []struct{ item, url string }{{itemMail, pageShop}, {itemShop, "https://shop.example.com/"}} {
		p := l.start(l.laptp, api.PathLogin, l.loginReq(tt.item, tt.url))
		l.waitAsked(i + 2)
		p.cancel()
	}
	// The pre-approval of the shop item on example.com is used once, with
	// no new message.
	before := len(l.approver.Asked())
	res = l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	mustStatus(t, res, http.StatusOK)
	if n := len(l.approver.Asked()); n != before {
		t.Errorf("the use asked the person")
	}
	if code := codeOf(t, l.totp(itemShop, pageShop)); len(code) != 6 {
		t.Errorf("code %q: a login by pre-approval gives one code", code)
	}
	// Used up: the next login needs a tap.
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	pr := l.waitAsked(before + 1)[before].Prompt
	l.tap(pr.RequestID, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
	l.vs.checkCleared(t)
}

func TestLoginPreapproveOtherClient(t *testing.T) {
	l := newLoginEnv(t, func(cfg *config.Broker) {
		s := cfg.Logins["web"]
		s.Clients = []string{"laptop", "ci"}
		cfg.Logins["web"] = s
	})
	mustStatus(t, l.loginPre(itemShop, pageShop), http.StatusOK)
	ci := l.httpClient("ci")
	p := l.start(ci, api.PathLogin, l.loginReq(itemShop, pageShop))
	pr := l.waitAsked(2)[1].Prompt
	l.tap(pr.RequestID, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
}

func TestLoginPreapproveEndsAfterSixtySeconds(t *testing.T) {
	l := newLoginEnv(t, nil)
	mustStatus(t, l.loginPre(itemShop, pageShop), http.StatusOK)
	l.clock.Advance(60 * time.Second)
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	pr := l.waitAsked(2)[1].Prompt
	l.tap(pr.RequestID, audit.AnswerDeny)
	mustStatus(t, p.wait(t), http.StatusForbidden)
}

// TestLoginPreapproveSlowTap: the 60 s start at the tap, not at the
// request. A tap after 100 s still gives a pre-approval.
func TestLoginPreapproveSlowTap(t *testing.T) {
	l := newLoginEnv(t, nil)
	p := l.start(l.laptp, api.PathPreapprove, api.PreapproveRequest{Login: itemShop, URL: pageShop, Uses: 1})
	pr := l.waitAsked(1)[0].Prompt
	l.clock.Advance(100 * time.Second)
	l.tap(pr.RequestID, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusOK)
	l.clock.Advance(30 * time.Second)
	res := l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	mustStatus(t, res, http.StatusOK)
	if n := len(l.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
}

func TestLoginPreapproveDeny(t *testing.T) {
	bad := map[string]api.PreapproveRequest{
		"two uses":     {Login: itemShop, URL: pageShop, Uses: 2},
		"no uses":      {Login: itemShop, URL: pageShop},
		"with times":   {Login: itemShop, URL: pageShop, Uses: 1, From: "2026-10-14T13:00:00Z", Until: "2026-10-14T14:00:00Z"},
		"with secrets": {Login: itemShop, URL: pageShop, Uses: 1, Secrets: []string{"github-token"}},
		"with a key":   {Login: itemShop, URL: pageShop, Uses: 1, Key: "deploy"},
		"no URL":       {Login: itemShop, Uses: 1},
		"no login":     {URL: pageShop, Uses: 1},
		"http page":    {Login: itemShop, URL: "http://example.com/", Uses: 1},
		"other page":   {Login: itemShop, URL: "https://evil.test/", Uses: 1},
		"windows":      {Login: itemShop, URL: pageShop, Uses: 1, Windows: []api.Window{{Kind: api.WindowDaily, From: "03:00", To: "04:00"}}},
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			l := newLoginEnv(t, nil)
			l.noMessage(l.post(t.Context(), l.laptp, api.PathPreapprove, body), http.StatusForbidden)
		})
	}
	t.Run("rule without preapprove", func(t *testing.T) {
		l := newLoginEnv(t, func(cfg *config.Broker) {
			s := cfg.Logins["web"]
			s.Rule.Preapprove = false
			cfg.Logins["web"] = s
		})
		l.noMessage(l.post(t.Context(), l.laptp, api.PathPreapprove, api.PreapproveRequest{Login: itemShop, URL: pageShop, Uses: 1}),
			http.StatusForbidden)
	})
}

// changeAfterAsk starts a login, changes the shop item when the person is
// asked, taps, and returns the answer.
func (l *loginTest) changeAfterAsk(change func()) *result {
	l.t.Helper()
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	pr := l.waitAsked(1)[0].Prompt
	change()
	l.tap(pr.RequestID, audit.AnswerApproveOnce)
	return p.wait(l.t)
}

func TestLoginItemChangesAfterTheTap(t *testing.T) {
	changes := map[string]func(l *loginTest){
		"username":   func(l *loginTest) { l.shop.Username = "mallory@example.com" },
		"name":       func(l *loginTest) { l.shop.Name = "Another name" },
		"collection": func(l *loginTest) { l.shop.Collections = []string{collNone} },
		"uri":        func(l *loginTest) { l.shop.URIs = []store.LoginURI{{URI: "https://evil.test"}} },
		"reprompt":   func(l *loginTest) { l.shop.Reprompt = true },
		"second collection": func(l *loginTest) {
			l.shop.Collections = []string{collWeb, collOther}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			l := newLoginEnv(t, nil)
			res := l.changeAfterAsk(func() { change(l) })
			mustStatus(t, res, http.StatusForbidden)
			if bytes.Contains(res.body, []byte(l.pw)) {
				t.Error("the password is in the answer")
			}
			if strings.Contains(eventNames(l.audit.all()), "secret_sent") {
				t.Error("a password was sent")
			}
			l.vs.checkCleared(t)
		})
	}
}

func TestLoginRuleChangesAfterTheTap(t *testing.T) {
	l := newLoginEnv(t, nil)
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	pr := l.waitAsked(1)[0].Prompt
	// A reload gives the section a longer window: the decided rule differs.
	cfg := *l.svc.view().cfg
	cfg.Logins = map[string]config.Logins{}
	for k, v := range l.svc.view().cfg.Logins {
		cfg.Logins[k] = v
	}
	w := cfg.Logins["web"]
	w.Rule.Window = 4 * time.Hour
	cfg.Logins["web"] = w
	v := *l.svc.view()
	v.cfg = &cfg
	l.svc.cur.Store(&v)
	l.tap(pr.RequestID, audit.AnswerApproveOnce)
	mustStatus(t, p.wait(t), http.StatusForbidden)
}

func TestLoginItemRuleInAnotherSection(t *testing.T) {
	l := newLoginEnv(t, func(cfg *config.Broker) {
		o := cfg.Logins["other"]
		o.Items = map[string]config.LoginItemRule{
			itemShop: {Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways}},
		}
		cfg.Logins["other"] = o
	})
	l.noMessage(l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop)), http.StatusForbidden)
	res := l.listReq(pageShop)
	ans, err := api.ReadAnswer[api.ListLoginsAnswer](bytes.NewReader(res.body))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ans.Logins {
		if e.ID == itemShop {
			t.Errorf("the list holds an item that another section has a rule for")
		}
	}
}

func TestLoginTOTPStoreFailure(t *testing.T) {
	l := newLoginEnv(t, nil)
	mustStatus(t, l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce), http.StatusOK)
	l.shop.fetchErr = errors.New("fake bw: down")
	mustStatus(t, l.totp(itemShop, pageShop), http.StatusServiceUnavailable)
	events := l.audit.all()
	if got := encodeEvents(t, events[len(events)-1:]); !strings.Contains(got, `"cause":"store"`) {
		t.Errorf("last entry %s", got)
	}
}

func TestLoginTOTPNoTicketIsLimited(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	l.svc.setNow(func() time.Time { return now })
	for i := range LoginTOTPNoTicketRate {
		if res := l.totp(itemShop, pageShop); res.status != http.StatusForbidden {
			t.Fatalf("request %d: status %d", i, res.status)
		}
	}
	n := len(l.audit.all())
	mustStatus(t, l.totp(itemShop, pageShop), http.StatusTooManyRequests)
	if got := len(l.audit.all()); got != n {
		t.Errorf("a limited request wrote an entry")
	}
	if l.vs.fetches() != 0 {
		t.Error("a request with no ticket fetched from the store")
	}
}

// A bad TOTP request shares the cap of the requests with no ticket, so a
// loop cannot fill the audit log.
func TestLoginTOTPBadRequestIsLimited(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	l.svc.setNow(func() time.Time { return now })
	for i := range LoginTOTPNoTicketRate {
		if res := l.totp("not-an-id", pageShop); res.status != http.StatusForbidden {
			t.Fatalf("request %d: status %d", i, res.status)
		}
	}
	n := len(l.audit.all())
	if n != LoginTOTPNoTicketRate {
		t.Errorf("got %d entries, want %d", n, LoginTOTPNoTicketRate)
	}
	mustStatus(t, l.totp("not-an-id", pageShop), http.StatusTooManyRequests)
	mustStatus(t, l.totp(itemShop, "http://example.com/"), http.StatusTooManyRequests)
	if got := len(l.audit.all()); got != n {
		t.Errorf("a limited request wrote an entry")
	}
}

func TestLoginListAudited(t *testing.T) {
	l := newLoginEnv(t, nil)
	// No match: one entry with a count of 0 for each section of the client.
	mustStatus(t, l.listReq("https://nothing.test/"), http.StatusOK)
	mustEvents(t, l.audit.all(), "login_list login_list")
	if got := encodeEvents(t, l.audit.all()); strings.Contains(got, `"count":1`) || strings.Contains(got, `"count":2`) {
		t.Errorf("entries %s", got)
	}
	// A bad URL.
	mustStatus(t, l.listReq("http://example.com/"), http.StatusForbidden)
	events := l.audit.all()
	mustEvents(t, events, "login_list login_list login_list")
	if got := encodeEvents(t, events[2:]); !strings.Contains(got, `"cause":"bad_url"`) {
		t.Errorf("entry %s", got)
	}
	// A store failure.
	l.vs.lmu.Lock()
	l.vs.listErr = errors.New("fake bw: down")
	l.vs.lmu.Unlock()
	mustStatus(t, l.listReq(pageShop), http.StatusServiceUnavailable)
	events = l.audit.all()
	if got := encodeEvents(t, events[len(events)-1:]); !strings.Contains(got, `"cause":"store"`) {
		t.Errorf("entry %s", got)
	}
}

func TestLoginListRateIsAudited(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	l.svc.setNow(func() time.Time { return now })
	for range LoginListRate {
		mustStatus(t, l.listReq(pageShop), http.StatusOK)
	}
	n := len(l.audit.all())
	mustStatus(t, l.listReq(pageShop), http.StatusTooManyRequests)
	events := l.audit.all()
	if len(events) != n+1 || !strings.Contains(encodeEvents(t, events[n:]), `"cause":"limit"`) {
		t.Errorf("entries %s", eventNames(events[n:]))
	}
}

func TestLoginRequestRate(t *testing.T) {
	l := newLoginEnv(t, nil)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	l.svc.setNow(func() time.Time { return now })
	for i := range LoginRequestRate {
		if res := l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, "https://nothing.test/")); res.status != http.StatusForbidden {
			t.Fatalf("request %d: status %d", i, res.status)
		}
	}
	// The cap counts requests, so the next one is refused before the store.
	// (A bad page is refused before the cap, so use a good page.)
	for range LoginRequestRate {
		l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq("cccccccc-0000-0000-0000-000000000009", pageShop))
	}
	before := l.vs.fetches()
	mustStatus(t, l.post(t.Context(), l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop)), http.StatusTooManyRequests)
	mustStatus(t, l.post(t.Context(), l.laptp, api.PathPreapprove,
		api.PreapproveRequest{Login: itemShop, URL: pageShop, Uses: 1}), http.StatusTooManyRequests)
	if l.vs.fetches() != before {
		t.Error("a limited request ran the store")
	}
	if n := len(l.approver.Asked()); n != 0 {
		t.Errorf("the approver was asked %d times", n)
	}
	now = now.Add(time.Minute)
	p := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	l.waitAsked(1)
	p.cancel()
}

func TestLoginPreapproveUsedOnce(t *testing.T) {
	l := newLoginEnv(t, nil)
	mustStatus(t, l.loginPre(itemShop, pageShop), http.StatusOK)
	p1 := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	p2 := l.start(l.laptp, api.PathLogin, l.loginReq(itemShop, pageShop))
	var won, other *pendingResult
	select {
	case r := <-p1.done:
		p1.done <- r
		won, other = p1, p2
	case r := <-p2.done:
		p2.done <- r
		won, other = p2, p1
	case <-time.After(waitLimit):
		t.Fatal("no request got the login")
	}
	mustStatus(t, won.wait(t), http.StatusOK)
	// The other one needs a tap of its own.
	l.waitAsked(2)
	other.cancel()
	if n := len(l.approver.Asked()); n != 2 {
		t.Errorf("%d messages, want 2", n)
	}
}
