package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/totp"
)

// The item and the pages of the recorded requests in
// testdata/agent-browser-0.38.1.
const (
	recItem     = "11111111-1111-1111-1111-111111111111"
	recPage     = "https://127.0.0.1:18766/login.html"
	recListPage = "https://example.com/"
	recColl     = "00000000-0000-0000-0000-0000000000aa"
	// recSeed is the base32 form of "12345678901234567890", the seed of
	// RFC 6238 appendix B.
	recSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

// recorded returns a recorded request of agent-browser.
func recorded(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "agent-browser-"+PluginVersion, name)) //nolint:gosec // G304: a file of the test data.
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// pluginLoginStore is a bw store with one login item, recItem, in the
// collection recColl.
type pluginLoginStore struct {
	memStore
	mu       sync.Mutex
	password string
	given    [][]byte
}

func (s *pluginLoginStore) item() store.LoginItem {
	host := 1
	return store.LoginItem{
		ID: recItem, Name: "Example shop", Username: "alice@example.com", Collections: []string{recColl},
		URIs: []store.LoginURI{{URI: "https://127.0.0.1:18766", Match: &host}, {URI: "https://example.com"}},
	}
}

func (s *pluginLoginStore) ListLogins(_ context.Context, collection string) ([]store.LoginItem, error) {
	if collection != recColl {
		return nil, nil
	}
	return []store.LoginItem{s.item()}, nil
}

func (s *pluginLoginStore) FetchLogin(_ context.Context, id string) (store.Login, error) {
	if id != recItem {
		return store.Login{}, fmt.Errorf("fake bw: not found: %w", store.ErrFailed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pw, seed := []byte(s.password), []byte(recSeed)
	s.given = append(s.given, pw, seed)
	return store.Login{LoginItem: s.item(), Password: store.NewValue(pw), TOTP: store.NewValue(seed)}, nil
}

// cleared reports whether every password and seed that the store gave out
// is cleared.
func (s *pluginLoginStore) cleared() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.given {
		if !bytes.Equal(b, make([]byte, len(b))) {
			return false
		}
	}
	return true
}

// pluginEnv is a test broker with [logins.web] for laptop: ask always,
// preapprove allowed.
type pluginEnv struct {
	tb *testBroker
	vs *pluginLoginStore
	pw string
}

func newPluginEnv(t *testing.T) *pluginEnv {
	t.Helper()
	// The password has the characters that JSON must escape.
	pw := madeUp(`shop"pass\word`) + "\té"
	vs := &pluginLoginStore{password: pw}
	tb := newTestBrokerFull(t, "", func(cfg *config.Broker) {
		cfg.Stores["vault"] = config.Store{Name: "vault", Type: config.StoreBW}
		cfg.Preapprove = config.DefaultPreapprove()
		cfg.Logins = map[string]config.Logins{"web": {Name: "web", Store: "vault", Collection: recColl,
			Clients: []string{"laptop"}, Rule: config.Rule{Ask: config.AskAlways, Preapprove: true}}}
	}, map[string]store.Store{"vault": vs})
	return &pluginEnv{tb: tb, vs: vs, pw: pw}
}

// plugin runs nodkey agent-browser-plugin with the request req, and
// returns the exit code, stdout and stderr.
func (e *pluginEnv) plugin(t *testing.T, req []byte) (int, string, string) {
	t.Helper()
	var b *Broker
	if e != nil {
		b = e.tb.client(t)
	}
	return runPlugin(t, b, req)
}

func runPlugin(t *testing.T, b *Broker, req []byte) (int, string, string) {
	t.Helper()
	r := pluginRunner{
		load: func(string) (*Broker, error) {
			if b == nil {
				return nil, errors.New("this test must not connect to a broker")
			}
			return b, nil
		},
		configPath: func() (string, error) { return "/nonexistent/client.toml", nil },
	}
	var stdout, stderr bytes.Buffer
	code := r.run(t.Context(), nil, bytes.NewReader(req), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// pluginAnswer is an answer of the plugin.
type pluginAnswer struct {
	Protocol   string `json:"protocol"`
	Success    bool   `json:"success"`
	Error      string `json:"error"`
	Credential *struct {
		Username string `json:"username"`
		Password string `json:"password"`
		URL      string `json:"url"`
	} `json:"credential"`
	Data     json.RawMessage `json:"data"`
	Manifest json.RawMessage `json:"manifest"`
}

// readAnswer checks that out is one line with one JSON object of the
// protocol, and returns it.
func readAnswer(t *testing.T, out string) pluginAnswer {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("stdout is not one line: %q", safe(out))
	}
	var a pluginAnswer
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil || a.Protocol != PluginProtocol {
		t.Fatalf("answer %q: %v", safe(out), err)
	}
	return a
}

// noValue fails when s holds the password in any common form.
func (e *pluginEnv) noValue(t *testing.T, where, s string) {
	t.Helper()
	pwJSON, _ := json.Marshal(e.pw)
	for _, v := range []string{e.pw, string(pwJSON[1 : len(pwJSON)-1]), base64.StdEncoding.EncodeToString([]byte(e.pw)),
		madeUpCore(e.pw)} {
		if v != "" && strings.Contains(s, v) {
			t.Errorf("the password is in %s", where)
		}
	}
}

// madeUpCore is the part of a madeUp value with no special characters.
func madeUpCore(v string) string {
	i := strings.LastIndex(v, "-")
	if i < 0 {
		return v
	}
	return v[i+1 : min(len(v), i+20)]
}

// auditText returns the audit log as text.
func (e *pluginEnv) auditText(t *testing.T) string {
	t.Helper()
	e.tb.audit.mu.Lock()
	defer e.tb.audit.mu.Unlock()
	data, err := json.Marshal(e.tb.audit.events)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestPluginContract: the recorded requests of agent-browser, against a
// test broker. nodkey preapprove waits more than 60 s for the tap; then
// auth login gets the login with no tap, and nodkey.totp one code. The
// password is nowhere but in the credential.
func TestPluginContract(t *testing.T) {
	e := newPluginEnv(t)
	tb := e.tb

	// nodkey preapprove --login: the tap comes after 100 s.
	g := testGranter(tb.client(t), nil)
	done := make(chan struct{})
	var preCode int
	var preErr bytes.Buffer
	go func() {
		defer close(done)
		preCode = g.runPreapprove(t.Context(), []string{"--login", recItem, "--url", recPage}, &bytes.Buffer{}, &preErr)
	}()
	asked := tb.waitAsked(t, 1)
	pr := asked[0].Prompt
	if pr.Kind != audit.KindPreapprove || pr.Login == nil || pr.Login.For != 60*time.Second {
		t.Fatalf("prompt %+v %q", pr, asked[0].Text)
	}
	tb.clock.Advance(100 * time.Second)
	if err := tb.approver.Tap(pr.RequestID, audit.AnswerApproveOnce); err != nil {
		t.Fatal(err)
	}
	<-done
	if preCode != exitOK {
		t.Fatalf("preapprove: exit %d: %s", preCode, safe(preErr.String()))
	}

	// agent-browser auth login: the recorded credential.resolve.
	code, out, errText := e.plugin(t, recorded(t, "credential-resolve.json"))
	if code != exitOK || errText != "" {
		t.Fatalf("exit %d, stderr %q", code, safe(errText))
	}
	a := readAnswer(t, out)
	if !a.Success || a.Credential == nil || a.Credential.Username != "alice@example.com" ||
		a.Credential.Password != e.pw || a.Credential.URL != recPage {
		t.Fatalf("answer %q", safe(out))
	}
	if n := len(tb.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1: the login must not ask", n)
	}

	// The credential's URL is the page as the broker read it.
	if strings.Contains(a.Credential.URL, "#") {
		t.Errorf("url %q", a.Credential.URL)
	}

	// The second login has no pre-approval: it needs a tap, and the
	// person is not asked.
	code, out, errText = e.plugin(t, recorded(t, "credential-resolve.json"))
	a = readAnswer(t, out)
	if code != exitOK || a.Success || !strings.Contains(a.Error, "nodkey preapprove --login") ||
		!strings.Contains(errText, "needs a tap") {
		t.Errorf("second login: exit %d, %q, stderr %q", code, safe(out), safe(errText))
	}
	if n := len(tb.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}

	// The recorded nodkey.totp: one code, the RFC 6238 code of now.
	_, out, _ = e.plugin(t, recorded(t, "plugin-run-totp.json"))
	a = readAnswer(t, out)
	var data struct {
		Code string `json:"code"`
	}
	if !a.Success || json.Unmarshal(a.Data, &data) != nil {
		t.Fatalf("totp answer %q", safe(out))
	}
	key, err := totp.Parse([]byte(recSeed))
	if err != nil {
		t.Fatal(err)
	}
	// The broker's own clock is the real one; the code is of now, or of
	// the step before when a step ended in between.
	now := time.Now()
	c1, _ := key.Code(now)
	c0, _ := key.Code(now.Add(-key.Period()))
	if data.Code != c1 && data.Code != c0 {
		t.Errorf("code %q, want %q", data.Code, c1)
	}
	// A second code needs a new login.
	_, out, _ = e.plugin(t, recorded(t, "plugin-run-totp.json"))
	if a = readAnswer(t, out); a.Success || !strings.Contains(a.Error, "already given") {
		t.Errorf("second code: %q", out)
	}

	// The recorded nodkey.list: IDs, names and usernames only.
	_, out, _ = e.plugin(t, recorded(t, "plugin-run-list.json"))
	a = readAnswer(t, out)
	if !a.Success || string(a.Data) != `{"logins":[{"id":"`+recItem+`","name":"Example shop","username":"alice@example.com"}]}` {
		t.Errorf("list answer %q", safe(out))
	}

	e.noValue(t, "the audit log", e.auditText(t))
	e.noValue(t, "the messages", tb.approver.Asked()[0].Text)
	if !e.vs.cleared() {
		t.Error("a value that the store gave out is not cleared")
	}
}

// TestPluginValuesOnlyInTheCredential: in every answer and on stderr the
// password is only in the credential of credential.resolve.
func TestPluginValuesOnlyInTheCredential(t *testing.T) {
	e := newPluginEnv(t)
	e.tb.approver.Auto(audit.AnswerApproveOnce)
	g := testGranter(e.tb.client(t), nil)
	var stderr bytes.Buffer
	if code := g.runPreapprove(t.Context(), []string{"--login", recItem, "--url", recPage}, &stderr, &stderr); code != exitOK {
		t.Fatalf("preapprove: %s", safe(stderr.String()))
	}
	e.noValue(t, "the stderr of preapprove", stderr.String())
	code, out, errText := e.plugin(t, recorded(t, "credential-resolve.json"))
	if code != exitOK || !readAnswer(t, out).Success {
		t.Fatalf("login: %q", safe(out))
	}
	e.noValue(t, "the plugin's stderr", errText)
	for _, name := range []string{"plugin-run-list.json", "plugin-run-totp.json", "credential-resolve.json"} {
		_, out, errText := e.plugin(t, recorded(t, name))
		e.noValue(t, name+" stdout", out)
		e.noValue(t, name+" stderr", errText)
	}
	e.noValue(t, "the audit log", e.auditText(t))
}

// TestPluginRefusals: requests that the plugin refuses before it loads
// the config. Each gets one answer with success false, exit code 0 (else
// agent-browser drops the answer), and one line on stderr.
func TestPluginRefusals(t *testing.T) {
	t.Parallel()
	env := func(item, url string) string {
		return `{"capability":"credential.read","protocol":"agent-browser.plugin.v1","request":{"itemRef":` + item +
			`,"profileName":"p","url":` + url + `},"type":"credential.resolve"}`
	}
	tests := map[string]struct{ req, want string }{
		"no url (recorded)": {string(recorded(t, "credential-resolve-no-url.json")), "item ID"},
		"no url":            {env(`"`+recItem+`"`, `null`), "no page URL"},
		"empty url":         {env(`"`+recItem+`"`, `""`), "no page URL"},
		"http page":         {env(`"`+recItem+`"`, `"http://example.com/"`), "https"},
		"user in url":       {env(`"`+recItem+`"`, `"https://a:b@example.com/"`), "page URL"},
		"item name":         {env(`"Example shop"`, `"https://example.com/"`), "item ID"},
		"no item":           {env(`null`, `"https://example.com/"`), "item ID"},
		"item not a string": {env(`1`, `"https://example.com/"`), "itemRef"},
		"other protocol":    {strings.Replace(env(`"`+recItem+`"`, `"https://example.com/"`), ".v1", ".v2", 1), "protocol"},
		"no protocol":       {`{"type":"credential.resolve","capability":"credential.read","request":{}}`, "protocol"},
		"wrong capability":  {strings.Replace(env(`"`+recItem+`"`, `"https://example.com/"`), "credential.read", "command.run", 1), "capability"},
		"unknown type":      {`{"protocol":"agent-browser.plugin.v1","type":"browser.launch","capability":"browser.provider","request":{}}`, "unknown request type"},
		"no request":        {`{"protocol":"agent-browser.plugin.v1","type":"credential.resolve","capability":"credential.read"}`, "request"},
		"request a list":    {`{"protocol":"agent-browser.plugin.v1","type":"nodkey.list","capability":"command.run","request":[]}`, "request"},
		"list no url":       {`{"protocol":"agent-browser.plugin.v1","type":"nodkey.list","capability":"command.run","request":{}}`, "payload"},
		"list http":         {`{"protocol":"agent-browser.plugin.v1","type":"nodkey.list","capability":"command.run","request":{"url":"http://example.com/"}}`, "https"},
		"totp no item":      {`{"protocol":"agent-browser.plugin.v1","type":"nodkey.totp","capability":"command.run","request":{"url":"https://example.com/"}}`, "item ID"},
		"not json":          {`not json`, "JSON"},
		"empty":             {``, "JSON"},
		"too long":          {`{"protocol":"` + strings.Repeat("a", maxPluginRequest) + `"}`, "longer"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			code, out, errText := runPlugin(t, nil, []byte(tt.req))
			a := readAnswer(t, out)
			if code != exitOK || a.Success || !strings.HasPrefix(a.Error, "nodkey: ") || !strings.Contains(a.Error, tt.want) {
				t.Errorf("exit %d, answer %q; want an error with %q", code, out, tt.want)
			}
			if strings.Count(errText, "\n") != 1 || !strings.HasPrefix(errText, "nodkey agent-browser-plugin: ") {
				t.Errorf("stderr %q", errText)
			}
			if strings.Contains(out, "Example shop") || strings.Contains(out, "a:b") {
				t.Errorf("the error repeats the request: %q", out)
			}
		})
	}
}

// TestPluginBrokerRefusals: the broker refuses, or cannot be reached.
func TestPluginBrokerRefusals(t *testing.T) {
	t.Parallel()
	e := newPluginEnv(t)
	other := `{"capability":"credential.read","protocol":"agent-browser.plugin.v1","request":{"itemRef":"` +
		recItem + `","url":"https://other.example.net/"},"type":"credential.resolve"}`
	// An origin that matches no URI of the item: denied, with no message.
	_, out, _ := e.plugin(t, []byte(other))
	if a := readAnswer(t, out); a.Success || !strings.Contains(a.Error, "denied") {
		t.Errorf("other origin: %q", out)
	}
	// Another item.
	otherItem := strings.Replace(string(recorded(t, "credential-resolve.json")), recItem, "22222222-2222-2222-2222-222222222222", 1)
	_, out, _ = e.plugin(t, []byte(otherItem))
	if a := readAnswer(t, out); a.Success {
		t.Errorf("other item: %q", out)
	}
	// A code with no login before it.
	_, out, _ = e.plugin(t, recorded(t, "plugin-run-totp.json"))
	if a := readAnswer(t, out); a.Success || !strings.Contains(a.Error, "in the last 2 minutes") {
		t.Errorf("totp: %q", out)
	}
	if n := len(e.tb.approver.Asked()); n != 0 {
		t.Errorf("%d messages, want 0", n)
	}
	// The config cannot be loaded.
	r := pluginRunner{load: func(string) (*Broker, error) { return nil, errors.New("config /x: broker: missing") },
		configPath: func() (string, error) { return "/x", nil }}
	var stdout, stderr bytes.Buffer
	if code := r.run(t.Context(), nil, bytes.NewReader(recorded(t, "credential-resolve.json")), &stdout, &stderr); code != exitOK {
		t.Errorf("exit %d", code)
	}
	if a := readAnswer(t, stdout.String()); a.Success || !strings.Contains(a.Error, "config /x") {
		t.Errorf("config: %q", stdout.String())
	}
}

// TestPluginDeadline: a broker that does not answer in time. The plugin
// answers before agent-browser stops it.
func TestPluginDeadline(t *testing.T) {
	t.Parallel()
	if PluginResolveTime >= 15*time.Second || PluginCommandTime >= 60*time.Second {
		t.Fatal("a wait is not shorter than agent-browser's limit")
	}
	fb := newFakeBroker(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	r := pluginRunner{load: func(string) (*Broker, error) { return fb.b, nil },
		configPath: func() (string, error) { return "/x", nil }}
	var stdout, stderr bytes.Buffer
	_ = r.run(ctx, nil, bytes.NewReader(recorded(t, "credential-resolve.json")), &stdout, &stderr)
	if a := readAnswer(t, stdout.String()); a.Success || !strings.Contains(a.Error, "in time") {
		t.Errorf("answer %q", stdout.String())
	}
}

func TestPluginManifestAndUsage(t *testing.T) {
	t.Parallel()
	code, out, _ := runPlugin(t, nil, []byte(`{"protocol":"agent-browser.plugin.v1","type":"plugin.manifest","capability":"","request":{}}`))
	if a := readAnswer(t, out); code != exitOK || !a.Success ||
		string(a.Manifest) != `{"name":"nodkey","capabilities":["credential.read","command.run"]}` {
		t.Errorf("manifest %q", out)
	}
	var stdout, stderr bytes.Buffer
	r := pluginRunner{}
	if code := r.run(t.Context(), []string{"--help"}, strings.NewReader(""), &stdout, &stderr); code != exitOK ||
		!strings.Contains(stderr.String(), PluginVersion) || stdout.Len() != 0 {
		t.Errorf("help: %d %q", code, stderr.String())
	}
	stderr.Reset()
	if code := r.run(t.Context(), []string{"extra"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage ||
		strings.Count(stderr.String(), "\n") != 1 || stdout.Len() != 0 {
		t.Errorf("usage: %d %q", code, stderr.String())
	}
}

// TestCredentialAnswer: the password is escaped as encoding/json does,
// in a buffer of the exact size; a password that is not UTF-8 is refused.
func TestCredentialAnswer(t *testing.T) {
	t.Parallel()
	for _, pw := range []string{"plain", `q"uo\te`, "tab\tnl\n\x00\x1f", "é世\U0001F600", "<>& ", ""} {
		b, err := credentialAnswer("alice@example.com", []byte(pw), recPage)
		if err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		if len(b) != cap(b) {
			t.Errorf("%q: the buffer grew", pw)
		}
		a := readAnswer(t, string(b))
		if !a.Success || a.Credential == nil || a.Credential.Password != pw || a.Credential.URL != recPage {
			t.Errorf("%q: %q", pw, b)
		}
	}
	if _, err := credentialAnswer("u", []byte{0xff, 'a'}, recPage); !errors.Is(err, errPasswordText) {
		t.Errorf("not UTF-8: %v", err)
	}
}

// TestPluginPageWithFragment: the page goes to the broker, and back to
// agent-browser, as the broker reads it: with no fragment.
func TestPluginPageWithFragment(t *testing.T) {
	t.Parallel()
	e := newPluginEnv(t)
	e.tb.approver.Auto(audit.AnswerApproveOnce)
	g := testGranter(e.tb.client(t), nil)
	var stderr bytes.Buffer
	if code := g.runPreapprove(t.Context(), []string{"--login", recItem, "--url", recPage}, &stderr, &stderr); code != exitOK {
		t.Fatalf("preapprove: %s", safe(stderr.String()))
	}
	req := strings.Replace(string(recorded(t, "credential-resolve.json")), recPage, recPage+"#top", 1)
	_, out, _ := e.plugin(t, []byte(req))
	if a := readAnswer(t, out); !a.Success || a.Credential.URL != recPage {
		t.Errorf("answer %q", safe(out))
	}
}
