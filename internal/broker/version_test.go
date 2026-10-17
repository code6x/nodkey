package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/transport"
)

// answer is the final answer to a request of a version test.
type answer struct {
	status int
	header http.Header
	body   []byte
}

// claim sends body as JSON to path with c, with each of claimed as a
// header api.VersionHeader, and returns the answer.
func (e *env) claim(c *http.Client, path string, body any, claimed ...string) answer {
	e.t.Helper()
	res, err := e.tryClaim(c, path, body, claimed...)
	if err != nil {
		e.t.Fatalf("the request failed: %v", err)
	}
	return res
}

// tryClaim is claim that does not fail the test, so it may run in its own
// goroutine.
func (e *env) tryClaim(c *http.Client, path string, body any, claimed ...string) (answer, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return answer{}, err
	}
	req, err := http.NewRequestWithContext(e.t.Context(), http.MethodPost, "https://"+e.addr+path, bytes.NewReader(data))
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Content-Type", api.ContentType)
	for _, v := range claimed {
		req.Header.Add(api.VersionHeader, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, api.MaxAnswer+1))
	if err != nil {
		return answer{}, err
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// mustAnswer fails unless res has the status.
func mustAnswer(t testing.TB, res answer, status int) {
	t.Helper()
	if res.status != status {
		t.Fatalf("status %d, want %d", res.status, status)
	}
}

// rawAnswers sends text on a new TLS connection as the client name, and
// returns the head of each answer that comes, up to the final one: the
// status line and the headers, as they are on the wire.
func (e *env) rawAnswers(name, text string) []string {
	e.t.Helper()
	d := tls.Dialer{Config: transport.ClientTLSConfig(e.clients[name].cert, e.broker.pin)}
	conn, err := d.DialContext(e.t.Context(), "tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, text); err != nil {
		e.t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(waitLimit))
	br := bufio.NewReader(conn)
	var heads []string
	for {
		var head strings.Builder
		for !strings.HasSuffix(head.String(), "\r\n\r\n") {
			b, err := br.ReadByte()
			if err != nil {
				e.t.Fatalf("reading an answer: %v (so far %q)", err, head.String())
			}
			head.WriteByte(b)
		}
		heads = append(heads, head.String())
		if !strings.HasPrefix(head.String(), "HTTP/1.1 1") {
			return heads
		}
	}
}

// headerOf parses the header of the head of an answer.
func headerOf(t testing.TB, head string) textproto.MIMEHeader {
	t.Helper()
	_, rest, _ := strings.Cut(head, "\r\n")
	h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(rest))).ReadMIMEHeader()
	if err != nil {
		t.Fatalf("the header of %q: %v", head, err)
	}
	return h
}

// TestVersionOnEveryAnswer: the broker sends its version on every answer,
// whatever the status: 200, every error, 404 and 405, and the 102
// Processing, which still has the short code. A broker without a valid
// version sends none.
func TestVersionOnEveryAnswer(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	post := func(path, ctype string, body string) string {
		return "POST " + path + " HTTP/1.1\r\nHost: broker\r\nContent-Type: " + ctype + "\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body
	}
	notAllowed, err := json.Marshal(secretsRequest("B", "backup-token")) // a secret of ci
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, text string
		status     string
	}{
		{"200", post(api.PathKeys, api.ContentType, "{}"), "200 OK"},
		{"400", post(api.PathKeys, api.ContentType, `{"x":1}`), "400 Bad Request"},
		{"403", post(api.PathSecrets, api.ContentType, string(notAllowed)), "403 Forbidden"},
		{"404", post("/v1/nope", api.ContentType, "{}"), "404 Not Found"},
		{"405", "GET /v1/keys HTTP/1.1\r\nHost: broker\r\n\r\n", "405 Method Not Allowed"},
		{"413", "POST /v1/keys HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\nContent-Length: 3000000\r\n\r\n",
			"413 Request Entity Too Large"},
		{"415", post(api.PathKeys, "text/plain", "{}"), "415 Unsupported Media Type"},
	} {
		heads := e.rawAnswers("laptop", tt.text)
		last := heads[len(heads)-1]
		if !strings.HasPrefix(last, "HTTP/1.1 "+tt.status+"\r\n") {
			t.Errorf("%s: the answer is %q", tt.name, last)
			continue
		}
		if got := headerOf(t, last).Values(api.VersionHeader); !slices.Equal(got, []string{"0.2.0"}) {
			t.Errorf("%s: the version header is %q, want 0.2.0", tt.name, got)
		}
	}

	// The 102 Processing has the version too, after the short code, and
	// the client still finds the code. The final answer has it as well.
	body, err := json.Marshal(secretsRequest("GH_TOKEN", "github-token"))
	if err != nil {
		t.Fatal(err)
	}
	e.approver.Auto(audit.AnswerDeny)
	heads := e.rawAnswers("laptop", post(api.PathSecrets, api.ContentType, string(body)))
	if len(heads) != 2 {
		t.Fatalf("answers %q, want a 102 and a final one", heads)
	}
	if !strings.HasPrefix(heads[0], "HTTP/1.1 102 Processing\r\nNodkey-Short-Code: ") ||
		!strings.HasSuffix(heads[0], "\r\nNodkey-Version: 0.2.0\r\n\r\n") {
		t.Errorf("the 102 answer is %q", heads[0])
	}
	if code, ok := api.ShortCode(http.StatusProcessing, headerOf(t, heads[0])); !ok ||
		code != e.waitAsked(1)[0].Prompt.ShortCode {
		t.Errorf("the short code of the 102 is %q, %v", code, ok)
	}
	if !strings.HasPrefix(heads[1], "HTTP/1.1 403 Forbidden\r\n") ||
		headerOf(t, heads[1]).Get(api.VersionHeader) != "0.2.0" {
		t.Errorf("the final answer is %q", heads[1])
	}

	// 429: over the cap of requests in progress.
	e.svc.setMaxPerClient(0)
	res := e.claim(e.httpClient("laptop"), api.PathKeys, api.KeysRequest{}, "0.2.0")
	if res.status != http.StatusTooManyRequests || res.header.Get(api.VersionHeader) != "0.2.0" {
		t.Errorf("429: status %d, version %q", res.status, res.header.Values(api.VersionHeader))
	}

	// 503: before Run.
	ne := newEnv(t, envOptions{version: "0.2.0", noRun: true})
	res = ne.claim(ne.httpClient("laptop"), api.PathKeys, api.KeysRequest{})
	if res.status != http.StatusServiceUnavailable || res.header.Get(api.VersionHeader) != "0.2.0" {
		t.Errorf("503: status %d, version %q", res.status, res.header.Values(api.VersionHeader))
	}

	// A source build sends its version as it is; a broker without a valid
	// version sends none.
	for v, want := range map[string][]string{"dev": {"dev"}, "": nil, "0.2.0 beta": nil} {
		ve := newEnv(t, envOptions{version: v})
		for _, path := range []string{api.PathKeys, "/v1/nope"} {
			res := ve.claim(ve.httpClient("laptop"), path, api.KeysRequest{})
			if got := res.header.Values(api.VersionHeader); !slices.Equal(got, want) {
				t.Errorf("a broker with the version %q, %s: the version header is %q, want %q", v, path, got, want)
			}
		}
	}
}

// waitNotices waits until the Service has stopped, so that every try of a
// notice about a version has ended, and returns the notices that went
// out.
func (e *env) waitNotices() []string {
	e.t.Helper()
	e.svc.Close() // it waits for the goroutines of the notices
	return e.notices.wentOut()
}

// versionLines returns the log lines about the versions of clients.
func (e *env) versionLines() []string {
	var lines []string
	for _, l := range strings.Split(e.logs.String(), "\n") {
		if strings.Contains(l, "version") {
			lines = append(lines, l)
		}
	}
	return lines
}

// TestVersionNoticeOncePerClient: a client that claims another release,
// or sends no valid version, gets one log line and one notice in each
// start of the broker, however many versions it claims. The text says
// which side is older and what to run. A value that is not a valid
// version is never logged or shown.
func TestVersionNoticeOncePerClient(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	laptop, ci := e.httpClient("laptop"), e.httpClient("ci")
	claims := [][]string{{"0.1.0"}, {"0.1.1"}, {"0.3.0"}, nil, {"<b>evil</b>"}, {"0.1.0", "0.3.0"}, {"dev"}, {"0.2.0"}}
	for _, c := range claims {
		mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, c...), http.StatusOK)
	}
	for _, c := range [][]string{{"0.1.0 <b>evil</b>"}, {"0.1.0"}, {"0.4.0"}, nil} {
		mustAnswer(t, e.claim(ci, api.PathKeys, api.KeysRequest{}, c...), http.StatusOK)
	}
	notices := e.waitNotices()
	want := []string{
		"The client laptop says that it runs nodkey 0.1.0, which is older than nodkey 0.2.0 on the broker. " +
			"To update it, run there: sudo nodkey update",
		"The client ci sent no version of nodkey, so it may run an older nodkey. The broker runs nodkey 0.2.0. " +
			"To update ci, follow section 13 of docs/setup.md.",
	}
	slices.Sort(notices)
	slices.Sort(want)
	if !slices.Equal(notices, want) {
		t.Errorf("notices:\n%s\nwant:\n%s", strings.Join(notices, "\n"), strings.Join(want, "\n"))
	}
	lines := e.versionLines()
	if len(lines) != 2 ||
		!slices.ContainsFunc(lines, func(l string) bool {
			return strings.Contains(l, `msg="broker: a client says that it runs an older nodkey than the broker; `+
				`update nodkey there" client=laptop client_version=0.1.0 broker_version=0.2.0`)
		}) ||
		!slices.ContainsFunc(lines, func(l string) bool {
			return strings.Contains(l, `msg="broker: a client sent no version of nodkey, so it may run an older `+
				`nodkey; update nodkey there" client=ci broker_version=0.2.0`)
		}) {
		t.Errorf("the log lines about versions:\n%s", strings.Join(lines, "\n"))
	}
	if strings.Contains(e.logs.String(), "evil") || strings.Contains(strings.Join(notices, ""), "evil") {
		t.Error("a value that is not a version is in the log or a notice")
	}
	if len(e.audit.all()) != 0 || len(e.approver.Asked()) != 0 || len(e.approver.Notices()) != 0 {
		t.Error("a version made an audit entry, a message or a notice of the approver")
	}
}

// TestVersionNoticeNewerClient: a client that claims a newer release than
// the broker's gets a notice that says to update the broker.
func TestVersionNoticeNewerClient(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	mustAnswer(t, e.claim(e.httpClient("laptop"), "/v1/nope", api.KeysRequest{}, "0.10.0"), http.StatusNotFound)
	want := []string{"The client laptop says that it runs nodkey 0.10.0, which is newer than nodkey 0.2.0 on the " +
		"broker. To update the broker, run as root on the broker host: nodkey update"}
	if got := e.waitNotices(); !slices.Equal(got, want) {
		t.Errorf("notices %q, want %q", got, want)
	}
	if lines := e.versionLines(); len(lines) != 1 || !strings.Contains(lines[0],
		`a client says that it runs a newer nodkey than the broker; update nodkey on the broker host" `+
			`client=laptop client_version=0.10.0 broker_version=0.2.0`) {
		t.Errorf("the log lines about versions:\n%s", strings.Join(lines, "\n"))
	}
}

// TestNoVersionNotice: no log line and no notice for the same release,
// for a client or a broker that is a build from the source, for a broker
// without a valid version, and for a client whose TLS key no [client.*]
// section pins.
func TestNoVersionNotice(t *testing.T) {
	for _, tt := range []struct {
		broker  string
		claimed [][]string
	}{
		{"0.2.0", [][]string{{"0.2.0"}, {"dev"}, {"1a2b3c4"}, {"0.3.0-rc.1"}, {"v0.1.0"}}},
		{"dev", [][]string{{"0.1.0"}, nil, {"<b>x</b>"}, {"dev"}}},
		{"", [][]string{{"0.1.0"}, nil}},
		{"0.2.0 beta", [][]string{{"0.1.0"}, nil}},
	} {
		e := newEnv(t, envOptions{version: tt.broker})
		for _, c := range tt.claimed {
			for _, client := range []string{"laptop", "ci"} {
				e.claim(e.httpClient(client), api.PathKeys, api.KeysRequest{}, c...)
			}
		}
		if got := e.waitNotices(); len(got) != 0 {
			t.Errorf("broker %q: notices %q, want none", tt.broker, got)
		}
		if lines := e.versionLines(); len(lines) != 0 {
			t.Errorf("broker %q: log lines about versions:\n%s", tt.broker, strings.Join(lines, "\n"))
		}
	}

	// A key that no [client.*] section pins: the TLS layer refuses it, so
	// the claim never reaches the broker.
	e := newEnv(t, envOptions{version: "0.2.0"})
	stranger, err := transport.NewClient(e.addr, newTLSKey(t, "").cert, e.broker.pin)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+e.addr+api.PathKeys,
		strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", api.ContentType)
	req.Header.Set(api.VersionHeader, "0.1.0")
	if resp, err := stranger.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Errorf("a client with an unknown key got an answer: %d", resp.StatusCode)
	}
	if got := e.waitNotices(); len(got) != 0 {
		t.Errorf("a client with an unknown key: notices %q, want none", got)
	}
	if lines := e.versionLines(); len(lines) != 0 {
		t.Errorf("a client with an unknown key: log lines about versions:\n%s", strings.Join(lines, "\n"))
	}
}

// TestVersionClaimChangesNothing: the claimed version is a claim. With any
// value, or none, a request gets the same answer and the same audit
// entries: for the list of keys, for a secret that the client may not
// use, for a wrong path, and for a secret that the person approves.
func TestVersionClaimChangesNothing(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	e.approver.Auto(audit.AnswerApproveOnce)
	c := e.httpClient("laptop")
	claims := [][]string{nil, {"0.2.0"}, {"0.1.0"}, {"0.3.0"}, {"dev"}, {"bad value"}, {"0.1.0", "0.2.0"},
		{strings.Repeat("9", 4000)}}
	type outcome struct {
		statuses []int
		bodies   [][]byte
		entries  string
	}
	var first *outcome
	for i, claimed := range claims {
		e.clock.Advance(time.Minute) // so the limit of 6 messages a minute does not hold a request
		before := len(e.audit.all())
		var o outcome
		for _, rq := range []struct {
			path string
			body any
		}{
			{api.PathKeys, api.KeysRequest{}},
			{api.PathSecrets, secretsRequest("B", "backup-token")},
			{"/v1/nope", api.KeysRequest{}},
			{api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")},
		} {
			res := e.claim(c, rq.path, rq.body, claimed...)
			o.statuses = append(o.statuses, res.status)
			o.bodies = append(o.bodies, res.body)
		}
		events := e.audit.all()[before:]
		names := eventNames(events)
		// The request IDs differ; the entries must not.
		o.entries = names
		if first == nil {
			first = &o
			if !slices.Equal(o.statuses, []int{200, 403, 404, 200}) ||
				names != "request denied:not_allowed request decision:approve_once secret_sent" {
				t.Fatalf("without a version: statuses %v, entries %s", o.statuses, names)
			}
			continue
		}
		if !slices.Equal(o.statuses, first.statuses) || o.entries != first.entries {
			t.Errorf("claim %d: statuses %v and entries %s; without a version %v and %s", i, o.statuses, o.entries,
				first.statuses, first.entries)
		}
		for j := range o.bodies {
			if !bytes.Equal(o.bodies[j], first.bodies[j]) {
				// The bodies are not printed: one holds a value.
				t.Errorf("claim %d: answer %d differs (%d bytes, without a version %d)", i, j, len(o.bodies[j]),
					len(first.bodies[j]))
			}
		}
	}
	e.main.checkCleared(t)
}

// TestVersionNoticeKeepsNeverAskNotices: a notice about a version does not
// take from the limit of the notices of "never ask" uses: right after it,
// the client still gets all of its approval.MaxNoticesPerMinute uses with
// a notice, and then the limit denies, as without it.
func TestVersionNoticeKeepsNeverAskNotices(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	ci := e.httpClient("ci")
	for i := range approval.MaxNoticesPerMinute {
		res := e.claim(ci, api.PathSecrets, secretsRequest("B", "backup-token"), "0.1."+strconv.Itoa(i))
		if res.status != http.StatusOK {
			t.Fatalf("\"never ask\" use %d: status %d", i+1, res.status)
		}
	}
	res := e.claim(ci, api.PathSecrets, secretsRequest("B", "backup-token"), "0.1.0")
	if res.status != http.StatusTooManyRequests {
		t.Errorf("one use over the limit: status %d, want 429", res.status)
	}
	if n := len(e.approver.Notices()); n != approval.MaxNoticesPerMinute {
		t.Errorf("%d notices of \"never ask\" uses, want %d", n, approval.MaxNoticesPerMinute)
	}
	if got := e.waitNotices(); len(got) != 1 {
		t.Errorf("%d notices about versions, want 1: %q", len(got), got)
	}
}

// failWith returns a fail function for the notice log that fails each
// try while failing is set.
func failWith(failing *atomic.Bool) func(string) error {
	return func(string) error {
		if failing.Load() {
			return errors.New("telegram: sendMessage: Telegram asks to wait (429)")
		}
		return nil
	}
}

// TestVersionNoticeRetry: a try that fails changes nothing for the
// request: its answer comes at once, as without it. The failure is
// logged, once for each try. The next try comes only with a request of
// the client, and only at least a minute after the failure: an earlier
// request, or the time alone, starts none. Once a notice went out, no
// more tries come in this start. The log line about the version comes
// once.
func TestVersionNoticeRetry(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	e.svc.setNow(e.clock.Now)
	var failing atomic.Bool
	failing.Store(true)
	e.notices.set(func(n *noticeLog) { n.fail = failWith(&failing) })
	laptop := e.httpClient("laptop")
	request := func() {
		t.Helper()
		mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.1.0"), http.StatusOK)
		e.svc.waitVersionTry(t, "laptop")
	}
	tries := func(want int) {
		t.Helper()
		if got, _ := e.notices.tried(); len(got) != want {
			t.Fatalf("%d tries, want %d", len(got), want)
		}
	}
	request() // the first try fails
	tries(1)
	request()
	request()
	e.clock.Advance(versionRetry - time.Second)
	request()
	tries(1)
	e.clock.Advance(time.Second) // a minute after the failure: still no try without a request
	tries(1)
	request() // the second try, which fails too
	tries(2)
	e.clock.Advance(versionRetry)
	failing.Store(false)
	request() // the third try goes out
	tries(3)
	e.clock.Advance(10 * versionRetry)
	request()
	if got := e.waitNotices(); len(got) != 1 {
		t.Errorf("%d notices went out, want 1", len(got))
	}
	tries(3)
	logs := e.logs.String()
	if n := strings.Count(logs, "a client says that it runs an older nodkey"); n != 1 {
		t.Errorf("%d log lines about the version, want 1:\n%s", n, logs)
	}
	if n := strings.Count(logs, `the notice about the version of a client did not go out; a request of the client `+
		`a minute later or more tries again" client=laptop error="telegram: sendMessage: Telegram asks to wait (429)"`); n != 2 ||
		strings.Contains(logs, "no new try") {
		t.Errorf("%d log lines about failed tries, want 2:\n%s", n, logs)
	}
}

// TestVersionNoticeHangs: a try that hangs does not hold the requests,
// and Close ends it. Its log line says that no new try comes.
func TestVersionNoticeHangs(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	e.notices.set(func(n *noticeLog) { n.gate = make(chan struct{}) }) // never opens
	laptop := e.httpClient("laptop")
	start := time.Now()
	for range 3 {
		mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.1.0"), http.StatusOK)
	}
	if d := time.Since(start); d > waitLimit/2 {
		t.Errorf("the requests took %s while the notice hung", d)
	}
	waitLog(t, e.logs, "a client says that it runs an older nodkey")
	closed := make(chan struct{})
	go func() {
		e.svc.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(waitLimit):
		t.Fatal("Close waits for a notice that hangs")
	}
	waitLog(t, e.logs, "the notice about the version of a client did not go out; the broker is stopping, so no "+
		"new try comes")
	if strings.Contains(e.logs.String(), "tries again") {
		t.Errorf("the log promises a new try while the broker stops:\n%s", e.logs.String())
	}
	if got, _ := e.notices.tried(); len(got) != 1 {
		t.Errorf("%d tries of the notice, want 1", len(got))
	}
}

// TestVersionNoticeFailsAfterTheApproverStopped: a try that fails after
// the approver stopped says that no new try comes, and none comes.
func TestVersionNoticeFailsAfterTheApproverStopped(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0", noRun: true})
	e.svc.setNow(e.clock.Now)
	gate := make(chan struct{})
	var failing atomic.Bool
	failing.Store(true)
	e.notices.set(func(n *noticeLog) { n.gate, n.fail = gate, failWith(&failing) })
	ctx, cancel := context.WithCancel(t.Context())
	e.startRun(ctx)
	laptop := e.httpClient("laptop")
	mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.1.0"), http.StatusOK)
	cancel() // the approver stops while the try waits at the gate
	select {
	case <-e.runErr:
	case <-time.After(waitLimit):
		t.Fatal("Run did not return")
	}
	close(gate) // the try fails
	e.svc.waitVersionTry(t, "laptop")
	logs := waitLog(t, e.logs, "the notice about the version of a client did not go out; the broker is stopping, "+
		"so no new try comes")
	if strings.Contains(logs, "tries again") {
		t.Errorf("the log promises a new try after the approver stopped:\n%s", logs)
	}
	e.clock.Advance(versionRetry)
	e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.1.0") // 503 now
	if got, _ := e.notices.tried(); len(got) != 1 {
		t.Errorf("%d tries, want 1", len(got))
	}
}

// TestVersionNoticeOneTryAtATime: many requests of one client at the same
// time, while a try runs, start no other try.
func TestVersionNoticeOneTryAtATime(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0"})
	e.svc.setNow(e.clock.Now)
	gate := make(chan struct{})
	var failing atomic.Bool
	failing.Store(true)
	e.notices.set(func(n *noticeLog) { n.gate, n.fail = gate, failWith(&failing) })
	laptop := e.httpClient("laptop")
	burst := func() {
		t.Helper()
		var wg sync.WaitGroup
		statuses := make([]int, 20)
		for i := range statuses {
			wg.Go(func() {
				res, err := e.tryClaim(laptop, api.PathKeys, api.KeysRequest{}, "0.1.0")
				if err == nil {
					statuses[i] = res.status
				}
			})
		}
		wg.Wait()
		for i, status := range statuses {
			if status != http.StatusOK {
				t.Fatalf("request %d: status %d", i, status)
			}
		}
	}
	burst() // the first try waits at the gate
	if tries, most := e.notices.tried(); len(tries) != 1 || most != 1 {
		t.Fatalf("%d tries, %d at the same time; want 1 and 1", len(tries), most)
	}
	close(gate) // the try fails
	e.svc.waitVersionTry(t, "laptop")
	e.clock.Advance(versionRetry)
	burst()
	e.svc.waitVersionTry(t, "laptop")
	if tries, most := e.notices.tried(); len(tries) != 2 || most != 1 {
		t.Errorf("%d tries, %d at the same time; want 2 and 1", len(tries), most)
	}
}

// TestVersionNoticeForEveryClient: with more old clients in one minute
// than the limit of the notices lets through, each client still gets its
// notice in the end. The limit here stands for that of Inform: 3 tries in
// any 60 seconds. So 3 clients cannot use up the places and hide another
// old client.
func TestVersionNoticeForEveryClient(t *testing.T) {
	more := []string{"agent-1", "agent-2", "agent-3"}
	e := newEnv(t, envOptions{version: "0.2.0", clients: more})
	e.svc.setNow(e.clock.Now)
	var mu sync.Mutex
	var sentAt []time.Time
	e.notices.set(func(n *noticeLog) {
		n.fail = func(string) error {
			mu.Lock()
			defer mu.Unlock()
			now := e.clock.Now()
			sentAt = slices.DeleteFunc(sentAt, func(at time.Time) bool { return now.Sub(at) >= time.Minute })
			if len(sentAt) >= 3 {
				return errors.New("telegram: too many notices of the broker in the last minute")
			}
			sentAt = append(sentAt, now)
			return nil
		}
	})
	clients := append([]string{"laptop", "ci"}, more...)
	round := func() {
		t.Helper()
		for _, name := range clients {
			mustAnswer(t, e.claim(e.httpClient(name), api.PathKeys, api.KeysRequest{}, "0.1.0"), http.StatusOK)
			e.svc.waitVersionTry(t, name)
		}
	}
	round() // 3 notices go out, 2 meet the limit
	if got := e.notices.wentOut(); len(got) != 3 {
		t.Fatalf("%d notices went out in the first minute, want 3", len(got))
	}
	round() // within the minute: no try
	e.clock.Advance(versionRetry)
	round() // the other 2 go out
	got := e.waitNotices()
	var want []string
	for _, name := range clients {
		want = append(want, "The client "+name+" says that it runs nodkey 0.1.0, which is older than nodkey 0.2.0 "+
			"on the broker. To update it, run there: sudo nodkey update")
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("notices:\n%s\nwant one for each client:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if tries, _ := e.notices.tried(); len(tries) != len(clients)+2 {
		t.Errorf("%d tries, want %d", len(tries), len(clients)+2)
	}
}

// TestVersionNoticeNeedsRun: before Run, and after the approver stopped,
// no notice goes out, and none is lost: a later request of the client,
// while Run runs, gets it.
func TestVersionNoticeNeedsRun(t *testing.T) {
	e := newEnv(t, envOptions{version: "0.2.0", noRun: true})
	laptop := e.httpClient("laptop")
	res := e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.1.0")
	if res.status != http.StatusServiceUnavailable {
		t.Fatalf("before Run: status %d", res.status)
	}
	ctx, cancel := context.WithCancel(t.Context())
	e.startRun(ctx)
	mustAnswer(t, e.claim(laptop, api.PathKeys, api.KeysRequest{}, "0.1.0"), http.StatusOK)
	waitLog(t, e.logs, "a client says that it runs an older nodkey")
	cancel()
	select {
	case <-e.runErr:
	case <-time.After(waitLimit):
		t.Fatal("Run did not return")
	}
	// The approver stopped: no notice for ci.
	e.claim(e.httpClient("ci"), api.PathKeys, api.KeysRequest{}, "0.1.0")
	if got := e.waitNotices(); len(got) != 1 || !strings.Contains(got[0], "The client laptop ") {
		t.Errorf("notices %q, want one for laptop", got)
	}
}
