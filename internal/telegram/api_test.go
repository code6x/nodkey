package telegram

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sendParams is a small sendMessage call for the tests of the client.
var sendParams = sendMessageParams{ChatID: approverID, Text: "hello", ParseMode: "HTML", LinkPreviewOptions: noPreview}

func callErr(t *testing.T, err error) *apiError {
	t.Helper()
	var e *apiError
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not an apiError", err)
	}
	return e
}

func checkWaits(t *testing.T, got []time.Duration, want ...time.Duration) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("waits %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("waits %v, want %v", got, want)
			return
		}
	}
}

// TestCallRetryAfter checks that a 429 answer is tried again after the
// wait that Telegram asks for.
func TestCallRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.f.reply("sendMessage", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 3","parameters":{"retry_after":3}}`)
	if err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil); err != nil {
		t.Fatal(err)
	}
	checkWaits(t, e.sleeps.all(), 3*time.Second)
	if n := len(e.f.callsOf("sendMessage")); n != 2 {
		t.Errorf("%d tries, want 2", n)
	}
}

// TestCallRetryAfterWithoutJSON checks that a 429 whose body is not the
// JSON of the Bot API is tried again after a wait, as a 429 of Telegram
// without retry_after.
func TestCallRetryAfterWithoutJSON(t *testing.T) {
	e := newEnv(t)
	e.f.reply("sendMessage", 429, `<html>429 Too Many Requests</html>`)
	if err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil); err != nil {
		t.Fatal(err)
	}
	checkWaits(t, e.sleeps.all(), time.Second)
}

// TestCallRetryAfterBounds checks that the wait of a 429 answer is at
// least 1 second and at most maxRetryAfter.
func TestCallRetryAfterBounds(t *testing.T) {
	for _, tc := range []struct {
		params string
		want   time.Duration
	}{
		{``, time.Second},
		{`,"parameters":{}`, time.Second},
		{`,"parameters":{"retry_after":-5}`, time.Second},
		{`,"parameters":{"retry_after":99999999999}`, maxRetryAfter},
	} {
		e := newEnv(t)
		e.f.reply("sendMessage", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests"`+tc.params+`}`)
		if err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil); err != nil {
			t.Fatal(err)
		}
		checkWaits(t, e.sleeps.all(), tc.want)
	}
}

// TestCallNoWaitPastDeadline checks that the client does not wait past
// the end of its context: it fails at once.
func TestCallNoWaitPastDeadline(t *testing.T) {
	e := newEnv(t)
	e.f.reply("sendMessage", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":60}}`)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := e.a.api.call(ctx, "sendMessage", sendParams, nil)
	if ce := callErr(t, err); ce.code != 429 {
		t.Errorf("error %v, want the 429 error", err)
	}
	checkWaits(t, e.sleeps.all())
}

// TestCallServerErrors checks that server errors are tried again with a
// growing wait, at most maxTries times.
func TestCallServerErrors(t *testing.T) {
	e := newEnv(t)
	e.f.reply("sendMessage", 500, `{"ok":false,"error_code":500,"description":"Internal Server Error"}`)
	e.f.reply("sendMessage", 502, `<html><body>Bad Gateway</body></html>`)
	if err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil); err != nil {
		t.Fatal(err)
	}
	checkWaits(t, e.sleeps.all(), 500*time.Millisecond, time.Second)

	e = newEnv(t)
	for range maxTries + 1 {
		e.f.reply("sendMessage", 503, `{"ok":false,"error_code":503,"description":"Service Unavailable"}`)
	}
	err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil)
	if ce := callErr(t, err); ce.code != 503 || !ce.temporary {
		t.Errorf("error %v, want the 503 error", err)
	}
	if n := len(e.f.callsOf("sendMessage")); n != maxTries {
		t.Errorf("%d tries, want %d", n, maxTries)
	}
	checkWaits(t, e.sleeps.all(), 500*time.Millisecond, time.Second, 2*time.Second, 4*time.Second)
}

// TestCallRefusals checks that a refused call is not tried again, and
// that its error holds a fixed reason and the code, never Telegram's
// description, which can quote the message text.
func TestCallRefusals(t *testing.T) {
	const quoted = "claimed text from the message"
	for _, tc := range []struct {
		status int
		desc   string
		reason string
	}{
		{400, "Bad Request: can't parse entities: " + quoted, "Telegram refused the request"},
		{400, "Bad Request: chat not found " + quoted, "Telegram does not know the chat"},
		{400, "Bad Request: message to edit not found " + quoted, "the message is gone"},
		{400, "Bad Request: query is too old and response timeout expired or query ID is invalid " + quoted,
			"the button press is too old to answer"},
		{401, "Unauthorized " + quoted, "Telegram does not accept the bot token"},
		{403, "Forbidden: bot was blocked by the user " + quoted, "the bot may not send to this chat"},
		{404, "Not Found " + quoted, "Telegram does not know the method or the bot token"},
		{409, "Conflict " + quoted, "another program polls with the bot token"},
	} {
		e := newEnv(t)
		e.f.reply("sendMessage", tc.status, `{"ok":false,"error_code":`+strconv.Itoa(tc.status)+
			`,"description":"`+tc.desc+`"}`)
		err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil)
		ce := callErr(t, err)
		if ce.code != tc.status || ce.temporary || !strings.Contains(err.Error(), tc.reason) ||
			!strings.HasPrefix(err.Error(), "telegram: sendMessage: ") {
			t.Errorf("%d %q: error %q", tc.status, tc.desc, err)
		}
		if strings.Contains(err.Error(), quoted) {
			t.Errorf("%d: the error holds the description", tc.status)
		}
		if n := len(e.f.callsOf("sendMessage")); n != 1 {
			t.Errorf("%d: %d tries, want 1", tc.status, n)
		}
	}
}

// TestCallBadAnswers checks answers that the client cannot use. An answer
// with HTTP status 200 is not tried again: the call may have worked.
func TestCallBadAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		tries  int
	}{
		{"not JSON", 200, `<html>hello</html>`, 1},
		{"ok with status 201", 201, `{"ok":true,"result":true}`, 1},
		{"ok false without code", 400, `{"ok":false}`, 1},
		{"too large", 200, `{"ok":true,"result":"` + strings.Repeat("x", maxResponseSize) + `"}`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.f.reply("sendMessage", tc.status, tc.body)
			if err := e.a.api.call(context.Background(), "sendMessage", sendParams, &message{}); err == nil {
				t.Error("no error")
			}
			if n := len(e.f.callsOf("sendMessage")); n != tc.tries {
				t.Errorf("%d tries, want %d", n, tc.tries)
			}
		})
	}
}

// TestCallNoRedirect checks that the client does not follow a redirect,
// so no other server gets the URL with the token.
func TestCallNoRedirect(t *testing.T) {
	other := newFake(t)
	e := newEnv(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G710: this test server redirects on purpose; the test checks that the client does not follow.
		http.Redirect(w, r, other.srv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	e.a.api.base = redirect.URL
	err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil)
	if ce := callErr(t, err); ce.code != http.StatusTemporaryRedirect {
		t.Errorf("error %v, want the redirect status", err)
	}
	if n := len(other.allCalls()); n != 0 {
		t.Errorf("the other server got %d calls", n)
	}
}

// TestCallNetworkErrors checks that a server that cannot be reached, or
// does not answer in time, gives a fixed reason, and is tried again.
func TestCallNetworkErrors(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		e := newEnv(t)
		closed := httptest.NewServer(http.NotFoundHandler())
		closed.Close()
		e.a.api.base = closed.URL
		err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil)
		if ce := callErr(t, err); ce.reason != "cannot connect to the server" || !ce.temporary || ce.code != 0 {
			t.Errorf("error %v", err)
		}
		if n := len(e.sleeps.all()); n != maxTries-1 {
			t.Errorf("%d waits, want %d", n, maxTries-1)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		e := newEnv(t)
		release := e.f.hold("sendMessage")
		defer release()
		e.a.api.timeout = 100 * time.Millisecond
		err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil)
		if ce := callErr(t, err); ce.reason != "the call timed out" || !ce.temporary {
			t.Errorf("error %v", err)
		}
		if n := len(e.f.callsOf("sendMessage")); n != maxTries {
			t.Errorf("%d tries, want %d", n, maxTries)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		e := newEnv(t)
		release := e.f.hold("sendMessage")
		defer release()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- e.a.api.call(ctx, "sendMessage", sendParams, nil) }()
		e.f.waitCalls("sendMessage", 1)
		cancel()
		err := <-done
		if !errors.Is(err, context.Canceled) || callErr(t, err).temporary {
			t.Errorf("error %v, want context.Canceled", err)
		}
		if n := len(e.f.callsOf("sendMessage")); n != 1 {
			t.Errorf("%d tries, want 1", n)
		}
	})
	t.Run("not a URL", func(t *testing.T) {
		e := newEnv(t)
		e.a.api.base = "http://127.0.0.1:99999\x7f"
		err := e.a.api.call(context.Background(), "sendMessage", sendParams, nil)
		if ce := callErr(t, err); ce.reason != "cannot make the request" {
			t.Errorf("error %v", err)
		}
	})
}

// TestHTTPClient checks the settings of the HTTP client: HTTP/1.1 only,
// no redirects, limits on each step.
func TestHTTPClient(t *testing.T) {
	c := newHTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("not an *http.Transport")
	}
	if tr.Protocols == nil || tr.Protocols.HTTP2() || tr.Protocols.UnencryptedHTTP2() || !tr.Protocols.HTTP1() {
		t.Errorf("protocols %v, want only HTTP/1.1", tr.Protocols)
	}
	if tr.TLSHandshakeTimeout <= 0 || tr.ResponseHeaderTimeout < pollTimeout || tr.MaxResponseHeaderBytes <= 0 {
		t.Errorf("transport limits %v %v %v", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, tr.MaxResponseHeaderBytes)
	}
	if c.CheckRedirect == nil || !errors.Is(c.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Error("the client follows redirects")
	}
}
