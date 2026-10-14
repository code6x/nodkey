package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// TestTokenNeverShown runs the approver with a made-up token through
// calls that work, every kind of failure, polling, refused taps and a
// polling conflict. Then it searches every error, every log line (text
// and JSON), every report for the audit log, every text for the audit log
// and every printed form of the approver for the token (THREAT-MODEL.md
// T19). A failure names where it found the token, never the token.
func TestTokenNeverShown(t *testing.T) {
	f := newFake(t)
	f.pollWait = 20 * time.Millisecond
	token := f.token
	secret := token[strings.IndexByte(token, ':')+1:]

	type output struct{ where, text string }
	var outputs []output
	add := func(where, text string) { outputs = append(outputs, output{where, text}) }
	addErr := func(where string, err error) {
		if err == nil {
			return
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			add(where+" "+verb, fmt.Sprintf(verb, err))
		}
		for e := err; e != nil; e = errors.Unwrap(e) {
			add(where+" unwrapped", e.Error())
		}
	}

	textLogs, jsonLogs := &syncBuffer{}, &syncBuffer{}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	logger := slog.New(slog.NewMultiHandler(slog.NewTextHandler(textLogs, opts), slog.NewJSONHandler(jsonLogs, opts)))
	taps := &tapLog{}
	read := func(string) ([]byte, error) { return []byte(token + "\n"), nil }
	a, err := newApprover(testTelegramConfig(), Options{Logger: logger, ForeignTap: taps.add}, read, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sleeps := &sleepLog{}
	a.api.timeout = 200 * time.Millisecond
	a.api.pollTimeout = 2 * time.Second
	a.api.sleep = sleeps.sleep
	ctx := context.Background()

	// Calls that work.
	shown, err := a.Ask(ctx, secretsPrompt())
	addErr("Ask", err)
	add("Shown.Text", shown.Text)
	add("Shown.ID", string(shown.ID))
	addErr("End", a.End(ctx, shown.ID, secretsPrompt(), approval.Ending{Answer: audit.AnswerApproveOnce, At: noon}))
	addErr("Notify", a.Notify(ctx, noticeOf(secretsPrompt())))
	addErr("Alert", a.Alert(ctx, "an alert"))

	// Telegram refuses or fails. The description holds the token, as a
	// broken or hostile server might send it.
	for _, r := range []struct {
		status int
		body   string
	}{
		{400, `{"ok":false,"error_code":400,"description":"Bad Request: ` + token + `"}`},
		{401, `{"ok":false,"error_code":401,"description":"Unauthorized ` + token + `"}`},
		{403, `{"ok":false,"error_code":403,"description":"Forbidden"}`},
		{404, `{"ok":false,"error_code":404,"description":"Not Found"}`},
		{409, `{"ok":false,"error_code":409,"description":"Conflict"}`},
		{429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":1}}`},
		{500, `{"ok":false,"error_code":500,"description":"Internal Server Error ` + token + `"}`},
		{502, `<html>` + token + `</html>`},
		{200, `not JSON ` + token},
		{201, `{"ok":true,"result":"` + token + `"}`},
		{200, `{"ok":true,"result":{"message_id":"` + token + `"}}`},
		{200, `{"ok":true,"result":"` + strings.Repeat(secret, maxResponseSize/len(secret)+1) + `"}`},
	} {
		f.reply("sendMessage", r.status, r.body)
		_, err := a.Ask(ctx, secretsPrompt())
		addErr(fmt.Sprintf("Ask with %d", r.status), err)
	}
	for range maxTries {
		f.reply("editMessageText", 503, `{"ok":false,"error_code":503,"description":"`+token+`"}`)
	}
	addErr("End with 503", a.End(ctx, shown.ID, secretsPrompt(), approval.Ending{Cause: audit.CauseExpired}))
	addErr("End with a bad ID", a.End(ctx, "x", secretsPrompt(), approval.Ending{}))

	// The network fails.
	release := f.hold("sendMessage")
	_, err = a.Ask(ctx, secretsPrompt())
	addErr("Ask timed out", err)
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err = a.Ask(cctx, secretsPrompt())
	addErr("Ask cancelled", err)
	release()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G710: this test server redirects on purpose; the test checks that the client does not follow.
		http.Redirect(w, r, f.srv.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirect.Close()
	for where, base := range map[string]string{
		"closed server":   closed.URL,
		"redirect":        redirect.URL,
		"bad URL":         f.srv.URL + "\x7f",
		"no such host":    "http://nodkey-test.invalid",
		"https to http":   strings.Replace(f.srv.URL, "http://", "https://", 1),
		"unknown scheme":  "nodkey://127.0.0.1",
		"empty base path": "",
	} {
		a.api.base = base
		_, err := a.Ask(ctx, secretsPrompt())
		addErr("Ask: "+where, err)
		addErr("Notify: "+where, a.Notify(ctx, noticeOf(secretsPrompt())))
	}
	a.api.base = f.srv.URL

	// Polling, refused taps, and a stop after Telegram refused getUpdates.
	f.reply("getUpdates", 500, `{"ok":false,"error_code":500,"description":"`+token+`"}`)
	f.reply("getUpdates", 429, `{"ok":false,"error_code":429,"description":"`+token+`","parameters":{"retry_after":1}}`)
	f.reply("getUpdates", 200, `{"ok":true,"result":[{"update_id":1},{"update_id":2,"callback_query":{"id":"x","from":"`+token+`"}}]}`)
	core := &stubCore{err: approval.ErrUnknownRequest}
	runCtx, stopRun := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Run(runCtx, core.answer) }()
	other := goodTap(5, dataOnce+testID(1))
	other.from = otherUserID
	edits := len(f.callsOf("editMessageReplyMarkup"))
	edited := goodTap(8, dataOnce+testID(3))
	edited.edited = true
	for _, s := range []tapSpec{other, goodTap(6, "o:short"), goodTap(7, dataOnce+testID(2)), edited} {
		f.waitAnswer(f.tap(s))
	}
	f.reply("getUpdates", 401, `{"ok":false,"error_code":401,"description":"Unauthorized `+token+`"}`)
	select {
	case err := <-done:
		addErr("Run after 401", err)
	case <-time.After(waitLimit):
		t.Fatal("Run did not stop after 401")
	}
	stopRun()
	if n := len(f.callsOf("editMessageReplyMarkup")); n != edits+2 {
		t.Errorf("%d edits of buttons during Run, want 2", n-edits)
	}

	// A polling conflict.
	f.reply("getUpdates", 409, `{"ok":false,"error_code":409,"description":"Conflict `+token+`"}`)
	addErr("Run after 409", a.Run(ctx, core.answer))

	// New with token files that are not valid.
	for _, content := range []string{token + "/", token + " " + token, "x" + token, token + "\n" + token} {
		_, err := newApprover(testTelegramConfig(), Options{}, func(string) ([]byte, error) { return []byte(content), nil },
			f.srv.URL)
		addErr("New", err)
	}

	// Printed forms of the approver and its parts.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		add("approver "+verb, fmt.Sprintf(verb, a))
		add("client "+verb, fmt.Sprintf(verb, a.api))
		add("token "+verb, fmt.Sprintf(verb, a.api.token))
		add("struct "+verb, fmt.Sprintf(verb, struct {
			A *Approver
			T botToken
		}{a, a.api.token}))
	}
	logger.Info("the approver", "approver", a, "client", a.api, "token", a.api.token)
	raw, err := json.Marshal(struct {
		A *Approver
		T botToken
	}{a, a.api.token})
	addErr("json", err)
	add("json", string(raw))

	add("text log", textLogs.String())
	add("JSON log", jsonLogs.String())
	for _, tap := range taps.all() {
		add("report", fmt.Sprintf("%+v", tap))
	}
	for _, c := range f.allCalls() {
		add("request body of "+c.Method, string(c.Raw))
	}

	if len(outputs) < 100 {
		t.Fatalf("only %d outputs to search", len(outputs))
	}
	if len(taps.all()) < 4 || !strings.Contains(textLogs.String(), "refused a button press") {
		t.Error("the refused taps did not happen")
	}
	for _, o := range outputs {
		if strings.Contains(o.text, secret) || strings.Contains(o.text, token) {
			t.Errorf("the token is in: %s", o.where)
		}
	}
}
