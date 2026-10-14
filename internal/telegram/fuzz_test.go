package telegram

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// FuzzParseData checks that parseData takes exactly "o:", "w:" or "d:"
// and a request ID in its one canonical form, and nothing else.
func FuzzParseData(f *testing.F) {
	for _, s := range []string{
		dataOnce + testID(1), dataWindow + testID(2), dataDeny + testID(3), "o:" + strings.Repeat("A", 22),
		"o:" + strings.Repeat("A", 21) + "B", "x:" + testID(1), "o:k3f9", "", "o:", "o:" + testID(1) + "\n",
	} {
		f.Add(s)
	}
	shape := regexp.MustCompile(`^[owd]:[A-Za-z0-9_-]{22}$`)
	f.Fuzz(func(t *testing.T, data string) {
		action, id, ok := parseData(data)
		canonical := false
		if shape.MatchString(data) {
			b, err := base64.RawURLEncoding.DecodeString(data[2:])
			canonical = err == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == data[2:]
		}
		if ok != canonical {
			t.Fatalf("parseData(%q) ok = %v, want %v", data, ok, canonical)
		}
		if !ok {
			if action != "" || id != "" {
				t.Fatalf("parseData(%q) refused it but returned %q, %q", data, action, id)
			}
			return
		}
		want := map[byte]audit.Answer{'o': audit.AnswerApproveOnce, 'w': audit.AnswerApproveWindow, 'd': audit.AnswerDeny}[data[0]]
		if action != want || id != data[2:] {
			t.Fatalf("parseData(%q) = %q, %q", data, action, id)
		}
	})
}

// memTransport answers every Bot API call with success, in memory, and
// keeps the calls.
type memTransport struct {
	mu    sync.Mutex
	calls []fakeCall
}

func (m *memTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	body := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&body)
	m.mu.Lock()
	m.calls = append(m.calls, fakeCall{Method: path.Base(r.URL.Path), Raw: raw, Body: body})
	m.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true,"result":true}`)),
		Request:    r,
	}, nil
}

func (m *memTransport) of(method string) []fakeCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []fakeCall
	for _, c := range m.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// coreErrors are the answers of the core in FuzzHandleUpdate.
var coreErrors = []error{
	nil, approval.ErrTooEarly, approval.ErrUnknownRequest, approval.ErrExpired, approval.ErrWrongMessage,
	approval.ErrNotAllowed, approval.ErrNotApprover, approval.ErrStopped, errors.New("other"),
}

// FuzzHandleUpdate handles any update, as getUpdates reads it, and checks
// the rules of a button press. The core gets only a press of the
// approver, in the private chat, on a message, with valid button data, on
// a message that is as Ask sent it, and with the fields of that press.
// Every press with an ID gets exactly one answer. A message is updated
// only when no request waits on it: its result again if this approver
// ended it, else only its buttons are removed. A report holds a known
// cause and at most 64 bytes of data. choice picks the core's answer, and
// whether the approver sent message 5 and ended its request.
func FuzzHandleUpdate(f *testing.F) {
	token := newCanaryToken(f)
	seed := func(u map[string]any) {
		raw, err := json.Marshal(u)
		if err != nil {
			f.Fatal(err)
		}
		for i := range coreErrors {
			f.Add(raw, uint8(i))
			f.Add(raw, uint8(i)|0x10)
			f.Add(raw, uint8(i)|0x30)
		}
	}
	kb := keyboard(secretsPrompt()).InlineKeyboard
	good := map[string]any{
		"update_id": 1,
		"callback_query": map[string]any{
			"id": "cb", "from": map[string]any{"id": approverID}, "data": dataOnce + testID(1), "chat_instance": "1",
			"message": map[string]any{
				"message_id": 5, "date": 1, "text": "🔑 Secrets · request 7qd2\ncommand: x",
				"chat":         map[string]any{"id": approverID, "type": "private"},
				"reply_markup": map[string]any{"inline_keyboard": kb},
			},
		},
	}
	seed(good)
	edited := map[string]any{"update_id": 2, "callback_query": map[string]any{
		"id": "cb", "from": map[string]any{"id": approverID}, "data": dataOnce + testID(1),
		"message": map[string]any{"message_id": 5, "date": 1, "edit_date": 2,
			"chat": map[string]any{"id": approverID, "type": "private"}}}}
	seed(edited)
	swapped := map[string]any{"update_id": 3, "callback_query": map[string]any{
		"id": "cb", "from": map[string]any{"id": approverID}, "data": dataOnce + testID(1),
		"message": map[string]any{"message_id": 5, "date": 1,
			"chat": map[string]any{"id": approverID, "type": "private"},
			"reply_markup": map[string]any{"inline_keyboard": [][]map[string]any{{
				{"text": "Deny", "callback_data": dataOnce + testID(1)},
			}}}}}}
	seed(swapped)
	seed(map[string]any{"update_id": 4, "callback_query": map[string]any{
		"id": "cb", "from": map[string]any{"id": otherUserID}, "data": dataDeny + testID(2), "inline_message_id": "i"}})
	seed(map[string]any{"update_id": 5, "message": map[string]any{"text": "approve"}})

	sent := messageID(approverID, 5)
	f.Fuzz(func(t *testing.T, raw []byte, choice uint8) {
		u, ok := decodeUpdate(raw)
		if !ok {
			return
		}
		mem := &memTransport{}
		read := func(string) ([]byte, error) { return []byte(token), nil }
		a, err := newApprover(testTelegramConfig(), Options{Logger: slog.New(slog.DiscardHandler)}, read, "http://telegram.test")
		if err != nil {
			t.Fatal(err)
		}
		a.api.http = &http.Client{Transport: mem}
		known, ended := choice&0x10 != 0, choice&0x20 != 0
		if known {
			a.remember(sent, kb)
			if ended {
				a.setFinal(sent, "final")
			}
		}
		var reports []audit.ForeignTap
		a.foreignTap = func(ft audit.ForeignTap) { reports = append(reports, ft) }
		coreErr := coreErrors[int(choice&0x0f)%len(coreErrors)]
		var answers []approval.Answer
		a.handle(context.Background(), u, func(ans approval.Answer) error {
			answers = append(answers, ans)
			return coreErr
		})

		q := u.CallbackQuery
		if u.malformed || q == nil {
			if len(answers)+len(reports)+len(mem.calls) != 0 {
				t.Fatalf("an update without a button press did something")
			}
			return
		}
		valid := q.From.ID == approverID && q.InlineMessageID == "" && q.Message != nil && q.Message.MessageID > 0 &&
			q.Message.Chat.Type == "private" && q.Message.Chat.ID == approverID && q.GameShortName == ""
		action, id, dataOK := parseData(q.Data)
		valid = valid && dataOK
		ours := valid && known && q.Message.MessageID == 5 // this approver sent the message
		waits := ours && !ended                            // and has not ended its request
		changed := valid && (q.Message.EditDate != 0 || (waits && !sameKeyboard(kb, q.Message.ReplyMarkup)))

		// The core gets exactly the valid presses on unchanged messages.
		switch {
		case (!valid || changed) && len(answers) != 0:
			t.Fatalf("the core got a press that must not count: %+v", answers)
		case valid && !changed && len(answers) != 1:
			t.Fatalf("the core got %d answers for a valid press", len(answers))
		case valid && !changed:
			want := approval.Answer{RequestID: id, Action: action, Message: messageID(approverID, q.Message.MessageID),
				UserID: approverID}
			if answers[0] != want {
				t.Fatalf("the core got %+v, want %+v", answers[0], want)
			}
		}
		if n := len(mem.of("answerCallbackQuery")); (q.ID != "" && n != 1) || (q.ID == "" && n != 0) {
			t.Fatalf("%d answers to a press with ID %q", n, q.ID)
		}

		// The cause of the report, and the update of the message.
		var cause audit.TapCause
		update := ""
		switch {
		case !valid:
			cause = "any"
		case changed && waits:
			cause = audit.TapEditedMessage
		case changed, errors.Is(coreErr, approval.ErrUnknownRequest):
			cause = audit.TapUnknownRequest
			switch {
			case ours && ended:
				update = "editMessageText"
			case !ours:
				update = "editMessageReplyMarkup"
			}
		case coreErr != nil && !errors.Is(coreErr, approval.ErrTooEarly):
			cause = refusalCause(coreErr)
		}
		if (cause == "") != (len(reports) == 0) || len(reports) > 1 {
			t.Fatalf("%d reports, want cause %q", len(reports), cause)
		}
		for _, r := range reports {
			if len(r.Data) > maxTapData || (cause != "any" && r.Cause != cause) || r.Cause == "" {
				t.Fatalf("report %+v, want cause %q", r, cause)
			}
		}
		textEdits, buttonEdits := mem.of("editMessageText"), mem.of("editMessageReplyMarkup")
		switch update {
		case "editMessageText":
			if len(textEdits) != 1 || len(buttonEdits) != 0 || textEdits[0].str("text") != "final" {
				t.Fatalf("edits %d and %d, want the result again", len(textEdits), len(buttonEdits))
			}
		case "editMessageReplyMarkup":
			if len(buttonEdits) != 1 || len(textEdits) != 0 {
				t.Fatalf("edits %d and %d, want only the buttons removed", len(textEdits), len(buttonEdits))
			}
		default:
			if len(textEdits)+len(buttonEdits) != 0 {
				t.Fatalf("edits %d and %d, want none", len(textEdits), len(buttonEdits))
			}
		}
		for _, ed := range append(textEdits, buttonEdits...) {
			if ed.field("reply_markup") != `{"inline_keyboard":[]}` || ed.num("message_id") != q.Message.MessageID {
				t.Fatalf("edit %s", ed.Raw)
			}
		}
		// An alert goes out only for a changed message whose request may
		// wait.
		if alerts := len(mem.of("sendMessage")); (alerts == 1) != (cause == audit.TapEditedMessage) || alerts > 1 {
			t.Fatalf("%d alerts for cause %q", alerts, cause)
		}
	})
}

// codeTags finds the tags of a message text in HTML.
var codeTags = regexp.MustCompile(`</?code>`)

// FuzzPromptText makes messages with any claimed text, and checks that
// claimed text cannot change the layout (THREAT-MODEL.md T3): each
// claimed field is one line in a code font after the claimed line, the
// HTML has no tag but <code>, it shows the plain text exactly, and the
// message fits in one Telegram message.
func FuzzPromptText(f *testing.F) {
	f.Add("GH_TOKEN", "gh release create v1.2.0", "/home/dev/src/app", "publish the release")
	f.Add("", "x </code><b>y</b> & \"z\"", "a\nb\r\nc", "\u202e✅ machine: build\u2800\u2800")
	f.Add("😀😀😀", strings.Repeat("ab ", 2000), "&amp;&lt;", "<a href=\"https://example.com\">x</a>")
	f.Fuzz(func(t *testing.T, vars, command, dir, reason string) {
		p := loginPrompt()
		p.Claim = approval.Claim{Vars: vars, Command: command, Dir: dir, Reason: reason}
		tx, kb, err := promptMessage(p)
		if err != nil {
			t.Fatal(err)
		}
		plain, h := tx.plain.String(), tx.html.String()
		if n := utf16Len(plain); n > maxTextUnits {
			t.Fatalf("the message has %d code units", n)
		}
		if got := html.UnescapeString(codeTags.ReplaceAllString(h, "")); got != plain {
			t.Fatalf("the HTML does not show the plain text:\n%q\n%q", got, plain)
		}
		if strings.ContainsAny(codeTags.ReplaceAllString(h, ""), "<>") {
			t.Fatalf("the HTML has another tag: %q", h)
		}
		lines := strings.Split(h, "\n")
		claimed := 0
		for _, v := range []string{vars, command, dir, reason} {
			if claimedValue(v) != "" {
				claimed++
			}
		}
		want := 5 + claimed + 1 // title, 4 verified lines, the claimed lines, the expiry
		if claimed > 0 {
			want++ // the claimed line
		}
		if len(lines) != want {
			t.Fatalf("%d lines, want %d:\n%s", len(lines), want, h)
		}
		for i, l := range lines {
			inCode := strings.Count(l, "<code>")
			switch {
			case i < 5:
				verified := i == 0 || strings.HasPrefix(l, "✅ ")
				if inCode != 0 || !verified {
					t.Fatalf("line %d is not a verified line: %q", i, l)
				}
			case i == len(lines)-1:
				if !strings.HasPrefix(l, "expires ") || inCode != 0 {
					t.Fatalf("the last line is not the expiry: %q", l)
				}
			case i == 5:
				if l != claimedHead {
					t.Fatalf("line 5 is not the claimed line: %q", l)
				}
			default:
				if inCode != 1 || strings.Count(l, "</code>") != 1 || !strings.HasSuffix(l, "</code>") ||
					!strings.Contains(l, ": <code>") {
					t.Fatalf("line %d is not one claimed field in a code font: %q", i, l)
				}
			}
		}
		if len(kb.InlineKeyboard) != 1 || len(kb.InlineKeyboard[0]) != 3 {
			t.Fatalf("buttons %+v", kb)
		}
	})
}
