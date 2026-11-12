package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/api"
)

const (
	testItem = "11111111-1111-1111-1111-111111111111"
	testPage = "https://example.com/sign-in"
)

// loginHandler answers the paths of website logins and keeps the bodies.
func loginHandler(t *testing.T, password string, bodies *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		*bodies = append(*bodies, r.URL.Path+" "+string(data))
		switch r.URL.Path {
		case api.PathLoginList:
			_, _ = io.WriteString(w, `{"logins":[{"logins":"web","id":"`+testItem+`","name":"Example shop","username":"alice@example.com"}]}`)
		case api.PathLogin:
			ans := api.LoginAnswer{Username: "alice@example.com", Password: []byte(password)}
			body, err := ans.Encode()
			if err != nil {
				t.Error(err)
			}
			w.Header().Set("Content-Type", api.ContentType)
			_, _ = w.Write(body)
		case api.PathLoginTOTP:
			_, _ = io.WriteString(w, `{"code":"287082"}`)
		case api.PathPreapprove:
			_, _ = io.WriteString(w, `{"id":"abcdefghijklmnopqrstuv","from":"2026-10-15T12:00:00Z","until":"2026-10-15T12:01:00Z"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestListLoginsLoginAndTOTP(t *testing.T) {
	t.Parallel()
	pw := madeUp("shop-password")
	var bodies []string
	fb := newFakeBroker(t, loginHandler(t, pw, &bodies))
	list, err := ListLogins(t.Context(), fb.b, testPage)
	if err != nil || len(list.Logins) != 1 || list.Logins[0].ID != testItem || list.Logins[0].Logins != "web" {
		t.Fatalf("list: %v %+v", err, list)
	}
	ans, err := Login(t.Context(), fb.b, testPage, testItem, nil)
	if err != nil || ans.Username != "alice@example.com" || string(ans.Password) != pw {
		t.Fatalf("login: %v", err)
	}
	// Nothing prints the password, and Clear wipes it.
	for _, s := range []string{fmt.Sprint(ans), fmt.Sprintf("%+v %#v %v", ans, *ans, *ans), slog.Any("a", ans).Value.String()} {
		if strings.Contains(s, pw) {
			t.Errorf("the password shows: %s", s)
		}
	}
	ans.Clear()
	if !bytes.Equal(ans.Password, make([]byte, len(pw))) {
		t.Error("Clear left the password")
	}
	code, err := LoginTOTP(t.Context(), fb.b, testPage, testItem)
	if err != nil || code.Code != "287082" {
		t.Fatalf("totp: %v", err)
	}
	if len(bodies) != 3 || !strings.Contains(bodies[1], `"item":"`+testItem+`"`) || !strings.Contains(bodies[1], `"url":"`+testPage+`"`) {
		t.Errorf("bodies %q", bodies)
	}
}

func TestLoginErrors(t *testing.T) {
	t.Parallel()
	status := http.StatusForbidden
	fb := newFakeBroker(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	for name, call := range map[string]func() error{
		"list":  func() error { _, err := ListLogins(t.Context(), fb.b, testPage); return err },
		"login": func() error { _, err := Login(t.Context(), fb.b, testPage, testItem, nil); return err },
		"totp":  func() error { _, err := LoginTOTP(t.Context(), fb.b, testPage, testItem); return err },
	} {
		err := call()
		var e *Error
		if err == nil || !asError(err, &e) || e.Status != http.StatusForbidden {
			t.Errorf("%s: %v, want a 403 error", name, err)
		}
	}
	// A request over a cap never reaches the broker.
	before := fb.requests.Load()
	long := "https://example.com/" + strings.Repeat("a", api.MaxURL)
	if _, err := ListLogins(t.Context(), fb.b, long); err == nil {
		t.Error("a long URL was sent")
	}
	if _, err := Login(t.Context(), fb.b, testPage, strings.Repeat("a", api.MaxItemID+1), nil); err == nil {
		t.Error("a long item was sent")
	}
	if fb.requests.Load() != before {
		t.Error("a request over a cap reached the broker")
	}
	// A bad answer is an error, and a password in a list is refused.
	fb2 := newFakeBroker(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"logins":[{"logins":"w","id":"i","name":"n","username":"u","password":"p"}]}`)
	})
	if _, err := ListLogins(t.Context(), fb2.b, testPage); err == nil {
		t.Error("a list with a password field was taken")
	}
}

func asError(err error, target **Error) bool { return errors.As(err, target) }

func TestPreapproveLoginUsage(t *testing.T) {
	t.Parallel()
	g := testGranter(nil, nil)
	bad := map[string][]string{
		"login without url":    {"--login", testItem},
		"url without login":    {"--url", testPage},
		"login with secret":    {"--login", testItem, "--url", testPage, "--secret", "a"},
		"login with key":       {"--login", testItem, "--url", testPage, "--key", "deploy"},
		"login with uses":      {"--login", testItem, "--url", testPage, "--uses", "1"},
		"login with until":     {"--login", testItem, "--url", testPage, "--until", "2026-10-28T04:00"},
		"login with from":      {"--login", testItem, "--url", testPage, "--from", "2026-10-28T04:00"},
		"login with host":      {"--login", testItem, "--url", testPage, "--host", "web-1"},
		"login with daily":     {"--login", testItem, "--url", testPage, "--daily", "03:00-05:00"},
		"login with cancel":    {"--login", testItem, "--cancel", "abcdefghijklmnopqrstuv"},
		"login with token":     {"--login", testItem, "--url", testPage, "--grant-token", "/tmp/x"},
		"item not a UUID":      {"--login", "shop", "--url", testPage},
		"http page":            {"--login", testItem, "--url", "http://example.com/"},
		"page that is no URL":  {"--login", testItem, "--url", "example"},
		"login twice":          {"--login", testItem, "--login", testItem, "--url", testPage},
		"url twice":            {"--login", testItem, "--url", testPage, "--url", testPage},
		"login without value":  {"--login"},
		"secret with a url":    {"--secret", "a", "--url", testPage, "--until", "2026-10-28T04:00", "--uses", "1"},
		"login and secret url": {"--login", testItem, "--url", testPage, "--secret", "a", "--uses", "1"},
	}
	for name, args := range bad {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := preIn(t.Context(), g, args...)
			lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
			if code != exitUsage || stdout != "" || len(lines) != 1 || !strings.HasPrefix(lines[0], "nodkey preapprove: ") ||
				!strings.HasSuffix(lines[0], "(exit 64)") {
				t.Errorf("exit %d, stdout %q, stderr %q; want one usage line", code, stdout, stderr)
			}
		})
	}
}

func TestPreapproveLoginApproves(t *testing.T) {
	t.Parallel()
	var bodies []string
	fb := newFakeBroker(t, loginHandler(t, "x", &bodies))
	code, stdout, stderr := preIn(t.Context(), testGranter(fb.b, nil),
		"--login", strings.ToUpper(testItem[:1])+testItem[1:], "--url", testPage, "--reason", "check the order")
	if code != exitOK || stdout != "abcdefghijklmnopqrstuv\n" ||
		!strings.Contains(stderr, "one login for this page, until 2026-10-15T12:01:00Z (exit 0)") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	var req map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(bodies[0], api.PathPreapprove+" ")), &req); err != nil {
		t.Fatal(err)
	}
	if req["login"] == "" || req["url"] != testPage || req["uses"] != float64(1) || req["from"] != "" || req["until"] != "" ||
		req["reason"] != "check the order" {
		t.Errorf("request %v", req)
	}
	if _, ok := req["windows"]; ok {
		t.Error("the request has windows")
	}
}

func TestPreapproveLoginWaitsAsLongAsOthers(t *testing.T) {
	t.Parallel()
	// The request has no limit of its own: it ends with the context.
	started := make(chan struct{})
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		code, _, _ := preIn(ctx, testGranter(fb.b, nil), "--login", testItem, "--url", testPage)
		done <- code
	}()
	<-started
	select {
	case code := <-done:
		t.Fatalf("it ended before the tap, with %d", code)
	default:
	}
	cancel()
	if code := <-done; code == exitOK {
		t.Error("a cancelled request succeeded")
	}
}
