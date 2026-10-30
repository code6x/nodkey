package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/transport"
)

// answer writes a final answer: status, and body as it is, as JSON.
func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", api.ContentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// secretsAnswer returns the JSON of an answer with the values, by
// variable, in order: pairs of variable and value.
func secretsAnswer(t testing.TB, pairs ...string) string {
	t.Helper()
	var ans api.SecretsAnswer
	for i := 0; i+1 < len(pairs); i += 2 {
		ans.Secrets = append(ans.Secrets, api.SecretValue{Var: pairs[i], Value: []byte(pairs[i+1])})
	}
	body, err := ans.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestRunAnswers: only a final 200 whose body passes api.ReadAnswer, with
// exactly one valid value for each variable in order, starts the command.
// 403 and 429 exit with 77; every other answer, also a redirect, a body
// that api.ReadAnswer refuses, and an answer that does not fit the
// request, with 69. nodkey run sends each request once, and never prints
// an answer body, a header or a value.
func TestRunAnswers(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	other := madeUp("other")
	tests := []struct {
		name    string
		handler func(t *testing.T) http.HandlerFunc
		code    int
		want    string // the last line, without "nodkey: " and " (exit N)"
	}{
		{"403 with text in the body and a header", func(*testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Note", value)
				_ = transport.WriteJSONBody(w, http.StatusForbidden, []byte(`{"error":"`+value+`"}`))
			}
		}, exitDenied, "denied"},
		{"429", func(*testing.T) http.HandlerFunc {
			return answer(http.StatusTooManyRequests, `{"error":"Too Many Requests"}`)
		},
			exitDenied, "denied by a limit of the broker"},
		{"400", func(*testing.T) http.HandlerFunc { return answer(http.StatusBadRequest, `{"error":"Bad Request"}`) },
			exitUnavailable, "the broker answered 400 Bad Request"},
		{"404", func(*testing.T) http.HandlerFunc { return answer(http.StatusNotFound, `{"error":"Not Found"}`) },
			exitUnavailable, "the broker answered 404 Not Found"},
		{"413", func(*testing.T) http.HandlerFunc {
			return answer(http.StatusRequestEntityTooLarge, `{"error":"Request Entity Too Large"}`)
		}, exitUnavailable, "the broker answered 413 Request Entity Too Large"},
		{"500 with a value in the body", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusInternalServerError, secretsAnswer(t, "GH_TOKEN", value))
		}, exitUnavailable, "the broker answered 500 Internal Server Error"},
		{"503", func(*testing.T) http.HandlerFunc {
			return answer(http.StatusServiceUnavailable, `{"error":"Service Unavailable"}`)
		}, exitUnavailable, "the broker answered 503 Service Unavailable; the broker could not finish the request; its journal says why (journalctl -u nodkey)"},
		{"a status without a name", func(*testing.T) http.HandlerFunc { return answer(299, `{}`) },
			exitUnavailable, "the broker answered 299"},
		{"201 with a valid answer", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusCreated, secretsAnswer(t, "GH_TOKEN", value))
		}, exitUnavailable, "the broker answered 201 Created"},
		{"a redirect", func(*testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://192.0.2.10:7743/v1/secrets")
				w.WriteHeader(http.StatusTemporaryRedirect)
			}
		}, exitUnavailable, "the broker answered 307 Temporary Redirect"},
		{"not JSON", func(*testing.T) http.HandlerFunc { return answer(http.StatusOK, "not json "+value) },
			exitUnavailable, "the answer of the broker is not valid"},
		{"null", func(*testing.T) http.HandlerFunc { return answer(http.StatusOK, "null") },
			exitUnavailable, "the answer of the broker is not valid"},
		{"an unknown field", func(t *testing.T) http.HandlerFunc {
			body := strings.TrimSuffix(secretsAnswer(t, "GH_TOKEN", value), "}") + `,"note":"x"}`
			return answer(http.StatusOK, body)
		}, exitUnavailable, "the answer of the broker is not valid"},
		{"a field in another case", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusOK, strings.Replace(secretsAnswer(t, "GH_TOKEN", value), `"secrets"`, `"Secrets"`, 1))
		}, exitUnavailable, "the answer of the broker is not valid"},
		{"data after the answer", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusOK, secretsAnswer(t, "GH_TOKEN", value)+"{}")
		}, exitUnavailable, "the answer of the broker is not valid"},
		{"larger than api.MaxAnswer", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusOK, secretsAnswer(t, "GH_TOKEN", value)+strings.Repeat(" ", api.MaxAnswer))
		}, exitUnavailable, "the answer of the broker is not valid"},
		{"a value over api.MaxValue", func(t *testing.T) http.HandlerFunc {
			long := []byte(strings.Repeat("v", api.MaxValue+1))
			body, err := json.Marshal(map[string]any{"secrets": []map[string]any{{"var": "GH_TOKEN", "value": long}}})
			if err != nil {
				t.Fatal(err)
			}
			return answer(http.StatusOK, string(body))
		}, exitUnavailable, "the answer of the broker is not valid"},
		{"a body shorter than its length", func(*testing.T) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"secrets":[`)
				_ = http.NewResponseController(w).Flush()
				panic(http.ErrAbortHandler) // drop the connection
			}
		}, exitUnavailable, "the answer of the broker is not valid"},
		{"no value", func(t *testing.T) http.HandlerFunc { return answer(http.StatusOK, secretsAnswer(t)) },
			exitUnavailable, "the answer of the broker has 0 values for 1 variables"},
		{"an extra value", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusOK, secretsAnswer(t, "GH_TOKEN", value, "OTHER", other))
		}, exitUnavailable, "the answer of the broker has 2 values for 1 variables"},
		{"another variable", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusOK, secretsAnswer(t, "OTHER", value))
		}, exitUnavailable, "the answer of the broker has another variable where GH_TOKEN should be"},
		{"an empty value", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusOK, secretsAnswer(t, "GH_TOKEN", ""))
		}, exitUnavailable, "the answer of the broker has an empty value for GH_TOKEN"},
		{"a value with a NUL byte", func(t *testing.T) http.HandlerFunc {
			return answer(http.StatusOK, secretsAnswer(t, "GH_TOKEN", value+"\x00"+other))
		}, exitUnavailable, "the answer of the broker has a value with a NUL byte for GH_TOKEN"},
		{"a dropped connection", func(*testing.T) http.HandlerFunc {
			return func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }
		}, exitUnavailable, "broke before the answer"},
		{"too many informational answers", func(t *testing.T) http.HandlerFunc {
			body := []byte(secretsAnswer(t, "GH_TOKEN", value))
			return func(w http.ResponseWriter, _ *http.Request) {
				for range maxInformational + 1 {
					h := http.Header{api.ShortCodeHeader: {"7qd2"}}
					if err := transport.WriteProcessing(w, h); err != nil {
						return
					}
				}
				_ = transport.WriteJSONBody(w, http.StatusOK, body)
			}
		}, exitUnavailable, "the broker sent more than 4 informational answers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeBroker(t, tt.handler(t))
			fx := &fakeExec{}
			code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token", "--",
				self(t))
			last := lastLine(stderr)
			if code != tt.code || !strings.HasPrefix(last, "nodkey: ") || !strings.Contains(last, tt.want) ||
				!strings.HasSuffix(last, " (exit "+itoa(tt.code)+")") {
				t.Errorf("exit code %d, stderr %q; want %d and %q in the last line", code, safe(stderr), tt.code, tt.want)
			}
			if fb.requests.Load() != 1 {
				t.Errorf("the broker got %d requests, want 1", fb.requests.Load())
			}
			if len(fx.ran()) != 0 {
				t.Error("the command started")
			}
			mustNotLeak(t, value, stderr)
			mustNotLeak(t, other, stderr)
		})
	}
}

// itoa writes n in decimal.
func itoa(n int) string {
	var b []byte
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		if n /= 10; n == 0 {
			return string(b)
		}
	}
}

// TestRunAnswerOrder: the values must come in the order of the request.
func TestRunAnswerOrder(t *testing.T) {
	t.Parallel()
	one, two := madeUp("one"), madeUp("two")
	for _, body := range []string{
		secretsAnswer(t, "NPM_TOKEN", two, "GH_TOKEN", one),
		secretsAnswer(t, "GH_TOKEN", one, "GH_TOKEN", two),
	} {
		fb := newFakeBroker(t, answer(http.StatusOK, body))
		fx := &fakeExec{}
		code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token",
			"--secret", "NPM_TOKEN=npm-token", "--", self(t))
		if code != exitUnavailable || !strings.Contains(stderr, "has another variable where") || len(fx.ran()) != 0 {
			t.Errorf("exit code %d, stderr %q; want 69 and no command", code, safe(stderr))
		}
		mustNotLeak(t, one, stderr)
		mustNotLeak(t, two, stderr)
	}
	fb := newFakeBroker(t, answer(http.StatusOK, secretsAnswer(t, "GH_TOKEN", one, "NPM_TOKEN", two)))
	fx := &fakeExec{}
	code, stderr := runIn(t.Context(), testRunner(fb.b, []string{"A=1"}, fx), "--secret", "GH_TOKEN=github-token",
		"--secret", "NPM_TOKEN=npm-token", "--", self(t))
	calls := fx.ran()
	if code != exitOK || len(calls) != 1 || len(calls[0].envv) != 3 || calls[0].envv[1] != "GH_TOKEN="+one ||
		calls[0].envv[2] != "NPM_TOKEN="+two {
		t.Errorf("exit code %d, stderr %q; the command did not start with the values in order", code, safe(stderr))
	}
}

// TestRunShortCode: nodkey run prints the short code of the first
// 102 Processing once, and only a code that has the form of a short code.
// It never prints another header, or a code from another status.
func TestRunShortCode(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	informational := func(status int, code string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set(api.ShortCodeHeader, code)
			w.Header().Set("X-Note", value)
			w.WriteHeader(status)
			w.Header().Del(api.ShortCodeHeader)
			w.Header().Del("X-Note")
		}
	}
	tests := []struct {
		name  string
		first []func(http.ResponseWriter)
		final string // the short code header of the final answer
		want  string
	}{
		{"one", []func(http.ResponseWriter){informational(http.StatusProcessing, "7qd2")}, "", "7qd2"},
		{"two", []func(http.ResponseWriter){
			informational(http.StatusProcessing, "7qd2"), informational(http.StatusProcessing, "k3f9"),
		}, "", "7qd2"},
		{"not a short code first", []func(http.ResponseWriter){
			informational(http.StatusProcessing, "7QD2"), informational(http.StatusProcessing, "k3f9"),
		}, "", "k3f9"},
		{"not a short code", []func(http.ResponseWriter){informational(http.StatusProcessing, value)}, "", ""},
		{"with letters that are not used", []func(http.ResponseWriter){informational(http.StatusProcessing, "l0o1")},
			"", ""},
		{"not 102", []func(http.ResponseWriter){informational(http.StatusEarlyHints, "7qd2")}, "", ""},
		{"in the final answer", nil, "7qd2", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := []byte(secretsAnswer(t, "GH_TOKEN", value))
			fb := newFakeBroker(t, func(w http.ResponseWriter, _ *http.Request) {
				for _, f := range tt.first {
					f(w)
				}
				if tt.final != "" {
					w.Header().Set(api.ShortCodeHeader, tt.final)
				}
				_ = transport.WriteJSONBody(w, http.StatusOK, body)
			})
			fx := &fakeExec{}
			code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token", "--",
				self(t))
			want := ""
			if tt.want != "" {
				want = "nodkey: waiting for approval (request " + tt.want + ")\n"
			}
			if code != exitOK || stderr != want {
				t.Errorf("exit code %d, stderr %q; want 0 and %q", code, safe(stderr), want)
			}
			mustNotLeak(t, value, stderr)
		})
	}
}

// TestRunRequest: the request is one POST of JSON to /v1/secrets, which
// the broker can read (transport.ReadJSON), with the header
// "Connection: close", so no other request goes on its connection.
func TestRunRequest(t *testing.T) {
	t.Parallel()
	var got *api.SecretsRequest
	var header http.Header
	var method string
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		method, header = r.Method+" "+r.RequestURI, r.Header.Clone()
		req, err := transport.ReadJSON[api.SecretsRequest](w, r)
		if err != nil {
			return
		}
		got = req
		transport.WriteError(w, http.StatusForbidden)
	})
	code, _ := runIn(t.Context(), testRunner(fb.b, []string{"NODKEY_REASON=because"}, &fakeExec{}),
		"--secret", "GH_TOKEN=github-token", "--secret", "GITHUB_TOKEN=github-token", "--", self(t), "a b", "")
	if code != exitDenied || got == nil {
		t.Fatalf("exit code %d; the broker could not read the request", code)
	}
	want := api.SecretsRequest{
		Secrets: []api.SecretRef{{Var: "GH_TOKEN", Name: "github-token"}, {Var: "GITHUB_TOKEN", Name: "github-token"}},
		Command: []string{self(t), "a b", ""},
		Reason:  "because",
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got.Dir != wd {
		t.Errorf("the request has the directory %q, want %q", got.Dir, wd)
	}
	got.Dir = ""
	if a, b := mustJSON(t, *got), mustJSON(t, want); !bytes.Equal(a, b) {
		t.Errorf("the request is %s\nwant %s", a, b)
	}
	if method != "POST "+api.PathSecrets || header.Get("Content-Type") != api.ContentType ||
		header.Get("Connection") != "close" {
		t.Errorf("the request is %s with the headers %v", method, header)
	}
}

// mustJSON returns v in JSON.
func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
