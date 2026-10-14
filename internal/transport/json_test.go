package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/code6x/nodkey/internal/claim"
)

// testRequest is a request type like the broker's.
type testRequest struct {
	Reason  string       `json:"reason"`
	Command []string     `json:"command"`
	Secrets []testSecret `json:"secrets"`
	Count   int          `json:"count"`
	Flag    bool         `json:"flag"`
	Opt     *string      `json:"opt"`
}

type testSecret struct {
	Var  string `json:"var"`
	Name string `json:"name"`
}

// jsonCanary is a made-up secret in request bodies. No error and no answer
// may repeat it.
const jsonCanary = "made-up-secret-7Qx2"

func TestDecodeJSON(t *testing.T) {
	opt := "x"
	for _, tt := range []struct {
		name string
		body string
		want *testRequest // nil means an error
		err  error
	}{
		{name: "empty object", body: `{}`, want: &testRequest{}},
		{name: "whitespace around", body: " \t\n{\"reason\":\"r\"}\r\n ", want: &testRequest{Reason: "r"}},
		{name: "all fields", body: `{"reason":"r","command":["gh","release"],"secrets":[{"var":"GH_TOKEN","name":"github-token"}],` +
			`"count":2,"flag":true,"opt":"x"}`, want: &testRequest{Reason: "r", Command: []string{"gh", "release"},
			Secrets: []testSecret{{Var: "GH_TOKEN", Name: "github-token"}}, Count: 2, Flag: true, Opt: &opt}},
		{name: "null value", body: `{"opt":null}`, want: &testRequest{}},
		{name: "escapes in a value", body: `{"reason":"a\u0072\n\"<\/"}`, want: &testRequest{Reason: "ar\n\"</"}},
		{name: "an escaped key", body: `{"\u0072eason":"x"}`, want: &testRequest{Reason: "x"}},
		{name: "a lone surrogate in a value", body: `{"reason":"\ud800"}`, want: &testRequest{Reason: "\uFFFD"}},
		{name: "control characters in a value", body: `{"reason":"\u0000\u001b[31m"}`, want: &testRequest{Reason: "\x00\x1b[31m"}},

		{name: "empty", body: ``, err: errNotObject},
		{name: "only whitespace", body: " \n ", err: errNotObject},
		{name: "null", body: `null`, err: errNotObject},
		{name: "an array", body: `[{}]`, err: errNotObject},
		{name: "a string", body: `"` + jsonCanary + `"`, err: errNotObject},
		{name: "a number", body: `1`, err: errNotObject},
		{name: "not closed", body: `{"reason":"` + jsonCanary + `"`, err: errSyntax},
		{name: "a string not closed", body: `{"reason":"` + jsonCanary, err: errSyntax},
		{name: "a second object", body: `{"reason":"x"}{"reason":"` + jsonCanary + `"}`, err: errTrailing},
		{name: "text after", body: `{"reason":"x"} ` + jsonCanary, err: errTrailing},
		{name: "a comma after", body: `{"reason":"x"},`, err: errTrailing},
		{name: "a second value after whitespace", body: "{}\n[]", err: errTrailing},
		{name: "a repeated key", body: `{"reason":"x","reason":"` + jsonCanary + `"}`, err: errDuplicate},
		{name: "a repeated key, escaped", body: `{"reason":"x","\u0072eason":"` + jsonCanary + `"}`, err: errDuplicate},
		{name: "a repeated key, escaped twice", body: `{"\u0072eason":"x","rea\u0073on":"y"}`, err: errDuplicate},
		{name: "a repeated key, nested", body: `{"secrets":[{"var":"A","var":"B"}]}`, err: errDuplicate},
		{name: "a key in upper case", body: `{"Reason":"` + jsonCanary + `"}`, err: errKeyName},
		{name: "a key in capitals", body: `{"REASON":"x"}`, err: errKeyName},
		{name: "a key with a long s", body: `{"reaſon":"x"}`, err: errKeyName},
		{name: "a key with a long s, escaped", body: `{"rea\u017fon":"x"}`, err: errKeyName},
		{name: "a capital, escaped", body: `{"\u0052eason":"x"}`, err: errKeyName},
		{name: "a NUL in a key, escaped", body: `{"reason\u0000":"x"}`, err: errKeyName},
		{name: "a lone surrogate in a key", body: `{"\ud800":"x"}`, err: errKeyName},
		{name: "a key with a slash, escaped", body: `{"reason\/":"x"}`, err: errKeyName},
		{name: "a key with the Kelvin sign", body: `{"secrets":[{"var":"A","name":"x","Key":"y"}]}`, err: errKeyName},
		{name: "a key with the Kelvin sign, escaped", body: `{"secrets":[{"var":"A","\u212aey":"y"}]}`, err: errKeyName},
		{name: "a key with a space", body: `{"rea son":"x"}`, err: errKeyName},
		{name: "an empty key", body: `{"":"x"}`, err: errKeyName},
		{name: "a secret as a key", body: `{"` + strings.ToLower(jsonCanary) + `":"x"}`, err: errKeyName},
		{name: "a key in upper case, nested", body: `{"secrets":[{"Var":"A"}]}`, err: errKeyName},
		{name: "a key that is too long", body: `{"` + strings.Repeat("a", 65) + `":1}`, err: errKeyName},
		{name: "an unknown key", body: `{"reason":"x","client":"` + jsonCanary + `"}`, err: errNotRequest},
		{name: "an unknown key, nested", body: `{"secrets":[{"var":"A","id":"x"}]}`, err: errNotRequest},
		{name: "a string for a number", body: `{"count":"` + jsonCanary + `"}`, err: errNotRequest},
		{name: "a fraction for an integer", body: `{"count":1.5}`, err: errNotRequest},
		{name: "a huge number", body: `{"count":1e400}`, err: errNotRequest},
		{name: "an integer out of range", body: `{"count":99999999999999999999}`, err: errNotRequest},
		{name: "an object for a string", body: `{"reason":{}}`, err: errNotRequest},
		{name: "too deep", body: `{"command":` + strings.Repeat("[", 16) + strings.Repeat("]", 16) + `}`, err: errTooDeep},
		{name: "invalid UTF-8", body: "{\"reason\":\"\xff" + jsonCanary + "\"}", err: errNotUTF8},
		{name: "a raw control character", body: "{\"reason\":\"\x01" + jsonCanary + "\"}", err: errSyntax},
		{name: "a comment", body: `{/* ` + jsonCanary + ` */}`, err: errSyntax},
		{name: "single quotes", body: `{'reason':'x'}`, err: errSyntax},
		{name: "a trailing comma", body: `{"reason":"x",}`, err: errSyntax},
		{name: "a byte order mark", body: "\ufeff{}", err: errNotObject},
		{name: "a bad escape", body: `{"reason":"\x41"}`, err: errSyntax},
		{name: "a short escape", body: `{"reason":"\u00"}`, err: errSyntax},
		{name: "a leading zero", body: `{"count":01}`, err: errSyntax},
		{name: "a number without digits", body: `{"count":-}`, err: errSyntax},
		{name: "a fraction without digits", body: `{"count":1.}`, err: errSyntax},
		{name: "an exponent without digits", body: `{"count":1e+}`, err: errSyntax},
		{name: "a cut literal", body: `{"flag":tru}`, err: errSyntax},
		{name: "a literal in capitals", body: `{"flag":TRUE}`, err: errSyntax},
		{name: "an empty member", body: `{,}`, err: errSyntax},
		{name: "a comma in an array", body: `{"command":["a",]}`, err: errSyntax},
		{name: "a missing comma", body: `{"reason":"x" "count":1}`, err: errSyntax},
		{name: "a key that is not a string", body: `{reason:"x"}`, err: errSyntax},
		{name: "too many keys", body: manyKeys(maxJSONKeys + 1), err: errTooManyKeys},
		{name: "keys up to the limit", body: manyKeys(maxJSONKeys), err: errNotRequest},
		{name: "too many values", body: manyValues(maxJSONValues + 1), err: errTooManyValues},
		{name: "values up to the limit", body: manyValues(maxJSONValues), want: &testRequest{Command: make([]string, maxJSONValues-2)}},
		{name: "a missing colon", body: `{"reason" "x"}`, err: errSyntax},
	} {
		got, err := decodeJSON[testRequest]([]byte(tt.body))
		if tt.want != nil {
			if err != nil {
				t.Errorf("%s: %v", tt.name, err)
			} else if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%s: got %+v, want %+v", tt.name, got, tt.want)
			}
			continue
		}
		if got != nil || !errors.Is(err, tt.err) {
			t.Errorf("%s: decodeJSON = %+v, %v; want %v", tt.name, got, err, tt.err)
		}
		if err != nil && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(jsonCanary)) {
			t.Errorf("%s: the error repeats the request: %v", tt.name, err)
		}
	}
}

// manyKeys returns a request body with n different keys in one object.
func manyKeys(n int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"k` + strconv.Itoa(i) + `":0`)
	}
	return b.String() + "}"
}

// manyValues returns a request body with n values in all: the object, the
// command line, and n-2 empty arguments.
func manyValues(n int) string {
	return `{"command":[` + strings.Repeat(`"",`, n-3) + `""]}`
}

// TestDecodeJSONKeepsKeysExact shows why keys must be lower case:
// encoding/json alone matches keys to fields without regard to case.
func TestDecodeJSONKeepsKeysExact(t *testing.T) {
	var loose testRequest
	if err := json.Unmarshal([]byte(`{"REASON":"x","rea`+"ſ"+`on":"y"}`), &loose); err != nil || loose.Reason != "y" {
		t.Fatalf("encoding/json no longer folds case (%q, %v); this test may go", loose.Reason, err)
	}
	if _, err := decodeJSON[testRequest]([]byte(`{"REASON":"x"}`)); !errors.Is(err, errKeyName) {
		t.Errorf("decodeJSON took a key in capitals: %v", err)
	}
}

// TestMaxRequestBodyFitsTheLargestRequest checks the sums in the comment
// of MaxRequestBody, and that the largest valid requests fit and decode,
// with every claimed field at its longest and full of characters that JSON
// escapes.
func TestMaxRequestBodyFitsTheLargestRequest(t *testing.T) {
	if maxClaimedText != claim.MaxInput {
		t.Fatalf("maxClaimedText is %d, but claim.MaxInput is %d", maxClaimedText, claim.MaxInput)
	}
	text := 2 + jsonEscapeFactor*maxClaimedText
	command := 1 + 3*maxArguments + jsonEscapeFactor*maxClaimedText
	ssh := maxCommandLines*command + text
	secrets := command + 3*text
	if text != 393218 || command != 405505 || ssh != 2015238 || secrets != 1585159 {
		t.Errorf("text field %d, command line %d, SSH request %d, request for secrets %d: "+
			"not the numbers in the comment of MaxRequestBody and in DESIGN.md", text, command, ssh, secrets)
	}
	if ssh+maxOtherFields > MaxRequestBody || secrets+maxOtherFields > MaxRequestBody {
		t.Fatalf("the largest request does not fit in MaxRequestBody")
	}

	worst := strings.Repeat("\x01", maxClaimedText) // each byte becomes \u0001
	commandLine := make([]string, maxArguments)
	for i := range commandLine {
		commandLine[i] = worst[:maxClaimedText/maxArguments]
	}
	type sshRequest struct {
		Commands [][]string `json:"commands"`
		Reason   string     `json:"reason"`
		Other    string     `json:"other"` // the other fields
	}
	sshReq := sshRequest{Reason: worst, Other: strings.Repeat("a", maxOtherFields-64)}
	for range maxCommandLines {
		sshReq.Commands = append(sshReq.Commands, commandLine)
	}
	type secretsRequest struct {
		Command []string     `json:"command"`
		Dir     string       `json:"dir"`
		User    string       `json:"user"`
		Reason  string       `json:"reason"`
		Secrets []testSecret `json:"secrets"`
	}
	secretsReq := secretsRequest{Command: commandLine, Dir: worst, User: worst, Reason: worst}
	for range 64 {
		secretsReq.Secrets = append(secretsReq.Secrets, testSecret{Var: strings.Repeat("A", 64), Name: strings.Repeat("a", 64)})
	}
	for name, req := range map[string]any{"SSH": sshReq, "secrets": secretsReq} {
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > MaxRequestBody {
			t.Errorf("the largest %s request has %d bytes, more than MaxRequestBody (%d)", name, len(body), MaxRequestBody)
		}
		var err2 error
		switch r := req.(type) {
		case sshRequest:
			var got *sshRequest
			got, err2 = decodeJSON[sshRequest](body)
			if err2 == nil && !reflect.DeepEqual(*got, r) {
				t.Errorf("the largest %s request decoded to another value", name)
			}
		case secretsRequest:
			var got *secretsRequest
			got, err2 = decodeJSON[secretsRequest](body)
			if err2 == nil && !reflect.DeepEqual(*got, r) {
				t.Errorf("the largest %s request decoded to another value", name)
			}
		}
		if err2 != nil {
			t.Errorf("the largest %s request: %v", name, err2)
		}
	}
}

// TestJSONEdgeCases covers more cases of decodeJSON, from the security
// review of issue #4.
func TestJSONEdgeCases(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		err  error // nil means it passes
	}{
		{"a repeated key, escaped", `{"reason":"x","\u0072eason":"y"}`, errDuplicate},
		{"a repeated key, escaped in both", `{"\u0072eason":"x","\u0072eason":"y"}`, errDuplicate},
		{"a capital, escaped", `{"\u0052eason":"x"}`, errKeyName},
		{"the same key in another case", `{"reason":"x","Reason":"y"}`, errKeyName},
		{"a NUL in a key, escaped", `{"reason\u0000":"x"}`, errKeyName},
		{"a lone surrogate in a key", `{"\ud800":"x"}`, errKeyName},
		{"a lone surrogate in a value", `{"reason":"\ud800"}`, nil},
		{"a long number", `{"count":` + strings.Repeat("9", 100000) + `}`, errNotRequest},
		{"a long fraction", `{"count":0.` + strings.Repeat("0", 100000) + `1}`, errNotRequest},
		{"exactly 16 levels", `{"command":` + strings.Repeat("[", 15) + strings.Repeat("]", 15) + `}`, errNotRequest},
		{"17 levels", `{"command":` + strings.Repeat("[", 16) + strings.Repeat("]", 16) + `}`, errTooDeep},
		{"a key of 64 characters", `{"` + strings.Repeat("a", 64) + `":1}`, errNotRequest},
		{"a key of 65 characters", `{"` + strings.Repeat("a", 65) + `":1}`, errKeyName},
	} {
		_, err := decodeJSON[testRequest]([]byte(tt.body))
		if !errors.Is(err, tt.err) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.err)
		}
	}
}

// TestDeepNestingIsCheap refuses a million open brackets at the 17th
// level, without reading on.
func TestDeepNestingIsCheap(t *testing.T) {
	body := []byte(`{"command":` + strings.Repeat("[", 1<<20))
	start := time.Now()
	if _, err := decodeJSON[testRequest](body); !errors.Is(err, errTooDeep) {
		t.Errorf("err = %v, want errTooDeep", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v", d)
	}
}

// exactBody returns a valid request body of exactly n bytes.
func exactBody(n int) string {
	const head, tail = `{"reason":"`, `"}`
	return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
}

// TestReadJSONAtTheLimit reads a body of exactly MaxRequestBody bytes, and
// refuses one byte more (413), with and without a Content-Length.
func TestReadJSONAtTheLimit(t *testing.T) {
	for _, tt := range []struct {
		name    string
		size    int
		chunked bool
		status  int
	}{
		{"exactly the limit", MaxRequestBody, false, http.StatusOK},
		{"exactly the limit, length not known", MaxRequestBody, true, http.StatusOK},
		{"one byte more", MaxRequestBody + 1, false, http.StatusRequestEntityTooLarge},
		{"one byte more, length not known", MaxRequestBody + 1, true, http.StatusRequestEntityTooLarge},
	} {
		body := exactBody(tt.size)
		r := newJSONRequest(t, strings.NewReader(body), "application/json")
		if tt.chunked {
			r.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		v, err := ReadJSON[testRequest](rec, r)
		got := rec.Code
		if err == nil && v != nil {
			got = http.StatusOK
		}
		if got != tt.status {
			t.Errorf("%s: status %d (err %v), want %d", tt.name, got, err, tt.status)
		}
	}
}

// TestJSONCost checks that hostile bodies from a client with a valid key
// (THREAT-MODEL.md T28) cost little: the limits of checkJSONShape stop
// them before encoding/json, which makes an error value for each value of
// the wrong type. It must stay fast also with the race detector.
func TestJSONCost(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		err  error
	}{
		{"unique keys", manyKeysBody(MaxRequestBody - 32), errTooManyKeys},
		{"numbers", `{"command":[` + strings.Repeat("0,", (MaxRequestBody-20)/2) + `0]}`, errTooManyValues},
		{"empty objects", `{"command":[` + strings.Repeat("{},", (MaxRequestBody-20)/3) + `{}]}`, errTooManyValues},
		// Under the limits, but each value of the wrong type.
		{"numbers up to the limit", `{"command":[` + strings.Repeat("0,", maxJSONValues-3) + `0]}`, errNotRequest},
		{"objects up to the limit", `{"command":[` + strings.Repeat("{},", maxJSONValues-3) + `{}]}`, errNotRequest},
		{"long numbers up to the limit", `{"command":[` + strings.Repeat(strings.Repeat("9", 28)+",", maxJSONValues-3) + `0]}`,
			errNotRequest},
	} {
		if len(tt.body) > MaxRequestBody {
			t.Fatalf("%s: %d bytes", tt.name, len(tt.body))
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		_, err := decodeJSON[testRequest]([]byte(tt.body))
		d := time.Since(start)
		runtime.ReadMemStats(&after)
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %d bytes, %v, %.1f MiB", tt.name, len(tt.body), d, float64(alloc)/(1<<20))
		if !errors.Is(err, tt.err) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.err)
		}
		if d > 2*time.Second || alloc > 64<<20 {
			t.Errorf("%s: too costly: %v, %.1f MiB", tt.name, d, float64(alloc)/(1<<20))
		}
	}
}

// manyKeysBody returns a body of about n bytes with different keys in one
// object.
func manyKeysBody(n int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; b.Len() < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"k` + strconv.Itoa(i) + `":0`)
	}
	return b.String() + "}"
}

// newJSONRequest returns a request to the broker with body and the content
// type ct; ct "" means no Content-Type header.
func newJSONRequest(t *testing.T, body io.Reader, ct string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/secrets", body)
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	return r
}

// checkAnswer checks an error answer of ReadJSON: the status, and nothing
// but the status text.
func checkAnswer(t *testing.T, what string, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("%s: status %d, want %d", what, rec.Code, status)
	}
	want := `{"error":"` + http.StatusText(status) + `"}`
	if got := rec.Body.String(); got != want {
		t.Errorf("%s: answer %q, want %q", what, got, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: answer Content-Type %q", what, ct)
	}
}

func TestReadJSONContentType(t *testing.T) {
	for _, tt := range []struct {
		ct string
		ok bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/json;charset=UTF-8", true},
		{"Application/JSON", true},
		{"", false},
		{"text/plain", false},
		{"application/x-www-form-urlencoded", false},
		{"application/jsonx", false},
		{"application/json; charset=latin1", false},
		{"application/json; boundary=x", false},
		{"application/json; charset=utf-8; charset=latin1", false},
		{"application/json, text/plain", false},
	} {
		rec := httptest.NewRecorder()
		got, err := ReadJSON[testRequest](rec, newJSONRequest(t, strings.NewReader(`{"reason":"x"}`), tt.ct))
		if tt.ok {
			if err != nil || got.Reason != "x" {
				t.Errorf("Content-Type %q: %+v, %v", tt.ct, got, err)
			}
			continue
		}
		if got != nil || !errors.Is(err, errContentType) {
			t.Errorf("Content-Type %q: %+v, %v; want errContentType", tt.ct, got, err)
		}
		checkAnswer(t, "Content-Type "+tt.ct, rec, http.StatusUnsupportedMediaType)
	}
	// Two Content-Type headers.
	r := newJSONRequest(t, strings.NewReader(`{}`), "application/json")
	r.Header.Add("Content-Type", "application/json")
	if _, err := ReadJSON[testRequest](httptest.NewRecorder(), r); !errors.Is(err, errContentType) {
		t.Errorf("two Content-Type headers: %v, want errContentType", err)
	}
}

// failReader fails the test if the body is read.
type failReader struct{ t *testing.T }

func (f failReader) Read([]byte) (int, error) {
	f.t.Error("the body was read")
	return 0, io.EOF
}

func TestReadJSONSizeLimit(t *testing.T) {
	// body returns a valid request of exactly n bytes.
	body := func(n int) string {
		const head, tail = `{"reason":"`, `"}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}

	rec := httptest.NewRecorder()
	if got, err := ReadJSON[testRequest](rec, newJSONRequest(t, strings.NewReader(body(MaxRequestBody)), "application/json")); err != nil || len(got.Reason) == 0 {
		t.Errorf("a body of exactly MaxRequestBody bytes: %v", err)
	}

	for _, tt := range []struct {
		name   string
		length int64 // the Content-Length; -1 means not known (chunked)
		body   io.Reader
	}{
		{"one byte too long", MaxRequestBody + 1, strings.NewReader(body(MaxRequestBody + 1))},
		{"one byte too long, length not known", -1, strings.NewReader(body(MaxRequestBody + 1))},
		{"much too long, length not known", -1, io.MultiReader(strings.NewReader(`{"reason":"`),
			strings.NewReader(strings.Repeat("a", 3*MaxRequestBody)))},
		{"a length that is too long; the body is not read", MaxRequestBody + 1, failReader{t}},
		{"a huge length; the body is not read", 1 << 40, failReader{t}},
	} {
		r := newJSONRequest(t, tt.body, "application/json")
		r.ContentLength = tt.length
		rec := httptest.NewRecorder()
		got, err := ReadJSON[testRequest](rec, r)
		if got != nil || !errors.Is(err, errTooLarge) {
			t.Errorf("%s: %v, want errTooLarge", tt.name, err)
		}
		checkAnswer(t, tt.name, rec, http.StatusRequestEntityTooLarge)
	}
}

func TestReadJSONErrorsSayLittle(t *testing.T) {
	for _, body := range []string{
		`{"reason":"x","client":"` + jsonCanary + `"}`,
		`{"reason":"` + jsonCanary + `","reason":"y"}`,
		`{"` + strings.ToLower(jsonCanary) + `":1}`,
		`{"count":"` + jsonCanary + `"}`,
		jsonCanary,
	} {
		rec := httptest.NewRecorder()
		_, err := ReadJSON[testRequest](rec, newJSONRequest(t, strings.NewReader(body), "application/json"))
		if err == nil {
			t.Errorf("%q: no error", body)
			continue
		}
		checkAnswer(t, body, rec, http.StatusBadRequest)
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(jsonCanary)) {
			t.Errorf("%q: the error repeats the request: %v", body, err)
		}
	}
	// A body that cannot be read.
	rec := httptest.NewRecorder()
	r := newJSONRequest(t, io.MultiReader(strings.NewReader("{"), errReader{}), "application/json")
	if _, err := ReadJSON[testRequest](rec, r); !errors.Is(err, errRead) {
		t.Errorf("a broken body: %v, want errRead", err)
	}
	checkAnswer(t, "a broken body", rec, http.StatusBadRequest)
}

// errReader fails every read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("the connection broke") }

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := WriteJSON(rec, http.StatusOK, whoAmI{Client: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != `{"client":"laptop"}` ||
		rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("WriteJSON wrote %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	// A value that is not JSON: a 500 answer, and an error that does not
	// repeat the value.
	rec = httptest.NewRecorder()
	err := WriteJSON(rec, http.StatusOK, map[string]any{"x": func() string { return jsonCanary }})
	if err == nil || strings.Contains(err.Error(), jsonCanary) {
		t.Errorf("WriteJSON of a function: %v", err)
	}
	checkAnswer(t, "WriteJSON of a function", rec, http.StatusInternalServerError)
	// WriteError writes only errors.
	for _, status := range []int{http.StatusOK, http.StatusFound, 299, 599, 0} {
		rec := httptest.NewRecorder()
		WriteError(rec, status)
		checkAnswer(t, "WriteError "+http.StatusText(status), rec, http.StatusInternalServerError)
	}
	rec = httptest.NewRecorder()
	WriteError(rec, http.StatusForbidden)
	checkAnswer(t, "WriteError 403", rec, http.StatusForbidden)
}

// FuzzDecodeJSON checks decodeJSON against encoding/json. A body that
// decodeJSON accepts must be one object with unique, lower-case keys, and
// must give the same value as json.Unmarshal. Every refusal must be a
// requestError, whose text is fixed.
func FuzzDecodeJSON(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"reason":"x"}`, `{"command":["a","b"],"count":1,"flag":true,"opt":null}`,
		`{"secrets":[{"var":"A","name":"b"}]}`, `{"reason":"x","reason":"y"}`, `{"Reason":"x"}`,
		`{"reason":"x"}{}`, `{"x":1}`, `[]`, `null`, "{\"reason\":\"\xff\"}", `{"count":1e400}`,
		`{"command":[[[[]]]]}`, `{"reason":"\u0000"}`, " {} ",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := decodeJSON[testRequest](data)
		if err != nil {
			var re *requestError
			if got != nil || !errors.As(err, &re) {
				t.Fatalf("decodeJSON = %v, %v; want no value and a requestError", got, err)
			}
			return
		}
		if !utf8.Valid(data) || !bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("{")) {
			t.Fatalf("decodeJSON accepted %q", data)
		}
		var ref testRequest
		if err := json.Unmarshal(data, &ref); err != nil {
			t.Fatalf("decodeJSON accepted %q, which encoding/json refuses: %v", data, err)
		}
		if !reflect.DeepEqual(*got, ref) {
			t.Fatalf("decodeJSON gave %+v, encoding/json %+v", *got, ref)
		}
		again, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if back, err := decodeJSON[testRequest](again); err != nil || !reflect.DeepEqual(back, got) {
			t.Fatalf("the value did not survive a round trip: %v", err)
		}
	})
}
