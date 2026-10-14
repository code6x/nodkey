package store

import (
	"errors"
	"strings"
	"testing"
)

// esc returns JSON escapes: a backslash, "u" and each code, such as
// esc("00e9") for the escape of "é". The tests build escapes with it, so
// that no tool that handles this file can turn them into characters.
func esc(codes ...string) string {
	var b strings.Builder
	for _, c := range codes {
		b.WriteString("\\" + "u" + c)
	}
	return b.String()
}

// realBWSAnswer is an answer of "bws secret get" in the form of bws 2.1.0
// (serde_json's pretty print), with made-up IDs and text.
var realBWSAnswer = `{
  "id": "6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b",
  "organizationId": "0a1b2c3d-0000-4000-8000-000000000001",
  "projectId": null,
  "key": "DEPLOY_TOKEN",
  "value": "made-up \"value\" é ✓ \\ / ` + esc("0001") + ` 😀 ` + esc("d83d", "de00") + `",
  "note": "line 1\nline 2",
  "creationDate": "2026-10-14T12:00:00.123456Z",
  "revisionDate": "2026-10-14T12:00:00.123456Z"
}
`

// realBWItem is an answer of "bw get item" in the form of bw 2026.9.1
// (JSON.stringify), with made-up IDs and text.
var realBWItem = `{"passwordHistory":[{"lastUsedDate":"2026-10-01T12:00:00.000Z","password":"old"}],` +
	`"revisionDate":"2026-10-14T12:00:00.000Z","creationDate":"2026-10-01T12:00:00.000Z","deletedDate":null,` +
	`"archivedDate":null,"object":"item","id":"6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b","organizationId":null,` +
	`"folderId":null,"type":1,"reprompt":0,"name":"deploy","notes":null,"favorite":false,` +
	`"fields":[{"name":"api","value":"other","type":1,"linkedId":null}],"login":{"fido2Credentials":[],` +
	`"uris":[{"match":null,"uri":"https://example.com"}],"username":"deploy","password":"p` + esc("00e4") + `ss\"word",` +
	`"totp":null,"passwordRevisionDate":null},"collectionIds":[],"attachments":[{"size":"12","sizeName":"12 B"}],` +
	`"key":null,"n":-1.5e+10}`

func TestParseRealAnswers(t *testing.T) {
	t.Parallel()
	v, err := parseBWSSecret([]byte(realBWSAnswer), testItemID)
	if err != nil {
		t.Fatalf("parseBWSSecret: %v", err)
	}
	if got, want := string(v.Bytes()), "made-up \"value\" é ✓ \\ / \x01 😀 😀"; got != want {
		t.Errorf("value = %q, want %q", got, want)
	}
	v, err = parseBWItem([]byte(realBWItem), strings.ToUpper(testItemID))
	if err != nil {
		t.Fatalf("parseBWItem: %v", err)
	}
	if got, want := string(v.Bytes()), "päss\"word"; got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
	status, err := parseBWStatus([]byte(`{"serverUrl":null,"lastSync":null,"userEmail":"nodkey@example.com",` +
		`"userId":"00000000-0000-0000-0000-000000000000","status":"locked"}`))
	if err != nil || status != bwLocked {
		t.Errorf("parseBWStatus = %q, %v", status, err)
	}
	for _, bad := range []string{`{"status":"Locked"}`, `{"status":"unknown"}`, `{}`, `{"status":null}`,
		`{"status":"locked","status":"unlocked"}`, `{"status":"` + strings.Repeat("x", maxStatusLen+1) + `"}`} {
		if _, err := parseBWStatus([]byte(bad)); !errors.Is(err, ErrBadAnswer) {
			t.Errorf("parseBWStatus(%q) = %v, want %v", bad, err, ErrBadAnswer)
		}
	}
}

func TestJSONStrings(t *testing.T) {
	t.Parallel()
	good := []struct{ in, want string }{
		{`"a"`, "a"},
		{`""`, ""},
		{`"\"\\\/\b\f\n\r\t"`, "\"\\/\b\f\n\r\t"},
		{`"` + esc("0041", "00e9", "20ac") + `"`, "Aé€"},
		{`"` + esc("d83d", "de00") + `"`, "😀"},
		{`"` + esc("D83D", "DE00") + `"`, "😀"},
		{`"` + esc("0000") + `"`, "\x00"},
		{"\"\x7f\"", "\x7f"},
		{"\"\xef\xbf\xbd\"", string(rune(0xfffd))}, // U+FFFD itself is valid
		{"\"\xf4\x8f\xbf\xbf\"", string(rune(0x10ffff))},
		{`"é✓😀"`, "é✓😀"},
		{`"` + esc("002f", "005C", "0022") + `"`, `/\"`},
		{`"` + esc("d7ff", "e000", "ffff") + `"`, string([]rune{0xd7ff, 0xe000, 0xffff})},
		{`"a` + esc("0062") + `c"`, "abc"},
		{`"` + string([]rune{0x2028, 0x2029}) + `"`, string([]rune{0x2028, 0x2029})},
	}
	for _, tc := range good {
		r := &jsonReader{data: []byte(tc.in)}
		b, err := r.secret()
		if err != nil || string(b) != tc.want || r.pos != len(tc.in) {
			t.Errorf("secret(%q) = %q, %v at %d, want %q", tc.in, b, err, r.pos, tc.want)
		}
		if err == nil && cap(b) != len(b) {
			t.Errorf("secret(%q): capacity %d for %d bytes", tc.in, cap(b), len(b))
		}
	}
	bad := []string{
		``, `"`, `"abc`, `abc"`, `'a'`, `"\"`, `"\x"`, `"` + "\\" + `u12"`, `"` + "\\" + `u12g4"`, `"` + "\\" + `U0041"`,
		`"` + esc("d800") + `"`, `"` + esc("dc00") + `"`, `"` + esc("d800", "0041") + `"`, `"` + esc("d800") + `x"`,
		`"` + esc("de00", "d83d") + `"`, `"` + esc("d83d", "d83d") + `"`, `"` + esc("d83d") + "\\" + `n"`,
		"\"\x00\"", "\"\x1f\"", "\"\n\"", "\"\t\"", "\"\xff\"", "\"\xc3\"", "\"\xed\xa0\x80\"",
		"\"\xc0\xaf\"", "\"\xf8\x88\x80\x80\x80\"", "\"\xf4\x90\x80\x80\"",
	}
	for _, in := range bad {
		r := &jsonReader{data: []byte(in)}
		if b, err := r.secret(); !errors.Is(err, ErrBadAnswer) || b != nil {
			t.Errorf("secret(%q) = %q, %v, want %v", in, b, err, ErrBadAnswer)
		}
	}
}

// TestJSONAnswers checks the reader on whole answers. It reads every
// value and keeps none.
func TestJSONAnswers(t *testing.T) {
	t.Parallel()
	value := func(in string) error {
		return readAnswer([]byte(in), func(r *jsonReader, _ string) error { return r.skip() })
	}
	good := []string{
		`{"value":"x"}`, " \t\r\n{\"value\":\"x\"} \t\r\n", `{"value":"x","a":[1,-0,0.5,1e5,1E-5,-1.25e+3,true,false,null,{},[]]}`,
		`{"a":{"b":{"c":[[[{"value":"no"}]]]}},"value":"x"}`, `{"value" : "x" , "b" : { } }`,
		`{"value":"x","":"empty key","` + esc("0076") + `alue2":1}`,
		`{"value":"x","a":` + strings.Repeat("[", maxDepth-1) + strings.Repeat("]", maxDepth-1) + `}`,
	}
	for _, in := range good {
		if err := value(in); err != nil {
			t.Errorf("readAnswer(%q) = %v", in, err)
		}
	}
	bad := []string{
		``, ` `, `null`, `"value"`, `[]`, `{`, `}`, `{"value":"x"`, `{"value":"x"}}`, `{"value":"x"},`,
		`{"value":"x"} {}`, `{"value":"x"}x`, "\xef\xbb\xbf{\"value\":\"x\"}", `{"value":"x",}`, `{,"value":"x"}`,
		`{"value" "x"}`, `{"value":"x" "a":1}`, `{value:"x"}`, `{"value":"x","a":}`, `{"value":"x","a":01}`,
		`{"value":"x","a":1.}`, `{"value":"x","a":.5}`, `{"value":"x","a":+1}`, `{"value":"x","a":1e}`,
		`{"value":"x","a":-}`, `{"value":"x","a":tru}`, `{"value":"x","a":nul}`, `{"value":"x","a":True}`,
		`{"value":"x","a":NaN}`, `{"value":"x","a":[1,]}`, `{"value":"x","a":[,1]}`, `{"value":"x","a":[1 2]}`,
		`{"value":"x","a":{"b":1,"b":2}}`, `{"value":"x","` + esc("0076") + `alue":"y"}`,
		"{\"value\":\"x\",\"a\":\"\xff\"}", "{\"value\":\"x\",\"a\x01\":1}",
		`{"value":"x","a":` + strings.Repeat("[", maxDepth) + strings.Repeat("]", maxDepth) + `}`,
		"{\"value\":\"x\"}\x00", "{\"value\":\"x\"}\v", `{"value":"x"}/* */`, `{"value":"x",/**/"a":1}`,
	}
	for _, in := range bad {
		if err := value(in); !errors.Is(err, ErrBadAnswer) {
			t.Errorf("readAnswer(%q) = %v, want %v", in, err, ErrBadAnswer)
		}
	}
}

// TestAnswersMustBeForTheAskedItem checks the "id" of both answers: it
// must be there, and be the asked ID, in upper or lower case.
func TestAnswersMustBeForTheAskedItem(t *testing.T) {
	t.Parallel()
	upper := strings.ToUpper(testItemID)
	parsers := map[string]func(data []byte, id string) (Value, error){
		"bws": parseBWSSecret,
		"bw":  parseBWItem,
	}
	answer := map[string]func(id string) string{
		"bws": func(id string) string { return `{"id":"` + id + `","value":"v"}` },
		"bw":  func(id string) string { return `{"id":"` + id + `","login":{"password":"v"}}` },
	}
	for name, parse := range parsers {
		for _, tc := range []struct{ answerID, askedID string }{
			{testItemID, testItemID}, {upper, testItemID}, {testItemID, upper},
		} {
			v, err := parse([]byte(answer[name](tc.answerID)), tc.askedID)
			if err != nil || string(v.Bytes()) != "v" {
				t.Errorf("%s: answer for %s, asked %s: %v", name, tc.answerID, tc.askedID, err)
			}
		}
		// The Kelvin sign folds to "k" in strings.EqualFold. A UUID never
		// has a "k", so this only shows that the comparison is ASCII.
		kelvin := string(rune(0x212a))
		for _, bad := range []string{
			answer[name]("00000000-0000-4000-8000-0000000000aa"), // another item
			answer[name](testItemID + " "),
			answer[name](testItemID[:35]),
			answer[name](kelvin),
			strings.Replace(answer[name](testItemID), `"id":"`+testItemID+`",`, "", 1), // no id
			strings.Replace(answer[name](testItemID), `"id":"`+testItemID+`"`, `"id":null`, 1),
			strings.Replace(answer[name](testItemID), `"id":"`+testItemID+`"`, `"id":7`, 1),
			strings.Replace(answer[name](testItemID), `"id"`, `"ID"`, 1),
			`{"id":"` + testItemID + `","id":"` + testItemID + `"}`,
		} {
			if v, err := parse([]byte(bad), testItemID); !errors.Is(err, ErrBadAnswer) || v.Bytes() != nil {
				t.Errorf("%s: %q = %v, want %v", name, bad, err, ErrBadAnswer)
			}
		}
	}
	if sameUUID(kelvinUUID(), strings.ReplaceAll(kelvinUUID(), string(rune(0x212a)), "k")) {
		t.Error("sameUUID folds the Kelvin sign")
	}
}

// kelvinUUID returns a text with the Kelvin sign in it.
func kelvinUUID() string { return "6f1e2d3c-" + string(rune(0x212a)) + "b5a-4987-8a6b-5c4d3e2f1a0b" }

func TestValuesWithNULAreRefused(t *testing.T) {
	t.Parallel()
	nul := esc("0000")
	for name, tc := range map[string]struct {
		answer string
		parse  func(data []byte, id string) (Value, error)
	}{
		"bws":       {`{"id":"` + testItemID + `","value":"a` + nul + `b"}`, parseBWSSecret},
		"bws start": {`{"id":"` + testItemID + `","value":"` + nul + `"}`, parseBWSSecret},
		"bw":        {`{"id":"` + testItemID + `","login":{"password":"a` + nul + `"}}`, parseBWItem},
	} {
		v, err := tc.parse([]byte(tc.answer), testItemID)
		if !errors.Is(err, ErrBadValue) || v.Bytes() != nil {
			t.Errorf("%s: %v, want %v", name, err, ErrBadValue)
		}
	}
	// Other control characters can be in a value.
	v, err := parseBWSSecret([]byte(`{"id":"`+testItemID+`","value":"a`+esc("0001")+`\n\t"}`), testItemID)
	if err != nil || string(v.Bytes()) != "a\x01\n\t" {
		t.Errorf("a value with control characters: %q, %v", v.Bytes(), err)
	}
}

func TestBWItemDates(t *testing.T) {
	t.Parallel()
	item := func(fields string) string {
		return `{"id":"` + testItemID + `",` + fields + `"login":{"password":"v"}}`
	}
	for fields, want := range map[string]error{
		``:                     nil, // a normal item of bw 2026.9.1
		`"deletedDate":null,`:  nil,
		`"archivedDate":null,`: nil,
		`"deletedDate":null,"archivedDate":null,`:                                             nil,
		`"deletedDate":"2026-10-13T12:00:00.000Z",`:                                           ErrTrashed,
		`"archivedDate":"2026-10-13T12:00:00.000Z",`:                                          ErrArchived,
		`"deletedDate":"2026-10-13T12:00:00.000Z","archivedDate":"2026-10-13T12:00:00.000Z",`: ErrTrashed,
		`"deletedDate":"",`:    ErrTrashed,
		`"archivedDate":"",`:   ErrArchived,
		`"deletedDate":0,`:     ErrBadAnswer,
		`"archivedDate":true,`: ErrBadAnswer,
		`"archivedDate":{},`:   ErrBadAnswer,
	} {
		v, err := parseBWItem([]byte(item(fields)), testItemID)
		if !errors.Is(err, want) || (want == nil) != (v.Bytes() != nil) {
			t.Errorf("%s: %v, want %v", fields, err, want)
		}
	}
}

func TestParseKey(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"abc": "abc", "abc\n": "abc", " abc \r\n": "abc", "\t\v\fabc": "abc", "a+/=:.-_~!": "a+/=:.-_~!",
	} {
		v, ok := parseKey([]byte(in), 16)
		if !ok || string(v.Bytes()) != want {
			t.Errorf("parseKey(%q) = %q, %v", in, v.Bytes(), ok)
		}
	}
	for _, in := range []string{"", " ", "\n\n", "a b", "a\nb", "a\x00", "a\x7f", "é", strings.Repeat("a", 17)} {
		if _, ok := parseKey([]byte(in), 16); ok {
			t.Errorf("parseKey(%q) worked", in)
		}
	}
	// The result is a copy: clearing the input leaves it.
	in := []byte("token\n")
	v, _ := parseKey(in, 16)
	clear(in)
	if string(v.Bytes()) != "token" {
		t.Error("parseKey did not copy the key")
	}
}
