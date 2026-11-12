package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestLoginRequestsAreStrict(t *testing.T) {
	good := `{"url":"https://example.com/","item":"11111111-1111-1111-1111-111111111111"}`
	var r LoginRequest
	if err := json.Unmarshal([]byte(good), &r); err != nil || r.Item == "" {
		t.Fatalf("good request: %v", err)
	}
	bad := []string{
		`{"url":"https://example.com/"}`,
		`{"url":"https://example.com/","item":null}`,
		`{"url":"https://example.com/","item":"x","other":"y"}`,
		`{"URL":"https://example.com/","item":"x"}`,
		`{"url":"` + strings.Repeat("a", MaxURL+1) + `","item":"x"}`,
		`{"url":"u","item":"` + strings.Repeat("a", MaxItemID+1) + `"}`,
		`[]`,
	}
	for _, b := range bad {
		if err := json.Unmarshal([]byte(b), &LoginRequest{}); err == nil {
			t.Errorf("accepted %.60s", b)
		}
		if err := json.Unmarshal([]byte(b), &TOTPRequest{}); err == nil {
			t.Errorf("TOTPRequest accepted %.60s", b)
		}
	}
	for _, b := range []string{`{}`, `{"url":1}`, `{"url":null}`, `{"url":"` + strings.Repeat("a", MaxURL+1) + `"}`} {
		if err := json.Unmarshal([]byte(b), &ListLoginsRequest{}); err == nil {
			t.Errorf("ListLoginsRequest accepted %.60s", b)
		}
	}
}

func TestListLoginsAnswer(t *testing.T) {
	data, err := json.Marshal(ListLoginsAnswer{})
	if err != nil || string(data) != `{"logins":[]}` {
		t.Fatalf("empty answer %s, %v", data, err)
	}
	a := ListLoginsAnswer{Logins: []LoginEntry{{Logins: "web", ID: "i", Name: "n", Username: "u"}}}
	data, _ = json.Marshal(a)
	got, err := ReadAnswer[ListLoginsAnswer](bytes.NewReader(data))
	if err != nil || len(got.Logins) != 1 || got.Logins[0] != a.Logins[0] {
		t.Fatalf("round trip: %v %+v", err, got)
	}
	for _, b := range []string{
		`{"logins":[{"logins":"w","id":"i","name":"n","username":"u","password":"p"}]}`,
		`{"logins":[{"logins":"w","id":"i","name":"n"}]}`,
		`{"logins":null}`,
	} {
		if _, err := ReadAnswer[ListLoginsAnswer](strings.NewReader(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestLoginAnswerEncodeAndHide(t *testing.T) {
	pw := []byte("made-up-password-" + t.Name())
	a := LoginAnswer{Username: "alice@example.com \"q\"", Password: bytes.Clone(pw)}
	body, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if cap(body) != len(body) {
		t.Errorf("the buffer is not exact: len %d cap %d", len(body), cap(body))
	}
	got, err := ReadAnswer[LoginAnswer](bytes.NewReader(body))
	if err != nil || got.Username != a.Username || !bytes.Equal(got.Password, pw) {
		t.Fatalf("round trip: %v", err)
	}
	got.Clear()
	if !bytes.Equal(got.Password, make([]byte, len(pw))) {
		t.Error("Clear left the password")
	}
	for _, s := range []string{fmt.Sprint(a), fmt.Sprintf("%v %+v %#v %s", a, a, a, a), slog.Any("a", a).Value.String()} {
		if strings.Contains(s, string(pw)) {
			t.Errorf("the password shows: %s", s)
		}
	}
	if _, err := json.Marshal(a); err == nil {
		t.Error("json.Marshal wrote the answer")
	}
	for _, b := range []string{
		`{"username":"u"}`, `{"username":"u","password":null}`, `{"username":"u","password":"!!"}`,
		`{"username":"u","password":"AA==","x":1}`,
		`{"username":"` + strings.Repeat("a", MaxLoginText+1) + `","password":"AA=="}`,
	} {
		if _, err := ReadAnswer[LoginAnswer](strings.NewReader(b)); err == nil {
			t.Errorf("accepted %.60s", b)
		}
	}
	big := LoginAnswer{Password: make([]byte, MaxValue+1)}
	if _, err := big.Encode(); err == nil {
		t.Error("Encode took a password over the cap")
	}
}

func TestTOTPAnswer(t *testing.T) {
	a, err := ReadAnswer[TOTPAnswer](strings.NewReader(`{"code":"287082"}`))
	if err != nil || a.Code != "287082" {
		t.Fatalf("good answer: %v", err)
	}
	if s := fmt.Sprintf("%v %+v %#v", *a, *a, *a); strings.Contains(s, "287082") {
		t.Errorf("the code shows: %s", s)
	}
	for _, b := range []string{`{"code":"12345"}`, `{"code":"123456789"}`, `{"code":"12a456"}`, `{"code":null}`, `{}`, `{"code":"123456","x":1}`} {
		if _, err := ReadAnswer[TOTPAnswer](strings.NewReader(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestPreapproveRequestLoginFields(t *testing.T) {
	r := PreapproveRequest{Login: "11111111-1111-1111-1111-111111111111", URL: "https://example.com/", Uses: 1}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back PreapproveRequest
	if err := json.Unmarshal(data, &back); err != nil || back.Login != r.Login || back.URL != r.URL {
		t.Fatalf("round trip: %v %s", err, data)
	}
	plain, _ := json.Marshal(PreapproveRequest{Uses: 1})
	if strings.Contains(string(plain), "login") || strings.Contains(string(plain), "url") || strings.Contains(string(plain), "windows") {
		t.Errorf("a request with no login writes its fields: %s", plain)
	}
	if err := json.Unmarshal(plain, &PreapproveRequest{}); err != nil {
		t.Errorf("a request with no login field: %v", err)
	}
}
