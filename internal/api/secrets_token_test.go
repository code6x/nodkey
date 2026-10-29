package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSecretsAnswerGrantToken(t *testing.T) {
	t.Parallel()
	tok := "nkg_" + strings.Repeat("A", 40)
	a := SecretsAnswer{Secrets: []SecretValue{{Var: "A", Value: []byte("v")}}, GrantToken: tok}
	b, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var got SecretsAnswer
	if err := json.Unmarshal(b, &got); err != nil || got.GrantToken != tok {
		t.Fatalf("round trip: %v", err)
	}
	if s := fmt.Sprintf("%v %+v %#v", got, got, got); strings.Contains(s, tok) {
		t.Error("the token is shown")
	}
	// Without a token: still valid. Unknown field and long token: refused.
	if err := json.Unmarshal([]byte(`{"secrets":[]}`), &got); err != nil {
		t.Errorf("no token: %v", err)
	}
	for _, in := range []string{`{"secrets":[],"x":"y"}`,
		`{"secrets":[],"grant_token":"` + strings.Repeat("a", MaxGrantToken+1) + `"}`,
		`{"secrets":[],"grant_token":1}`} {
		if err := json.Unmarshal([]byte(in), &got); err == nil {
			t.Errorf("accepted %.40s", in)
		}
	}
	a.GrantToken = `a"b`
	if _, err := a.Encode(); err == nil {
		t.Error("encoded a token that needs escaping")
	}
}
