package doctor

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// docsPattern is the form of a docs section in a Problem.
var docsPattern = regexp.MustCompile(`^(docs/setup\.md|DESIGN\.md) section [0-9]+`)

// checkProblem fails t unless p is a complete Problem: every FAIL says
// what, why, the fix and the docs section (issue #124).
func checkProblem(t *testing.T, p *Problem) {
	t.Helper()
	if p == nil {
		t.Fatal("got no problem, want a FAIL")
	}
	if p.What == "" || p.Why == "" || p.Fix == "" {
		t.Errorf("problem %+v: want what, why and fix", *p)
	}
	if !docsPattern.MatchString(p.Docs) {
		t.Errorf("problem docs %q: want a docs section", p.Docs)
	}
}

func pass(string) func() (string, *Problem) {
	return func() (string, *Problem) { return "fine", nil }
}

func TestRunSkipsAfterFail(t *testing.T) {
	bad := &Problem{What: "w", Why: "y", Fix: "f", Docs: "docs/setup.md section 11"}
	r := Run([]Check{
		{Name: "a", Run: pass("a")},
		{Name: "b", Needs: []string{"a"}, Run: func() (string, *Problem) { return "", bad }},
		{Name: "c", Needs: []string{"a", "b"}, Run: func() (string, *Problem) { t.Error("c ran"); return "", nil }},
		{Name: "d", Needs: []string{"a"}, Run: pass("d")},
	})
	want := []Status{OK, Fail, Skip, OK}
	for i, s := range want {
		if r.Checks[i].Status != s {
			t.Errorf("check %d: status %s, want %s", i, r.Checks[i].Status, s)
		}
	}
	if r.OK() {
		t.Error("OK() with a FAIL")
	}
	if !(Report{}).OK() || !Run([]Check{{Name: "a", Run: pass("a")}}).OK() {
		t.Error("not OK() without a FAIL")
	}
}

func TestWriteText(t *testing.T) {
	r := Run([]Check{
		{Name: "a", Run: pass("a")},
		{Name: "b", Run: func() (string, *Problem) {
			return "", &Problem{What: "broken", Why: "it matters", Fix: "do this", Docs: "docs/setup.md section 11"}
		}},
		{Name: "c", Needs: []string{"b"}},
	})
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	want := "ok   a: fine\nFAIL b: broken\n     why: it matters\n     fix: do this\n     see: docs/setup.md section 11\nskip c: needs b\n"
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}

func TestWriteJSONForm(t *testing.T) {
	var b bytes.Buffer
	if err := (Report{}).WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	if b.String() != `{"ok":true,"checks":[]}`+"\n" {
		t.Errorf("empty report: %s", b.String())
	}
	b.Reset()
	r := Run([]Check{{Name: "b", Run: func() (string, *Problem) {
		return "", &Problem{What: "w", Why: "y", Fix: "f", Docs: "d"}
	}}})
	if err := r.WriteJSON(&b); err != nil {
		t.Fatal(err)
	}
	want := `{"ok":false,"checks":[{"name":"b","status":"FAIL","what":"w","why":"y","fix":"f","docs":"d"}]}`
	if strings.TrimSpace(b.String()) != want {
		t.Errorf("got %s, want %s", b.String(), want)
	}
	var v map[string]any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
}
