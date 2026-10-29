package grantkey

import (
	"fmt"
	"strings"
	"testing"
)

func mustNew(t testing.TB) Token {
	t.Helper()
	tok, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRoundTrip(t *testing.T) {
	for i := 0; i < 200; i++ {
		tok := mustNew(t)
		if len(tok.Reveal()) != Length {
			t.Fatalf("length %d", len(tok.Reveal()))
		}
		got, err := Parse(tok.Reveal())
		if err != nil || got.Reveal() != tok.Reveal() {
			t.Fatalf("round trip failed: %v", err)
		}
		if !Equal(Hash(got), Hash(tok)) {
			t.Fatal("hash differs")
		}
	}
}

func TestUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		v := mustNew(t).Reveal()
		if seen[v] {
			t.Fatal("duplicate token")
		}
		seen[v] = true
	}
}

func TestHashDiffers(t *testing.T) {
	if Equal(Hash(mustNew(t)), Hash(mustNew(t))) {
		t.Fatal("equal hashes")
	}
}

func TestParseRejects(t *testing.T) {
	good := mustNew(t).Reveal()
	flip := func(s string, i int) string {
		c := byte('0')
		if s[i] == '0' {
			c = '1'
		}
		return s[:i] + string(c) + s[i+1:]
	}
	cases := map[string]string{
		"empty":        "",
		"prefix":       "nkx_" + good[4:],
		"no prefix":    good[4:],
		"short":        good[:Length-1],
		"long":         good + "0",
		"bad char":     good[:10] + "-" + good[11:],
		"underscore":   good[:10] + "_" + good[11:],
		"unicode":      good[:10] + "é" + good[12:],
		"checksum":     flip(good, Length-1),
		"body changed": flip(good, 10),
		"space":        good + " ",
		"newline":      good + "\n",
		"leading ws":   " " + good[:Length-1],
		"inner ws":     good[:10] + " " + good[11:],
		"nul":          good[:10] + "\x00" + good[11:],
	}
	for name, in := range cases {
		_, err := Parse(in)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), in) && in != "" {
			t.Errorf("%s: error holds input", name)
		}
	}
}

func TestParseRejectsOverflow(t *testing.T) {
	// 43 'z' is above 2^256, with a valid checksum.
	body := prefix + strings.Repeat("z", randChars)
	if _, err := Parse(body + checksum(body)); err == nil {
		t.Fatal("accepted a value above 32 bytes")
	}
}

func TestNeverPrinted(t *testing.T) {
	tok := mustNew(t)
	v := tok.Reveal()
	body := v[len(prefix):]
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%T"} {
		for _, arg := range []any{tok, &tok, []Token{tok}, map[string]Token{"a": tok}, struct{ T Token }{tok}} {
			out := fmt.Sprintf(f, arg)
			if strings.Contains(out, v) || strings.Contains(out, body[:12]) {
				t.Errorf("%s leaks: %s", f, out)
			}
		}
	}
	if fmt.Sprint(tok) != "nkg_…" || tok.String() != "nkg_…" {
		t.Error("unexpected redaction")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(mustNew(f).Reveal())
	f.Add("")
	f.Add("nkg_")
	f.Add(prefix + strings.Repeat("z", randChars+sumChars))
	f.Fuzz(func(t *testing.T, s string) {
		tok, err := Parse(s)
		if err != nil {
			if len(s) >= 8 && strings.Contains(err.Error(), s) {
				t.Fatal("error holds input")
			}
			return
		}
		if tok.Reveal() != s || len(s) != Length {
			t.Fatal("accepted but not equal")
		}
		body := s[:len(prefix)+randChars]
		if body+checksum(body) != s {
			t.Fatal("re-encode differs")
		}
	})
}
