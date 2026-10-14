package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestReadAnchors(t *testing.T) {
	h1, h2 := sha256.Sum256([]byte("one")), sha256.Sum256([]byte("two"))
	a1, a2 := Anchor{Seq: 1, Hash: h1}, Anchor{Seq: 2, Hash: h2}
	line := func(a Anchor) string { return JournalPrefix + a.String() }
	long := strings.Repeat("x", 3*maxAnchorLine)
	tests := []struct {
		name string
		text string
		want []Anchor
	}{
		{"empty", "", nil},
		{"one line", line(a1) + "\n", []Anchor{a1}},
		{"no newline at the end", line(a1), []Anchor{a1}},
		{"carriage return", line(a1) + "\r\n" + line(a2) + "\r\n", []Anchor{a1, a2}},
		{"other lines", "nodkey: broker started\n" + line(a1) + "\nlevel=INFO msg=x\n" + line(a2) + "\n", []Anchor{a1, a2}},
		{"the same anchor twice", line(a1) + "\n" + line(a1) + "\n", []Anchor{a1, a1}},
		{"a long line, then an anchor", long + "\n" + line(a2) + "\n", []Anchor{a2}},
		{"a long line that ends in an anchor", long + line(a1) + "\n" + line(a2) + "\n", []Anchor{a2}},
		{"text before", "Oct 14 12:00:00 broker nodkey[1]: " + line(a1) + "\n", nil},
		{"a space before", " " + line(a1) + "\n", nil},
		{"text after", line(a1) + " more\n", nil},
		{"two carriage returns", line(a1) + "\r\r\n", nil},
		{"no prefix", a1.String() + "\n", nil},
		{"a bad anchor", JournalPrefix + "0:" + hex.EncodeToString(h1[:]) + "\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadAnchors(strings.NewReader(tt.text))
			if err != nil {
				t.Fatalf("ReadAnchors: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ReadAnchors = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("anchor %d = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestReadAnchorsReadError(t *testing.T) {
	_, err := ReadAnchors(&failingReader{data: []byte(JournalPrefix + canary + "\n")})
	if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "CANARY") {
		t.Errorf("ReadAnchors = %v; want the read error of line 2, without the text", err)
	}
	var ve *VerifyError
	if errors.As(err, &ve) {
		t.Errorf("ReadAnchors = %v; a read error is not a *VerifyError", err)
	}
}
