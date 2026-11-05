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

func TestReadJournal(t *testing.T) {
	h1, h2 := sha256.Sum256([]byte("one")), sha256.Sum256([]byte("two"))
	a1, a2 := Anchor{Seq: 1, Hash: h1}, Anchor{Seq: 2, Hash: h2}
	id := LogID(sha256.Sum256([]byte("line 1")))
	hexID := id.String()
	anchor := func(a Anchor) string { return JournalPrefix + a.String() + " " + hexID }
	open := func(a Anchor) string { return JournalOpenPrefix + a.String() + " " + hexID }
	newOpen := JournalOpenPrefix + "0:" + zeros + " " + zeros
	tests := []struct {
		name string
		text string
		want []JournalLine
	}{
		{"empty", "", nil},
		{"every kind, in order", "x\n" + open(a1) + "\n" + anchor(a2) + "\n" + JournalPrefix + a1.String() + "\n" + newOpen + "\r\n",
			[]JournalLine{
				{Line: 2, Kind: JournalOpen, Anchor: a1, LogID: id},
				{Line: 3, Kind: JournalAnchor, Anchor: a2, LogID: id},
				{Line: 4, Kind: JournalOldAnchor, Anchor: a1},
				{Line: 5, Kind: JournalOpen},
			}},
		{"no newline at the end", anchor(a1), []JournalLine{{Line: 1, Kind: JournalAnchor, Anchor: a1, LogID: id}}},
		// Lines that are not exactly one of the forms are skipped.
		{"an anchor with a bad hash", JournalPrefix + "1:" + strings.Repeat("g", 64) + " " + hexID + "\n", nil},
		{"an anchor with a short hash", JournalPrefix + "1:abcd " + hexID + "\n", nil},
		{"an anchor with seq 0", JournalPrefix + "0:" + zeros + " " + hexID + "\n", nil},
		{"an anchor with two spaces", JournalPrefix + a1.String() + "  " + hexID + "\n", nil},
		{"an anchor with a space at the end", anchor(a1) + " \n", nil},
		{"an anchor with a space at the end, old form", JournalPrefix + a1.String() + " \n", nil},
		{"an anchor with text after", anchor(a1) + " more\n", nil},
		{"an anchor with a short log ID", JournalPrefix + a1.String() + " " + hexID[:62] + "\n", nil},
		{"an anchor with an upper-case log ID", JournalPrefix + a1.String() + " " + strings.ToUpper(hexID) + "\n", nil},
		{"an anchor with a zero log ID", JournalPrefix + a1.String() + " " + zeros + "\n", nil},
		{"two spaces after the prefix", "audit anchor  " + a1.String() + " " + hexID + "\n", nil},
		{"a long line", strings.Repeat("x", 3*maxAnchorLine) + anchor(a1) + "\n" + anchor(a2) + "\n",
			[]JournalLine{{Line: 2, Kind: JournalAnchor, Anchor: a2, LogID: id}}},
		{"text before", "nodkey[1]: " + anchor(a1) + "\n", nil},
		{"an open without a log ID", JournalOpenPrefix + a1.String() + "\n", nil},
		{"an open with a bad log ID", JournalOpenPrefix + a1.String() + " " + strings.Repeat("x", 64) + "\n", nil},
		{"an open with a space at the end", open(a1) + " \n", nil},
		{"an open with text after", open(a1) + " more\n", nil},
		{"an open with two spaces", JournalOpenPrefix + a1.String() + "  " + hexID + "\n", nil},
		{"an open with a bad head", JournalOpenPrefix + "1:xyz " + hexID + "\n", nil},
		{"an open of entry 0 with a hash", JournalOpenPrefix + "0:" + hex.EncodeToString(h1[:]) + " " + zeros + "\n", nil},
		{"an open of entry 0 with a log ID", JournalOpenPrefix + "0:" + zeros + " " + hexID + "\n", nil},
		{"an open of entry 1 with a zero log ID", JournalOpenPrefix + a1.String() + " " + zeros + "\n", nil},
		{"an open too long", open(a1) + strings.Repeat("0", maxAnchorLine) + "\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadJournal(strings.NewReader(tt.text))
			if err != nil {
				t.Fatalf("ReadJournal: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ReadJournal = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("line %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLogID(t *testing.T) {
	if !(LogID{}).IsZero() || (LogID{}).String() != zeros {
		t.Errorf("zero LogID: %q, %v", LogID{}.String(), LogID{}.IsZero())
	}
	id := LogID(sha256.Sum256([]byte("x")))
	if id.IsZero() || id.String() != hex.EncodeToString(id[:]) {
		t.Errorf("LogID = %q", id.String())
	}
}
