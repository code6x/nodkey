package audit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestVerifyJournal checks the open lines and the log IDs with journals
// made by hand (DESIGN.md section 9, issue #40). The tests in
// journal_linux_test.go make them with Open and Append.
func TestVerifyJournal(t *testing.T) {
	c := newChain(t)
	a1 := c.add(BrokerStarted{Version: "dev"})
	a2 := c.add(Request{Subject: secretsSubject()})
	a3 := c.add(BrokerStopped{})
	log := c.bytes()
	id := LogID(sha256.Sum256(c.lines[0]))
	other := LogID(sha256.Sum256([]byte("another log")))
	bad := Anchor{Seq: 3, Hash: sha256.Sum256([]byte("not entry 3"))}

	anchor := func(a Anchor) JournalLine { return JournalLine{Kind: JournalAnchor, Anchor: a, LogID: id} }
	old := func(a Anchor) JournalLine { return JournalLine{Kind: JournalOldAnchor, Anchor: a} }
	open := func(a Anchor) JournalLine { return JournalLine{Kind: JournalOpen, Anchor: a, LogID: id} }
	of := func(l JournalLine, logID LogID) JournalLine { l.LogID = logID; return l }
	newOpen := JournalLine{Kind: JournalOpen}

	tests := []struct {
		name    string
		journal []JournalLine
		extra   []Anchor
		want    Result // Entries, TornLines, Last and LogID are set below
		problem string // the start of the problem; "" for a pass
	}{
		{name: "a new log, then a restart",
			journal: []JournalLine{newOpen, anchor(a1), anchor(a2), open(a2), anchor(a3)},
			want:    Result{Anchors: 3, Opens: 1, NewStarts: 1}},
		{name: "old-form anchors, then an open with the log ID",
			journal: []JournalLine{old(a1), old(a2), open(a2), anchor(a3)},
			want:    Result{Anchors: 3, Opens: 1}},
		{name: "extra anchors count like old-form anchors", journal: []JournalLine{anchor(a2)}, extra: []Anchor{a1, a3},
			want: Result{Anchors: 3}},
		{name: "a wrong extra anchor", journal: []JournalLine{anchor(a2)}, extra: []Anchor{bad},
			problem: "line 3: is entry 3, and its hash is not the hash in the anchor"},
		{name: "another log, with other hashes for the same seqs, is not checked",
			journal: []JournalLine{of(newOpen, LogID{}), of(anchor(a1), other), of(anchor(bad), other), of(open(bad), other),
				of(anchor(Anchor{Seq: 7, Hash: a1.Hash}), other), newOpen, anchor(a1), anchor(a2), anchor(a3)},
			want: Result{Anchors: 3, NewStarts: 2, OtherLogs: []OtherLog{{LogID: other, Newest: 7}}}},
		{name: "an anchor of another log does not count as the last one",
			journal: []JournalLine{anchor(a1), anchor(a2), of(anchor(a3), other), open(a2), anchor(a3)},
			want:    Result{Anchors: 3, Opens: 1, OtherLogs: []OtherLog{{LogID: other, Newest: 3}}}},
		{name: "an entry added while the broker was stopped",
			journal: []JournalLine{anchor(a1), anchor(a2), {Line: 9, Kind: JournalOpen, Anchor: a3, LogID: id}},
			problem: "journal line 9: the broker opened the log at entry 3, but the last anchor of this log before it is entry 2"},
		{name: "a log cut while the broker was stopped",
			journal: []JournalLine{anchor(a1), anchor(a2), anchor(a3), open(a2)},
			problem: "journal line 0: the broker opened the log at entry 2, but the last anchor of this log before it is entry 3"},
		{name: "an entry changed while the broker was stopped",
			journal: []JournalLine{anchor(a1), anchor(a2), old(a3), open(bad)},
			problem: "journal line 0: the broker opened the log at entry 3, and its hash is not the hash in the anchor before it"},
		{name: "an open before any anchor of the log",
			journal: []JournalLine{open(a2), anchor(a3)},
			problem: "journal line 0: the journal has no anchor of this log before the broker opened it at entry 2"},
		{name: "two anchors of the log for one entry",
			journal: []JournalLine{anchor(a3), old(bad)},
			problem: "two anchors for entry 3 have different hashes"},
		{name: "an anchor of the log that does not match",
			journal: []JournalLine{anchor(bad)},
			problem: "line 3: is entry 3, and its hash is not the hash in the anchor"},
		{name: "no line of the log", journal: []JournalLine{newOpen, of(anchor(a1), other)},
			problem: "the journal has no anchor and no open line of this log"},
		{name: "an empty journal", problem: "the journal has no anchor and no open line of this log"},
		{name: "only extra anchors", extra: []Anchor{a1},
			problem: "the journal has no anchor and no open line of this log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := VerifyJournal(bytes.NewReader(log), tt.journal, tt.extra...)
			if tt.problem != "" {
				var ve *VerifyError
				if !errors.As(err, &ve) || !strings.HasPrefix(ve.Error(), tt.problem) {
					t.Fatalf("VerifyJournal = %+v, %v; want %q", res, err, tt.problem)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyJournal: %v", err)
			}
			want := tt.want
			want.Entries, want.Last, want.LogID = 3, a3, id
			if !reflect.DeepEqual(res, want) {
				t.Errorf("VerifyJournal = %+v, want %+v", res, want)
			}
		})
	}
}

// TestVerifyJournalFailsOnABadLog: the checks of Verify come first.
func TestVerifyJournalFailsOnABadLog(t *testing.T) {
	c := newChain(t)
	a1 := c.add(BrokerStarted{Version: "dev"})
	journal := []JournalLine{{Kind: JournalAnchor, Anchor: a1, LogID: sha256.Sum256(c.lines[0])}}
	for _, tt := range []struct {
		name, log, want string
	}{
		{"empty", "", "the log is empty"},
		{"a torn line only", string(c.lines[0]), "line 1: has no newline at the end"},
		{"line 1 too long", strings.Repeat("x", MaxLineSize+1) + "\n", "line 1: is longer than"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyJournal(strings.NewReader(tt.log), journal)
			var ve *VerifyError
			if !errors.As(err, &ve) || !strings.HasPrefix(ve.Error(), tt.want) {
				t.Errorf("VerifyJournal: %v; want %q", err, tt.want)
			}
		})
	}
}
