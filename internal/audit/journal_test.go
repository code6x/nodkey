package audit

import (
	"bytes"
	"cmp"
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
	at := func(l JournalLine, line uint64) JournalLine { l.Line = line; return l }
	// Two open lines that do not match: entries added while stopped.
	gaps := []JournalLine{anchor(a1), at(open(a2), 5), anchor(a2), at(open(a3), 7), anchor(a3)}
	gap5 := "journal line 5: the broker opened the log at entry 2, but the last anchor of this log before it is entry 1"
	gap7 := "journal line 7: the broker opened the log at entry 3, but the last anchor of this log before it is entry 2"
	// Old-form anchors of two logs, X and Y, from an earlier version:
	// X was deleted, and the broker started Y. Then the broker was
	// upgraded and opened Y, a person moved Y away, and the broker
	// started this log.
	x2 := Anchor{Seq: 2, Hash: sha256.Sum256([]byte("entry 2 of X"))}
	y1 := Anchor{Seq: 1, Hash: sha256.Sum256([]byte("entry 1 of Y"))}
	y2 := Anchor{Seq: 2, Hash: sha256.Sum256([]byte("entry 2 of Y"))}
	y5 := Anchor{Seq: 5, Hash: sha256.Sum256([]byte("entry 5 of Y"))}
	twoOldLogs := []JournalLine{old(bad), old(x2), old(y1), old(y2), of(open(y2), other), of(anchor(y5), other),
		newOpen, anchor(a1), anchor(a2), anchor(a3)}

	tests := []struct {
		name    string
		journal []JournalLine
		extra   []Anchor
		accept  []Anchor
		want    Result // Entries, TornLines, Last and LogID are set below
		problem string // the start of the problem; "" for a pass
		more    string // more text that the problem must have
		newest  uint64 // Result.NewestAnchor; 0 means 3
	}{
		{name: "a new log, then a restart",
			journal: []JournalLine{newOpen, anchor(a1), anchor(a2), open(a2), anchor(a3)},
			want:    Result{Anchors: 3, Opens: 1, NewStarts: 1}},
		{name: "old-form anchors, then an open with the log ID",
			journal: []JournalLine{old(a1), old(a2), open(a2), anchor(a3)},
			want:    Result{Anchors: 3, Opens: 1}},
		{name: "an old-form anchor after new-form anchors counts as the last one",
			journal: []JournalLine{anchor(a1), anchor(a2), old(a3), open(a3)},
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
		{name: "two open lines that do not match are both reported", journal: gaps, problem: gap5, more: gap7},
		{name: "an accepted gap passes, and only that gap", journal: gaps, accept: []Anchor{a2}, problem: gap7},
		{name: "two accepted gaps", journal: gaps, accept: []Anchor{a3, a2},
			want: Result{Anchors: 3, AcceptedOpens: 2}},
		{name: "an accepted head is not a proven anchor",
			journal: []JournalLine{anchor(a1), anchor(a2), open(a3)}, accept: []Anchor{a3},
			want: Result{Anchors: 2, AcceptedOpens: 1}, newest: 2},
		{name: "a first open line after a line of another log cannot be accepted",
			journal: []JournalLine{old(a1), old(bad), of(open(bad), other), open(a3)}, accept: []Anchor{a3},
			problem: "journal line 0: the journal has no anchor of this log before the broker opened it at entry 3",
			more:    "--accept-open for entry 3: no open line"},
		{name: "an accepted head is an anchor, so it must match the log", journal: gaps, accept: []Anchor{a2, bad},
			problem: "two anchors for entry 3 have different hashes"},
		{name: "an accept for an open line that passes is refused",
			journal: []JournalLine{anchor(a1), anchor(a2), open(a2), anchor(a3)}, accept: []Anchor{a2},
			problem: "--accept-open for entry 2: no open line of this log with that head can be accepted"},
		{name: "after a gap, the next open line is checked against it",
			journal: []JournalLine{anchor(a1), at(open(a2), 3), at(open(a3), 4)}, accept: []Anchor{a2},
			problem: "journal line 4: the broker opened the log at entry 3, but the last anchor of this log before it is entry 2"},
		{name: "an open line right after an open line matches it",
			journal: []JournalLine{anchor(a1), anchor(a2), open(a2), open(a2), anchor(a3)},
			want:    Result{Anchors: 3, Opens: 2}},
		{name: "a journal that lost its oldest lines, with the gap accepted",
			journal: []JournalLine{open(a2), anchor(a3)}, accept: []Anchor{a2},
			want: Result{Anchors: 1, AcceptedOpens: 1}},
		{name: "old-form anchors of two logs, then a moved log", journal: twoOldLogs,
			want: Result{Anchors: 3, NewStarts: 1, OtherLogs: []OtherLog{{LogID: other, Newest: 5}}}},
		{name: "an old-form anchor takes the log ID of the next open line with one",
			journal: []JournalLine{old(bad), newOpen, of(open(bad), other), anchor(a1), anchor(a2), anchor(a3)},
			want:    Result{Anchors: 3, NewStarts: 1, OtherLogs: []OtherLog{{LogID: other, Newest: 3}}}},
		{name: "no line of the log", journal: []JournalLine{newOpen, of(anchor(a1), other)},
			problem: "the journal has no anchor and no open line of this log"},
		{name: "an empty journal", problem: "the journal has no anchor and no open line of this log"},
		{name: "only extra anchors", extra: []Anchor{a1},
			problem: "the journal has no anchor and no open line of this log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := VerifyJournal(bytes.NewReader(log), tt.journal, tt.extra, tt.accept)
			if tt.problem != "" {
				var ve *VerifyError
				if !errors.As(err, &ve) || !strings.HasPrefix(err.Error(), tt.problem) ||
					!strings.Contains(err.Error(), tt.more) {
					t.Fatalf("VerifyJournal = %+v, %v; want %q and %q", res, err, tt.problem, tt.more)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyJournal: %v", err)
			}
			want := tt.want
			want.Entries, want.Last, want.LogID, want.NewestAnchor = 3, a3, id, cmp.Or(tt.newest, 3)
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
			_, err := VerifyJournal(strings.NewReader(tt.log), journal, nil, nil)
			var ve *VerifyError
			if !errors.As(err, &ve) || !strings.HasPrefix(ve.Error(), tt.want) {
				t.Errorf("VerifyJournal: %v; want %q", err, tt.want)
			}
		})
	}
}
