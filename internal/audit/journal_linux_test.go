package audit

// The open lines and the log IDs, with logs made by Open and Append, and
// changed while the broker is stopped (DESIGN.md section 9, THREAT-MODEL.md
// T17, issue #40). The journal of a test is the journal of every broker
// run, with other log lines between them: see journalCopy.

import (
	"bytes"
	"crypto/sha256"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// verifyJournal checks the log at path with the journal text, like
// journalctl -o cat | nodkey audit verify.
func verifyJournal(t *testing.T, path, journal string, extra ...Anchor) (Result, error) {
	t.Helper()
	lines, err := ReadJournal(strings.NewReader(journal))
	if err != nil {
		t.Fatalf("ReadJournal: %v", err)
	}
	return VerifyJournal(bytes.NewReader(readLog(t, path)), lines, extra, nil)
}

func mustVerifyJournal(t *testing.T, path, journal string, extra ...Anchor) Result {
	t.Helper()
	res, err := verifyJournal(t, path, journal, extra...)
	if err != nil {
		t.Fatalf("VerifyJournal: %v", err)
	}
	return res
}

// logIDOf returns the log ID of the log at path.
func logIDOf(t *testing.T, path string) LogID {
	t.Helper()
	first, _, _ := bytes.Cut(readLog(t, path), []byte("\n"))
	return sha256.Sum256(first)
}

// laterHooks are testHooks with a clock an hour later, so a new log has
// another line 1.
func laterHooks() hooks {
	h := testHooks()
	h.now = func() time.Time { return testTime.Add(time.Hour) }
	return h
}

// restart is a broker run that writes broker_started and is then killed.
func restart(t *testing.T, path string, h hooks) *testLog {
	t.Helper()
	l := mustOpen(t, path, h)
	mustAppend(t, l, BrokerStarted{Version: "dev"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return l
}

// TestVerifyJournalPassesGoodRuns: a log of three runs passes, and each
// later run has an open line that is checked.
func TestVerifyJournalPassesGoodRuns(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	run2 := restart(t, path, testHooks())
	run3 := restart(t, path, testHooks())
	res := mustVerifyJournal(t, path, journalCopy(run1, run2, run3))
	want := Result{Entries: 6, Last: res.Last, Anchors: 6, NewestAnchor: 6, LogID: logIDOf(t, path), Opens: 2, NewStarts: 1}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("VerifyJournal = %+v, want %+v", res, want)
	}
}

// TestVerifyJournalFindsAnEntryAddedWhileStopped: a well-formed entry,
// appended while the broker is stopped, continues the chain, so every
// anchor passes (TestAnchorsMissAnEntryAddedWhileStopped). The open line
// of the next run finds it: its head is the added entry, not the last
// anchor.
func TestVerifyJournalFindsAnEntryAddedWhileStopped(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	c := newChain(t)
	c.lines = bytes.Split(bytes.TrimSuffix(readLog(t, path), []byte("\n")), []byte("\n"))
	c.last = Anchor{Seq: 4, Hash: sha256.Sum256(c.lines[3])}
	c.add(Denied{Subject: secretsSubject(), Cause: CauseApprover}) // the added entry 5
	writeLog(t, path, c.bytes(), 0o600)

	run2 := restart(t, path, testHooks())
	journal := journalCopy(run1, run2)
	if _, err := Verify(bytes.NewReader(readLog(t, path)), anchorsOf(t, journal)...); err != nil {
		t.Fatalf("Verify with every anchor: %v; the anchors alone do not find it", err)
	}
	// Line 1 and 7 are the other log lines, 2 the open line of the new
	// log, 3 to 6 the anchors of run 1, 8 the open line of run 2.
	_, err := verifyJournal(t, path, journal)
	checkVerifyError(t, err, 0, "journal line 8: the broker opened the log at entry 5, but the last anchor of this "+
		"log before it is entry 4: entries were added or removed while the broker was stopped")
}

// TestVerifyJournalFindsACutLog: the log is cut while the broker is
// stopped, and the next run writes the entries again. The anchor checks
// find it first.
func TestVerifyJournalFindsACutLog(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	lines := bytes.SplitAfter(readLog(t, path), []byte("\n"))
	writeLog(t, path, bytes.Join(lines[:2], nil), 0o600)
	run2 := mustOpen(t, path, testHooks())
	mustAppend(t, run2, BrokerStarted{Version: "dev"})
	mustAppend(t, run2, Denied{Subject: secretsSubject(), Cause: CauseExpired})
	_, err := verifyJournal(t, path, journalCopy(run1, run2))
	checkVerifyError(t, err, 0, "two anchors for entry 3 have different hashes")

	// Cut, and nothing written again: the anchors of run 1 find it.
	path = logPath(t)
	run1 = firstRun(t, path)
	lines = bytes.SplitAfter(readLog(t, path), []byte("\n"))
	writeLog(t, path, bytes.Join(lines[:2], nil), 0o600)
	run2 = mustOpen(t, path, testHooks())
	if err := run2.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = verifyJournal(t, path, journalCopy(run1, run2))
	checkVerifyError(t, err, 0, "no entry 3: the log ends at entry 2")
}

// TestVerifyJournalShowsADeletedLog: the log is deleted while the broker
// is stopped, and the broker starts a new one at entry 1. The new log
// passes, and the result names the old log with its newest entry.
func TestVerifyJournalShowsADeletedLog(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	oldID := logIDOf(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	run2 := restart(t, path, laterHooks())
	run3 := restart(t, path, laterHooks())
	journal := journalCopy(run1, run2, run3)
	if _, err := Verify(bytes.NewReader(readLog(t, path)), anchorsOf(t, journal)...); err == nil {
		t.Error("Verify with every anchor of both logs: no error")
	}
	res := mustVerifyJournal(t, path, journal)
	want := Result{Entries: 2, Last: res.Last, Anchors: 2, NewestAnchor: 2, LogID: logIDOf(t, path), Opens: 1, NewStarts: 2,
		OtherLogs: []OtherLog{{LogID: oldID, Newest: 4}}}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("VerifyJournal = %+v, want %+v", res, want)
	}
}

// TestVerifyJournalChecksAMovedLog: a person moves the log away on
// purpose, and the broker starts a new one. It is not a cut: each log
// passes with the same journal, and names the other one.
func TestVerifyJournalChecksAMovedLog(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	moved := path + ".1"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	run2 := restart(t, path, laterHooks())
	run3 := restart(t, path, laterHooks())
	journal := journalCopy(run1, run2, run3)
	oldID, newID := logIDOf(t, moved), logIDOf(t, path)

	res := mustVerifyJournal(t, path, journal)
	if res.LogID != newID || res.Opens != 1 || res.Anchors != 2 ||
		!reflect.DeepEqual(res.OtherLogs, []OtherLog{{LogID: oldID, Newest: 4}}) {
		t.Errorf("VerifyJournal of the new log = %+v", res)
	}
	res = mustVerifyJournal(t, moved, journal)
	if res.LogID != oldID || res.Entries != 4 || res.Opens != 0 || res.Anchors != 4 ||
		!reflect.DeepEqual(res.OtherLogs, []OtherLog{{LogID: newID, Newest: 2}}) {
		t.Errorf("VerifyJournal of the moved log = %+v", res)
	}
}

// TestVerifyJournalFindsAReplacedLog: while the broker is stopped, the log
// is replaced by another whole chain, so line 1 is new. The broker opens
// it and goes on. The journal has no anchor of that log before its open
// line.
func TestVerifyJournalFindsAReplacedLog(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	fake := newChain(t)
	fake.add(BrokerStarted{Version: "made-up"})
	fake.add(Request{Subject: secretsSubject()})
	fake.add(Denied{Subject: secretsSubject(), Cause: CauseApprover})
	fake.add(BrokerStopped{})
	writeLog(t, path, fake.bytes(), 0o600)

	run2 := restart(t, path, testHooks())
	_, err := verifyJournal(t, path, journalCopy(run1, run2))
	checkVerifyError(t, err, 0, "journal line 8: the journal has no anchor of this log before the broker opened it "+
		"at entry 4: the log was replaced, or the journal lost its older lines")
	// The same when the journal lost the lines of run 1.
	_, err = verifyJournal(t, path, journalCopy(run2))
	checkVerifyError(t, err, 0, "journal line 2: the journal has no anchor of this log")
	// And a journal of another log only names no line of this one.
	other := logPath(t)
	run3 := firstRun(t, other)
	_, err = verifyJournal(t, path, journalCopy(run3))
	checkVerifyError(t, err, 0, "the journal has no anchor and no open line of this log")
}

// TestVerifyJournalReadsOldAnchors: the journal of an earlier version has
// anchors without the log ID. They count as anchors of the log, for the
// anchor checks and for the open lines.
func TestVerifyJournalReadsOldAnchors(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	var oldForm strings.Builder
	for _, a := range anchorsOf(t, run1.journal.String()) {
		oldForm.WriteString(JournalPrefix + a.String() + "\n")
	}
	run2 := restart(t, path, testHooks())
	journal := "nodkey: broker started\n" + oldForm.String() + journalCopy(run2)
	res := mustVerifyJournal(t, path, journal)
	if res.Entries != 5 || res.Anchors != 5 || res.Opens != 1 || res.NewStarts != 0 || len(res.OtherLogs) != 0 {
		t.Errorf("VerifyJournal = %+v; want 5 entries and anchors, 1 open", res)
	}
	// An old-form anchor of another log is taken as one of this log.
	bad := Anchor{Seq: 2, Hash: sha256.Sum256([]byte("not entry 2"))}
	_, err := verifyJournal(t, path, journal+JournalPrefix+bad.String()+"\n")
	checkVerifyError(t, err, 0, "two anchors for entry 2 have different hashes")
	// And an extra anchor too.
	_, err = verifyJournal(t, path, journal, bad)
	checkVerifyError(t, err, 0, "two anchors for entry 2 have different hashes")
}

// TestVerifyJournalSkipsFalseLines: lines that are almost an anchor or an
// open line are skipped, so they can neither pass nor fail a log.
func TestVerifyJournalSkipsFalseLines(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	run2 := restart(t, path, testHooks())
	id := logIDOf(t, path)
	a4 := anchorsOf(t, run1.journal.String())[3]
	five := Anchor{Seq: 5, Hash: sha256.Sum256([]byte("not entry 5"))}
	false1 := strings.Join([]string{
		JournalPrefix + "4:" + strings.Repeat("g", 64) + " " + id.String(),
		JournalPrefix + five.String() + "  " + id.String(),
		JournalPrefix + five.String() + " " + id.String() + " more",
		JournalPrefix + five.String() + " " + id.String() + strings.Repeat(" ", maxAnchorLine),
		JournalOpenPrefix + a4.String() + " " + strings.Repeat("z", 64),
		JournalOpenPrefix + "1:" + strings.Repeat("0", 64) + " " + id.String()[:63],
		JournalOpenPrefix + five.String() + " " + id.String() + " ",
	}, "\n") + "\n"
	// Before the open line of run 2: a false open line would fail it, and
	// a false anchor 5 would fail the open line of run 2.
	journal := journalCopy(run1) + false1 + journalCopy(run2)
	if res := mustVerifyJournal(t, path, journal); res.Opens != 1 || res.Anchors != 5 {
		t.Errorf("VerifyJournal = %+v; want 1 open and 5 anchors", res)
	}
}

// TestVerifyJournalAfterATornLine: Open records a torn line. Its open line
// holds the head before the log_recovered entry, and the log passes.
func TestVerifyJournalAfterATornLine(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	f, err := openFile(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"seq":5,"time":"2026-`)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	run2 := restart(t, path, testHooks())
	if len(run2.alerts) != 1 || run2.alerts[0].Seq != 5 {
		t.Fatalf("alerts = %+v; want the log_recovered entry 5", run2.alerts)
	}
	lines, err := ReadJournal(strings.NewReader(run2.journal.String()))
	if err != nil || len(lines) != 3 {
		t.Fatalf("ReadJournal of run 2 = %+v, %v; want an open line and two anchors", lines, err)
	}
	head := anchorsOf(t, run1.journal.String())[3]
	if lines[0].Kind != JournalOpen || lines[0].Anchor != head || lines[0].LogID != logIDOf(t, path) {
		t.Errorf("open line = %+v; want the head %v, before the log_recovered entry", lines[0], head)
	}
	res := mustVerifyJournal(t, path, journalCopy(run1, run2))
	if res.Entries != 6 || res.TornLines != 1 || res.Opens != 1 || res.Anchors != 6 {
		t.Errorf("VerifyJournal = %+v; want 6 entries, 1 torn line, 1 open, 6 anchors", res)
	}

	// A log that is only a torn line: the open line has a zero log ID, and
	// the anchors have the hash of the torn bytes, which are line 1.
	path = logPath(t)
	writeLog(t, path, []byte(`{"seq":1,"ti`), 0o600)
	run := restart(t, path, testHooks())
	if !strings.HasPrefix(run.journal.String(), newOpenLine) {
		t.Errorf("journal = %q; want it to start with %q", run.journal.String(), newOpenLine)
	}
	res = mustVerifyJournal(t, path, journalCopy(run))
	if res.LogID != LogID(sha256.Sum256([]byte(`{"seq":1,"ti`))) || res.NewStarts != 1 || res.Anchors != 2 {
		t.Errorf("VerifyJournal = %+v; want the hash of the torn bytes as the log ID", res)
	}
}

// TestOpenRefusesALongFirstLine: Open reads line 1 for the log ID; a line
// 1 longer than MaxLineSize is refused, like a long last line.
func TestOpenRefusesALongFirstLine(t *testing.T) {
	c := newChain(t)
	c.add(BrokerStarted{Version: "dev"})
	ok := append(c.bytes(), c.bytes()...) // two lines, so line 1 is not the last line
	long := append(append(bytes.Repeat([]byte("x"), MaxLineSize+1), '\n'), bytes.Repeat(c.bytes(), 3)...)
	path := logPath(t)
	writeLog(t, path, long, 0o600)
	if _, err := openLog(t, path, testHooks()); err == nil || !strings.Contains(err.Error(), "its first line is longer than") {
		t.Errorf("Open: %v; want the long line 1 refused", err)
	}
	if got := readLog(t, path); !bytes.Equal(got, long) {
		t.Error("Open changed the log")
	}
	// A line 1 of MaxLineSize bytes is fine.
	edge := append(append(bytes.Repeat([]byte("x"), MaxLineSize), '\n'), ok...)
	writeLog(t, path, edge, 0o600)
	l := mustOpen(t, path, testHooks())
	if want := openLine(c.last, LogID(sha256.Sum256(bytes.Repeat([]byte("x"), MaxLineSize)))); l.journal.String() != want {
		t.Errorf("journal = %q, want %q", l.journal.String(), want)
	}
}
