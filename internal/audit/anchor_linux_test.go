package audit

// What the anchors find when the log is changed while the broker is
// stopped (DESIGN.md section 9, THREAT-MODEL.md T17). The attacker is the
// broker user: it can read and write the log, and stop the broker, which
// systemd then starts again. It cannot change the journal. The journal of
// a test is the journal of every broker run, with other log lines between
// them, as journalctl -o cat prints it.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// journalCopy returns the journal of the broker runs, with another log
// line of the broker between them.
func journalCopy(runs ...*testLog) string {
	var b strings.Builder
	for _, r := range runs {
		b.WriteString("nodkey: broker started\n")
		b.WriteString(r.journal.String())
	}
	return b.String()
}

// anchorsOf reads the anchors of a journal copy with ReadAnchors.
func anchorsOf(t *testing.T, journal string) []Anchor {
	t.Helper()
	anchors, err := ReadAnchors(strings.NewReader(journal))
	if err != nil || len(anchors) == 0 {
		t.Fatalf("ReadAnchors = %v, %v; want anchors", anchors, err)
	}
	return anchors
}

// firstRun is a broker run that approves a request and sends the secret,
// and is then killed: there is no broker_stopped entry.
func firstRun(t *testing.T, path string) *testLog {
	t.Helper()
	l := mustOpen(t, path, testHooks())
	mustAppend(t, l, BrokerStarted{Version: "dev"})
	mustAppend(t, l, Request{Subject: secretsSubject()})
	mustAppend(t, l, Decision{Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce})
	mustAppend(t, l, SecretSent{Subject: secretsSubject()})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return l
}

// checkVerifyError checks that err is a *VerifyError on line with a
// problem that starts with want.
func checkVerifyError(t *testing.T, err error, line uint64, want string) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.Line != line || !strings.HasPrefix(ve.Problem, want) {
		t.Errorf("Verify: %v; want line %d: %q", err, line, want)
	}
}

// TestEveryAnchorFindsACutLog: the log is cut after entry 2 while the
// broker is stopped, so the decision and secret_sent entries are gone.
// The next run writes entries 3 and 4 again. The newest anchor alone does
// not find this; every anchor since the log began does.
func TestEveryAnchorFindsACutLog(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	lines := bytes.SplitAfter(readLog(t, path), []byte("\n"))
	writeLog(t, path, bytes.Join(lines[:2], nil), 0o600)

	run2 := mustOpen(t, path, testHooks())
	mustAppend(t, run2, BrokerStarted{Version: "dev"})
	mustAppend(t, run2, Denied{Subject: secretsSubject(), Cause: CauseExpired})
	if len(run2.alerts) != 0 {
		t.Errorf("alerts = %v; the cut leaves no torn line", run2.alerts)
	}
	all := anchorsOf(t, journalCopy(run1, run2))
	log := readLog(t, path)
	if _, err := Verify(bytes.NewReader(log), all[len(all)-1]); err != nil {
		t.Errorf("Verify with the newest anchor: %v; it cannot find the cut (DESIGN.md section 9)", err)
	}
	_, err := Verify(bytes.NewReader(log), all...)
	checkVerifyError(t, err, 0, "two anchors for entry 3 have different hashes")
}

// TestEveryAnchorFindsADemotedEntry: with append access only, such as with
// chattr +a, the attacker appends a log_recovered entry that names the
// last real entry, the decision, as a torn line. The broker starts again
// without an alert, because the log ends in a newline. Every anchor finds
// it: entry 3 is now the forged entry.
func TestEveryAnchorFindsADemotedEntry(t *testing.T) {
	path := logPath(t)
	run1 := mustOpen(t, path, testHooks())
	mustAppend(t, run1, BrokerStarted{Version: "dev"})
	mustAppend(t, run1, Request{Subject: secretsSubject()})
	mustAppend(t, run1, Decision{Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce})
	if err := run1.Close(); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(readLog(t, path), []byte("\n")), []byte("\n"))
	decision := lines[2]
	sum := sha256.Sum256(decision)
	forged := appendLine(nil, 3, testTime, eventLogRecovered, sha256.Sum256(lines[1]),
		mustEncode(t, logRecovered{TornLength: len(decision), TornSHA256: hex.EncodeToString(sum[:])}))
	f, err := openFile(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(forged, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	run2 := mustOpen(t, path, testHooks())
	mustAppend(t, run2, BrokerStarted{Version: "dev"})
	if len(run2.alerts) != 0 {
		t.Errorf("alerts = %v", run2.alerts)
	}
	all := anchorsOf(t, journalCopy(run1, run2))
	log := readLog(t, path)
	if res, err := Verify(bytes.NewReader(log), all[len(all)-1]); err != nil || res.TornLines != 1 {
		t.Errorf("Verify with the newest anchor = %+v, %v; it shows the decision as a torn line", res, err)
	}
	_, err = Verify(bytes.NewReader(log), all...)
	checkVerifyError(t, err, 4, "is entry 3, and its hash is not the hash in the anchor")
}

// TestAnchorsMissAnEntryAddedWhileStopped shows a risk that remains
// (THREAT-MODEL.md T17): a well-formed entry, appended while the broker is
// stopped, continues the chain. The next run builds on it, so every anchor
// passes. Only the missing anchor for that entry in the journal shows it.
func TestAnchorsMissAnEntryAddedWhileStopped(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	c := newChain(t)
	c.lines = bytes.Split(bytes.TrimSuffix(readLog(t, path), []byte("\n")), []byte("\n"))
	c.last = Anchor{Seq: 4, Hash: sha256.Sum256(c.lines[3])}
	c.add(Denied{Subject: secretsSubject(), Cause: CauseApprover}) // the forged entry 5
	writeLog(t, path, c.bytes(), 0o600)

	run2 := mustOpen(t, path, testHooks())
	mustAppend(t, run2, BrokerStarted{Version: "dev"})
	all := anchorsOf(t, journalCopy(run1, run2))
	res, err := Verify(bytes.NewReader(readLog(t, path)), all...)
	if err != nil || res.Entries != 6 || res.Anchors != 5 {
		t.Fatalf("Verify with every anchor = %+v, %v; want it to pass with 6 entries and 5 anchors", res, err)
	}
	for _, a := range all {
		if a.Seq == 5 {
			t.Fatalf("the journal has an anchor for the forged entry: %v", a)
		}
	}
}

// TestEveryAnchorFindsANewLogAfterADelete: the log is removed while the
// broker is stopped, and the broker starts a new one. Every anchor finds
// it. A log that a person moved away on purpose looks the same: then use
// only the anchors since the new log began.
func TestEveryAnchorFindsANewLogAfterADelete(t *testing.T) {
	path := logPath(t)
	run1 := firstRun(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	later := testHooks() // the new log starts later, so its first entry differs
	later.now = func() time.Time { return testTime.Add(time.Hour) }
	run2 := mustOpen(t, path, later)
	mustAppend(t, run2, BrokerStarted{Version: "dev"})
	all := anchorsOf(t, journalCopy(run1, run2))
	log := readLog(t, path)
	if _, err := Verify(bytes.NewReader(log), anchorsOf(t, journalCopy(run2))...); err != nil {
		t.Errorf("Verify with the anchors of the new log: %v", err)
	}
	_, err := Verify(bytes.NewReader(log), all...)
	checkVerifyError(t, err, 0, "two anchors for entry 1 have different hashes")
}

// TestReadAnchorsReadsTheJournal: ReadAnchors finds every anchor that
// Append wrote, among other lines.
func TestReadAnchorsReadsTheJournal(t *testing.T) {
	l := mustOpen(t, logPath(t), testHooks())
	var want []Anchor
	for _, ev := range sampleEvents() {
		want = append(want, mustAppend(t, l, ev))
	}
	journal := "time=2026-10-14T12:00:00Z level=INFO msg=started\n" + l.journal.String() + "audit anchor 99:short\n"
	got, err := ReadAnchors(strings.NewReader(journal))
	if err != nil || len(got) != len(want) {
		t.Fatalf("ReadAnchors = %d anchors, %v; want %d", len(got), err, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("anchor %d = %v, want %v", i, got[i], want[i])
		}
	}
}
