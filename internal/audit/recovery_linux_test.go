package audit

import (
	"crypto/sha256"
	"testing"
)

// TestOpenFindsARecoveryWithoutAStart: a start records a torn line with a
// log_recovered entry, and stops before it writes anything else, such as
// broker_started; so its alert may never have gone out. The next Open
// finds the log_recovered entry as the last entry and reports it with
// LastRecovery, and does not call Alert again. That holds for each later
// start until an entry follows it. A log_recovered entry that Open writes
// itself is reported by Alert only.
func TestOpenFindsARecoveryWithoutAStart(t *testing.T) {
	base := newChain(t)
	base.add(BrokerStarted{Version: "dev"})
	base.add(BrokerStopped{})
	next := newChain(t)
	next.lines, next.last = append([][]byte(nil), base.lines...), base.last
	next.add(Request{Subject: secretsSubject()})
	torn := half(next.lines[2])
	path := logPath(t)
	writeLog(t, path, append(base.bytes(), torn...), 0o600)

	first := mustOpen(t, path, testHooks())
	want := Recovery{Seq: 3, TornLength: len(torn), TornSHA256: sha256.Sum256(torn)}
	if len(first.alerts) != 1 || first.alerts[0] != want {
		t.Fatalf("alerts = %+v, want one: %+v", first.alerts, want)
	}
	if rec, ok := first.LastRecovery(); ok {
		t.Errorf("LastRecovery after Open wrote the entry itself = %+v; want none", rec)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// Two starts that stop before broker_started.
	for i := range 2 {
		l := mustOpen(t, path, testHooks())
		if len(l.alerts) != 0 {
			t.Errorf("start %d: alerts = %+v, want none: there is no new torn line", i+2, l.alerts)
		}
		if rec, ok := l.LastRecovery(); !ok || rec != want {
			t.Errorf("start %d: LastRecovery = %+v, %v; want %+v", i+2, rec, ok, want)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// A start that writes broker_started ends it.
	l := mustOpen(t, path, testHooks())
	mustAppend(t, l, BrokerStarted{Version: "dev"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if rec, ok := mustOpen(t, path, testHooks()).LastRecovery(); ok {
		t.Errorf("LastRecovery after broker_started = %+v; want none", rec)
	}
	mustVerify(t, path)

	// A new log, and a log whose last entry is another event.
	if rec, ok := mustOpen(t, logPath(t), testHooks()).LastRecovery(); ok {
		t.Errorf("LastRecovery of a new log = %+v; want none", rec)
	}
	other := logPath(t)
	writeLog(t, other, base.bytes(), 0o600)
	if rec, ok := mustOpen(t, other, testHooks()).LastRecovery(); ok {
		t.Errorf("LastRecovery after broker_stopped = %+v; want none", rec)
	}
}
