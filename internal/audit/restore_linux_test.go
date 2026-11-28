package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// restoreLog makes a log with a broker_started, a scheduled decision and a
// broker_stopped, and returns its path, its logger and the seq of the
// decision. Close the logger before the log is changed.
func restoreLog(t *testing.T) (string, *testLog, uint64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := mustOpen(t, path, testHooks())
	mustAppend := func(ev Event) Anchor {
		t.Helper()
		a, err := l.Append(ev)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		return a
	}
	mustAppend(BrokerStarted{Version: "1.2.0"})
	a := mustAppend(Decision{Subject: preapproveSubject(), UserID: 1, Answer: AnswerApproveOnce})
	mustAppend(BrokerStopped{})
	return path, l, a.Seq
}

func readForRestoreCause(t *testing.T, path string, wall time.Time) (RestoreLog, ResetCause) {
	t.Helper()
	got, cause, err := ReadForRestore(path, wall)
	if (cause == "") != (err == nil) {
		t.Fatalf("cause %q with error %v: want an error exactly with a cause", cause, err)
	}
	if cause != "" && got.Records != nil {
		t.Errorf("cause %q with %d records, want none", cause, len(got.Records))
	}
	return got, cause
}

// TestReadForRestore: a log that matches its head file gives its records
// and the head.
func TestReadForRestore(t *testing.T) {
	path, l, seq := restoreLog(t)
	_ = l.Close()
	got, cause := readForRestoreCause(t, path, testTime)
	if cause != "" || got.Head != seq || len(got.Records) != 3 {
		t.Fatalf("got head %d, %d records, cause %q; want head %d, 3 records", got.Head, len(got.Records), cause, seq)
	}
}

// TestReadForRestoreNothing: no log, or no head file, is no cause, and
// nothing makes a grant.
func TestReadForRestoreNothing(t *testing.T) {
	dir := t.TempDir()
	if got, cause := readForRestoreCause(t, filepath.Join(dir, "audit.jsonl"), testTime); cause != "" || got.Head != 0 {
		t.Errorf("no log: head %d, cause %q", got.Head, cause)
	}
	path, l, _ := restoreLog(t)
	_ = l.Close()
	if err := os.Remove(path + HeadSuffix); err != nil {
		t.Fatal(err)
	}
	// A broken log with no head file is not read: nothing can be rebuilt.
	writeFile(t, path, []byte("not a log\n"))
	if got, cause := readForRestoreCause(t, path, testTime); cause != "" || got.Head != 0 || got.Records != nil {
		t.Errorf("no head file: head %d, %d records, cause %q; want nothing", got.Head, len(got.Records), cause)
	}
}

// TestReadForRestoreRefuses: a changed log, a cut or older log, a log of
// another head, a missing log with a head, an entry in another format,
// and a clock set back each give their cause.
func TestReadForRestoreRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(t *testing.T, path string, l *testLog)
		wall  time.Time
		cause ResetCause
	}{
		{name: "changed", cause: ResetChain, edit: func(t *testing.T, path string, _ *testLog) {
			b, _ := os.ReadFile(path)
			writeFile(t, path, bytes.Replace(b, []byte(`"user_id":1`), []byte(`"user_id":2`), 1))
		}},
		{name: "cut", cause: ResetHead, edit: func(t *testing.T, path string, _ *testLog) {
			b, _ := os.ReadFile(path)
			writeFile(t, path, b[:bytes.IndexByte(b, '\n')+1])
		}},
		{name: "older copy", cause: ResetHead, edit: func(t *testing.T, path string, l *testLog) {
			l2 := reopen(t, path, l)
			old, _ := os.ReadFile(path)
			if _, err := l2.Append(Decision{Subject: preapproveSubject(), UserID: 1, Answer: AnswerApproveOnce}); err != nil {
				t.Fatal(err)
			}
			_ = l2.Close()
			writeFile(t, path, old)
		}},
		{name: "other log", cause: ResetHead, edit: func(t *testing.T, path string, _ *testLog) {
			// A log with another line 1, and the same entries after it.
			other := filepath.Join(t.TempDir(), "audit.jsonl")
			l2 := mustOpen(t, other, testHooks())
			for _, ev := range []Event{BrokerStarted{Version: "9.9.9"},
				Decision{Subject: preapproveSubject(), UserID: 1, Answer: AnswerApproveOnce}} {
				if _, err := l2.Append(ev); err != nil {
					t.Fatal(err)
				}
			}
			_ = l2.Close()
			b, _ := os.ReadFile(other + HeadSuffix)
			writeFile(t, path+HeadSuffix, b)
		}},
		{name: "log missing", cause: ResetHead, edit: func(t *testing.T, path string, _ *testLog) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "bad head file", cause: ResetHead, edit: func(t *testing.T, path string, _ *testLog) {
			writeFile(t, path+HeadSuffix, []byte("x\n"))
		}},
		{name: "format", cause: ResetFormat, edit: func(t *testing.T, path string, l *testLog) {
			line := appendLine(nil, l.last.Seq+1, testTime, "future_event", l.last.Hash, []byte(`{"x":1}`))
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}},
		{name: "clock", cause: ResetClock, wall: testTime.Add(-time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, l, _ := restoreLog(t)
			_ = l.Close()
			if tc.edit != nil {
				tc.edit(t, path, l)
			}
			wall := tc.wall
			if wall.IsZero() {
				wall = testTime
			}
			if _, cause := readForRestoreCause(t, path, wall); cause != tc.cause {
				t.Errorf("cause %q, want %q", cause, tc.cause)
			}
		})
	}
}

// TestReadForRestoreAddedDecision: a decision added while the broker was
// stopped is after the head, and the head file still matches.
func TestReadForRestoreAddedDecision(t *testing.T) {
	path, l, seq := restoreLog(t)
	_ = l.Close()
	head, _ := os.ReadFile(path + HeadSuffix)
	l2 := reopen(t, path, l)
	a, err := l2.Append(Decision{Subject: preapproveSubject(), UserID: 1, Answer: AnswerApproveOnce})
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()
	writeFile(t, path+HeadSuffix, head)
	got, cause := readForRestoreCause(t, path, testTime)
	if cause != "" || got.Head != seq || got.Head >= a.Seq {
		t.Fatalf("head %d, cause %q; want head %d, before the added entry %d", got.Head, cause, seq, a.Seq)
	}
}

// TestGrantsResetMovesTheHead: a grants_reset entry is the new head, so the
// next start matches it.
func TestGrantsResetMovesTheHead(t *testing.T) {
	path, l, _ := restoreLog(t)
	a, err := l.Append(GrantsReset{Cause: ResetClock})
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if got, cause := readForRestoreCause(t, path, testTime); cause != "" || got.Head != a.Seq {
		t.Fatalf("head %d, cause %q; want the grants_reset entry %d", got.Head, cause, a.Seq)
	}
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// reopen opens the log at path again, after l was closed.
func reopen(t *testing.T, path string, _ *testLog) *testLog {
	t.Helper()
	return mustOpen(t, path, testHooks())
}
