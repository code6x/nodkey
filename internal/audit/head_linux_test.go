package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHeadFile: Append writes the head file after each grant-making entry
// and after no other entry, and ReadHead reads it back.
func TestHeadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := mustOpen(t, path, testHooks())
	append1 := func(ev Event) Anchor {
		t.Helper()
		a, err := l.Append(ev)
		if err != nil {
			t.Fatalf("Append(%T): %v", ev, err)
		}
		return a
	}
	readHead := func() (Head, error) {
		t.Helper()
		return ReadHead(path)
	}
	append1(BrokerStarted{Version: "1.2.0"})
	if _, err := readHead(); !errors.Is(err, ErrNoHead) {
		t.Fatalf("ReadHead before a grant-making entry: %v, want ErrNoHead", err)
	}

	scheduled := Decision{Subject: preapproveSubject(), UserID: 1, Answer: AnswerApproveOnce}
	a := append1(scheduled)
	h, err := readHead()
	if err != nil || h.Anchor != a || h.LogID != l.id || h.LogID.IsZero() {
		t.Fatalf("ReadHead = %v, %v; want %v with the log ID", h, err, a)
	}
	fi, err := os.Stat(path + HeadSuffix)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("head file: %v, mode %v; want 0600", err, fi.Mode().Perm())
	}
	if _, err := os.Stat(path + HeadSuffix + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the temporary head file is still there: %v", err)
	}

	// Entries that make no grant leave the head as it is.
	standing := preapproveSubject()
	standing.Kind = KindStanding
	standing.Windows = []string{"daily 03:00-05:00"}
	for _, ev := range []Event{
		Decision{Subject: preapproveSubject(), UserID: 1, Answer: AnswerDeny},
		Decision{Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveWindow, WindowMinutes: 5},
		GrantUsed{Subject: preapproveSubject(), Via: ViaScheduled},
		GrantEnded{Subject: preapproveSubject(), Cause: EndRevoked},
		SecretSent{Subject: secretsSubject()},
	} {
		append1(ev)
		if got, err := readHead(); err != nil || got != h {
			t.Errorf("after %T: head %v, %v; want %v", ev, got, err, h)
		}
	}

	// A standing use and a renew are grant-making.
	for _, ev := range []Event{
		GrantUsed{Subject: standing, Via: ViaStanding, NewTokenHash: strings.Repeat("cd", 32)},
		Decision{Subject: standing, UserID: 1, Answer: AnswerRenew, RenewOf: testRequestID(9)},
	} {
		a := append1(ev)
		if got, err := readHead(); err != nil || got.Anchor != a {
			t.Errorf("after %T: head %v, %v; want %v", ev, got, err, a)
		}
	}
}

// TestHeadFileWriteFails: when the head file cannot be written, Append
// fails, and every later Append fails too.
func TestHeadFileWriteFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := mustOpen(t, path, testHooks())
	// A directory with a file in it: the rename onto it fails.
	if err := os.MkdirAll(filepath.Join(path+HeadSuffix, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Decision{Subject: preapproveSubject(), UserID: 1, Answer: AnswerApproveOnce}); !errors.Is(err, ErrBroken) {
		t.Fatalf("Append: %v, want ErrBroken", err)
	}
	if _, err := l.Append(BrokerStopped{}); !errors.Is(err, ErrBroken) {
		t.Fatalf("Append after: %v, want ErrBroken", err)
	}
}

// TestReadHeadRefuses: a head file in another form, or a file that is not
// private, is an error, and the error holds no text from the file.
func TestReadHeadRefuses(t *testing.T) {
	good := "12:" + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 32)
	for name, content := range map[string]string{
		"no newline":   good,
		"two lines":    good + "\n" + good + "\n",
		"upper case":   strings.ToUpper(good) + "\n",
		"zero log ID":  "12:" + strings.Repeat("ab", 32) + " " + strings.Repeat("0", 64) + "\n",
		"seq 0":        "0:" + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 32) + "\n",
		"leading zero": "012:" + strings.Repeat("ab", 32) + " " + strings.Repeat("cd", 32) + "\n",
		"two spaces":   strings.Replace(good, " ", "  ", 1) + "\n",
		"text":         "hunter2-secret\n",
		"empty":        "",
	} {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		if err := os.WriteFile(path+HeadSuffix, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadHead(path)
		if err == nil || errors.Is(err, ErrNoHead) || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "abab") {
			t.Errorf("%s: ReadHead: %v, want an error without the text", name, err)
		}
	}

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path+HeadSuffix, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, err := ReadHead(path); err != nil || h.String() != good {
		t.Fatalf("ReadHead of a good file: %v, %v", h, err)
	}
	if err := os.Chmod(path+HeadSuffix, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHead(path); err == nil {
		t.Error("ReadHead of a file that others can read: no error")
	}
	link := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.Symlink(path+HeadSuffix, link+HeadSuffix); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHead(link); err == nil || errors.Is(err, ErrNoHead) {
		t.Errorf("ReadHead of a symbolic link: %v, want an error", err)
	}
}
