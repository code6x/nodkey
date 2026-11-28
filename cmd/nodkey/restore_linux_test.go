package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

func restoreTestLog(t *testing.T) (*audit.Logger, string) {
	t.Helper()
	path := filepath.Join(privateTestDir(t), "audit.jsonl")
	l, err := audit.Open(path, audit.Options{Journal: io.Discard, Alert: func(audit.Recovery) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func logEvents(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var names []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		_, rest, _ := strings.Cut(s.Text(), `"event":"`)
		name, _, _ := strings.Cut(rest, `"`)
		names = append(names, name)
	}
	return names
}

func droppedGrant(reason approval.DropReason) approval.RestoredGrant {
	return approval.RestoredGrant{Reason: reason, UsesLeft: 2, Subject: audit.Subject{
		RequestID: "AAAAAAAAAAAAAAAAAAAAAA", GrantID: "BBBBBBBBBBBBBBBBBBBBBB", Client: "laptop",
		Kind: audit.KindPreapprove, Secrets: []string{"github-token"}, Uses: 3,
		NotBefore: "2026-10-14T12:00:00Z", NotAfter: "2026-10-14T14:00:00Z", Reason: "claimed <b>text</b>",
	}}
}

// TestRestoredWrite: a refused log gets one grants_reset entry; each
// dropped grant gets a grant_ended entry with its cause.
func TestRestoredWrite(t *testing.T) {
	l, path := restoreTestLog(t)
	if err := (restored{cause: audit.ResetClock}).write(l); err != nil {
		t.Fatal(err)
	}
	r := restored{dropped: []approval.RestoredGrant{droppedGrant(approval.DropEnded), droppedGrant(approval.DropClient)}}
	if err := r.write(l); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(logEvents(t, path), " "); got != "grants_reset grant_ended grant_ended" {
		t.Errorf("entries %q", got)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"cause":"ended"`) || !strings.Contains(string(b), `"cause":"config_changed"`) {
		t.Errorf("the causes are not in the log: %s", b)
	}
}

// TestRestoredNotice: the notice lists the grants by ID, never with
// claimed text; a refused log says so; nothing gives no notice.
func TestRestoredNotice(t *testing.T) {
	if msg := (restored{}).notice(); msg != "" {
		t.Errorf("no grants: notice %q", msg)
	}
	r := restored{open: []approval.RestoredGrant{droppedGrant("")}, dropped: []approval.RestoredGrant{droppedGrant(approval.DropHead)}}
	msg := r.notice()
	if !strings.Contains(msg, "1 grant(s) from before are open again, 1 dropped") ||
		!strings.Contains(msg, "BBBBBBBBBBBBBBBBBBBBBB: laptop, github-token, open") ||
		!strings.Contains(msg, "dropped: its last use is not proven") || strings.Contains(msg, "claimed") {
		t.Errorf("notice %q", msg)
	}
	for _, c := range []audit.ResetCause{audit.ResetChain, audit.ResetHead, audit.ResetClock, audit.ResetFormat} {
		if msg := (restored{cause: c}).notice(); !strings.Contains(msg, "did not open any grant") || !strings.Contains(msg, "nodkey audit verify") {
			t.Errorf("cause %s: notice %q", c, msg)
		}
	}
}
