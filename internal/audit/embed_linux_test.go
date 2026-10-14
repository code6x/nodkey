package audit_test

// A type of another package can embed an event. It then has the Event
// methods, and its own fields would go into the entry. Append must refuse
// it: the events are only the types of package audit.

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/audit"
)

// brokerRequest is what a broker might write by mistake: its own type,
// which embeds an event and also holds the values it fetched.
type brokerRequest struct {
	audit.SecretSent
	Values map[string]string
}

// withSeq adds a field with the name of a chain field.
type withSeq struct {
	audit.Signed
	Seq uint64 `json:"seq"`
}

const secret = "CANARY-secret-value-0d1e"

func secretsSubject() audit.Subject {
	return audit.Subject{
		RequestID: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		Client:    "laptop",
		Kind:      audit.KindSecrets,
		Secrets:   []string{"github-token"},
	}
}

func TestAppendRefusesAnEventOfAnotherPackage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := audit.OpenWithoutDirCheck(path, audit.Options{Journal: io.Discard, Alert: func(audit.Recovery) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	login := audit.Subject{RequestID: secretsSubject().RequestID, Client: "laptop", Kind: audit.KindSSHLogin, Key: "deploy"}
	for _, ev := range []audit.Event{
		brokerRequest{SecretSent: audit.SecretSent{Subject: secretsSubject()}, Values: map[string]string{"GH_TOKEN": secret}},
		&brokerRequest{SecretSent: audit.SecretSent{Subject: secretsSubject()}, Values: map[string]string{"GH_TOKEN": secret}},
		withSeq{Signed: audit.Signed{Subject: login}, Seq: 1},
	} {
		_, err := l.Append(ev)
		if err == nil {
			t.Errorf("Append(%T): no error", ev)
			continue
		}
		if strings.Contains(err.Error(), "CANARY") {
			t.Errorf("Append(%T): %v; the error shows the value", ev, err)
		}
	}
	// The log was not touched, and it still works.
	if _, err := l.Append(audit.SecretSent{Subject: secretsSubject()}); err != nil {
		t.Fatalf("Append(SecretSent): %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the test reads the log it made in its own temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("CANARY")) || bytes.Count(data, []byte(`"seq":`)) != 1 {
		t.Errorf("log:\n%s\nwant one entry, without the value", data)
	}
	if res, err := audit.Verify(bytes.NewReader(data)); err != nil || res.Entries != 1 {
		t.Errorf("Verify = %+v, %v; want 1 entry", res, err)
	}
}
