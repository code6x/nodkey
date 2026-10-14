package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// zeros is the prev of the first entry.
var zeros = strings.Repeat("0", 64)

// canary stands for a secret that got into a claimed field by mistake. No
// error may ever show it.
const canary = "CANARY-made-up-token-6b1f"

// testTime is the clock of the tests.
var testTime = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// testRequestID returns a request ID made from n. It is 16 bytes in
// base64url, as the broker makes them.
func testRequestID(n byte) string {
	id := make([]byte, 16)
	for i := range id {
		id[i] = n + byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(id)
}

// testHostKey returns a made-up SHA256 host key fingerprint.
func testHostKey() string {
	sum := sha256.Sum256([]byte("made-up host key"))
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// secretsSubject and loginSubject are valid subjects.
func secretsSubject() Subject {
	return Subject{
		RequestID: testRequestID(1),
		Client:    "laptop",
		Kind:      KindSecrets,
		Secrets:   []string{"github-token"},
		Command:   "gh release create v1.2.0",
		Reason:    "publish the release; " + canary,
	}
}

func loginSubject() Subject {
	return Subject{
		RequestID:  testRequestID(2),
		Client:     "laptop",
		Kind:       KindSSHLogin,
		Key:        "deploy",
		Hosts:      []string{"web-1"},
		HostKey:    testHostKey(),
		RemoteUser: "deploy",
		Command:    "ssh deploy@web-1",
		Reason:     "apply the nginx fix",
	}
}

func grantSubject() Subject {
	return Subject{
		RequestID:  testRequestID(3),
		Client:     "laptop",
		Kind:       KindSSHGrant,
		Key:        "deploy",
		Hosts:      []string{"web-1", "web-2"},
		RemoteUser: "deploy",
		Reason:     "apply the nginx fix",
	}
}

// sampleEvents returns one valid event of each kind, with the fields set.
func sampleEvents() []Event {
	return []Event{
		BrokerStarted{Version: "1.2.0"},
		Request{Subject: secretsSubject(), Message: "<b>🔑 Secrets · request 7qd2</b>\n✅ machine: laptop"},
		Decision{Subject: secretsSubject(), UserID: 123456789, Answer: AnswerApproveWindow, WindowMinutes: 15},
		SecretSent{Subject: secretsSubject()},
		Request{Subject: loginSubject()},
		GrantUsed{Subject: loginSubject(), Via: ViaGrant},
		Signed{Subject: loginSubject()},
		Request{Subject: grantSubject(), Message: "🔐 SSH grant"},
		Decision{Subject: grantSubject(), UserID: 123456789, Answer: AnswerDeny},
		Denied{Subject: grantSubject(), Cause: CauseApprover},
		ForeignTap{UserID: 987654321, ChatID: 987654321, MessageID: 42, Data: "o:" + testRequestID(9), Cause: TapEditedMessage},
		Failure{Subject: secretsSubject(), Code: CodeStoreFailed},
		Failure{Code: CodePollConflict},
		BrokerStopped{},
	}
}

// chain builds a log in memory with the code that Append uses.
type chain struct {
	t     testing.TB
	lines [][]byte // the lines, without newlines
	last  Anchor
}

func newChain(t testing.TB) *chain {
	t.Helper()
	return &chain{t: t}
}

// add adds an entry and returns its anchor.
func (c *chain) add(ev Event) Anchor {
	c.t.Helper()
	name, body, err := encodeEvent(ev)
	if err != nil {
		c.t.Fatalf("encodeEvent: %v", err)
	}
	line := appendLine(nil, c.last.Seq+1, testTime, name, c.last.Hash, body)
	c.last = Anchor{Seq: c.last.Seq + 1, Hash: sha256.Sum256(line)}
	c.lines = append(c.lines, line)
	return c.last
}

// addAll adds every sample event.
func (c *chain) addAll() *chain {
	c.t.Helper()
	for _, ev := range sampleEvents() {
		c.add(ev)
	}
	return c
}

// tear adds a torn line and the log_recovered entry that Open writes for
// it.
func (c *chain) tear(torn []byte) Anchor {
	c.t.Helper()
	c.lines = append(c.lines, bytes.Clone(torn))
	sum := sha256.Sum256(torn)
	return c.add(logRecovered{TornLength: len(torn), TornSHA256: hex.EncodeToString(sum[:])})
}

// bytes returns the log: each line and a newline.
func (c *chain) bytes() []byte {
	var b []byte
	for _, line := range c.lines {
		b = append(append(b, line...), '\n')
	}
	return b
}

// half returns the first half of a line, as a power cut can leave it.
func half(line []byte) []byte {
	return bytes.Clone(line[:len(line)/2])
}
