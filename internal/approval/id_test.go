package approval_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// codeAlphabet is the alphabet of short codes: no 0, 1, i, l or o.
const codeAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// TestRequestIDs checks the IDs and short codes: an ID is 16 random bytes
// in base64url, a short code is 4 characters, and no two requests at the
// same time share either.
func TestRequestIDs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.fill(approval.MaxOpenMessages + approval.MaxQueued)
		ids, codes := map[string]bool{}, map[string]bool{}
		for _, x := range e.fake.Asked() {
			ids[x.Prompt.RequestID] = true
			codes[x.Prompt.ShortCode] = true
			checkID(t, x.Prompt.RequestID, x.Prompt.ShortCode)
		}
		live, liveCodes, waiting := e.core.Live()
		if live != approval.MaxOpenMessages+approval.MaxQueued || liveCodes != live || waiting != approval.MaxOpenMessages {
			t.Errorf("%d IDs, %d codes, %d waiting; want %d, %d, %d", live, liveCodes, waiting,
				approval.MaxOpenMessages+approval.MaxQueued, approval.MaxOpenMessages+approval.MaxQueued, approval.MaxOpenMessages)
		}
		if len(ids) != approval.MaxOpenMessages || len(codes) != approval.MaxOpenMessages {
			t.Errorf("%d IDs and %d codes for %d messages", len(ids), len(codes), approval.MaxOpenMessages)
		}
		for range 200 {
			r := e.now(secretsReq("laptop", "no-such-secret"))
			checkID(t, r.RequestID, r.ShortCode)
			if ids[r.RequestID] {
				t.Fatalf("the ID %s came twice", r.RequestID)
			}
			ids[r.RequestID] = true
		}
	})
}

func checkID(t *testing.T, id, code string) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(b) != 16 || len(id) != 22 {
		t.Errorf("request ID %q: %d bytes, %v; want 16 bytes in base64url", id, len(b), err)
	}
	if len(code) != 4 || strings.Trim(code, codeAlphabet) != "" {
		t.Errorf("short code %q; want 4 characters of %q", code, codeAlphabet)
	}
}

// chunks is a source of random bytes that hands out the given chunks, in
// order, and then fails.
type chunks struct{ next [][]byte }

func (c *chunks) Read(p []byte) (int, error) {
	if len(c.next) == 0 {
		return 0, errors.New("no more random bytes")
	}
	n := copy(p, c.next[0])
	c.next = c.next[1:]
	return n, nil
}

// TestRequestIDsDoNotRepeat checks that a request never gets the ID or the
// short code of a request that still waits, even if the random source
// repeats.
func TestRequestIDsDoNotRepeat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		id1 := bytes.Repeat([]byte{1}, 16)
		id2 := bytes.Repeat([]byte{2}, 16)
		code1 := bytes.Repeat([]byte{3}, 16) // "5555"
		code2 := bytes.Repeat([]byte{4}, 16) // "6666"
		e.core.SetRandom(&chunks{next: [][]byte{id1, code1, id1, id2, code1, code2}})

		first := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, first)
		second := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, second)
		asked := e.asked(2)
		want := []struct{ id, code string }{
			{base64.RawURLEncoding.EncodeToString(id1), "5555"},
			{base64.RawURLEncoding.EncodeToString(id2), "6666"},
		}
		for i, w := range want {
			if p := asked[i].Prompt; p.RequestID != w.id || p.ShortCode != w.code {
				t.Errorf("request %d: ID %s, code %s; want %s, %s", i+1, p.RequestID, p.ShortCode, w.id, w.code)
			}
		}
		// The source has failed now: the request is denied.
		r := e.now(secretsReq("laptop", "db-password"))
		checkDenied(t, r, audit.CauseError)
		if r.RequestID != "" || r.Err == nil {
			t.Errorf("ID %q, err %v; want no ID and an error", r.RequestID, r.Err)
		}
		e.asked(2)
	})
}

// TestRequestIDSourceFails checks the failures of the random source: a
// short read, an error, and bytes that never make a short code.
func TestRequestIDSourceFails(t *testing.T) {
	for name, source := range map[string]io.Reader{
		"error":      &chunks{},
		"short read": &chunks{next: [][]byte{{1, 2, 3}}},
		"no code":    bytes.NewReader(append(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{255}, 256)...)),
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, nil)
				defer e.stop()
				e.core.SetRandom(source)
				r := e.now(secretsReq("laptop", "github-token"))
				checkDenied(t, r, audit.CauseError)
				e.asked(0)
			})
		})
	}
}
