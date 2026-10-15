//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// auditLog reads the audit log of the broker, one case after the other:
// each case checks the entries that it caused.
type auditLog struct {
	path string
	seen int // the entries that the cases have checked
}

// entry is one entry of the audit log.
type entry map[string]any

// field returns the field k as text: a string as it is, a list of strings
// joined with ",", a number in decimal, and "" when the entry does not
// have it.
func (en entry) field(k string) string {
	switch v := en[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case []any:
		parts := make([]string, len(v))
		for i, p := range v {
			parts[i], _ = p.(string)
		}
		return strings.Join(parts, ",")
	case nil:
		return ""
	}
	return "(not a string, a number or a list)"
}

// name returns the event of the entry, with its answer, cause, via or
// code, such as "decision:approve_once" or "denied:not_allowed".
func (en entry) name() string {
	name := en.field("event")
	for _, k := range []string{"answer", "cause", "via", "code"} {
		if v := en.field(k); v != "" {
			name += ":" + v
		}
	}
	return name
}

// eventNames returns the names of entries.
func eventNames(entries []entry) []string {
	out := make([]string, len(entries))
	for i, en := range entries {
		out[i] = en.name()
	}
	return out
}

// entries returns the complete lines of the audit log, as entries. The
// broker writes each line with one write call, but a read can come in the
// middle of it, so a last line without its newline is left for later.
func (a *auditLog) entries(t *testing.T) []entry {
	t.Helper()
	data, err := os.ReadFile(a.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil // the broker makes it at its start
	case err != nil:
		t.Fatal(err)
	}
	data = data[:bytes.LastIndexByte(data, '\n')+1]
	var out []entry
	for line := range strings.Lines(string(data)) {
		var en entry
		if err := json.Unmarshal([]byte(line), &en); err != nil {
			t.Fatalf("audit log line %d is not JSON: %v", len(out)+1, err)
		}
		out = append(out, en)
	}
	return out
}

// next waits until the audit log has len(want) entries after those that
// the cases have checked, at most settleLimit, and returns them. The
// broker writes the entries of a request before it answers the client. It fails unless their names
// are want, in this order, and unless each of them has the fields of
// subject, where "" means that the entry does not have the field. The
// entries of one request also share its request ID.
func (a *auditLog) next(t *testing.T, subject map[string]string, want ...string) []entry {
	t.Helper()
	deadline := time.Now().Add(settleLimit)
	var got []entry
	for {
		all := a.entries(t)
		got = all[min(a.seen, len(all)):]
		if len(got) >= len(want) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got = got[:min(len(got), len(want))]
	a.seen += len(got)
	if !slices.Equal(eventNames(got), want) {
		t.Fatalf("audit entries %q, want %q", eventNames(got), want)
	}
	for i, en := range got {
		for k, v := range subject {
			if g := en.field(k); g != v {
				t.Errorf("audit entry %d (%s) has %s %q, want %q", a.seen-len(got)+i+1, en.name(), k, redact(g), v)
			}
		}
		if id := got[0].field("request_id"); en.field("request_id") != id {
			t.Errorf("audit entry %d (%s) has another request ID than the entries before it", a.seen-len(got)+i+1, en.name())
		}
	}
	return got
}

// unchecked reports the entries that no case has checked yet, and marks
// them as checked, so that one failed case does not make every later case
// fail.
func (a *auditLog) unchecked(t *testing.T) {
	t.Helper()
	all := a.entries(t)
	if len(all) > a.seen {
		t.Errorf("audit entries that no case expected: %q", eventNames(all[a.seen:]))
		a.seen = len(all)
	}
}
