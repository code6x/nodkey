package audit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestReadRecords: every entry of a log that passes comes back, in order,
// with its seq, time, hash and event. A torn line is not a record.
func TestReadRecords(t *testing.T) {
	c := newChain(t).addAll()
	c.tear(half(c.lines[1]))
	c.add(BrokerStarted{Version: "1.2.0"})
	recs, res, err := ReadRecords(bytes.NewReader(c.bytes()))
	if err != nil {
		t.Fatalf("ReadRecords: %v", err)
	}
	want := append(sampleEvents(), logRecovered{}, BrokerStarted{Version: "1.2.0"})
	if len(recs) != len(want) || res.Entries != uint64(len(want)) || res.TornLines != 1 {
		t.Fatalf("got %d records, %d entries, %d torn lines; want %d, %d, 1", len(recs), res.Entries, res.TornLines, len(want), len(want))
	}
	seq := uint64(0)
	for i, line := range c.lines {
		if i == len(sampleEvents()) {
			continue // the torn line
		}
		r := recs[seq]
		seq++
		if r.Seq != seq || r.Hash != sha256.Sum256(line) || !r.Time.Equal(testTime) {
			t.Errorf("record %d: seq %d, time %v, hash ok %v", seq, r.Seq, r.Time, r.Hash == sha256.Sum256(line))
		}
		if _, ok := r.Event.(logRecovered); ok {
			continue
		}
		if !reflect.DeepEqual(r.Event, want[seq-1]) {
			t.Errorf("record %d: event %#v, want %#v", seq, r.Event, want[seq-1])
		}
	}
	if res.Last != c.last {
		t.Errorf("Last = %v, want %v", res.Last, c.last)
	}
}

// TestReadRecordsChain: a chain that fails gives a *VerifyError and no
// records.
func TestReadRecordsChain(t *testing.T) {
	c := newChain(t).addAll()
	changed := bytes.Replace(c.lines[2], []byte(`"answer"`), []byte(` "answer"`), 1)
	for name, log := range map[string][]byte{
		"changed":  join(replaced(c.lines, 2, changed)...),
		"cut":      join(without(c.lines, 3)...),
		"empty":    nil,
		"torn end": append(c.bytes(), half(c.lines[0])...),
	} {
		recs, _, err := ReadRecords(bytes.NewReader(log))
		var ve *VerifyError
		if !errors.As(err, &ve) || recs != nil {
			t.Errorf("%s: err %v, %d records; want a *VerifyError and none", name, err, len(recs))
		}
	}
}

// TestReadRecordsFormat: an entry that passes the chain but is not as
// Append writes it gives a *FormatError with its seq, no records, and no
// text from the log.
func TestReadRecordsFormat(t *testing.T) {
	const secret = "hunter2-secret"
	var prev [sha256.Size]byte
	good := appendLine(nil, 1, testTime, eventBrokerStarted, prev, []byte(`{"version":"1.2.0"}`))
	for name, line := range map[string]string{
		"unknown event": string(appendLine(nil, 2, testTime, "future_event", sha256.Sum256(good), []byte(`{"x":"`+secret+`"}`))),
		"unknown field": string(appendLine(nil, 2, testTime, eventBrokerStarted, sha256.Sum256(good), []byte(`{"version":"1.2.0","x":"`+secret+`"}`))),
		"field twice":   string(appendLine(nil, 2, testTime, eventBrokerStarted, sha256.Sum256(good), []byte(`{"version":"1.2.0","version":"`+secret+`"}`))),
		"other order":   strings.Replace(string(appendLine(nil, 2, testTime, eventBrokerStarted, sha256.Sum256(good), []byte(`{"version":"1.2.0"}`))), `{"seq":2,"time":"2026-10-14T12:00:00.000Z"`, `{"time":"2026-10-14T12:00:00.000Z","seq":2`, 1),
		"other time":    strings.Replace(string(appendLine(nil, 2, testTime, eventBrokerStarted, sha256.Sum256(good), []byte(`{"version":"1.2.0"}`))), `.000Z"`, `Z"`, 1),
	} {
		recs, _, err := ReadRecords(bytes.NewReader(join(good, []byte(line))))
		var fe *FormatError
		var ve *VerifyError
		switch {
		case errors.As(err, &ve):
			t.Errorf("%s: a *VerifyError (%v); the line must pass the chain for this test", name, err)
		case !errors.As(err, &fe) || fe.Seq != 2 || recs != nil:
			t.Errorf("%s: err %v, %d records; want a *FormatError for entry 2 and none", name, err, len(recs))
		case strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "future_event"):
			t.Errorf("%s: the error holds text from the log: %v", name, err)
		}
	}
}
