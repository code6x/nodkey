package audit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"strconv"
	"time"
)

// Record is one entry of the log, as ReadRecords read it.
type Record struct {
	// Seq is the seq of the entry.
	Seq uint64
	// Time is the time of the entry.
	Time time.Time
	// Hash is the SHA-256 of the line of the entry.
	Hash [sha256.Size]byte
	// Event is the event of the entry, decoded strictly by DecodeEvent.
	Event Event
}

// FormatError says that an entry passed the checks of the chain, but its
// line is not as this version of nodkey writes it: an unknown event, an
// unknown field, or a field in another order or form. Like VerifyError, it
// never holds text from the log.
type FormatError struct {
	// Seq is the seq of the entry.
	Seq uint64
	err error
}

func (e *FormatError) Error() string {
	return "audit log: entry " + strconv.FormatUint(e.Seq, 10) + ": " + e.err.Error()
}

// ReadRecords reads a log from r, checks its whole chain as Verify does
// with no anchors, and decodes every entry with DecodeEvent. The broker
// reads the log with it at start, to rebuild grants (DESIGN.md section 9,
// "The log is an input at start").
//
// A torn line is not in the chain, so it is not a record; the
// log_recovered entry after it is. It returns a *VerifyError when the
// chain fails, a *FormatError when an entry does not decode, and another
// error when r fails. On any error it returns no records.
//
// The fields of an event are cut from the bytes of the line: the line
// must start with seq, time, event and prev exactly as Append writes them,
// and the rest is the body that DecodeEvent reads. A line in another form,
// even one that Verify passes, is a *FormatError.
func ReadRecords(r io.Reader) ([]Record, Result, error) {
	var recs []Record
	res, err := verify(r, func(LogID) []Anchor { return nil }, func(l *logLine) error {
		rec, err := recordOf(l)
		if err != nil {
			return &FormatError{Seq: l.e.seq, err: err}
		}
		recs = append(recs, rec)
		return nil
	})
	if err != nil {
		return nil, Result{}, err
	}
	return recs, res, nil
}

// recordOf decodes the entry of the line l, which passed the checks of
// the chain.
func recordOf(l *logLine) (Record, error) {
	t, err := time.Parse(time.RFC3339Nano, l.e.time)
	if err != nil {
		return Record{}, errors.New("the time does not parse" + errFormat)
	}
	// The head of the line as Append writes it, without the closing "}".
	head := appendLine(nil, l.e.seq, t, l.e.event, l.e.prev, nil)
	head = head[:len(head)-1]
	rest, ok := bytes.CutPrefix(l.line, head)
	if !ok {
		return Record{}, errors.New("seq, time, event and prev are not in the order and form that Append writes" + errFormat)
	}
	var body []byte
	switch {
	case len(rest) == 1 && rest[0] == '}':
		body = []byte("{}")
	case len(rest) > 2 && rest[0] == ',':
		body = append([]byte{'{'}, rest[1:]...)
	default:
		return Record{}, errors.New("the fields after prev are not in the form that Append writes" + errFormat)
	}
	ev, err := DecodeEvent(l.e.event, body)
	if err != nil {
		return Record{}, err
	}
	return Record{Seq: l.e.seq, Time: t, Hash: l.hash, Event: ev}, nil
}
