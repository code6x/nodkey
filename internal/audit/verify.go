package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Result is what Verify found in a log that passed.
type Result struct {
	// Entries is the number of entries in the chain.
	Entries uint64
	// TornLines is the number of torn lines, each right before the
	// log_recovered entry that names it. They are not in the chain.
	TornLines uint64
	// Last is the anchor of the last entry. Entries after the newest
	// anchor are not proven: removing entries from the end of the log
	// leaves a chain that passes.
	Last Anchor
	// Anchors is the number of different anchors that Verify checked.
	// Each one matched its entry.
	Anchors uint64
	// LogID is the log ID of the log: the SHA-256 of its line 1.
	LogID LogID
	// Opens is the number of open lines of this log that VerifyJournal
	// checked. Each one matched the last anchor before it.
	Opens uint64
	// NewStarts is the number of open lines with a zero log ID: each is
	// a start on a log with no line 1 yet, such as a new log. VerifyJournal
	// does not check them.
	NewStarts uint64
	// OtherLogs are the other logs that the journal names, in the order
	// of their first line in the journal. VerifyJournal does not check
	// them. A log that was deleted, or moved away, is one of them.
	OtherLogs []OtherLog
}

// OtherLog is a log in the journal other than the log that VerifyJournal
// checked.
type OtherLog struct {
	LogID LogID
	// Newest is the highest seq in the journal lines of this log: in its
	// anchors and in the heads of its open lines.
	Newest uint64
}

// VerifyError says which line of a log failed the check, and why. It
// never holds text from the log, which could hold a secret pasted by
// mistake: only fixed words and numbers, such as line numbers and seq
// values.
type VerifyError struct {
	// Line is the line number, from 1. It is 0 when the problem is not on
	// one line, such as an anchor for an entry that is not in the log.
	Line uint64
	// Problem says what is wrong.
	Problem string
}

func (e *VerifyError) Error() string {
	if e.Line == 0 {
		return e.Problem
	}
	return "line " + strconv.FormatUint(e.Line, 10) + ": " + e.Problem
}

// problem makes a VerifyError from a fixed format and numbers. It takes
// no other values, so it cannot put text from the log into the error.
func problem(line uint64, format string, args ...uint64) *VerifyError {
	values := make([]any, len(args))
	for i, a := range args {
		values[i] = a
	}
	return &VerifyError{Line: line, Problem: fmt.Sprintf(format, values...)}
}

// Verify reads a log from r, line by line, and checks every line. It
// returns a *VerifyError for the first problem, or another error if r
// fails. The rules (DESIGN.md section 9):
//
//   - No line is longer than MaxLineSize bytes.
//   - Each line is one JSON object with seq, time, event and prev. seq is
//     1 in the first entry and counts up by one. prev is the hash of the
//     entry before, or 64 zeros in the first entry. time is in UTC.
//   - The hash of a line is the SHA-256 of its bytes, without the newline.
//   - A torn line is allowed only right before a log_recovered entry whose
//     torn_length and torn_sha256 match it. It is not in the chain: the
//     log_recovered entry has the seq and prev that the torn line would
//     have had. A log_recovered entry must come right after its torn line.
//   - The last line ends in a newline. A log with no entry fails.
//   - Each anchor must match the entry with its seq, and that entry must
//     be in the log. Two anchors for one entry must not differ: that
//     happens when the log was cut or changed while the broker was
//     stopped, and the broker then wrote that entry again. Pass every
//     anchor since the log began (see Anchor).
//
// Verify does not check that time goes forward. The clock can go back,
// such as after an NTP correction, or after a power cut on a machine
// without a clock battery. seq and prev prove the order, and an attacker
// who can compute the chain again can fix the times too.
func Verify(r io.Reader, anchors ...Anchor) (Result, error) {
	return verify(r, func(LogID) []Anchor { return anchors })
}

// VerifyJournal checks a log from r, like Verify, with the lines of its
// journal from ReadJournal, in the order of the journal. extra are more
// anchors, such as from --anchor flags; they count like old-form anchors.
// The log ID of the log is the SHA-256 of its line 1. The checks after
// those of Verify:
//
//   - The anchors that Verify checks are extra, the old-form anchors, and
//     the anchors with the log ID. Anchors of other log IDs are of other
//     logs, so they are not checked against this log.
//   - Each open line with the log ID must hold the last anchor of the log
//     before it in the journal (old-form anchors count as anchors of the
//     log). If it does not, entries were added or changed while the
//     broker was stopped. If no anchor of the log comes before it, the log
//     was replaced, or the journal lost its older lines.
//   - The journal must have a line of this log: an anchor or an open line.
//
// Open lines with a zero log ID are counted in Result.NewStarts, and the
// other log IDs are listed in Result.OtherLogs: a log that was deleted and
// started again at entry 1 shows up there, and so does a log that a
// person moved away. Check that log with the same journal.
func VerifyJournal(r io.Reader, journal []JournalLine, extra ...Anchor) (Result, error) {
	var id LogID
	res, err := verify(r, func(first LogID) []Anchor {
		id = first
		anchors := slices.Clone(extra)
		for _, jl := range journal {
			if jl.Kind == JournalOldAnchor || (jl.Kind == JournalAnchor && jl.LogID == id) {
				anchors = append(anchors, jl.Anchor)
			}
		}
		return anchors
	})
	if err != nil {
		return Result{}, err
	}
	if err := checkOpens(&res, journal); err != nil {
		return Result{}, err
	}
	return res, nil
}

// checkOpens makes the checks of the open lines for the log res.LogID,
// and adds what it found to res.
func checkOpens(res *Result, journal []JournalLine) error {
	last := make(map[LogID]Anchor)
	others := make(map[LogID]int) // the index in res.OtherLogs
	seen := false                 // the journal has a line of this log
	for _, jl := range journal {
		id := jl.LogID
		if jl.Kind == JournalOldAnchor {
			id = res.LogID
		}
		if id != res.LogID {
			if id.IsZero() { // an open line of a log with no line 1
				res.NewStarts++
				continue
			}
			i, ok := others[id]
			if !ok {
				i = len(res.OtherLogs)
				others[id] = i
				res.OtherLogs = append(res.OtherLogs, OtherLog{LogID: id})
			}
			res.OtherLogs[i].Newest = max(res.OtherLogs[i].Newest, jl.Anchor.Seq)
			continue
		}
		seen = true
		if jl.Kind != JournalOpen {
			last[id] = jl.Anchor
			continue
		}
		prev, ok := last[id]
		switch {
		case !ok:
			return problem(0, "journal line %d: the journal has no anchor of this log before the broker opened it at "+
				"entry %d: the log was replaced, or the journal lost its older lines", jl.Line, jl.Anchor.Seq)
		case prev.Seq != jl.Anchor.Seq:
			return problem(0, "journal line %d: the broker opened the log at entry %d, but the last anchor of this log "+
				"before it is entry %d: entries were added or removed while the broker was stopped",
				jl.Line, jl.Anchor.Seq, prev.Seq)
		case prev.Hash != jl.Anchor.Hash:
			return problem(0, "journal line %d: the broker opened the log at entry %d, and its hash is not the hash "+
				"in the anchor before it: entries were changed while the broker was stopped", jl.Line, jl.Anchor.Seq)
		}
		res.Opens++
	}
	if !seen {
		return problem(0, "the journal has no anchor and no open line of this log; check that the journal "+
			"is of this broker, and that it still has the lines since the log began")
	}
	return nil
}

// verify is Verify. anchors gets the log ID, once line 1 is read, and
// returns the anchors to check.
func verify(r io.Reader, anchors func(LogID) []Anchor) (Result, error) {
	v := verifier{found: make(map[uint64]bool)}
	var want []Anchor
	setAnchors := func(id LogID) error {
		v.res.LogID = id
		want = anchors(id)
		v.want = make(map[uint64][sha256.Size]byte, len(want))
		for _, a := range want {
			if a.Seq == 0 {
				return problem(0, "an anchor needs an entry number from 1")
			}
			if h, ok := v.want[a.Seq]; ok && h != a.Hash {
				return problem(0, "two anchors for entry %d have different hashes: the log was cut or changed, "+
					"and the entry was written again, or the anchors come from two logs", a.Seq)
			}
			v.want[a.Seq] = a.Hash
		}
		return nil
	}
	br := bufio.NewReaderSize(r, MaxLineSize+1)
	var no uint64 // the number of the last line read
	var pending *logLine
	for {
		raw, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			if no == 0 {
				// Line 1 is too long to have a log ID: check the
				// anchors alone, for the error that Verify gives.
				if err := setAnchors(LogID{}); err != nil {
					return Result{}, err
				}
			}
			// A line this long is not a log_recovered entry, so the line
			// before it is not torn: check it first.
			if pending != nil {
				if err := v.apply(pending); err != nil {
					return Result{}, err
				}
			}
			return Result{}, problem(no+1, "is longer than %d bytes", MaxLineSize)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return Result{}, fmt.Errorf("audit log: reading line %d: %w", no+1, err)
		}
		if len(raw) > 0 {
			no++
			cur := readLine(no, raw)
			if no == 1 {
				// Line 1 is applied only with line 2, so the anchors are
				// set before any entry is checked.
				if err := setAnchors(LogID(cur.hash)); err != nil {
					return Result{}, err
				}
			}
			// The role of a line depends on the next one: a line is torn
			// when the next line is its log_recovered entry.
			if pending != nil {
				if !pending.recovery && cur.recovers(pending) {
					cur.recovery = true
					v.res.TornLines++
				} else if err := v.apply(pending); err != nil {
					return Result{}, err
				}
			}
			pending = cur
		}
		if err != nil {
			break // io.EOF
		}
	}
	if pending == nil {
		if err := setAnchors(LogID{}); err != nil {
			return Result{}, err
		}
		return Result{}, problem(0, "the log is empty")
	}
	if err := v.apply(pending); err != nil {
		return Result{}, err
	}
	for _, a := range want {
		if !v.found[a.Seq] {
			return Result{}, problem(0, "no entry %d: the log ends at entry %d", a.Seq, v.res.Last.Seq)
		}
	}
	v.res.Anchors = uint64(len(v.found))
	return v.res, nil
}

// verifier is the state of Verify: the chain so far.
type verifier struct {
	want     map[uint64][sha256.Size]byte // the anchors
	found    map[uint64]bool              // the anchors that matched
	res      Result
	lastLine uint64 // the line of the last entry
}

// apply checks l as the next entry of the chain, and adds it.
func (v *verifier) apply(l *logLine) error {
	switch {
	case !l.newline:
		return problem(l.no, "has no newline at the end: it is a torn line, and no log_recovered entry follows it")
	case l.problem != "":
		return &VerifyError{Line: l.no, Problem: l.problem}
	case l.e.event == eventLogRecovered && !l.recovery:
		return problem(l.no, "is a log_recovered entry, but the line before it is not the torn line that it names")
	case l.e.seq != v.res.Last.Seq+1:
		return problem(l.no, "has seq %d, want %d", l.e.seq, v.res.Last.Seq+1)
	case l.e.prev != v.res.Last.Hash && v.res.Entries == 0:
		return problem(l.no, "has a prev that is not 64 zeros, which the first entry needs")
	case l.e.prev != v.res.Last.Hash:
		return problem(l.no, "has a prev that is not the hash of the entry before it, on line %d", v.lastLine)
	}
	if h, ok := v.want[l.e.seq]; ok {
		if h != l.hash {
			return problem(l.no, "is entry %d, and its hash is not the hash in the anchor", l.e.seq)
		}
		v.found[l.e.seq] = true
	}
	v.res.Entries++
	v.res.Last = Anchor{Seq: l.e.seq, Hash: l.hash}
	v.lastLine = l.no
	return nil
}

// logLine is one line that Verify read.
type logLine struct {
	no       uint64            // the line number, from 1
	hash     [sha256.Size]byte // the SHA-256 of the line, without its newline
	length   int               // the length of the line, without its newline
	e        entry             // the entry, if problem is ""
	problem  string            // why the line is not a valid entry; a fixed text
	newline  bool              // the line ends in a newline
	recovery bool              // the line is the log_recovered entry of the torn line before it
}

// readLine reads the line raw, with its newline if it has one. It keeps no
// reference to raw.
func readLine(no uint64, raw []byte) *logLine {
	l := &logLine{no: no}
	if n := len(raw); n > 0 && raw[n-1] == '\n' {
		raw, l.newline = raw[:n-1], true
	}
	l.hash = sha256.Sum256(raw)
	l.length = len(raw)
	l.e, l.problem = parseEntry(raw)
	return l
}

// recovers reports whether l is the log_recovered entry of the line torn.
func (l *logLine) recovers(torn *logLine) bool {
	return l.problem == "" && l.e.event == eventLogRecovered &&
		l.e.tornLength == torn.length && l.e.tornHash == torn.hash
}

// entry is what Verify and Open read from a line.
type entry struct {
	seq        uint64
	event      string
	prev       [sha256.Size]byte
	tornLength int               // log_recovered only
	tornHash   [sha256.Size]byte // log_recovered only
}

// eventPattern is the form of an event name. Verify does not need to know
// every event, so a log from a newer nodkey still passes.
var eventPattern = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)

// The problems of a line that is not a valid entry. Each is a fixed text,
// so it cannot hold text from the log.
const (
	problemJSON       = "is not valid JSON"
	problemNotObject  = "is not a JSON object"
	problemTwice      = "has a field twice: "
	problemCase       = "has a field whose name differs only in case from "
	problemSeq        = "has no seq, or its seq is not a whole number from 1"
	problemTime       = "has no time, or its time is not a UTC time such as 2026-10-14T12:00:00.000Z"
	problemEvent      = "has no event, or its event is not an event name"
	problemPrev       = "has no prev, or its prev is not 64 lowercase hex digits"
	problemTornLength = "is a log_recovered entry without a torn_length from 1 to 65536"
	problemTornHash   = "is a log_recovered entry without a torn_sha256 of 64 lowercase hex digits"
	problemDepth      = "nests objects and arrays more than 16 levels deep"
)

// maxDepth is the most levels of objects and arrays in one line; the text
// of problemDepth names it. An entry has two: the object, and an array of
// names in it. The rest is room for the fields of a newer nodkey. Verify
// checks this itself, before it decodes a line: the limit of
// encoding/json is about 10000 levels, but it differs between Go versions,
// and the result of Verify must not.
const maxDepth = 16

// tooDeep reports whether line has more than maxDepth levels of objects
// and arrays. It counts "{" and "[" outside strings, and it knows the
// escapes in strings, such as \" and \\. It does not check that line is
// valid JSON; the decoder does that next.
func tooDeep(line []byte) bool {
	depth := 0
	inString, escaped := false, false
	for _, c := range line {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
		case c == '{' || c == '[':
			if depth++; depth > maxDepth {
				return true
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return false
}

// entryFields are the fields that parseEntry reads. A line may have other
// fields: those of its event.
var entryFields = []string{"seq", "time", "event", "prev", "torn_length", "torn_sha256"}

// parseEntry reads one line, without its newline. It returns a problem, a
// fixed text, if the line is not a valid entry.
//
// It is stricter than encoding/json: the line must be one JSON object, and
// none of the fields above may be there twice. A name that differs from
// one of them only in case, such as "SEQ", is refused too: encoding/json
// ignores case, so it would read "SEQ" as seq, while other readers, such
// as jq, would not. So every reader sees the same values.
func parseEntry(line []byte) (entry, string) {
	var e entry
	if tooDeep(line) {
		return e, problemDepth
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	if err != nil {
		return e, problemJSON
	}
	if tok != json.Delim('{') {
		return e, problemNotObject
	}
	values := make(map[string]json.RawMessage, len(entryFields))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return e, problemJSON
		}
		key, ok := tok.(string)
		if !ok {
			return e, problemJSON
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return e, problemJSON
		}
		for _, name := range entryFields {
			// name is one of entryFields, not text from the line.
			if key != name {
				// encoding/json matches a name to a field with Unicode
				// case folding, as strings.EqualFold does. So "SEQ"
				// and "ſeq" (with a long s) are seq there.
				if strings.EqualFold(key, name) {
					return e, problemCase + name
				}
				continue
			}
			if _, twice := values[name]; twice {
				return e, problemTwice + name
			}
			values[name] = value
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return e, problemJSON
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return e, problemJSON // more after the object
	}

	var ok bool
	if e.seq, ok = parseNumber(values["seq"]); !ok || e.seq == 0 {
		return e, problemSeq
	}
	if t, ok := parseString(values["time"]); !ok || !isUTCTime(t) {
		return e, problemTime
	}
	if e.event, ok = parseString(values["event"]); !ok || !eventPattern.MatchString(e.event) {
		return e, problemEvent
	}
	if prev, ok := parseString(values["prev"]); !ok || !decodeHex64(&e.prev, prev) {
		return e, problemPrev
	}
	if e.event != eventLogRecovered {
		return e, ""
	}
	n, ok := parseNumber(values["torn_length"])
	if !ok || n < 1 || n > MaxLineSize {
		return e, problemTornLength
	}
	e.tornLength = int(n)
	if h, ok := parseString(values["torn_sha256"]); !ok || !decodeHex64(&e.tornHash, h) {
		return e, problemTornHash
	}
	return e, ""
}

// parseNumber reads a JSON number that is a whole number without a sign.
func parseNumber(raw json.RawMessage) (uint64, bool) {
	if len(raw) == 0 || strings.Trim(string(raw), "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw), 10, 64)
	return n, err == nil
}

// parseString reads a JSON string.
func parseString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// isUTCTime reports whether s is an RFC 3339 time in UTC.
func isUTCTime(s string) bool {
	if !strings.HasSuffix(s, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

// isHex64 reports whether s is 64 lowercase hex digits, as hex.EncodeToString
// writes a SHA-256.
func isHex64(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// decodeHex64 decodes s, 64 lowercase hex digits, into h.
func decodeHex64(h *[sha256.Size]byte, s string) bool {
	if !isHex64(s) {
		return false
	}
	_, err := hex.Decode(h[:], []byte(s))
	return err == nil
}
