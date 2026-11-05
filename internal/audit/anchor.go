package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// JournalPrefix starts each line that Append writes to the journal. The
// rest of the line is the entry's anchor and the log ID, such as
// "audit anchor 12:9f86d081… 3a7bd3e2…", ready for nodkey audit verify.
// Earlier versions wrote the anchor only, without the log ID; ReadJournal
// still reads that old form.
const JournalPrefix = "audit anchor "

// JournalOpenPrefix starts the line that Open writes to the journal, once,
// such as "audit open 12:9f86d081… 3a7bd3e2…": the last entry that Open
// found in the log, and the log ID. A log with no complete line has the
// head "0:" and 64 zeros, and the log ID 64 zeros.
const JournalOpenPrefix = "audit open "

// Anchor names one entry: its seq and the SHA-256 of its line. Written as
// text, it is "SEQ:HASH", such as "12:9f86d081…" with 64 hex digits.
//
// An anchor proves that the entries up to it have not changed since the
// broker wrote it. It does not prove what happened before: after a
// restart, the broker builds on the log as it finds it, so its new
// anchors cover any change made while it was stopped. So check a log with
// every anchor since the log began, not only the newest one. The "audit
// open" line of each start closes the gap: it holds the last entry that
// Open found, and VerifyJournal checks that it is the last anchor before
// it. So an entry added or changed while the broker was stopped is found.
type Anchor struct {
	Seq  uint64
	Hash [sha256.Size]byte
}

// String returns the anchor as "SEQ:HASH".
func (a Anchor) String() string {
	return strconv.FormatUint(a.Seq, 10) + ":" + hex.EncodeToString(a.Hash[:])
}

var errBadAnchor = errors.New("an anchor is SEQ:HASH: the entry number (1 or more), a colon, " +
	`and the SHA-256 of that entry's line as 64 hex digits, as in the journal's "audit anchor" lines`)

// ParseAnchor reads an anchor written as "SEQ:HASH". The error does not
// repeat the text.
func ParseAnchor(s string) (Anchor, error) {
	seqText, hashText, ok := strings.Cut(s, ":")
	if !ok || len(hashText) != 2*sha256.Size {
		return Anchor{}, errBadAnchor
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil || seq == 0 {
		return Anchor{}, errBadAnchor
	}
	a := Anchor{Seq: seq}
	if _, err := hex.Decode(a.Hash[:], []byte(hashText)); err != nil {
		return Anchor{}, errBadAnchor
	}
	return a, nil
}

// LogID names one log: the SHA-256 of its first line, the bytes before
// the first newline. It tells the lines of two logs apart in one journal,
// such as of a log that was deleted and of the new log after it. It is
// zero while the log has no newline yet: then it is empty, or one torn
// line.
type LogID [sha256.Size]byte

// String returns the log ID as 64 lowercase hex digits.
func (id LogID) String() string { return hex.EncodeToString(id[:]) }

// IsZero reports whether id is 64 zeros: the log had no line 1 yet.
func (id LogID) IsZero() bool { return id == LogID{} }

// JournalKind is the kind of a journal line.
type JournalKind int

// The kinds of journal lines.
const (
	// JournalAnchor is "audit anchor SEQ:HASH LOGID", from Append.
	JournalAnchor JournalKind = iota + 1
	// JournalOldAnchor is "audit anchor SEQ:HASH", from Append of an
	// earlier version. It has no log ID; VerifyJournal takes it as an
	// anchor of the log that it checks.
	JournalOldAnchor
	// JournalOpen is "audit open SEQ:HASH LOGID", from Open.
	JournalOpen
)

// JournalLine is one line of the journal that ReadJournal found.
type JournalLine struct {
	// Line is the line number in the journal copy, from 1.
	Line uint64
	Kind JournalKind
	// Anchor is the entry of an anchor line, or for an open line, the
	// last entry that Open found. That is seq 0 and a zero hash for a log
	// with no complete line.
	Anchor Anchor
	// LogID is the log ID. It is zero for JournalOldAnchor, and for an
	// open line of a log that had no line 1 yet.
	LogID LogID
}

// parseJournalLine reads one line, without its line end. It reports false
// for every line that is not exactly an anchor or an open line. SEQ:HASH
// must be in the form that Anchor.String writes: no leading zero in SEQ,
// and lowercase hex.
func parseJournalLine(line []byte) (JournalLine, bool) {
	if rest, ok := bytes.CutPrefix(line, []byte(JournalPrefix)); ok {
		anchorText, idText, hasID := bytes.Cut(rest, []byte(" "))
		a, err := ParseAnchor(string(anchorText))
		if err != nil || a.String() != string(anchorText) {
			return JournalLine{}, false
		}
		if !hasID {
			return JournalLine{Kind: JournalOldAnchor, Anchor: a}, true
		}
		var id LogID
		// Append writes an anchor only after entry 1, so its log ID is
		// never zero.
		if !decodeHex64((*[sha256.Size]byte)(&id), string(idText)) || id.IsZero() {
			return JournalLine{}, false
		}
		return JournalLine{Kind: JournalAnchor, Anchor: a, LogID: id}, true
	}
	if rest, ok := bytes.CutPrefix(line, []byte(JournalOpenPrefix)); ok {
		anchorText, idText, hasID := bytes.Cut(rest, []byte(" "))
		if !hasID {
			return JournalLine{}, false
		}
		var id LogID
		if !decodeHex64((*[sha256.Size]byte)(&id), string(idText)) {
			return JournalLine{}, false
		}
		var a Anchor
		if string(anchorText) != "0:"+zeroHash {
			var err error
			if a, err = ParseAnchor(string(anchorText)); err != nil || a.String() != string(anchorText) {
				return JournalLine{}, false
			}
		}
		// A log with a newline has a complete line, so it has entries.
		// A log without one has neither.
		if (a.Seq == 0) != id.IsZero() {
			return JournalLine{}, false
		}
		return JournalLine{Kind: JournalOpen, Anchor: a, LogID: id}, true
	}
	return JournalLine{}, false
}

// zeroHash is 64 zeros: the hash of the head of an open line for a log
// with no entry.
var zeroHash = strings.Repeat("0", 2*sha256.Size)

// maxAnchorLine is longer than any journal line with an anchor. A longer
// line is skipped without being read into memory.
const maxAnchorLine = 256

// ReadJournal reads the anchor and open lines from a copy of the journal,
// such as the output of journalctl -o cat. It uses only the lines that are
// exactly one of the forms of JournalKind, with a newline or a carriage
// return and a newline at the end; the last line may have no line end.
// It skips every other line, so the
// broker's other log lines may be there too. It returns the lines in the
// order of the journal: VerifyJournal needs that order. An error is only a
// read error, and it never holds text from r.
func ReadJournal(r io.Reader) ([]JournalLine, error) {
	br := bufio.NewReaderSize(r, maxAnchorLine)
	var lines []JournalLine
	for no := uint64(1); ; no++ {
		line, err := br.ReadSlice('\n')
		long := false
		for errors.Is(err, bufio.ErrBufferFull) { // skip the rest of a long line
			long = true
			_, err = br.ReadSlice('\n')
		}
		if !long {
			if l, ok := bytes.CutSuffix(line, []byte("\n")); ok {
				line = bytes.TrimSuffix(l, []byte("\r")) // only a CR before the LF
			}
			if jl, ok := parseJournalLine(line); ok {
				jl.Line = no
				lines = append(lines, jl)
			}
		}
		if errors.Is(err, io.EOF) {
			return lines, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading the journal: line %d: %w", no, err)
		}
	}
}

// ReadAnchors reads the anchors of every "audit anchor" line, in both
// forms, with ReadJournal, and returns them in the order of the lines. It
// does not tell logs apart, and it skips the open lines; VerifyJournal
// does both. An error is only a read error, and it never holds text from
// r.
func ReadAnchors(r io.Reader) ([]Anchor, error) {
	lines, err := ReadJournal(r)
	if err != nil {
		return nil, err
	}
	var anchors []Anchor
	for _, jl := range lines {
		if jl.Kind != JournalOpen {
			anchors = append(anchors, jl.Anchor)
		}
	}
	return anchors, nil
}
