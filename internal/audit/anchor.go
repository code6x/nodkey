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
// rest of the line is the entry's anchor, such as
// "audit anchor 12:9f86d081…", ready for nodkey audit verify.
const JournalPrefix = "audit anchor "

// Anchor names one entry: its seq and the SHA-256 of its line. Written as
// text, it is "SEQ:HASH", such as "12:9f86d081…" with 64 hex digits.
//
// An anchor proves that the entries up to it have not changed since the
// broker wrote it. It does not prove what happened before: after a
// restart, the broker builds on the log as it finds it, so its new
// anchors cover any change made while it was stopped. So check a log with
// every anchor since the log began, not only the newest one.
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

// maxAnchorLine is longer than any journal line with an anchor. A longer
// line is skipped without being read into memory.
const maxAnchorLine = 256

// ReadAnchors reads the anchors from a copy of the journal, such as the
// output of journalctl -o cat. It uses only the lines that are exactly
// JournalPrefix and an anchor, with a newline or a carriage return and a
// newline at the end. It skips every other line, so the broker's other log
// lines may be there too. It returns the anchors in the order of the
// lines; Verify refuses two anchors for one entry with different hashes.
// An error is only a read error, and it never holds text from r.
func ReadAnchors(r io.Reader) ([]Anchor, error) {
	br := bufio.NewReaderSize(r, maxAnchorLine)
	var anchors []Anchor
	for no := 1; ; no++ {
		line, err := br.ReadSlice('\n')
		long := false
		for errors.Is(err, bufio.ErrBufferFull) { // skip the rest of a long line
			long = true
			_, err = br.ReadSlice('\n')
		}
		if !long {
			line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
			if rest, ok := bytes.CutPrefix(line, []byte(JournalPrefix)); ok {
				if a, perr := ParseAnchor(string(rest)); perr == nil {
					anchors = append(anchors, a)
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return anchors, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading the anchors: line %d: %w", no, err)
		}
	}
}
