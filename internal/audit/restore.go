package audit

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// RestoreLog is what ReadForRestore found: the records to rebuild grants
// from, and the seq of the head entry.
type RestoreLog struct {
	Records []Record
	// Head is the seq of the entry in the head file, or 0 when there is
	// no head file: then no entry makes a grant.
	Head uint64
}

// ReadForRestore reads the log at path and its head file at start, before
// Open, to rebuild grants (DESIGN.md section 8, "Grants after a restart").
// It returns a cause, and no records, when no grant may be rebuilt from
// the log at all:
//
//   - ResetChain: the chain does not verify, or the log cannot be read.
//   - ResetFormat: an entry is not as this version writes it.
//   - ResetHead: the head file cannot be read, or its entry is not in the
//     log with the same hash, or the log ID differs. A log that was cut,
//     or an older copy, is shorter than the head.
//   - ResetClock: wall is earlier than the time of the last entry.
//
// Each error says how to fix it. The broker then sends an alarm and appends a grants_reset entry with the
// cause. A log with no head file is no cause, and it is not read: there
// is nothing to rebuild. The error says what went wrong, without text from
// the log; it is nil when the cause is "".
func ReadForRestore(path string, wall time.Time) (RestoreLog, ResetCause, error) {
	l, cause, err := readForRestore(path, wall)
	if err != nil && cause != ResetFormat {
		err = fmt.Errorf("%w%s", err, restoreFix)
	}
	return l, cause, err
}

// restoreFix ends each error of ReadForRestore.
const restoreFix = "; no grant from before this start is open again, and each must be approved again. " +
	"Check the log with \"nodkey audit verify --anchors\" (DESIGN.md section 15)"

func readForRestore(path string, wall time.Time) (RestoreLog, ResetCause, error) {
	head, herr := ReadHead(path)
	if errors.Is(herr, ErrNoHead) {
		// No entry ever made a grant, or the log is from a version
		// without the head file: nothing to rebuild, and no reason to read
		// the log.
		return RestoreLog{}, "", nil
	}
	f, err := os.OpenFile(path, readFlags, 0) //nolint:gosec // G304: the path of the audit log, from the broker config.
	if errors.Is(err, os.ErrNotExist) {
		return RestoreLog{}, ResetHead, errors.New("audit log: the log is missing, but its head file is there")
	}
	if err != nil {
		return RestoreLog{}, ResetChain, fmt.Errorf("audit log: %w", err)
	}
	defer func() { _ = f.Close() }() // read only; a close error changes nothing
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return RestoreLog{}, ResetChain, errors.New("audit log: is not a regular file that can be read")
	}
	recs, res, err := ReadRecords(f)
	var fe *FormatError
	switch {
	case errors.As(err, &fe):
		return RestoreLog{}, ResetFormat, err // it says how to fix it already
	case err != nil:
		return RestoreLog{}, ResetChain, fmt.Errorf("audit log: %w", err)
	}
	if last := recs[len(recs)-1]; wall.Before(last.Time) {
		return RestoreLog{}, ResetClock, errors.New("audit log: the clock is earlier than the time of the last entry; " +
			"set the clock right, then restart the broker")
	}
	switch {
	case herr != nil:
		return RestoreLog{}, ResetHead, herr
	case head.LogID != res.LogID:
		return RestoreLog{}, ResetHead, errors.New("audit log: the head file is of another log")
	case head.Anchor.Seq > res.Last.Seq:
		return RestoreLog{}, ResetHead, fmt.Errorf("audit log: the log ends at entry %d, before the head entry %d: "+
			"it was cut, or an older copy was put back", res.Last.Seq, head.Anchor.Seq)
	case recs[head.Anchor.Seq-1].Hash != head.Anchor.Hash:
		return RestoreLog{}, ResetHead, fmt.Errorf("audit log: entry %d is not the entry that the head file names", head.Anchor.Seq)
	}
	return RestoreLog{Records: recs, Head: head.Anchor.Seq}, "", nil
}
