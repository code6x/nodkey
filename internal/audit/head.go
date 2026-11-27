package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// HeadSuffix is added to the path of the log for the path of its head
// file, such as audit.jsonl.head (DESIGN.md section 9, "The head file").
const HeadSuffix = ".head"

// headWriteFlags open the temporary head file: like the log, but it is
// made new each time.
const headWriteFlags = (writeFlags &^ os.O_APPEND) | os.O_TRUNC

// maxHeadSize is more than the length of a head line.
const maxHeadSize = 256

// Head is what the head file holds: the log ID and the anchor of the last
// grant-making entry that Append wrote.
type Head struct {
	LogID  LogID
	Anchor Anchor
}

// String returns the head as its line in the file, without the newline:
// the anchor and the log ID, as in an "audit anchor" line of the journal.
func (h Head) String() string { return h.Anchor.String() + " " + h.LogID.String() }

// makesGrant reports whether ev is a grant-making entry: an approving or
// renewing decision of kind preapprove or standing, a use of a standing
// grant, which makes its next token, or a grants_reset barrier.
func makesGrant(ev Event) bool {
	switch e := ev.(type) {
	case Decision:
		return e.Kind.IsPreapprove() && (e.Answer == AnswerApproveOnce || e.Answer == AnswerRenew)
	case GrantUsed:
		return e.Via == ViaStanding
	case GrantsReset:
		return true // the head names the barrier, so the next start matches it
	}
	return false
}

// writeHead writes h to the head file of the log at path: a temporary
// file, fsync, rename, then a sync of the directory. So the head file is
// the old head or the new one, never part of one.
func writeHead(path string, h Head, syncDir func(string) error) error {
	tmp := path + HeadSuffix + ".tmp"
	f, err := os.OpenFile(tmp, headWriteFlags, 0o600) //nolint:gosec // G304: next to the log, in the directory that CheckParentDirs checked.
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New(tmp + " is not a regular file")
	}
	if err == nil {
		_, err = io.WriteString(f, h.String()+"\n")
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path+HeadSuffix)
	}
	if err == nil {
		err = syncDir(filepath.Dir(path))
	}
	return err
}

// ErrNoHead is the error of ReadHead when the log has no head file, such
// as before the first grant-making entry, or after an upgrade from a
// version without it.
var ErrNoHead = errors.New("audit log: no head file")

// ReadHead reads the head file of the log at path. It must be a regular
// file, owned by the user that runs nodkey and private to it, with one
// line in the form that Append writes. The error never holds text from
// the file.
func ReadHead(path string) (Head, error) {
	if !supported {
		return Head{}, fmt.Errorf("audit log: %w: nodkey version 1 runs on Linux only", errors.ErrUnsupported)
	}
	name := path + HeadSuffix
	self, err := currentUser(os.Geteuid())
	if err != nil {
		return Head{}, err
	}
	f, err := os.OpenFile(name, readFlags, 0) //nolint:gosec // G304: next to the log, in the directory that CheckParentDirs checked.
	if errors.Is(err, os.ErrNotExist) {
		return Head{}, ErrNoHead
	}
	if err != nil {
		return Head{}, fmt.Errorf("audit head file: %w", err) // a *fs.PathError names the path
	}
	defer func() { _ = f.Close() }() // read only; a close error changes nothing
	fi, err := f.Stat()
	if err != nil {
		return Head{}, fmt.Errorf("audit head file: %w", err)
	}
	if err := checkOpenFile(fi, self); err != nil {
		return Head{}, fmt.Errorf("audit head file %s: %w", name, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHeadSize))
	if err != nil {
		return Head{}, fmt.Errorf("audit head file %s: %w", name, err)
	}
	h, ok := parseHead(b)
	if !ok {
		return Head{}, fmt.Errorf("audit head file %s: is not one line \"SEQ:HASH LOGID\" as the broker writes it; "+
			"no grant is rebuilt (DESIGN.md section 8, \"Grants after a restart\")", name)
	}
	return h, nil
}

// parseHead reads the bytes of a head file.
func parseHead(b []byte) (Head, bool) {
	line, ok := bytes.CutSuffix(b, []byte("\n"))
	if !ok {
		return Head{}, false
	}
	anchor, id, ok := strings.Cut(string(line), " ")
	if !ok {
		return Head{}, false
	}
	var h Head
	var err error
	if h.Anchor, err = ParseAnchor(anchor); err != nil || !decodeHex64((*[32]byte)(&h.LogID), id) || h.LogID.IsZero() {
		return Head{}, false
	}
	// Only the form that String writes: one way to write each head.
	if h.String() != string(line) {
		return Head{}, false
	}
	return h, true
}
