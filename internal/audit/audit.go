// Package audit writes the broker's audit log and checks it (DESIGN.md
// section 9, THREAT-MODEL.md T17).
//
// The log is one file of JSON Lines: one entry per line. Every entry has
// the fields seq (1, 2, 3, …), time (UTC), event and prev, and then the
// fields of its event. prev is the SHA-256, in hex, of the line before it,
// as written and without its newline; the first entry has 64 zeros. So
// each line is linked to the one before it, and a change breaks the chain
// at the next line.
//
// The broker only appends. Each entry is one write call, then a sync to
// disk. Append returns an error if that fails, and then every later Append
// fails too, so the broker denies every request until it starts again.
// The number and hash of each entry also go to a journal writer (stderr in
// the broker), as an anchor that Verify can check later.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// MaxLineSize is the longest line of the log, in bytes, without its
// newline. Append refuses a longer entry, and Verify refuses a longer
// line.
const MaxLineSize = 64 << 10

// timeFormat is the form of the time field: RFC 3339 in UTC, with
// milliseconds, such as 2026-10-14T12:00:00.000Z.
const timeFormat = "2006-01-02T15:04:05.000Z07:00"

var (
	// ErrClosed is returned by Append after Close.
	ErrClosed = errors.New("audit log: it is closed")
	// ErrBroken is in the error of the Append whose write, sync or
	// journal write failed, and of every Append after it. The log may then
	// end in a torn line, so nothing more is written to it until it is
	// opened again. So a caller that sees ErrBroken knows at once that
	// every later entry fails too.
	ErrBroken = errors.New("audit log: a write failed, so nothing more is written until the broker starts again")
)

// Recovery tells about a torn last line that Open found and recorded with
// a log_recovered entry.
type Recovery struct {
	// Seq is the seq of the log_recovered entry.
	Seq uint64
	// TornLength is the number of torn bytes.
	TornLength int
	// TornSHA256 is the SHA-256 of the torn bytes.
	TornSHA256 [sha256.Size]byte
}

// Options are what Open needs from the broker. Both fields are required.
type Options struct {
	// Journal gets one line for each entry: JournalPrefix and the entry's
	// anchor. It never gets the content of an entry. In the broker it is
	// stderr, which systemd keeps in the journal.
	Journal io.Writer
	// Alert is called when Open found a torn last line and added a
	// log_recovered entry for it, before Open returns. The broker sends an
	// alert message.
	Alert func(Recovery)
}

// file is what Logger needs from the open log: *os.File has it. It is the
// seam where tests make writes and syncs fail.
type file interface {
	Write(p []byte) (int, error)
	Sync() error
}

// hooks are the parts of Open that tests replace.
type hooks struct {
	checkDirs func(path string) error // checks the directories on the way to the log
	euid      func() int              // the user ID that runs nodkey
	wrap      func(*os.File) file     // the file that Append writes to and syncs
	syncDir   func(dir string) error  // syncs a directory to disk
	now       func() time.Time        // the clock
}

// realHooks are the hooks that Open uses.
func realHooks() hooks {
	return hooks{
		checkDirs: config.CheckParentDirs,
		euid:      os.Geteuid,
		wrap:      func(f *os.File) file { return f },
		syncDir:   syncDir,
		now:       time.Now,
	}
}

// Logger appends entries to the audit log. It is safe for many
// goroutines. Make it with Open.
type Logger struct {
	mu      sync.Mutex
	f       *os.File // the open log; it holds the lock; nil after Close
	w       file     // writes to f and syncs it
	journal io.Writer
	now     func() time.Time
	last    Anchor // the last entry; seq 0 and a zero hash when there is none
	err     error  // set after a failed write, sync or journal write
}

// Open opens the audit log at path for appending, and makes it if it is
// missing. The broker must open it only once, at start.
//
// It checks the file and fails closed:
//
//   - Every directory on the way must pass config.CheckParentDirs: owned
//     by root or by the user that runs nodkey, and not writable by group
//     or others.
//   - It opens the file with O_WRONLY, O_APPEND, O_CREAT, O_NOFOLLOW and
//     O_CLOEXEC, and mode 0600 for a new file. O_NOFOLLOW refuses a
//     symbolic link. It adds O_NONBLOCK, so that a FIFO there cannot make
//     the open wait, and turns it off once the file is known to be a
//     regular file.
//   - The open file must be a regular file, owned by the user that runs
//     nodkey. Its mode may give only read and write to the owner, such as
//     0600: an execute bit, or any bit for group or others, is refused.
//   - It takes an exclusive flock on the open file, without waiting. If
//     another process holds it, such as a second broker, Open fails.
//   - It reads the end of the file, not the whole file, to find the last
//     entry. The last complete line must be a valid entry.
//   - A new or empty file: Open syncs its directory, so the new name is on
//     disk too.
//
// A torn last line: if the file does not end in a newline, the bytes after
// the last newline are a torn line, such as from a power cut during a
// write. Open then writes, with one write call, a newline and a
// log_recovered entry. That entry holds the length and SHA-256 of the
// torn bytes. Its prev is the hash of the last complete line, so the torn
// line stays outside the chain, but the entry still pins its bytes. Then
// Open calls opts.Alert. Open refuses torn bytes longer than MaxLineSize,
// and a last complete line that is not a valid entry: then something
// other than a power cut changed the log, and a person must look.
func Open(path string, opts Options) (*Logger, error) {
	return open(path, opts, realHooks())
}

func open(path string, opts Options, h hooks) (*Logger, error) {
	if !supported {
		return nil, fmt.Errorf("audit log: %w: nodkey version 1 runs on Linux only", errors.ErrUnsupported)
	}
	if opts.Journal == nil || opts.Alert == nil {
		return nil, errors.New("audit log: Options.Journal and Options.Alert are required")
	}
	self, err := currentUser(h.euid())
	if err != nil {
		return nil, err
	}
	if err := h.checkDirs(path); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	// Opening a device or a FIFO can have side effects, so look first. The
	// check of the open file below is the one that counts.
	if fi, err := os.Lstat(path); err == nil {
		if err := checkKind(fi); err != nil {
			return nil, fmt.Errorf("audit log %s: %w", path, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("audit log: %w", err) // a *fs.PathError names the path
	}
	f, err := os.OpenFile(path, writeFlags, 0o600) //nolint:gosec // G304: the path comes from the broker config; CheckParentDirs checked the way to it, and the open file is checked next.
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("audit log %s: is a symbolic link; use the path of the file itself", path)
		}
		return nil, fmt.Errorf("audit log: %w", err)
	}
	l := &Logger{f: f, w: h.wrap(f), journal: opts.Journal, now: h.now}
	rec, recovered, err := l.start(path, self, h)
	if err != nil {
		_ = f.Close() // Open failed; a close error adds nothing
		return nil, err
	}
	if recovered {
		opts.Alert(rec)
	}
	return l, nil
}

// start checks the open log, locks it, finds the last entry, and records
// a torn last line. It reports whether it recorded one.
func (l *Logger) start(path string, self uint32, h hooks) (Recovery, bool, error) {
	fi, err := l.f.Stat()
	if err != nil {
		return Recovery{}, false, fmt.Errorf("audit log: %w", err)
	}
	if err := checkOpenFile(fi, self); err != nil {
		return Recovery{}, false, fmt.Errorf("audit log %s: %w", path, err)
	}
	if err := clearNonblock(l.f); err != nil {
		return Recovery{}, false, fmt.Errorf("audit log %s: %w", path, err)
	}
	if err := lockFile(l.f); err != nil {
		return Recovery{}, false, fmt.Errorf("audit log %s: %w", path, err)
	}
	size, t, err := readTailOf(path, fi)
	if err != nil {
		return Recovery{}, false, fmt.Errorf("audit log %s: %w", path, err)
	}
	if size == 0 {
		if err := h.syncDir(filepath.Dir(path)); err != nil {
			return Recovery{}, false, fmt.Errorf("audit log %s: syncing its directory: %w", path, err)
		}
	}
	if t.hasLast {
		e, bad := parseEntry(t.last)
		if bad != "" {
			return Recovery{}, false, fmt.Errorf("audit log %s: the last complete line is not a valid entry: it %s; "+
				"check the log with nodkey audit verify", path, bad)
		}
		l.last = Anchor{Seq: e.seq, Hash: sha256.Sum256(t.last)}
	}
	if t.torn == nil {
		return Recovery{}, false, nil
	}
	sum := sha256.Sum256(t.torn)
	a, err := l.append(logRecovered{TornLength: len(t.torn), TornSHA256: hex.EncodeToString(sum[:])}, true)
	if err != nil {
		return Recovery{}, false, err
	}
	return Recovery{Seq: a.Seq, TornLength: len(t.torn), TornSHA256: sum}, true, nil
}

// currentUser returns euid as a user ID.
func currentUser(euid int) (uint32, error) {
	if euid < 0 || uint64(euid) > math.MaxUint32 {
		return 0, errors.New("audit log: cannot get the user ID on this system")
	}
	return uint32(euid), nil
}

// checkKind checks the Lstat information of a log that is there.
func checkKind(fi fs.FileInfo) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return errors.New("is a symbolic link; use the path of the file itself")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("is not a regular file")
	}
	return nil
}

// checkOpenFile checks the open log. These are the checks of the config
// package for audit_log, made again on the file that is open now.
func checkOpenFile(fi fs.FileInfo, self uint32) error {
	if err := checkKind(fi); err != nil {
		return err
	}
	owner, ok := fileOwner(fi)
	if !ok {
		return errors.New("cannot check the owner on this system")
	}
	if owner != self {
		return fmt.Errorf("is owned by user ID %d; it must be owned by the user that runs nodkey (ID %d)", owner, self)
	}
	switch perm := fi.Mode().Perm(); {
	case perm&0o077 != 0:
		return fmt.Errorf("group or others have access (mode %04o); it must be private to its owner, such as mode 0600", perm)
	case perm&0o100 != 0:
		return fmt.Errorf("its owner may run it as a program (mode %04o); the audit log must allow only read and "+
			"write, such as mode 0600", perm)
	}
	return nil
}

// readTailOf opens the log at path again, read only, to read its end. The
// file that opens must be the one that is locked, fi. It returns the size
// of the log and its end.
func readTailOf(path string, fi fs.FileInfo) (int64, tail, error) {
	r, err := os.OpenFile(path, readFlags, 0) //nolint:gosec // G304: the same path as the open log; the file must be the same file.
	if err != nil {
		return 0, tail{}, err
	}
	defer func() { _ = r.Close() }() // read only; a close error changes nothing
	rfi, err := r.Stat()
	if err != nil {
		return 0, tail{}, err
	}
	if !os.SameFile(fi, rfi) {
		return 0, tail{}, errors.New("the file changed while it was opened")
	}
	t, err := readTail(r, rfi.Size())
	return rfi.Size(), t, err
}

// tail is the end of the log.
type tail struct {
	last    []byte // the last complete line, without its newline
	hasLast bool   // the log has a complete line
	torn    []byte // the bytes after the last newline; nil if the log ends in a newline
}

// readTail reads the end of a log of size bytes. It reads at most
// 2*MaxLineSize+2 bytes: the longest torn line, the longest complete line,
// and the newlines around it.
func readTail(r io.ReaderAt, size int64) (tail, error) {
	var t tail
	if size == 0 {
		return t, nil
	}
	n := min(size, 2*MaxLineSize+2)
	start := size - n
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, start); err != nil {
		return t, err
	}
	end := len(buf) - 1 // the newline after the last complete line
	if i := bytes.LastIndexByte(buf, '\n'); i != end {
		if (i < 0 && start > 0) || len(buf)-1-i > MaxLineSize {
			return t, fmt.Errorf("it ends in more than %d bytes without a newline; that is not a torn line, "+
				"so the broker does not start; check the log with nodkey audit verify", MaxLineSize)
		}
		t.torn = buf[i+1:]
		if i < 0 {
			return t, nil // the log is one torn line
		}
		end = i
	}
	j := bytes.LastIndexByte(buf[:end], '\n')
	if (j < 0 && start > 0) || end-1-j > MaxLineSize {
		return t, fmt.Errorf("its last complete line is longer than %d bytes; "+
			"check the log with nodkey audit verify", MaxLineSize)
	}
	t.last, t.hasLast = buf[j+1:end], true
	return t, nil
}

// syncDir syncs the directory dir to disk.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the directory of the audit log, which CheckParentDirs checked.
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// Append writes one entry to the log and syncs it to disk. It returns the
// entry's anchor when the entry is on disk and its anchor is in the
// journal. On any error the caller must deny: nothing is approved without
// a record (DESIGN.md section 9).
//
// An event that fails its checks, or that makes a line longer than
// MaxLineSize, is not written, and Append returns an error (CheckEvent
// returns the same error without a log). After a write, sync or journal
// error, the log may end in a torn line. So the error of that Append
// holds ErrBroken, and so does the error of every later Append, until the
// log is opened again (a broker restart), and Open records the torn line.
//
// No error holds the value of a field.
func (l *Logger) Append(ev Event) (Anchor, error) {
	if _, ok := ev.(logRecovered); ok {
		return Anchor{}, errors.New("audit log: only Open writes a log_recovered entry")
	}
	return l.append(ev, false)
}

// CheckEvent returns the error that Append returns for ev on a log that
// works: ev is not an event of this package, it fails its checks, or its
// line would be longer than MaxLineSize, even with the largest seq. It
// writes nothing. The broker's tests use it in place of a log file, to
// show that every entry the broker makes can be written (issue #11).
func CheckEvent(ev Event) error {
	if _, ok := ev.(logRecovered); ok {
		return errors.New("audit log: only Open writes a log_recovered entry")
	}
	name, body, err := encodeEvent(ev)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	// The time field has the same length for every year from 1000 to 9999.
	line := appendLine(nil, math.MaxUint64, time.Time{}, name, [sha256.Size]byte{}, body)
	if len(line) > MaxLineSize {
		return fmt.Errorf("audit log: the %s entry would be %d bytes, more than %d", name, len(line), MaxLineSize)
	}
	return nil
}

// append writes ev. afterTorn puts a newline before the entry, to end a
// torn line.
func (l *Logger) append(ev Event, afterTorn bool) (Anchor, error) {
	name, body, err := encodeEvent(ev)
	if err != nil {
		return Anchor{}, fmt.Errorf("audit log: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.f == nil:
		return Anchor{}, ErrClosed
	case l.err != nil:
		return Anchor{}, l.err
	case l.last.Seq == math.MaxUint64:
		return Anchor{}, errors.New("audit log: no seq is left")
	}
	seq := l.last.Seq + 1
	line := appendLine(nil, seq, l.now(), name, l.last.Hash, body)
	if len(line) > MaxLineSize {
		return Anchor{}, fmt.Errorf("audit log: the %s entry would be %d bytes, more than %d", name, len(line), MaxLineSize)
	}
	a := Anchor{Seq: seq, Hash: sha256.Sum256(line)}
	out := make([]byte, 0, len(line)+2)
	if afterTorn {
		out = append(out, '\n')
	}
	out = append(append(out, line...), '\n')
	// One Write call for the whole line, so it goes to the end of the file
	// in one piece (O_APPEND). For a regular file, (*os.File).Write makes
	// one write(2) call. Only after a short write, such as on a full disk,
	// does it call write(2) again for the rest: then the line is complete,
	// or Write returns an error and Append fails.
	n, err := l.w.Write(out)
	if err == nil && n != len(out) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return Anchor{}, l.fail(fmt.Errorf("audit log: write: %w", err))
	}
	if err := l.w.Sync(); err != nil {
		return Anchor{}, l.fail(fmt.Errorf("audit log: sync: %w", err))
	}
	l.last = a
	// The anchor goes to the journal only when the entry is on disk.
	if _, err := io.WriteString(l.journal, JournalPrefix+a.String()+"\n"); err != nil {
		return Anchor{}, l.fail(fmt.Errorf("audit log: journal: %w", err))
	}
	return a, nil
}

// fail records the first failed write, so that every later Append fails
// too. It returns err with ErrBroken, so the caller of the Append that
// failed knows at once that the log is broken.
func (l *Logger) fail(err error) error {
	l.err = fmt.Errorf("%w (%w)", ErrBroken, err)
	return l.err
}

// appendLine appends one entry to b, without the newline: the fields seq,
// time, event and prev, then the fields of the event from body, a JSON
// object.
func appendLine(b []byte, seq uint64, t time.Time, name string, prev [sha256.Size]byte, body []byte) []byte {
	b = append(b, `{"seq":`...)
	b = strconv.AppendUint(b, seq, 10)
	b = append(b, `,"time":"`...)
	b = t.UTC().AppendFormat(b, timeFormat)
	b = append(b, `","event":"`...)
	b = append(b, name...)
	b = append(b, `","prev":"`...)
	b = hex.AppendEncode(b, prev[:])
	b = append(b, '"')
	if len(body) > len("{}") {
		b = append(b, ',')
		b = append(b, body[1:len(body)-1]...)
	}
	return append(b, '}')
}

// Close closes the log and releases its lock. Append fails after Close.
// The broker appends a broker_stopped entry first.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
