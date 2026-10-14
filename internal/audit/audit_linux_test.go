package audit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// testHooks returns the hooks of Open for a test, with a fixed clock. The
// test files are below the system temporary directory, which everyone
// can write to, so config.CheckParentDirs would refuse them.
// TestOpenChecksParentDirs checks that Open uses it.
func testHooks() hooks {
	h := realHooks()
	h.checkDirs = func(string) error { return nil }
	h.now = func() time.Time { return testTime }
	return h
}

// testLog is a log that a test opened.
type testLog struct {
	*Logger
	journal bytes.Buffer
	alerts  []Recovery
}

// openLog opens the log at path with h. It closes the log at the end of
// the test.
func openLog(t *testing.T, path string, h hooks) (*testLog, error) {
	t.Helper()
	tl := &testLog{}
	l, err := open(path, Options{Journal: &tl.journal, Alert: func(r Recovery) { tl.alerts = append(tl.alerts, r) }}, h)
	if err != nil {
		return tl, err
	}
	tl.Logger = l
	t.Cleanup(func() { _ = l.Close() })
	return tl, nil
}

func mustOpen(t *testing.T, path string, h hooks) *testLog {
	t.Helper()
	tl, err := openLog(t, path, h)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return tl
}

func mustAppend(t *testing.T, l *testLog, ev Event) Anchor {
	t.Helper()
	a, err := l.Append(ev)
	if err != nil {
		t.Fatalf("Append(%s): %v", ev.eventName(), err)
	}
	return a
}

// logPath returns the path of a new log in a new directory.
func logPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.jsonl")
}

// writeLog writes data to path with exactly mode.
func writeLog(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// openFile opens a file that the test made, with flags.
func openFile(path string, flags int) (*os.File, error) {
	return os.OpenFile(path, flags, 0o600) //nolint:gosec // G304: tests open only files in their own temporary directory.
}

// mkdirMode makes the directory path with exactly mode.
func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readLog(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: tests read only files in their own temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustVerify(t *testing.T, path string, anchors ...Anchor) Result {
	t.Helper()
	res, err := Verify(bytes.NewReader(readLog(t, path)), anchors...)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return res
}

// journalOf returns the journal lines for anchors.
func journalOf(anchors ...Anchor) string {
	var b strings.Builder
	for _, a := range anchors {
		b.WriteString(JournalPrefix + a.String() + "\n")
	}
	return b.String()
}

func TestAppendWritesTheChain(t *testing.T) {
	path := logPath(t)
	l := mustOpen(t, path, testHooks())
	var anchors []Anchor
	for _, ev := range sampleEvents() {
		anchors = append(anchors, mustAppend(t, l, ev))
	}
	data := readLog(t, path)
	first, _, _ := bytes.Cut(data, []byte("\n"))
	want := `{"seq":1,"time":"2026-10-14T12:00:00.000Z","event":"broker_started","prev":"` + zeros + `","version":"1.2.0"}`
	if string(first) != want {
		t.Errorf("first line:\n%s\nwant:\n%s", first, want)
	}
	if want := newChain(t).addAll().bytes(); !bytes.Equal(data, want) {
		t.Errorf("log:\n%s\nwant:\n%s", data, want)
	}
	res := mustVerify(t, path, anchors...)
	if res.Entries != uint64(len(anchors)) || res.Last != anchors[len(anchors)-1] {
		t.Errorf("Verify = %+v; want %d entries, the last %v", res, len(anchors), anchors[len(anchors)-1])
	}
	// The journal gets the anchors and nothing else.
	if got, want := l.journal.String(), journalOf(anchors...); got != want {
		t.Errorf("journal:\n%s\nwant:\n%s", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
	if len(l.alerts) != 0 {
		t.Errorf("alerts = %v, want none", l.alerts)
	}
	// O_NONBLOCK was only for the open.
	rc, err := l.f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uintptr
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFL, 0)
	}); err != nil || errno != 0 {
		t.Fatalf("F_GETFL: %v %v", err, errno)
	}
	if flags&syscall.O_NONBLOCK != 0 || flags&syscall.O_APPEND == 0 {
		t.Errorf("flags of the open log = %#o; want O_APPEND and no O_NONBLOCK", flags)
	}
}

func TestOpenContinuesTheChain(t *testing.T) {
	path := logPath(t)
	l := mustOpen(t, path, testHooks())
	mustAppend(t, l, BrokerStarted{Version: "dev"})
	mustAppend(t, l, Request{Subject: secretsSubject()})
	mustAppend(t, l, BrokerStopped{})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l = mustOpen(t, path, testHooks())
	a := mustAppend(t, l, BrokerStarted{Version: "dev"})
	if a.Seq != 4 {
		t.Errorf("seq after a restart = %d, want 4", a.Seq)
	}
	if res := mustVerify(t, path); res.Entries != 4 || res.Last != a {
		t.Errorf("Verify = %+v; want 4 entries, the last %v", res, a)
	}
	if len(l.alerts) != 0 {
		t.Errorf("alerts = %v, want none", l.alerts)
	}
}

func TestOpenRecoversATornLine(t *testing.T) {
	base := newChain(t)
	base.add(BrokerStarted{Version: "dev"})
	base.add(Request{Subject: secretsSubject()})
	// next is the line that the power cut tore.
	nc := newChain(t)
	nc.lines, nc.last = append([][]byte(nil), base.lines...), base.last
	nc.add(Decision{Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce})
	next := nc.lines[2]

	tests := []struct {
		name string
		base *chain
		torn []byte
	}{
		{"half a line", base, half(next)},
		{"a whole entry without its newline", base, next},
		{"zeros", base, make([]byte, 4096)},
		{"the longest torn line", base, bytes.Repeat([]byte("x"), MaxLineSize)},
		{"only a torn line", newChain(t), half(next)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := logPath(t)
			writeLog(t, path, append(tt.base.bytes(), tt.torn...), 0o600)
			l := mustOpen(t, path, testHooks())

			// What Open must write: a newline, and a log_recovered entry
			// with the seq and prev that the torn line would have had.
			want := newChain(t)
			want.lines, want.last = append([][]byte(nil), tt.base.lines...), tt.base.last
			rec := want.tear(tt.torn)
			if got := readLog(t, path); !bytes.Equal(got, want.bytes()) {
				t.Errorf("log:\n%q\nwant:\n%q", got, want.bytes())
			}
			wantAlert := Recovery{Seq: rec.Seq, TornLength: len(tt.torn), TornSHA256: sha256.Sum256(tt.torn)}
			if len(l.alerts) != 1 || l.alerts[0] != wantAlert {
				t.Errorf("alerts = %+v, want one: %+v", l.alerts, wantAlert)
			}
			if got := l.journal.String(); got != journalOf(rec) {
				t.Errorf("journal = %q, want %q", got, journalOf(rec))
			}
			if res := mustVerify(t, path, rec); res.TornLines != 1 || res.Last != rec {
				t.Errorf("Verify = %+v; want 1 torn line, the last entry %v", res, rec)
			}
			// The broker goes on as usual.
			a := mustAppend(t, l, BrokerStarted{Version: "dev"})
			if a.Seq != rec.Seq+1 {
				t.Errorf("seq after the recovery = %d, want %d", a.Seq, rec.Seq+1)
			}
			mustVerify(t, path, rec, a)
		})
	}
}

// TestOpenRefusesADamagedEnd: Open recovers a torn line only. Anything
// else at the end of the log needs a person, so the broker does not
// start, and Open changes nothing.
func TestOpenRefusesADamagedEnd(t *testing.T) {
	base := newChain(t)
	base.add(BrokerStarted{Version: "dev"})
	base.add(Request{Subject: secretsSubject()})
	good := base.bytes()
	// A log_recovered entry for a torn line, as Open writes it.
	twice := newChain(t)
	twice.lines, twice.last = append([][]byte(nil), base.lines...), base.last
	twice.tear(half(base.lines[1]))

	tests := []struct {
		name string
		log  []byte
		want string
	}{
		{"torn bytes longer than a line", append(bytes.Clone(good), bytes.Repeat([]byte("x"), MaxLineSize+1)...),
			"ends in more than 65536 bytes without a newline"},
		{"last line is not an entry", append(bytes.Clone(good), `{"reason":"`+canary+"\"}\n"...),
			"the last complete line is not a valid entry: it has no seq"},
		{"last line is not JSON", append(bytes.Clone(good), canary+"\n"...),
			"the last complete line is not a valid entry: it is not valid JSON"},
		{"last line too long", append(bytes.Clone(good), append(bytes.Repeat([]byte("x"), MaxLineSize+1), '\n')...),
			"its last complete line is longer than 65536 bytes"},
		{"empty last line", append(bytes.Clone(good), '\n'),
			"the last complete line is not a valid entry: it is not valid JSON"},
		// A second power cut during the recovery write left the newline
		// after the torn line, and half of the log_recovered entry.
		{"a torn line, then half of its log_recovered entry",
			append(join(base.lines[0], base.lines[1], twice.lines[2]), half(twice.lines[3])...),
			"the last complete line is not a valid entry: it is not valid JSON"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := logPath(t)
			writeLog(t, path, tt.log, 0o600)
			for range 2 { // the second time shows that the lock was released
				l, err := openLog(t, path, testHooks())
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("Open: %v; want an error with %q", err, tt.want)
				}
				if strings.Contains(err.Error(), "CANARY") {
					t.Errorf("Open: %v; the error shows text from the log", err)
				}
				if len(l.alerts) != 0 {
					t.Errorf("alerts = %v, want none", l.alerts)
				}
			}
			if got := readLog(t, path); !bytes.Equal(got, tt.log) {
				t.Error("Open changed the log")
			}
		})
	}
}

// faultyFile writes to the log file until a test makes it fail.
type faultyFile struct {
	mu       sync.Mutex
	f        *os.File
	writeErr error // when set, a write fails with it
	partial  int   // a failing write first writes this many bytes
	syncErr  error // when set, a sync fails with it
}

// errShort makes a write write only the partial bytes, with no error.
var errShort = errors.New("short write without an error")

func (ff *faultyFile) Write(p []byte) (int, error) {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	if ff.writeErr == nil {
		return ff.f.Write(p)
	}
	n := min(ff.partial, len(p))
	if _, err := ff.f.Write(p[:n]); err != nil {
		return 0, err
	}
	if errors.Is(ff.writeErr, errShort) {
		return n, nil
	}
	return n, ff.writeErr
}

func (ff *faultyFile) Sync() error {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	if ff.syncErr != nil {
		return ff.syncErr
	}
	return ff.f.Sync()
}

// set makes the next writes and syncs fail with these errors; nil makes
// them work again.
func (ff *faultyFile) set(writeErr error, partial int, syncErr error) {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	ff.writeErr, ff.partial, ff.syncErr = writeErr, partial, syncErr
}

// faultyHooks returns test hooks that write through ff.
func faultyHooks(ff *faultyFile) hooks {
	h := testHooks()
	h.wrap = func(f *os.File) file {
		ff.f = f
		return ff
	}
	return h
}

var (
	errDiskFull = errors.New("made-up error: no space left on device")
	errIO       = errors.New("made-up error: input/output error")
)

// TestAppendFailsClosed: after a failed write or sync, Append fails, and
// every later Append fails too, until the log is opened again. A restart
// records the torn line, and the log passes Verify.
func TestAppendFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		writeErr error
		partial  int
		syncErr  error
		want     string
		torn     bool // the log ends in a torn line afterwards
	}{
		{name: "write fails after part of the line", writeErr: errDiskFull, partial: 10, want: "audit log: write: ", torn: true},
		{name: "write fails before the line", writeErr: errDiskFull, want: "audit log: write: "},
		{name: "short write", writeErr: io.ErrShortWrite, partial: 1, want: "audit log: write: ", torn: true},
		{name: "short write without an error", writeErr: errShort, partial: 5, want: "audit log: write: short write", torn: true},
		{name: "sync fails", syncErr: errIO, want: "audit log: sync: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := logPath(t)
			ff := &faultyFile{}
			l := mustOpen(t, path, faultyHooks(ff))
			first := mustAppend(t, l, BrokerStarted{Version: "dev"})

			ff.set(tt.writeErr, tt.partial, tt.syncErr)
			_, err := l.Append(Request{Subject: secretsSubject()})
			cause := tt.writeErr
			if cause == nil {
				cause = tt.syncErr
			} else if errors.Is(cause, errShort) {
				cause = io.ErrShortWrite
			}
			if !errors.Is(err, cause) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Append: %v; want %q and %v", err, tt.want, cause)
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Errorf("Append: %v; the error shows a field", err)
			}
			// The disk works again, but the log may end in a torn line.
			ff.set(nil, 0, nil)
			for range 2 {
				if _, err := l.Append(BrokerStopped{}); !errors.Is(err, ErrBroken) || !errors.Is(err, cause) {
					t.Errorf("Append after the failure: %v; want ErrBroken and %v", err, cause)
				}
			}
			if got := l.journal.String(); got != journalOf(first) {
				t.Errorf("journal = %q; want only the first entry", got)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}

			// A restart.
			l = mustOpen(t, path, testHooks())
			if got := len(l.alerts); got != map[bool]int{false: 0, true: 1}[tt.torn] {
				t.Errorf("alerts after the restart = %v; want a torn line: %v", l.alerts, tt.torn)
			}
			if tt.torn && l.alerts[0].TornLength != tt.partial {
				t.Errorf("torn length = %d, want %d", l.alerts[0].TornLength, tt.partial)
			}
			a := mustAppend(t, l, BrokerStarted{Version: "dev"})
			res := mustVerify(t, path, first, a)
			if tt.torn != (res.TornLines == 1) {
				t.Errorf("Verify = %+v; want a torn line: %v", res, tt.torn)
			}
		})
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errIO }

// TestAppendFailsWhenTheJournalFails: the anchor must reach the journal.
// If it does not, Append fails, and every later Append too.
func TestAppendFailsWhenTheJournalFails(t *testing.T) {
	path := logPath(t)
	l, err := open(path, Options{Journal: failingWriter{}, Alert: func(Recovery) {}}, testHooks())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if _, err := l.Append(BrokerStarted{Version: "dev"}); !errors.Is(err, errIO) || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("Append: %v; want a journal error", err)
	}
	if _, err := l.Append(BrokerStopped{}); !errors.Is(err, ErrBroken) {
		t.Errorf("Append after the failure: %v; want ErrBroken", err)
	}
	// The entry is on disk; the chain is whole.
	if res := mustVerify(t, path); res.Entries != 1 {
		t.Errorf("Verify = %+v; want 1 entry", res)
	}
}

// TestOpenFailsWhenTheRecoveryFails: if Open cannot record a torn line,
// the broker does not start.
func TestOpenFailsWhenTheRecoveryFails(t *testing.T) {
	base := newChain(t)
	base.add(BrokerStarted{Version: "dev"})
	torn := half(base.lines[0])
	log := append(base.bytes(), torn...)

	t.Run("nothing written", func(t *testing.T) {
		path := logPath(t)
		writeLog(t, path, log, 0o600)
		l, err := openLog(t, path, faultyHooks(&faultyFile{writeErr: errDiskFull}))
		if !errors.Is(err, errDiskFull) || len(l.alerts) != 0 {
			t.Fatalf("Open: %v, alerts %v; want the write error and no alert", err, l.alerts)
		}
		if !bytes.Equal(readLog(t, path), log) {
			t.Error("the log changed")
		}
		// Once the disk works again, a restart records the torn line.
		l = mustOpen(t, path, testHooks())
		if len(l.alerts) != 1 {
			t.Errorf("alerts = %v, want one", l.alerts)
		}
		mustVerify(t, path)
	})
	t.Run("only the newline written", func(t *testing.T) {
		path := logPath(t)
		writeLog(t, path, log, 0o600)
		if _, err := openLog(t, path, faultyHooks(&faultyFile{writeErr: errDiskFull, partial: 1})); !errors.Is(err, errDiskFull) {
			t.Fatalf("Open: %v; want the write error", err)
		}
		// Now the torn line ends in a newline, and no log_recovered entry
		// follows it. That needs a person: Open refuses the log.
		if _, err := openLog(t, path, testHooks()); err == nil || !strings.Contains(err.Error(), "is not a valid entry") {
			t.Fatalf("Open: %v; want the last line refused", err)
		}
	})
	t.Run("sync fails", func(t *testing.T) {
		path := logPath(t)
		writeLog(t, path, log, 0o600)
		l, err := openLog(t, path, faultyHooks(&faultyFile{syncErr: errIO}))
		if !errors.Is(err, errIO) || len(l.alerts) != 0 {
			t.Fatalf("Open: %v, alerts %v; want the sync error and no alert", err, l.alerts)
		}
	})
}

func TestOpenTakesALock(t *testing.T) {
	path := logPath(t)
	first := mustOpen(t, path, testHooks())
	mustAppend(t, first, BrokerStarted{Version: "dev"})
	_, err := openLog(t, path, testHooks())
	if err == nil || !strings.Contains(err.Error(), "another process has it open for writing, such as a second broker") {
		t.Fatalf("second Open: %v; want it refused", err)
	}
	// The first broker goes on.
	mustAppend(t, first, BrokerStopped{})
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := mustOpen(t, path, testHooks())
	mustAppend(t, second, BrokerStarted{Version: "dev"})
	mustVerify(t, path)
}

func TestOpenRefusesALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.jsonl")
	c := newChain(t)
	c.add(BrokerStarted{Version: "dev"})
	writeLog(t, target, c.bytes(), 0o600)
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openLog(t, link, testHooks()); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Errorf("Open of a link: %v; want it refused", err)
	}
	if !bytes.Equal(readLog(t, target), c.bytes()) {
		t.Error("Open changed the file behind the link")
	}

	// A link to a file that is not there: Open makes no file.
	missing := filepath.Join(dir, "missing.jsonl")
	dangling := filepath.Join(dir, "dangling.jsonl")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := openLog(t, dangling, testHooks()); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Errorf("Open of a link to a missing file: %v; want it refused", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open made the file behind the link: %v", err)
	}

	// The open itself refuses a link too, in case one is put there after
	// the first look.
	for _, p := range []string{link, dangling} {
		f, err := openFile(p, writeFlags)
		if err == nil {
			_ = f.Close()
		}
		if !errors.Is(err, syscall.ELOOP) {
			t.Errorf("OpenFile(%s, writeFlags): %v; want ELOOP", p, err)
		}
	}
}

func TestOpenRefusesTheWrongModeOrOwner(t *testing.T) {
	c := newChain(t)
	c.add(BrokerStarted{Version: "dev"})
	for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o644, 0o666} {
		path := logPath(t)
		writeLog(t, path, c.bytes(), mode)
		_, err := openLog(t, path, testHooks())
		if err == nil || !strings.Contains(err.Error(), "group or others have access") {
			t.Errorf("Open of a log with mode %04o: %v; want it refused", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o700, 0o300} {
		path := logPath(t)
		writeLog(t, path, c.bytes(), mode)
		_, err := openLog(t, path, testHooks())
		if err == nil || !strings.Contains(err.Error(), "its owner may run it as a program") {
			t.Errorf("Open of a log with mode %04o: %v; want it refused", mode, err)
		}
	}
	// Tests cannot make a file that another user owns, so they ask for
	// another user instead.
	path := logPath(t)
	writeLog(t, path, c.bytes(), 0o600)
	h := testHooks()
	h.euid = func() int { return os.Geteuid() + 1 }
	if _, err := openLog(t, path, h); err == nil || !strings.Contains(err.Error(), "it must be owned by the user that runs nodkey") {
		t.Errorf("Open of a log of another user: %v; want it refused", err)
	}
	if !bytes.Equal(readLog(t, path), c.bytes()) {
		t.Error("Open changed the log")
	}
}

func TestOpenRefusesWhatIsNotAFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "dir.jsonl")
	mkdirMode(t, sub, 0o700)
	for _, p := range []string{fifo, sub, os.DevNull} {
		done := make(chan error, 1)
		go func() {
			_, err := open(p, Options{Journal: io.Discard, Alert: func(Recovery) {}}, testHooks())
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
				t.Errorf("Open(%s): %v; want it refused", p, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("Open(%s) waits", p)
		}
	}
	// The open itself does not wait on a FIFO either, in case one is put
	// there after the first look.
	done := make(chan error, 1)
	go func() {
		f, err := openFile(fifo, writeFlags)
		if err == nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("OpenFile of a FIFO with no reader: no error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OpenFile of a FIFO with no reader waits")
	}
}

func TestOpenChecksParentDirs(t *testing.T) {
	// The real check: a directory that others can write to is refused,
	// and no file is made.
	shared := filepath.Join(t.TempDir(), "shared")
	mkdirMode(t, shared, 0o777)
	path := filepath.Join(shared, "audit.jsonl")
	h := testHooks()
	h.checkDirs = config.CheckParentDirs
	if _, err := openLog(t, path, h); err == nil || !strings.Contains(err.Error(), "group or others can write to this directory") {
		t.Errorf("Open below a directory that others can write to: %v; want it refused", err)
	}
	// Any error of the check is passed on.
	h.checkDirs = func(string) error { return errors.New("made-up check failure") }
	if _, err := openLog(t, path, h); err == nil || !strings.Contains(err.Error(), "made-up check failure") {
		t.Errorf("Open: %v; want the error of the check", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open made the log after a failed check: %v", err)
	}
}

func TestOpenSyncsTheDirectoryOfANewLog(t *testing.T) {
	var synced []string
	h := testHooks()
	h.syncDir = func(dir string) error {
		synced = append(synced, dir)
		return nil
	}
	path := logPath(t)
	l := mustOpen(t, path, h)
	if want := []string{filepath.Dir(path)}; len(synced) != 1 || synced[0] != want[0] {
		t.Errorf("synced directories = %q, want %q", synced, want)
	}
	mustAppend(t, l, BrokerStarted{Version: "dev"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	mustOpen(t, path, h)
	if len(synced) != 1 {
		t.Errorf("synced directories = %q; want no sync for a log with entries", synced)
	}

	h.syncDir = func(string) error { return errIO }
	if _, err := openLog(t, logPath(t), h); !errors.Is(err, errIO) {
		t.Errorf("Open when the directory sync fails: %v; want the error", err)
	}
}

func TestOpenNeedsTheJournalAndTheAlert(t *testing.T) {
	path := logPath(t)
	for _, opts := range []Options{{Alert: func(Recovery) {}}, {Journal: io.Discard}} {
		if _, err := open(path, opts, testHooks()); err == nil {
			t.Errorf("Open with %+v: no error", opts)
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open made the log: %v", err)
	}
}

// TestAppendRefusesAnEvent: an event that fails its checks is not written,
// and it does not stop the log.
func TestAppendRefusesAnEvent(t *testing.T) {
	path := logPath(t)
	l := mustOpen(t, path, testHooks())
	bad := secretsSubject()
	bad.Client = "laptop " + canary // a space is not allowed in a name
	probe := appendLine(nil, 1, testTime, eventRequest, [sha256.Size]byte{}, mustEncode(t, Request{Subject: secretsSubject()}))
	longest := MaxLineSize - len(probe) - len(`,"message":""`)
	for _, ev := range []Event{
		nil,
		&Request{Subject: secretsSubject()},
		(*Signed)(nil),
		Request{Subject: bad},
		logRecovered{TornLength: 1, TornSHA256: zeros},
		Request{Subject: secretsSubject(), Message: strings.Repeat("m", longest+1)},
	} {
		_, err := l.Append(ev)
		if err == nil {
			t.Errorf("Append(%#v): no error", ev)
			continue
		}
		if errors.Is(err, ErrBroken) || strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "mmmm") {
			t.Errorf("Append(%T): %v", ev, err)
		}
	}
	a := mustAppend(t, l, Request{Subject: secretsSubject(), Message: strings.Repeat("m", longest)})
	if res := mustVerify(t, path, a); res.Entries != 1 {
		t.Errorf("Verify = %+v; want 1 entry", res)
	}
	if got := l.journal.String(); got != journalOf(a) {
		t.Errorf("journal = %q, want %q", got, journalOf(a))
	}
}

func TestAppendAfterClose(t *testing.T) {
	l := mustOpen(t, logPath(t), testHooks())
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(BrokerStopped{}); !errors.Is(err, ErrClosed) {
		t.Errorf("Append after Close: %v; want ErrClosed", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestAppendFromManyGoroutines runs with -race in CI.
func TestAppendFromManyGoroutines(t *testing.T) {
	t.Parallel()
	path := logPath(t)
	l := mustOpen(t, path, realHooksWithoutDirCheck())
	const goroutines, each = 16, 10
	anchors := make(chan Anchor, goroutines*each)
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range each {
				a, err := l.Append(Request{Subject: loginSubject()})
				if err != nil {
					t.Error(err)
					return
				}
				anchors <- a
			}
		})
	}
	wg.Wait()
	close(anchors)
	var all []Anchor
	seen := map[uint64]bool{}
	for a := range anchors {
		if seen[a.Seq] {
			t.Errorf("seq %d twice", a.Seq)
		}
		seen[a.Seq] = true
		all = append(all, a)
	}
	res := mustVerify(t, path, all...)
	if res.Entries != goroutines*each {
		t.Errorf("Verify = %+v; want %d entries", res, goroutines*each)
	}
	if lines := strings.Count(l.journal.String(), "\n"); lines != goroutines*each {
		t.Errorf("journal has %d lines, want %d", lines, goroutines*each)
	}
}

// realHooksWithoutDirCheck are the hooks of Open, with the real clock,
// for a log below the system temporary directory.
func realHooksWithoutDirCheck() hooks {
	h := realHooks()
	h.checkDirs = func(string) error { return nil }
	return h
}

// TestFieldsCannotBreakTheLine: the client writes Command and Reason. No
// text there can end the line or add an entry.
func TestFieldsCannotBreakTheLine(t *testing.T) {
	path := logPath(t)
	l := mustOpen(t, path, testHooks())
	s := secretsSubject()
	s.Reason = "a\nb\r\n{\"seq\":99,\"event\":\"decision\"}  \x00\x1b[2J" + canary
	s.Command = "x\n" + `"},{"seq":2` + "\xff"
	ev := Request{Subject: s, Message: "<b>bold</b> & \"quoted\"\n"}
	mustAppend(t, l, ev)
	data := readLog(t, path)
	if n := bytes.Count(data, []byte("\n")); n != 1 {
		t.Fatalf("the log has %d lines, want 1:\n%q", n, data)
	}
	for _, raw := range []string{"\r", " ", " ", "\x00", "\x1b"} {
		if bytes.Contains(data, []byte(raw)) {
			t.Errorf("the log holds %q as it is", raw)
		}
	}
	mustVerify(t, path)
}

// TestReadTailOfRefusesAnotherFile: Open reads the end of the log through
// a second, read-only open. If the path names another file by then, Open
// fails.
func TestReadTailOfRefusesAnotherFile(t *testing.T) {
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.jsonl")
	other := filepath.Join(dir, "other.jsonl")
	writeLog(t, locked, nil, 0o600)
	writeLog(t, other, nil, 0o600)
	fi, err := os.Stat(locked)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := readTailOf(other, fi); err == nil || !strings.Contains(err.Error(), "the file changed while it was opened") {
		t.Errorf("readTailOf of another file: %v; want it refused", err)
	}
	if _, _, err := readTailOf(locked, fi); err != nil {
		t.Errorf("readTailOf of the same file: %v", err)
	}
}

// TestOpenUsesTheRealDirCheck calls the exported Open, which the other
// tests do not: it must refuse a log below a directory that others can
// write to, and make no file. The test makes that directory itself, so
// the result does not depend on TMPDIR.
func TestOpenUsesTheRealDirCheck(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	mkdirMode(t, shared, 0o777)
	path := filepath.Join(shared, "audit.jsonl")
	l, err := Open(path, Options{Journal: io.Discard, Alert: func(Recovery) {}})
	if err == nil {
		_ = l.Close()
		t.Fatal("Open below a directory that others can write to: no error")
	}
	if !strings.Contains(err.Error(), "group or others can write to this directory") {
		t.Errorf("Open: %v; want the directory refused", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open made the log: %v", err)
	}
}

// TestOpenByManyBrokersAtOnce: many brokers open the same new log at the
// same time. Exactly one may win, and the log passes Verify.
func TestOpenByManyBrokersAtOnce(t *testing.T) {
	t.Parallel()
	for round := range 10 {
		path := logPath(t)
		var mu sync.Mutex
		var opened []*Logger
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 32 {
			wg.Go(func() {
				<-start
				l, err := open(path, Options{Journal: io.Discard, Alert: func(Recovery) {}}, testHooks())
				if err != nil {
					return
				}
				if _, err := l.Append(BrokerStarted{Version: "dev"}); err != nil {
					t.Error(err)
				}
				mu.Lock()
				opened = append(opened, l)
				mu.Unlock()
			})
		}
		close(start)
		wg.Wait()
		if len(opened) != 1 {
			t.Fatalf("round %d: %d brokers opened the log, want 1", round, len(opened))
		}
		if res := mustVerify(t, path); res.Entries != 1 {
			t.Errorf("round %d: Verify = %+v, want 1 entry", round, res)
		}
		for _, l := range opened {
			_ = l.Close()
		}
	}
}
