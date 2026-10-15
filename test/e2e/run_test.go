//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// One run of the test is one test process. Its Docker objects and its
// files carry its run ID, and while it runs, it holds a lock on its lock
// file. A run that is killed, such as by the -timeout of go test or by
// Ctrl-C, cannot clean up. So each run first removes what earlier runs left
// (removeStale): only objects and files with a run ID, and only of runs
// that have ended.

// runID names the Docker objects and the files of this run: its start time
// in Unix seconds and 4 random bytes, such as "1760511234-a1b2c3d4". The
// time tells a later run how old they are.
var runID = func() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strconv.FormatInt(time.Now().Unix(), 10) + "-" + hex.EncodeToString(b)
}()

// runIDPattern matches a run ID, and takes its start time.
var runIDPattern = regexp.MustCompile(`^([0-9]{10})-[0-9a-f]{8}$`)

// The prefix of the names of the Docker objects, the private directories
// and the lock files of the runs, before the run ID.
const runPrefix = "nodkey-e2e-"

// How long until the objects of an ended run count as left behind.
const (
	// staleDead is for a run whose lock file is there and not locked. A
	// run locks its file right after it makes it, at its start.
	staleDead = 10 * time.Second
	// staleUnknown is for a run whose lock file this run cannot see: one
	// with another TMPDIR, another host that uses the same Docker, or one
	// from before a restart. A run takes seconds, and go test ends it
	// after 10 minutes by default.
	staleUnknown = time.Hour
)

// lockPath returns the lock file of the run id. It is in the system's
// temporary directory, so that the runs of every user see it.
func lockPath(id string) string {
	return filepath.Join(os.TempDir(), runPrefix+id+".lock")
}

// takeRunLock makes the lock file of this run and locks it. The lock holds
// until the process ends, also when it is killed. The file is empty, and
// others may read it, so that their runs can test the lock too.
func takeRunLock() (*os.File, error) {
	path := lockPath(runID)
	//nolint:gosec // G302, G304: an empty lock file, readable by others on purpose.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, err
	}
	// The umask may have taken the read bit of others: set it again.
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return f, nil
}

// releaseRunLock removes the lock file of this run, and unlocks it.
func releaseRunLock(f *os.File) {
	_ = os.Remove(f.Name())
	_ = f.Close()
}

// runState is what a run can learn about another run from its lock file.
type runState int

const (
	runLive    runState = iota // its lock is held: it runs
	runDead                    // its lock file is there, and nobody holds the lock
	runUnknown                 // its lock file is not there, not a regular file, or cannot be read
)

// stateOf returns the state of the run id.
func stateOf(id string) runState {
	return stateAt(lockPath(id))
}

// stateAt returns the state of the run whose lock file is path. Any local
// user can make a file in the shared temporary directory, with the name
// of a lock file. So stateAt never waits in open (a FIFO would wait for a
// writer, for ever), follows no link, and takes only a regular file:
// anything else is runUnknown.
func stateAt(path string) runState {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a lock file of a run of this test, which it only locks.
	if err != nil {
		return runUnknown
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return runUnknown
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	switch {
	case errors.Is(err, syscall.EWOULDBLOCK):
		return runLive
	case err != nil:
		return runUnknown
	}
	return runDead // the lock ends when f closes
}

// isStale reports whether id is the run ID of another run that has ended:
// its lock file is not locked, or, when this run cannot see its lock file,
// it started long ago. Anything else is not a run ID of this test, and is
// never stale.
func isStale(id string) bool {
	m := runIDPattern.FindStringSubmatch(id)
	if m == nil || id == runID {
		return false
	}
	secs, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return false
	}
	age := time.Since(time.Unix(secs, 0))
	switch stateOf(id) {
	case runDead:
		return age > staleDead
	case runUnknown:
		return age > staleUnknown
	}
	return false
}

// bases are the directories that may hold the private directory of a run
// (runDirectory): $XDG_RUNTIME_DIR, and the user's cache directory.
func bases() []string {
	var out []string
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		out = append(out, d)
	}
	if d, err := os.UserCacheDir(); err == nil {
		out = append(out, d)
	}
	return out
}

// removeStale removes what earlier runs of this test left, when they have
// ended (isStale): their containers, networks and images, their private
// directories, and their lock files. It never touches an object or a file
// without a run ID in its name or its label. It logs what it removes.
func removeStale(t *testing.T) {
	t.Helper()
	for _, kind := range []struct {
		what string
		list []string // a docker command that prints "ID RUNID" lines
		rm   []string // the docker command that removes one of them
	}{
		{"container", []string{"ps", "--all", "--filter", "label=nodkey-e2e", "--format", `{{.ID}} {{.Label "nodkey-e2e"}}`}, nil},
		{"network", []string{"network", "ls", "--filter", "label=nodkey-e2e", "--format", `{{.ID}} {{.Label "nodkey-e2e"}}`},
			[]string{"network", "rm"}},
		{"image", []string{"image", "ls", "nodkey-e2e-sshd", "--format", `nodkey-e2e-sshd:{{.Tag}} {{.Tag}}`},
			[]string{"image", "rm"}},
	} {
		stdout, stderr, err := runDocker(dockerLimit, kind.list...)
		if err != nil {
			t.Logf("cannot list the %ss of earlier runs: %v: %s", kind.what, err, strings.TrimSpace(stderr))
			continue
		}
		for line := range strings.Lines(stdout) {
			name, id, _ := strings.Cut(strings.TrimSpace(line), " ")
			if !isStale(id) {
				continue
			}
			var rmErr error
			if kind.rm == nil {
				rmErr = removeContainer(name)
			} else if _, stderr, err := runDocker(dockerLimit, append(kind.rm, name)...); err != nil {
				rmErr = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr))
			}
			if rmErr != nil {
				t.Logf("cannot remove the %s %s of the ended run %s: %v", kind.what, name, id, rmErr)
				continue
			}
			t.Logf("removed the %s %s of the ended run %s", kind.what, name, id)
		}
	}
	for _, base := range bases() {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, en := range entries {
			if id, ok := strings.CutPrefix(en.Name(), runPrefix); ok && en.IsDir() && isStale(id) {
				dir := filepath.Join(base, en.Name())
				if err := os.RemoveAll(dir); err != nil {
					t.Logf("cannot remove the private directory %s of the ended run %s: %v", dir, id, err)
					continue
				}
				t.Logf("removed the private directory %s of the ended run %s", dir, id)
			}
		}
	}
	// The lock files last: the checks above read them.
	if entries, err := os.ReadDir(os.TempDir()); err == nil {
		for _, en := range entries {
			name := en.Name()
			if id, ok := strings.CutPrefix(strings.TrimSuffix(name, ".lock"), runPrefix); ok &&
				strings.HasSuffix(name, ".lock") && isStale(id) {
				// The lock file of another user stays: the directory has its sticky bit.
				_ = os.Remove(filepath.Join(os.TempDir(), name))
			}
		}
	}
}

// run holds the private directory of this run, made once.
var run struct {
	once   sync.Once
	dir    string // the private directory, base/nodkey-e2e-<runID>
	nodkey string // the nodkey binary in it
	err    string
}

// runDirectory returns the private directory of this run, and the nodkey
// binary in it. It holds every file of the test, also the throwaway keys,
// and TestMain removes it at the end.
//
// Every directory on the way to it passes the file checks of nodkey
// (DESIGN.md section 14): the system temporary directory fails them, so it
// is in one of bases, as in the tests of nodkey broker. nodkey keygen
// checks the directories on the way and its new file as the broker checks
// a key file, so a key that it makes there is the probe. A program there
// must run too: the fake store.
func runDirectory(t *testing.T) (dir, nodkey string) {
	t.Helper()
	run.once.Do(func() {
		var tried []string
		for _, base := range bases() {
			d := filepath.Join(base, runPrefix+runID)
			if err := os.Mkdir(d, 0o700); err != nil {
				tried = append(tried, fmt.Sprintf("%s: %v", base, err))
				continue
			}
			bin := filepath.Join(d, "nodkey")
			if err := buildNodkey(bin); err != nil {
				_ = os.RemoveAll(d)
				run.err = err.Error()
				return
			}
			if err := probeDir(d, bin); err != nil {
				_ = os.RemoveAll(d)
				tried = append(tried, fmt.Sprintf("%s: %v", base, err))
				continue
			}
			run.dir, run.nodkey = d, bin
			return
		}
		run.err = fmt.Sprintf("no directory passes the file checks of nodkey: tried %q", tried)
	})
	if run.err != "" {
		t.Fatal(run.err)
	}
	return run.dir, run.nodkey
}

// probeDir reports whether dir passes the checks of a key file, and
// whether a program there can run.
func probeDir(dir, bin string) error {
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory, private to its owner.
		return err
	}
	probe := filepath.Join(dir, "probe.key")
	keygen := exec.CommandContext(context.Background(), bin, "keygen", "--out", probe) //nolint:gosec // G204: the nodkey binary of the test.
	keygen.Env = append([]string{"PATH=" + clientPath}, quickExit()...)
	out, err := keygen.CombinedOutput()
	_ = os.Remove(probe)
	if err != nil {
		return fmt.Errorf("nodkey keygen: %w: %s", err, strings.TrimSpace(string(out)))
	}
	script := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: a program of the test.
		return err
	}
	defer func() { _ = os.Remove(script) }()
	if err := exec.CommandContext(context.Background(), script).Run(); err != nil { //nolint:gosec // G204: a program that the test wrote.
		return fmt.Errorf("a program there cannot run: %w", err)
	}
	return nil
}

// subdirectory makes a new directory with the prefix name in the private
// directory of this run, for one test, and removes it when the test ends.
func subdirectory(t *testing.T, name string) string {
	t.Helper()
	parent, _ := runDirectory(t)
	dir, err := os.MkdirTemp(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestLockState: a run learns the state of another run from its lock file
// at once, and takes only a regular file. A FIFO, a link or a directory
// with the name of a lock file, which any local user can make in the
// shared temporary directory, is runUnknown: removeStale never waits on it.
func TestLockState(t *testing.T) {
	dir := t.TempDir()
	free := filepath.Join(dir, "free.lock")
	writeFile(t, free, nil)
	held := filepath.Join(dir, "held.lock")
	writeFile(t, held, nil)
	lock, err := os.Open(held) //nolint:gosec // G304: a file of the test.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.lock")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.lock")
	if err := os.Symlink(free, link); err != nil {
		t.Fatal(err)
	}
	// The case that the review found: a FIFO with the name of the lock file
	// of an old run, in the shared temporary directory. That run counts as
	// one whose lock file cannot be checked, so it is stale after an hour.
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	old := "1700000000-" + hex.EncodeToString(b)
	if err := syscall.Mkfifo(lockPath(old), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(lockPath(old)) })

	for _, tt := range []struct {
		name string
		got  func() bool
	}{
		{"a regular file that nobody locks", func() bool { return stateAt(free) == runDead }},
		{"a regular file that a run locks", func() bool { return stateAt(held) == runLive }},
		{"a FIFO", func() bool { return stateAt(fifo) == runUnknown }},
		{"a link to a regular file", func() bool { return stateAt(link) == runUnknown }},
		{"a directory", func() bool { return stateAt(dir) == runUnknown }},
		{"no file", func() bool { return stateAt(filepath.Join(dir, "missing.lock")) == runUnknown }},
		{"a FIFO as the lock file of an old run", func() bool { return isStale(old) }},
	} {
		done := make(chan bool, 1)
		go func() { done <- tt.got() }()
		select {
		case ok := <-done:
			if !ok {
				t.Errorf("%s: the wrong state", tt.name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the check waits", tt.name)
		}
	}
}
