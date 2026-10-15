package client

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// uid returns the user ID of the test.
func uid(t *testing.T) uint32 {
	t.Helper()
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	return self
}

// TestListenAgentModes: the agent makes the socket's directory with mode
// 0700 and the socket with mode 0600, whatever the umask. The socket
// works, and close removes it.
func TestListenAgentModes(t *testing.T) { // not parallel: it changes the umask
	for _, mask := range []int{0, 0o022, 0o777} {
		dir := filepath.Join(shortTempDir(t), "nodkey")
		path := filepath.Join(dir, socketName)
		self := uid(t)
		old := syscall.Umask(mask)
		sock, err := listenAgent(t.Context(), path, self, noDirCheck)
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %04o: %v", mask, err)
		}
		mustMode(t, dir, fs.ModeDir, 0o700)
		mustMode(t, path, fs.ModeSocket, 0o600)
		c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
		if err != nil {
			t.Fatalf("umask %04o: the socket does not take a connection: %v", mask, err)
		}
		_ = c.Close()
		sock.close()
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("umask %04o: the socket is still there after close: %v", mask, err)
		}
		mustMode(t, dir, fs.ModeDir, 0o700) // the directory stays
	}
}

// TestListenAgentRefusesTheDirectory: a directory that is there must be a
// real directory of the user with mode 0700. nodkey does not change it.
func TestListenAgentRefusesTheDirectory(t *testing.T) {
	t.Parallel()
	base := shortTempDir(t)
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil { //nolint:gosec // G302: the test needs a directory that others can read.
		t.Fatal(err)
	}
	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		dir  string
		want string
	}{
		{open, "has mode 0755; the directory of the socket must have mode 0700"},
		{link, "is a symbolic link"},
		{file, "is not a directory"},
		{filepath.Join(base, "missing", "nodkey"), "no such file or directory"},
	}
	for _, tt := range tests {
		_, err := listenAgent(t.Context(), filepath.Join(tt.dir, socketName), uid(t), noDirCheck)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v; want %q", tt.dir, err, tt.want)
		}
	}
	mustMode(t, open, fs.ModeDir, 0o755)
	if _, err := os.Lstat(filepath.Join(private, socketName)); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a socket was made through the link")
	}
	// Another user would own the directory: the user ID differs.
	if _, err := listenAgent(t.Context(), filepath.Join(private, socketName), uid(t)+1, noDirCheck); err == nil ||
		!strings.Contains(err.Error(), "must be owned by the user") {
		t.Errorf("a directory of another user: %v", err)
	}
}

// TestListenAgentStaleSocket: a socket that no program serves is left
// from an agent that ended without removing it; the new agent removes
// it. A socket that a program serves, and anything that is not a socket,
// stay, and the agent does not start.
func TestListenAgentStaleSocket(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(shortTempDir(t), "nodkey")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, socketName)
	listen := func() *net.UnixListener {
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
		if err != nil {
			t.Fatal(err)
		}
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			t.Fatal("not a Unix listener")
		}
		ul.SetUnlinkOnClose(false)
		return ul
	}

	// A program serves the socket.
	live := listen()
	if _, err := listenAgent(t.Context(), path, uid(t), noDirCheck); err == nil ||
		!strings.Contains(err.Error(), "another program serves this socket") {
		t.Errorf("a socket that a program serves: %v", err)
	}
	c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatalf("the socket of the other program was removed: %v", err)
	}
	_ = c.Close()

	// The program ended without removing it. A child that another test
	// forks at this moment holds the socket until it runs its program, so
	// wait until the socket refuses connections.
	_ = live.Close()
	waitFor(t, "the socket to refuse connections", func() bool {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
		if err == nil {
			_ = c.Close()
		}
		return errors.Is(err, syscall.ECONNREFUSED)
	})
	sock, err := listenAgain(t, path)
	if err != nil {
		t.Fatalf("a stale socket: %v", err)
	}
	sock.close()

	// Anything else stays.
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenAgain(t, path); err == nil ||
		!strings.Contains(err.Error(), "is there, and it is not a socket") {
		t.Errorf("a file at the socket's path: %v", err)
	}
	mustMode(t, path, 0, 0o600)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := listenAgain(t, path); err == nil ||
		!strings.Contains(err.Error(), "is there, and it is not a socket") {
		t.Errorf("a symbolic link at the socket's path: %v", err)
	}
	mustMode(t, path, fs.ModeSymlink, 0o777)
}

// listenAgain is listenAgent on a path whose lock the test held before.
// A child that another test forks keeps a copy of each open file until it
// runs its program, and with it the lock: so listenAgain tries again for a
// while when the lock is still held.
func listenAgain(t *testing.T, path string) (*agentSocket, error) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		s, err := listenAgent(t.Context(), path, uid(t), noDirCheck)
		if err == nil || !strings.Contains(err.Error(), "another nodkey ssh-agent uses this socket") ||
			time.Now().After(deadline) {
			return s, err
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAgentSocketCloseKeepsAnotherSocket: close removes the socket only
// while it is the one that the agent made. A socket that another program
// put at the path later stays.
func TestAgentSocketCloseKeepsAnotherSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(shortTempDir(t), "nodkey", socketName)
	sock, err := listenAgent(t.Context(), path, uid(t), noDirCheck)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	sock.close()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the other socket was removed: %v", err)
	}
}

// TestListenAgentLock: an agent holds the lock of its socket while it
// runs. A second agent on the same path stops at once, with a clear
// error, and leaves the first one's socket. Of two agents that start at
// the same time, one gets the socket. The lock file stays, with mode
// 0600, and the next agent can use it.
func TestListenAgentLock(t *testing.T) {
	t.Parallel()
	path := filepath.Join(shortTempDir(t), "nodkey", socketName)
	first, err := listenAgent(t.Context(), path, uid(t), noDirCheck)
	if err != nil {
		t.Fatal(err)
	}
	_, err = listenAgent(t.Context(), path, uid(t), noDirCheck)
	if want := path + ": another nodkey ssh-agent uses this socket; stop it, or give another --socket"; err == nil ||
		err.Error() != want {
		t.Errorf("a second agent: %v; want %q", err, want)
	}
	c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatalf("the second agent removed the socket of the first: %v", err)
	}
	_ = c.Close()
	first.close()
	mustMode(t, path+".lock", 0, 0o600)
	again, err := listenAgain(t, path)
	if err != nil {
		t.Fatalf("an agent after the first one ended: %v", err)
	}
	again.close()

	// Two agents at the same time, many times: each time one of them
	// gets the socket, and it works.
	for range 20 {
		path := filepath.Join(shortTempDir(t), "nodkey", socketName)
		results := make(chan *agentSocket, 2)
		for range 2 {
			go func() {
				s, err := listenAgent(t.Context(), path, uid(t), noDirCheck)
				if err != nil && !strings.Contains(err.Error(), "another nodkey ssh-agent uses this socket") {
					t.Errorf("an agent that lost the race: %v", err)
				}
				results <- s
			}()
		}
		var won []*agentSocket
		for range 2 {
			if s := <-results; s != nil {
				won = append(won, s)
			}
		}
		if len(won) != 1 {
			t.Fatalf("%d agents got the socket; want 1", len(won))
		}
		c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
		if err != nil {
			t.Fatalf("the socket of the agent that won does not work: %v", err)
		}
		_ = c.Close()
		won[0].close()
	}
}

// TestLockSocketRefuses: the lock file must be a regular file of the
// user, not a symbolic link or a FIFO; nodkey does not wait on a FIFO.
func TestLockSocketRefuses(t *testing.T) {
	t.Parallel()
	dir := shortTempDir(t)
	link := filepath.Join(dir, "link.sock")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), link+".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err := lockSocket(link, uid(t)); err == nil {
		t.Error("lockSocket took a symbolic link")
	}
	if _, err := os.Lstat(filepath.Join(dir, "elsewhere")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("lockSocket made the target of the link")
	}
	fifo := filepath.Join(dir, "fifo.sock")
	if err := syscall.Mkfifo(fifo+".lock", 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := lockSocket(fifo, uid(t)); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Errorf("a FIFO: %v", err)
	}
	if _, err := lockSocket(filepath.Join(dir, "other.sock"), uid(t)+1); err == nil {
		t.Error("lockSocket took a lock file of another user")
	}
}

// agentCheckedDir returns a new directory with a short path that passes
// config.CheckParentDirs, such as one in $XDG_RUNTIME_DIR or in the home
// directory. The system temporary directory does not pass: everyone can
// write to it. The test is skipped when there is no such directory.
func agentCheckedDir(t *testing.T) string {
	t.Helper()
	for _, base := range []string{os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("HOME")} {
		if base == "" || !filepath.IsAbs(base) || len(base) > 40 {
			continue
		}
		if err := config.CheckParentDirs(filepath.Join(base, "x")); err != nil {
			continue
		}
		dir, err := os.MkdirTemp(base, "nodkey-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })  //nolint:gosec // G703: dir is the new directory that MkdirTemp made.
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the execute bit.
			t.Fatal(err)
		}
		return dir
	}
	t.Skip("no short directory that passes config.CheckParentDirs")
	return ""
}

// TestListenAgentChecksTheDirectories: with config.CheckParentDirs, the
// directories on the way to the socket must be owned by the user or
// root, and others must not be able to write to them. So the system
// temporary directory is refused, and so is a directory on the way that
// others can write to.
func TestListenAgentChecksTheDirectories(t *testing.T) {
	t.Parallel()
	base := agentCheckedDir(t)
	sock, err := listenAgent(t.Context(), filepath.Join(base, "nodkey", socketName), uid(t), config.CheckParentDirs)
	if err != nil {
		t.Fatalf("a directory that passes the checks: %v", err)
	}
	sock.close()
	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil { //nolint:gosec // G302: the test needs a directory that others can write to.
		t.Fatal(err)
	}
	paths := []string{filepath.Join(shared, "nodkey", socketName)}
	if fi, err := os.Stat(os.TempDir()); err == nil && fi.Mode().Perm()&0o002 != 0 {
		paths = append(paths, filepath.Join(shortTempDir(t), "nodkey", socketName))
	}
	for _, path := range paths {
		_, err := listenAgent(t.Context(), path, uid(t), config.CheckParentDirs)
		if err == nil || !strings.Contains(err.Error(), "group or others can write to this directory") {
			t.Errorf("%s: %v", path, err)
		}
		if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: the directory of the socket was made", path)
		}
	}
}

// TestCheckSocketPath: the socket path is absolute, clean, not in /, and
// short enough for a Unix socket.
func TestCheckSocketPath(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		path string
		ok   bool
	}{
		{"/run/user/1000/nodkey/agent.sock", true},
		{"/" + strings.Repeat("a", maxSocketPath-3) + "/s", true},
		{"/" + strings.Repeat("a", maxSocketPath-2) + "/s", false},
		{"agent.sock", false},
		{"./agent.sock", false},
		{"/run/user/1000/../1001/agent.sock", false},
		{"/run/user/1000//agent.sock", false},
		{"/run/user/1000/nodkey/", false},
		{"/agent.sock", false},
		{"/run/a\x00b/agent.sock", false},
	} {
		if err := checkSocketPath(tt.path); (err == nil) != tt.ok {
			t.Errorf("%q: %v", tt.path, err)
		}
	}
}

// TestDefaultSocket: the default socket is $XDG_RUNTIME_DIR/nodkey/agent.sock
// (DESIGN.md section 6). Without XDG_RUNTIME_DIR, the user must give
// --socket.
func TestDefaultSocket(t *testing.T) {
	t.Parallel()
	env := func(v string) func(string) string {
		return func(name string) string {
			if name == "XDG_RUNTIME_DIR" {
				return v
			}
			return ""
		}
	}
	if got, err := defaultSocket(env("/run/user/1000")); err != nil || got != "/run/user/1000/nodkey/agent.sock" {
		t.Errorf("defaultSocket = %q, %v", got, err)
	}
	for _, v := range []string{"", "run/user/1000"} {
		if _, err := defaultSocket(env(v)); err == nil || !strings.Contains(err.Error(), "--socket") {
			t.Errorf("XDG_RUNTIME_DIR=%q: %v", v, err)
		}
	}
}
