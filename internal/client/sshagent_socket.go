package client

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The socket of nodkey ssh-agent (DESIGN.md section 15). It is in a
// directory with mode 0700, owned by the user that runs the agent, such
// as $XDG_RUNTIME_DIR/nodkey; nodkey makes the directory when it is
// missing. The socket has mode 0600. Every directory on the way passes
// config.CheckParentDirs, so no other user can swap the directory or the
// socket. The directory keeps other users away from the socket, and the
// agent checks the user of each connection too (SO_PEERCRED). While the
// agent runs, it holds a lock on the file PATH.lock next to the socket,
// so a second agent on the same path stops at once.

// socketDirName is the directory of the default socket, in
// $XDG_RUNTIME_DIR.
const socketDirName = "nodkey"

// socketName is the name of the default socket.
const socketName = "agent.sock"

// maxSocketPath is the longest path of a Unix socket: the kernel's
// sun_path holds 108 bytes, with a NUL byte at the end.
const maxSocketPath = 107

// staleCheckTimeout bounds the connection to a socket that is already
// there, to learn whether a program serves it.
const staleCheckTimeout = 2 * time.Second

// defaultSocket returns the default socket: $XDG_RUNTIME_DIR/nodkey/agent.sock.
// systemd makes XDG_RUNTIME_DIR for each user who logs in, with mode 0700.
func defaultSocket(getenv func(string) string) (string, error) {
	dir := getenv("XDG_RUNTIME_DIR")
	if dir == "" || !filepath.IsAbs(dir) {
		return "", errors.New("XDG_RUNTIME_DIR is not set, or not an absolute path; give the socket with --socket PATH")
	}
	return filepath.Join(dir, socketDirName, socketName), nil
}

// checkSocketPath checks the form of the socket's path: absolute, clean
// (no "//", "." or ".." parts, and no "/" at the end), not in "/" itself,
// and short enough for a Unix socket.
func checkSocketPath(path string) error {
	switch {
	case !filepath.IsAbs(path):
		return errors.New("the socket path must be absolute, so that SSH_AUTH_SOCK works in every directory")
	case filepath.Clean(path) != path, strings.ContainsRune(path, 0):
		return errors.New(`the socket path must be clean: no "//", "." or ".." parts, and no "/" at the end`)
	case filepath.Dir(path) == string(filepath.Separator):
		return errors.New("the socket must not be in /: its directory must have mode 0700")
	case len(path) > maxSocketPath:
		return fmt.Errorf("the socket path is longer than %d bytes, the limit of a Unix socket", maxSocketPath)
	}
	return nil
}

// agentSocket is the listening socket of nodkey ssh-agent.
type agentSocket struct {
	path string
	ln   *net.UnixListener
	fi   fs.FileInfo // the socket file that Listen made
	lock *os.File    // PATH.lock, with the lock of the agent
}

// listenAgent makes the socket at path, for the user self. checkDirs is
// config.CheckParentDirs; tests replace it, because the system temporary
// directory does not pass it.
//
//  1. The directories on the way to the socket's directory must pass
//     checkDirs: owned by root or by self, and group and others cannot
//     write to them. So no other user can swap the directory.
//  2. The socket's directory is made with mode 0700 if it is missing. If
//     it is there, it must be a directory, not a symbolic link, owned by
//     self, with mode 0700, such as $XDG_RUNTIME_DIR itself. nodkey never
//     changes a directory that it did not make.
//  3. The agent takes the lock of the socket (lockSocket) and holds it
//     until close. A second agent on the same path stops here, so two
//     agents never remove each other's socket.
//  4. A socket that is already at path is removed only when it is owned
//     by self and no program serves it: it is left from an agent that
//     ended without removing it. Anything else at path is an error, and
//     stays.
//  5. The new socket gets mode 0600, whatever the umask.
func listenAgent(ctx context.Context, path string, self uint32, checkDirs func(string) error) (*agentSocket, error) {
	if err := checkSocketPath(path); err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := checkDirs(dir); err != nil {
		return nil, err // the error names the directory
	}
	if err := makeSocketDir(dir, self); err != nil {
		return nil, err
	}
	if err := checkDirs(path); err != nil {
		return nil, err
	}
	lock, err := lockSocket(path, self)
	if err != nil {
		return nil, err
	}
	if err := removeStale(ctx, path, self); err != nil {
		_ = lock.Close()
		return nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("cannot make the socket: %w", err) // a *net.OpError names the path
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		_ = lock.Close()
		return nil, errors.New("cannot make the socket: it is not a Unix socket")
	}
	// close removes the socket only while it is the one that Listen made.
	ul.SetUnlinkOnClose(false)
	s := &agentSocket{path: path, ln: ul, lock: lock}
	if s.fi, err = os.Lstat(path); err != nil { //nolint:gosec // G703: the socket path of the user; checkSocketPath and checkDirs checked it.
		_ = ul.Close()
		_ = lock.Close()
		return nil, err
	}
	if err := s.setMode(self); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// setMode gives the new socket mode 0600 and checks it. bind(2) makes it
// with the mode that the umask allows.
func (s *agentSocket) setMode(self uint32) error {
	if err := os.Chmod(s.path, 0o600); err != nil {
		return err
	}
	fi, err := os.Lstat(s.path)
	if err != nil {
		return err
	}
	owner, ok := ownerOf(fi)
	if !os.SameFile(fi, s.fi) || fi.Mode().Type() != fs.ModeSocket || !ok || owner != self ||
		fi.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s: the new socket is not a socket of the user with mode 0600", s.path)
	}
	return nil
}

// close stops listening, removes the socket if it is still the one that
// Listen made, and then gives up the lock. So an agent never removes the
// socket of another one.
func (s *agentSocket) close() {
	_ = s.ln.Close()
	// The path of the user; listenAgent checked it. Only the socket that
	// Listen made is removed.
	if fi, err := os.Lstat(s.path); err == nil && os.SameFile(fi, s.fi) { //nolint:gosec // G703: see above.
		_ = os.Remove(s.path) //nolint:gosec // G703: see above.
	}
	_ = s.lock.Close()
}

// lockSocket takes the lock of the socket at path: an flock on the file
// PATH.lock, in the socket's directory. nodkey makes that file with mode
// 0600 if it is missing. If it is there, it must be a regular file of
// self, not a symbolic link. If another process holds the lock, such as a
// second nodkey ssh-agent on the same path, lockSocket fails at once. The
// lock ends when the returned file is closed, also when the agent ends in
// a crash. The file stays: removing it would let two agents lock two
// different files.
func lockSocket(path string, self uint32) (*os.File, error) {
	name := path + ".lock"
	// O_EXCL makes it only when it is missing, so that the mode can be
	// set after the umask. O_NOFOLLOW refuses a symbolic link, and
	// O_NONBLOCK does not wait on a FIFO, which the check below refuses.
	const flags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	f, err := os.OpenFile(name, flags|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: next to the user's socket path, which listenAgent checked.
	switch {
	case err == nil:
		if err := f.Chmod(0o600); err != nil {
			_ = f.Close()
			return nil, err
		}
	case errors.Is(err, fs.ErrExist):
		f, err = os.OpenFile(name, flags, 0) //nolint:gosec // G304: see above.
		if err != nil {
			return nil, fmt.Errorf("cannot open the lock file of the socket: %w", err) // a *fs.PathError names it
		}
	default:
		return nil, fmt.Errorf("cannot make the lock file of the socket: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if owner, ok := ownerOf(fi); !fi.Mode().IsRegular() || !ok || owner != self {
		_ = f.Close()
		return nil, fmt.Errorf("%s: is not a regular file of the user; nodkey does not use it as a lock", name)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: another nodkey ssh-agent uses this socket; stop it, or give another --socket",
				path)
		}
		return nil, fmt.Errorf("cannot lock the socket: %w", err)
	}
	return f, nil
}

// makeSocketDir makes the socket's directory dir with mode 0700, or checks
// the one that is there: a directory, not a symbolic link, owned by self,
// with mode 0700.
func makeSocketDir(dir string, self uint32) error {
	// dir is the directory of the user's socket path: checkSocketPath and
	// checkDirs checked it.
	err := os.Mkdir(dir, 0o700) //nolint:gosec // G703: see above.
	switch {
	case err == nil:
		// The umask may have taken bits away. The directory is new and
		// nodkey's own.
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the execute bit; 0700 gives nothing to group and others.
			return err
		}
	case !errors.Is(err, fs.ErrExist):
		return err // a *fs.PathError names the directory
	}
	fi, err := os.Lstat(dir) //nolint:gosec // G703: see above.
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s: is a symbolic link; the directory of the socket must be a directory with mode 0700", dir)
	case !fi.IsDir():
		return fmt.Errorf("%s: is not a directory", dir)
	}
	owner, ok := ownerOf(fi)
	switch {
	case !ok:
		return fmt.Errorf("%s: cannot check the owner on this system", dir)
	case owner != self:
		return fmt.Errorf("%s: is owned by user ID %d; the directory of the socket must be owned by the user that "+
			"runs nodkey ssh-agent (ID %d)", dir, owner, self)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return fmt.Errorf("%s: has mode %04o; the directory of the socket must have mode 0700, so that no other "+
			"user can reach the socket", dir, perm)
	}
	return nil
}

// removeStale removes a socket at path that no program serves. It must be
// a socket owned by self. If a program serves it, such as another nodkey
// ssh-agent, or anything else is at path, it stays, and the agent does not
// start.
func removeStale(ctx context.Context, path string, self uint32) error {
	fi, err := os.Lstat(path) //nolint:gosec // G703: the user's socket path, which listenAgent checked.
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case fi.Mode().Type() != fs.ModeSocket:
		return fmt.Errorf("%s: is there, and it is not a socket; nodkey does not remove it", path)
	}
	if owner, ok := ownerOf(fi); !ok || owner != self {
		return fmt.Errorf("%s: is a socket of another user; nodkey does not remove it", path)
	}
	dialCtx, cancel := context.WithTimeout(ctx, staleCheckTimeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(dialCtx, "unix", path)
	if err == nil {
		_ = c.Close()
		return fmt.Errorf("%s: another program serves this socket, such as another nodkey ssh-agent; stop it, "+
			"or give another --socket", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%s: cannot check the socket that is there: %w", path, err)
	}
	// Nobody serves it: an agent ended without removing it.
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) { //nolint:gosec // G703: a stale socket of the user, as checked above.
		return err
	}
	return nil
}
