package audit

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// supported says that Open works on this system.
const supported = true

// writeFlags open the log for appending. O_NOFOLLOW refuses a symbolic
// link, and O_NONBLOCK makes the open fail on a FIFO, instead of waiting
// for a reader. On a regular file, O_NONBLOCK changes nothing.
const writeFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK

// readFlags open the log again, read only, to read its end.
const readFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK

// fileOwner returns the user ID that owns the file.
func fileOwner(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// clearNonblock turns O_NONBLOCK off again, once f is known to be a
// regular file, so a write never fails with EAGAIN.
func clearNonblock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) { setErr = syscall.SetNonblock(int(fd), false) }); err != nil {
		return err
	}
	return setErr
}

// lockFile takes an exclusive flock on f, without waiting. The lock
// belongs to the open file, so it holds until f is closed, and a second
// broker cannot take it.
func lockFile(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := rc.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		return err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		return errors.New("another process has it open for writing, such as a second broker; " +
			"only one broker may write to one audit log")
	}
	return lockErr
}
