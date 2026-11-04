package client

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// peerCredentials returns the user ID and the process ID of the process
// that connected to c, as the kernel recorded them at connect(2)
// (SO_PEERCRED). The process cannot change them. The process ID is 0 when
// the process is in a PID namespace that nodkey cannot see. On Linux 6.5
// and newer it also returns a pidfd of the process; the caller closes it
// (peer.close).
func peerCredentials(c *net.UnixConn) (peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return peer{}, err
	}
	var p peer
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		var cred *syscall.Ucred
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if credErr == nil {
			p = peer{uid: cred.Uid, pid: cred.Pid}
			peerPidfd(int(fd), &p)
		}
	}); err != nil {
		p.close()
		return peer{}, err
	}
	if credErr != nil {
		return peer{}, credErr
	}
	return p, nil
}

// ownerOf returns the user ID that owns the file of fi.
func ownerOf(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// lockFile takes an exclusive lock on f (flock), or fails at once with
// syscall.EWOULDBLOCK when another process holds it. The lock ends when f
// is closed, also when the process ends.
func lockFile(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := raw.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		return err
	}
	return lockErr
}

// The events of poll(2) that say that the other side of a connection is
// gone. POLLRDHUP is Linux's own: the other side closed the connection, or
// its half for writing. poll reports it also when bytes that nobody read
// wait in the socket.
const (
	pollERR   = 0x8
	pollHUP   = 0x10
	pollNVAL  = 0x20
	pollRDHUP = 0x2000
)

// pollFd is struct pollfd of poll(2).
type pollFd struct {
	fd      int32
	events  int16
	revents int16
}

// hungUp reports whether the other side of the connection fd has hung up,
// with poll(2) (as ppoll, which every Linux architecture has), without
// waiting.
func hungUp(fd uintptr) (bool, error) {
	p := pollFd{fd: int32(fd), events: pollRDHUP} //nolint:gosec // G115: a file descriptor fits in an int32.
	var noWait syscall.Timespec
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&p)), 1, //nolint:gosec // G103: struct pollfd for ppoll(2), as the C library passes it.
			uintptr(unsafe.Pointer(&noWait)), 0, 0, 0) //nolint:gosec // G103: struct timespec for ppoll(2).
		switch {
		case errno == 0:
			return p.revents&(pollRDHUP|pollHUP|pollERR|pollNVAL) != 0, nil
		case errors.Is(errno, syscall.EINTR):
			continue
		default:
			return false, errno
		}
	}
}

// waitHangUp waits until the process at the other end of c closes the
// connection, as ssh does when it ends, and reports true then. It returns
// false when the read deadline of c passes first, or when poll fails. It
// reads no data, so bytes that the process sent before it hung up, such
// as its next request, do not end the watch, and stay for
// readAgentMessage.
//
// Go's poller wakes it when the socket can be read: when bytes come, and
// when the other side hangs up. Each time, hungUp asks the kernel whether
// the other side is gone.
func waitHangUp(c *net.UnixConn) bool {
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	gone := false
	err = raw.Read(func(fd uintptr) bool {
		h, err := hungUp(fd)
		if err != nil {
			return true // the watch ends; the request still waits
		}
		gone = h
		return h
	})
	return err == nil && gone
}

// Linux numbers that the syscall package of Go does not have. They are the
// same on amd64 and arm64, the systems that nodkey is released for.
const (
	soPeerPidfd        = 77  // SO_PEERPIDFD, Linux 6.5
	sysPidfdSendSignal = 424 // pidfd_send_signal(2), Linux 5.1
)

// peerPidfd sets the pidfd of the process that connected to fd
// (SO_PEERPIDFD) in p. On a kernel without SO_PEERPIDFD it leaves p as it
// is. Any other error, such as when the process already ended,
// marks p as gone: its claimed context is not sent.
func peerPidfd(fd int, p *peer) {
	pidfd, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, soPeerPidfd)
	switch {
	case errors.Is(err, syscall.ENOPROTOOPT):
	case err != nil || pidfd < 0:
		p.gone = true
	default:
		syscall.CloseOnExec(pidfd)
		p.pidfd = os.NewFile(uintptr(pidfd), "pidfd")
	}
}

// processRuns reports whether the process of pidfd has not ended, with
// signal 0 (pidfd_send_signal), which sends nothing. It reports false on
// any error, also after pidfd was closed.
func processRuns(pidfd *os.File) bool {
	raw, err := pidfd.SyscallConn()
	if err != nil {
		return false
	}
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(sysPidfdSendSignal, fd, 0, 0, 0, 0, 0)
	}); err != nil {
		return false
	}
	return errno == 0
}
