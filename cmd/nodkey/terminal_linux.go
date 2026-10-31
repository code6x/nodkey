package main

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether w is a terminal: an *os.File whose file
// descriptor answers the ioctl TCGETS, as isatty(3) checks. A pipe, a
// file and /dev/null are not, though /dev/null is a character device.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	terminal := false
	if err := rc.Control(func(fd uintptr) {
		var t syscall.Termios
		//nolint:gosec // G103: TCGETS writes a Termios, and the pointer lives only in this call.
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
		terminal = errno == 0
	}); err != nil {
		return false
	}
	return terminal
}

// echoOff turns off the echo of the terminal f, so that what the person
// types is not shown. restore turns it back on. It fails when f is not a
// terminal.
func echoOff(f *os.File) (restore func(), err error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var old syscall.Termios
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		//nolint:gosec // G103: TCGETS writes a Termios, and the pointer lives only in this call.
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&old)))
		if errno != 0 {
			return
		}
		t := old
		t.Lflag &^= syscall.ECHO
		//nolint:gosec // G103: TCSETS reads a Termios, and the pointer lives only in this call.
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&t)))
	}); err != nil {
		return nil, err
	}
	if errno != 0 {
		return nil, errno
	}
	return func() {
		_ = rc.Control(func(fd uintptr) {
			//nolint:gosec // G103: TCSETS reads a Termios, and the pointer lives only in this call.
			_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
		})
	}, nil
}
