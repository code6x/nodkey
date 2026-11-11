package client

import (
	"syscall"
	"unsafe"
)

// isTerminal reports whether fd is a terminal: the TCGETS ioctl, as
// isatty does, works only on a terminal.
func isTerminal(fd uintptr) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t))) //nolint:gosec // G103: the ioctl needs the address.
	return errno == 0
}
