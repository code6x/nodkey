package client

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"unsafe"
)

// TestIsTerminal: a pseudo-terminal is a terminal; a pipe, a file and
// /dev/null are not.
func TestIsTerminal(t *testing.T) {
	t.Parallel()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("no pseudo-terminal: %v", err)
		}
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer func() { _ = ptmx.Close() }()
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 { //nolint:gosec // G103: the ioctl needs the address.
		t.Fatalf("unlockpt: %v", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 { //nolint:gosec // G103: the same.
		t.Fatalf("ptsname: %v", e)
	}
	pts, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pts.Close() }()
	if !isTerminal(pts.Fd()) {
		t.Error("a pseudo-terminal is not a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	f, err := os.Create(t.TempDir() + "/out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	for name, fd := range map[string]uintptr{"a pipe": w.Fd(), "a file": f.Fd(), os.DevNull: null.Fd()} {
		if isTerminal(fd) {
			t.Errorf("%s is a terminal", name)
		}
	}
}
