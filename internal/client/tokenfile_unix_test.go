//go:build unix

package client

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestNoFollowFIFO: the open of the token file does not wait on a named
// pipe that was put in place of the file.
func TestNoFollowFIFO(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("no named pipe here: %v", err)
	}
	f, err := os.OpenFile(p, os.O_RDONLY|noFollow, 0) //nolint:gosec // G304: the test's own pipe.
	if err != nil {
		t.Fatalf("the open: %v", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTokenFileInfo(p, fi); err == nil {
		t.Error("a named pipe passed the check")
	}
}
