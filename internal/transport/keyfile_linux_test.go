package transport

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestGenerateKeyFileMode shows that the key file gets mode 0600 whatever
// the umask. The umask belongs to the whole process, so this test does not
// run in parallel with others.
func TestGenerateKeyFileMode(t *testing.T) {
	dir := t.TempDir()
	for i, mask := range []int{0o000, 0o022, 0o077, 0o277} {
		old := syscall.Umask(mask)
		path := filepath.Join(dir, "key"+string(rune('a'+i)))
		_, err := generateKeyFile(path, noCheck, noCheck)
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %04o: %v", mask, err)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode() != 0o600 {
			t.Errorf("umask %04o: mode %v, want -rw-------", mask, fi.Mode())
		}
	}
}
