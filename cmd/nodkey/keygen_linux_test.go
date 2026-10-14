package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

// keygenChildDir names the directory of a child process of
// TestKeygenWithABrokenPipe.
const keygenChildDir = "NODKEY_TEST_KEYGEN_DIR"

// TestKeygenWithABrokenPipe runs keygen in a child process whose stdout is
// a pipe that nobody reads, as in "nodkey keygen --out FILE | true". The
// pin cannot be printed, so keygen must remove the key file and exit with
// 1. Without ignoreBrokenPipe, Go stops the child with SIGPIPE first, and
// the key file stays.
func TestKeygenWithABrokenPipe(t *testing.T) {
	if dir := os.Getenv(keygenChildDir); dir != "" {
		// The child: a key file in its own directory, then the pin to the
		// broken pipe.
		writeKeyFile = func(path string) (config.Pin, error) {
			return madeUpPin, os.WriteFile(path, []byte("made-up key\n"), 0o600)
		}
		os.Exit(run([]string{"keygen", "--out", filepath.Join(dir, "client.key")}, os.Stdin, os.Stdout, os.Stderr))
	}
	dir := t.TempDir()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil { // nobody reads
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestKeygenWithABrokenPipe$") //nolint:gosec // G204: the test runs its own binary again.
	cmd.Env = append(os.Environ(), keygenChildDir+"="+dir)
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	_ = w.Close()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != exitFailure {
		t.Fatalf("keygen with a broken stdout: %v (exit code -1 means a signal); want exit code %d; stderr %q",
			err, exitFailure, stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(dir, "client.key")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the key file is still there: %v", err)
	}
	if !strings.Contains(stderr.String(), "cannot print the pin, so the new key file was removed (exit 1)") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
