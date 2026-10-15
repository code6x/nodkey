package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
)

// runChild names a child process of TestRunNeverIgnoresSIGPIPE.
const runChild = "NODKEY_TEST_RUN_SIGPIPE"

// TestRunNeverIgnoresSIGPIPE runs nodkey run in a child process, as the
// main function does, and checks that SIGPIPE is not ignored afterwards.
// An ignored signal stays ignored after execve, so the command would run
// with SIGPIPE ignored (keygen ignores it, for its own reason).
func TestRunNeverIgnoresSIGPIPE(t *testing.T) {
	if os.Getenv(runChild) != "" {
		// The child: a command that is not there, so nodkey run stops
		// before it reads a config. 10 means SIGPIPE is ignored now.
		code := run([]string{"run", "--secret", "GH_TOKEN=github-token", "--", "nodkey-test-no-such-command"},
			os.Stdin, os.Stdout, os.Stderr)
		if signal.Ignored(syscall.SIGPIPE) {
			os.Exit(10)
		}
		os.Exit(code)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRunNeverIgnoresSIGPIPE$") //nolint:gosec // G204: the test runs its own binary again.
	cmd.Env = append(os.Environ(), runChild+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 {
		t.Fatalf("nodkey run: %v (10 means SIGPIPE is ignored); stderr %q; want exit code 127", err, stderr.String())
	}
	if !strings.HasSuffix(stderr.String(), "not found (exit 127)\n") {
		t.Errorf("stderr = %q", stderr.String())
	}
}
