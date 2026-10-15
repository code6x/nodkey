//go:build e2e

package e2e

import (
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"
)

// wrapperArg is the first argument of the test binary when it runs as the
// wrapper of a client program (wrapper).
const wrapperArg = "nodkey-e2e-wrapper"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == wrapperArg {
		os.Exit(wrapper(os.Args[2:]))
	}
	stderr := os.Stderr //nolint:forbidigo // TestMain reports on stderr, as the testing package does.
	// The lock tells later runs that this run has not ended (removeStale).
	// Without it, they wait an hour before they remove what it left.
	lock, err := takeRunLock()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "e2e: cannot make the lock file of this run:", err)
	}
	code := m.Run()
	// The cleanups of the tests removed their containers and networks.
	// Remove the image and the private directory, and check that nothing
	// of this run is left.
	if err := removeImage(); err != nil {
		_, _ = fmt.Fprintln(stderr, "e2e:", err)
		code = 1
	}
	if image.built {
		left, err := leftovers()
		switch {
		case err != nil:
			_, _ = fmt.Fprintln(stderr, "e2e: cannot list what the test left in Docker:", err)
			code = 1
		case len(left) > 0:
			_, _ = fmt.Fprintf(stderr, "e2e: the test left these in Docker: %q\n", left)
			code = 1
		}
	}
	if run.dir != "" {
		if err := os.RemoveAll(run.dir); err != nil {
			_, _ = fmt.Fprintln(stderr, "e2e: cannot remove the private directory of the test:", err)
			code = 1
		}
	}
	if lock != nil {
		releaseRunLock(lock)
	}
	os.Exit(code)
}

// wrapper runs the command after "--" as its child, with the same stdin,
// stdout and stderr, and returns its exit code. The arguments before "--"
// do nothing: they are there to be seen in /proc/PID/cmdline of a parent
// of ssh, where nodkey ssh-agent reads them as claimed text. The test puts
// the second canary there.
func wrapper(args []string) int {
	i := slices.Index(args, "--")
	if i < 0 || i == len(args)-1 {
		return 2
	}
	cmd := exec.CommandContext(context.Background(), args[i+1], args[i+2:]...) //nolint:gosec // G204: the wrapper runs the command of the test.
	//nolint:forbidigo // the wrapper passes its own stdin, stdout and stderr to the command.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// When the wrapper dies, so does the command: ssh or git.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		return exit.ExitCode()
	}
	return 127
}

// goTool returns the go command of the Go version that built this test,
// so that nodkey is built with the same version: such as when the test
// runs with another Go than the one first in PATH.
func goTool() string {
	//nolint:staticcheck // SA1019: the root of the toolchain that built this test binary is what is wanted here.
	if root := runtime.GOROOT(); root != "" {
		if p := filepath.Join(root, "bin", "go"); fileExists(p) {
			return p
		}
	}
	return "go"
}

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// goBuildLimit bounds a build of the go command, also without a cache.
const goBuildLimit = 10 * time.Minute

// goBuild runs the go command with args in the module root, with env added
// to the environment of the test.
func goBuild(env []string, args ...string) error {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("no go.mod two levels up from the test: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), goBuildLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool(), args...) //nolint:gosec // G204: the test builds nodkey with its own arguments.
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go %q: %w\n%s", args, err, out)
	}
	return nil
}

// buildNodkey builds the nodkey binary from this repository as bin. When
// the test runs with the race detector, so does nodkey: the broker and the
// clients then report data races too.
func buildNodkey(bin string) error {
	args := []string{"build", "-o", bin}
	if raceEnabled {
		args = append(args, "-race")
	}
	if err := goBuild(nil, append(args, "./cmd/nodkey")...); err != nil {
		return err
	}
	info, err := buildinfo.ReadFile(bin)
	if err != nil {
		return err
	}
	if info.GoVersion != runtime.Version() {
		return fmt.Errorf("nodkey was built with %s, the test with %s", info.GoVersion, runtime.Version())
	}
	return nil
}

// buildClientTest builds the test binary of internal/client into dir, for
// the root-only test in a container, and returns its path. It is static
// (no cgo), so it runs in the container whatever C library the host has.
func buildClientTest(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "client.test")
	if err := goBuild([]string{"CGO_ENABLED=0"}, "test", "-c", "-o", bin, "./internal/client"); err != nil {
		t.Fatal(err)
	}
	return bin
}
