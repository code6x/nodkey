package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// runMasked runs the command for nodkey run --mask, and returns the exit
// code of nodkey run. The command is a child of nodkey, not a replacement:
// its stdout and stderr go through a maskWriter each, to nodkey's stdout
// and stderr (DESIGN.md section 5). When the command dies of a signal,
// nodkey ends itself with the same signal, so that a shell sees it.
func runMasked(path string, argv, envv []string, values [][]byte, stderr io.Writer) int {
	code, sig, err := maskedCommand(path, argv, envv, values, os.Stdout, stderr) //nolint:forbidigo // the command's own stdout.
	if err != nil {
		return fail(stderr, exitCannotRun, err.Error())
	}
	if sig != 0 {
		raise(sig)
	}
	return code
}

// maskedCommand starts the command with stdin as nodkey's, and its stdout
// and stderr masked to stdout and stderr. It waits until the command ended
// and its output is all written. It returns the exit code of the command,
// with the signal that ended it (and 128 and its number as the code), or
// an error when the command could not start.
//
// While the command runs, nodkey passes on SIGTERM and SIGHUP to it. It
// catches SIGINT and SIGQUIT and does nothing with them: a terminal sends
// them to the command too, as the command is in the same process group.
// A signal that nodkey ignores stays ignored, also in the command.
func maskedCommand(path string, argv, envv []string, values [][]byte, stdout, stderr io.Writer) (int, syscall.Signal, error) {
	outMask := newMaskWriter(stdout, values)
	errMask := newMaskWriter(stderr, values)
	defer outMask.clear()
	defer errMask.clear()
	cmd := &exec.Cmd{
		Path:   path,
		Args:   argv,
		Env:    envv,
		Stdin:  os.Stdin, // the command reads nodkey's stdin, as after execve
		Stdout: outMask,
		Stderr: errMask,
	}
	sigs := make(chan os.Signal, 4)
	var caught []os.Signal
	for _, s := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP, os.Interrupt, syscall.SIGQUIT} {
		if !signal.Ignored(s) {
			caught = append(caught, s)
		}
	}
	signal.Notify(sigs, caught...)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 0, 0, fmt.Errorf("cannot run %q: %w", path, err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	// Write what is held back. A write that fails cannot be reported to
	// anyone: the command's own exit code stays.
	_ = outMask.Close()
	_ = errMask.Close()
	st := cmd.ProcessState
	if st == nil {
		return 0, 0, fmt.Errorf("cannot run %q: %w", path, err)
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), ws.Signal(), nil
	}
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) && st.ExitCode() == 0 {
		// The command exited with 0, and its output could not be written
		// (such as a closed stdout): not a success.
		return 1, 0, nil
	}
	return st.ExitCode(), 0, nil
}
