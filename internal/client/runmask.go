package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

// runMasked runs the command for nodkey run --mask, and returns the exit
// code of nodkey run. The command is a child of nodkey, not a replacement:
// its stdout and stderr go through a maskWriter each, to nodkey's stdout
// and stderr (DESIGN.md section 5). When the command dies of SIGINT,
// SIGTERM, SIGHUP or SIGKILL, nodkey ends itself with the same signal, so
// that a shell sees it. For another signal, it exits with 128 and its
// number: Go would print a trace for SIGSEGV or SIGQUIT, not die of it.
func runMasked(path string, argv, envv []string, values [][]byte, stderr io.Writer) int {
	code, sig, err := maskedCommand(path, argv, envv, values, os.Stdout, stderr) //nolint:forbidigo // the command's own stdout.
	if err != nil {
		return fail(stderr, exitCannotRun, err.Error())
	}
	switch sig {
	case syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGKILL:
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
// A signal that nodkey ignores stays ignored, also in the command. Once
// the command has ended, these signals end nodkey again, also while a
// process that the command left behind keeps the pipes open.
//
// nodkey catches SIGPIPE too, so a write to a closed stdout or stderr
// fails and does not end nodkey. Then nodkey closes the pipe from the
// command, so the command gets SIGPIPE or EPIPE on its next write.
func maskedCommand(path string, argv, envv []string, values [][]byte, stdout, stderr io.Writer) (int, syscall.Signal, error) {
	sigs := make(chan os.Signal, 4)
	var caught []os.Signal
	for _, s := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP, os.Interrupt, syscall.SIGQUIT} {
		if !signal.Ignored(s) {
			caught = append(caught, s)
		}
	}
	signal.Notify(sigs, caught...)
	stopSignals := sync.OnceFunc(func() { signal.Stop(sigs) })
	defer stopSignals()
	// SIGPIPE stays caught until all of the output is written, also after
	// the command ended.
	pipes := make(chan os.Signal, 1)
	if !signal.Ignored(syscall.SIGPIPE) {
		signal.Notify(pipes, syscall.SIGPIPE)
		defer signal.Stop(pipes)
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		return 0, 0, fmt.Errorf("cannot run %q: cannot make a pipe: %w", path, err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return 0, 0, fmt.Errorf("cannot run %q: cannot make a pipe: %w", path, err)
	}
	cmd := &exec.Cmd{
		Path:   path,
		Args:   argv,
		Env:    envv,
		Stdin:  os.Stdin, // the command reads nodkey's stdin, as after execve
		Stdout: outW,
		Stderr: errW,
	}
	err = cmd.Start()
	// The command has its own copies of the write ends now.
	_ = outW.Close()
	_ = errW.Close()
	if err != nil {
		_ = outR.Close()
		_ = errR.Close()
		return 0, 0, fmt.Errorf("cannot run %q: %w", path, err)
	}
	var wg sync.WaitGroup
	var outErr, errErr error
	wg.Go(func() { outErr = copyMasked(outR, stdout, values) })
	wg.Go(func() { errErr = copyMasked(errR, stderr, values) })

	// late is a SIGTERM or SIGHUP that came when the command had just
	// ended, so it could not be passed on. It then ends nodkey.
	var late syscall.Signal
	exited, forwarded := make(chan struct{}), make(chan struct{})
	pass := func(s os.Signal) {
		if s != syscall.SIGTERM && s != syscall.SIGHUP {
			return
		}
		if err := cmd.Process.Signal(s); err != nil {
			late = s.(syscall.Signal) //nolint:forcetypeassert // SIGTERM and SIGHUP are syscall.Signal.
		}
	}
	go func() {
		defer close(forwarded)
		for {
			select {
			case s := <-sigs:
				pass(s)
			case <-exited:
				return
			}
		}
	}()
	waitErr := cmd.Wait() // the pipes are files: Wait does not wait for the output
	stopSignals()
	close(exited)
	<-forwarded
	for drained := false; !drained; {
		select {
		case s := <-sigs:
			pass(s)
		default:
			drained = true
		}
	}
	wg.Wait()
	if late != 0 {
		return 128 + int(late), late, nil
	}
	st := cmd.ProcessState
	if st == nil {
		return 0, 0, fmt.Errorf("cannot run %q: %w", path, waitErr)
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), ws.Signal(), nil
	}
	if st.ExitCode() == 0 && (outErr != nil || errErr != nil) {
		// The command exited with 0, and its output could not be written
		// (such as a closed stdout): not a success.
		return 1, 0, nil
	}
	var ee *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &ee) {
		return 0, 0, fmt.Errorf("cannot run %q: %w", path, waitErr)
	}
	return st.ExitCode(), 0, nil
}

// copyMasked copies r to w through a maskWriter, until r ends, and closes
// r. When a write to w fails, it closes r at once, so the command gets
// SIGPIPE or EPIPE, and returns the error. It wipes its buffer and the
// held data.
func copyMasked(r *os.File, w io.Writer, values [][]byte) error {
	defer func() { _ = r.Close() }()
	m := newMaskWriter(w, values)
	defer m.clear()
	buf := make([]byte, 32*1024)
	defer clear(buf)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := m.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return m.Close()
		}
		if err != nil {
			_ = m.Close()
			return err
		}
	}
}

// onTerminal reports whether both stdout and stderr of nodkey are
// terminals. Then nodkey run without --mask or --no-mask replaces itself
// with the command, so the command owns the terminal (DESIGN.md section 5).
func onTerminal() bool {
	return isTerminal(1) && isTerminal(2)
}
