package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

// Limits of the output of one run of a store program.
const (
	// maxStdout is the most that a program may write to stdout: 1 MiB.
	// The answers are much smaller: a bws secret, or a bw item with its
	// notes, custom fields and password history.
	maxStdout = 1 << 20
	// maxStderr is the most that a program may write to stderr: 64 KiB.
	// stderr is only counted, never read or kept.
	maxStderr = 64 << 10
	// firstBufferSize is the size of the first buffer for stdout. Most
	// answers fit in it.
	firstBufferSize = 4 << 10
)

var (
	// errTimedOut is the cause of a run's context when its time is up.
	errTimedOut = errors.New("store: the time limit passed")
	// errOverflow is the cause of a run's context when the program wrote
	// too much, and the error that output returns then.
	errOverflow = errors.New("store: too much output")
)

// runner runs the program of one store.
type runner struct {
	store     string        // the store's name, for errors
	program   string        // the program's absolute path
	home      string        // the program's private home and working directory
	timeout   time.Duration // the time limit of one run
	waitDelay time.Duration // see deps.waitDelay
}

// run runs the program once with args, and returns what it wrote to
// stdout. The caller must clear the result. env holds the variables that
// the program gets on top of HOME; nothing comes from the broker's own
// environment. step names the run in errors, such as "bw sync".
//
// stdin is /dev/null. The program runs in a process group of its own, so
// that a timeout, too much output or the end of ctx kills the program and
// every process it started in that group. After the run, the group is
// killed too, in case the program left a process behind. If the broker
// ends during the run, the program gets SIGKILL (see setProcessGroup).
//
// Errors give a fixed text, and the exit code or the signal, never the
// output. A run fails when the program exits with a code that is not 0,
// when it takes longer than the time limit, when it writes more than
// maxStdout or maxStderr, when it leaves a process that holds its output
// open, and when ctx ends, even after the program has finished.
func (r *runner) run(ctx context.Context, step string, args, env []string) ([]byte, error) {
	if !supported {
		return nil, fmt.Errorf("store %q: %s: %w: %w", r.store, step, ErrStart, errors.ErrUnsupported)
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	runCtx, stop := context.WithTimeoutCause(runCtx, r.timeout, errTimedOut)
	defer stop()

	stdout := &output{keep: true, max: maxStdout, full: func() { cancel(errOverflow) }}
	stderr := &output{max: maxStderr, full: func() { cancel(errOverflow) }}
	defer stderr.clear()

	cmd := exec.CommandContext(runCtx, r.program, args...) //nolint:gosec // G204: the program comes from the broker config, which CheckFiles checked; the arguments are fixed words and a checked UUID or path.
	cmd.Env = append([]string{"HOME=" + r.home}, env...)
	cmd.Dir = r.home
	cmd.Stdin = nil // /dev/null
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = r.waitDelay
	setProcessGroup(cmd)
	// Start sets cmd.Process before it watches runCtx, so Cancel can read
	// it.
	cmd.Cancel = func() error { return killProcessGroup(cmd.Process) }

	// The program gets SIGKILL when the thread that started it ends
	// (Pdeathsig). Go can end a thread while the broker goes on, so the
	// run keeps its thread until the program has been waited for. Then
	// only the end of the broker kills the program.
	err := func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		return cmd.Run()
	}()
	if cmd.Process != nil {
		// Whatever the program left in its group. The program has been
		// waited for; while a process is left in the group, its ID stays
		// in use, so the signal reaches only that group.
		_ = killProcessGroup(cmd.Process)
	}
	if err == nil && !stdout.over && !stderr.over && ctx.Err() == nil {
		return stdout.buf, nil
	}
	stdout.clear()
	switch {
	case stdout.over || stderr.over:
		return nil, stepError(r.store, step, ErrTooMuchOutput)
	case ctx.Err() != nil:
		return nil, stepError(r.store, step, ctx.Err())
	case errors.Is(context.Cause(runCtx), errTimedOut):
		return nil, fmt.Errorf("store %q: %s: %w (after %s)", r.store, step, ErrTimeout, r.timeout)
	case errors.Is(err, exec.ErrWaitDelay):
		return nil, stepError(r.store, step, ErrLeftRunning)
	}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return nil, fmt.Errorf("store %q: %s: %w (%s); to see why, run %s by hand as the broker's user, with HOME set to %s", r.store, step, ErrFailed, exitDetail(exit), r.program, r.home)
	case cmd.Process != nil:
		// It ran, but its output could not be read to the end.
		return nil, fmt.Errorf("store %q: %s: %w (its output could not be read)", r.store, step, ErrFailed)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return nil, fmt.Errorf("store %q: %s: %w: %w", r.store, step, ErrStart, errno)
	}
	return nil, stepError(r.store, step, ErrStart)
}

// output takes what a program writes to stdout or stderr. It keeps the
// bytes of stdout, and only counts those of stderr. When a program writes
// more than max bytes, output calls full once and refuses the rest.
//
// os/exec copies the program's output with io.Copy, which calls ReadFrom.
// So the bytes go straight into output's own memory, and no other buffer
// of nodkey holds a copy. clear overwrites that memory.
type output struct {
	keep    bool   // keep the bytes (stdout), or only count them (stderr)
	max     int    // the most bytes the program may write
	full    func() // called once when the program writes more
	buf     []byte // the bytes kept
	n       int    // the number of bytes written
	over    bool   // more than max bytes were written
	scratch []byte // stderr is read into it, then dropped
}

// Write takes p, as io.Writer.
func (o *output) Write(p []byte) (int, error) {
	if o.over || len(p) > o.max-o.n {
		o.overflow()
		return 0, errOverflow
	}
	if o.keep {
		o.reserve(len(p))
		o.buf = append(o.buf, p...)
	}
	o.n += len(p)
	return len(p), nil
}

// ReadFrom reads from rd until its end, as io.ReaderFrom.
func (o *output) ReadFrom(rd io.Reader) (int64, error) {
	var total int64
	for {
		if o.over {
			return total, errOverflow
		}
		// Read at most one byte more than allowed, to see an overflow.
		room := o.max + 1 - o.n
		var p []byte
		if o.keep {
			o.reserve(1)
			p = o.buf[len(o.buf):min(cap(o.buf), len(o.buf)+room)]
		} else {
			if o.scratch == nil {
				o.scratch = make([]byte, firstBufferSize)
			}
			p = o.scratch[:min(len(o.scratch), room)]
		}
		n, err := rd.Read(p)
		total += int64(n)
		o.n += n
		if o.keep {
			o.buf = o.buf[:len(o.buf)+n]
		}
		if o.n > o.max {
			o.overflow()
			return total, errOverflow
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// reserve makes room for at least n more bytes in buf. A new buffer gets
// the old bytes, and the old buffer is cleared. buf never grows past
// max+1 bytes.
func (o *output) reserve(n int) {
	if cap(o.buf)-len(o.buf) >= n {
		return
	}
	size := max(2*cap(o.buf), firstBufferSize, len(o.buf)+n)
	size = min(size, o.max+1)
	b := make([]byte, len(o.buf), size)
	copy(b, o.buf)
	clear(o.buf[:cap(o.buf)])
	o.buf = b
}

// overflow marks o as over its limit, and calls full the first time.
func (o *output) overflow() {
	if o.over {
		return
	}
	o.over = true
	if o.full != nil {
		o.full()
	}
}

// clear overwrites the memory of o.
func (o *output) clear() {
	clear(o.buf[:cap(o.buf)])
	o.buf = nil
	clear(o.scratch)
}
