package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"syscall"
)

// supported says that store programs can run on this system.
const supported = true

// setProcessGroup makes the program the leader of a new process group, so
// that killProcessGroup reaches every process it starts in that group. The
// program also gets SIGKILL when the broker ends (Pdeathsig), so it never
// outlives a broker that crashed during a run.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// killProcessGroup sends SIGKILL to the process group of p. When the
// group is gone, it returns os.ErrProcessDone.
func killProcessGroup(p *os.Process) error {
	// The group ID is the leader's process ID. Never send to -0 or -1:
	// those reach nodkey's own group and every process it may signal.
	if p == nil || p.Pid <= 1 {
		return errors.New("store: no process group to stop")
	}
	err := syscall.Kill(-p.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

// exitDetail says how a program ended: its exit code, or the signal that
// stopped it.
func exitDetail(exit *exec.ExitError) string {
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("stopped by signal %d", int(ws.Signal()))
	}
	return fmt.Sprintf("exit code %d", exit.ExitCode())
}

// fileOwner returns the user ID that owns the file.
func fileOwner(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
