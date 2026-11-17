package contract

// The helper: the test binary run again as the command of nodkey run. It
// writes what it finds to the report file (event), never a value: only a
// SHA-256 of one.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// The modes of the helper.
const (
	helperFacts   = "facts"   // report facts, then exit 0
	helperSignals = "signals" // report each signal; exit 100+n on SIGTERM or SIGHUP
	helperProgram = "program" // a program with a password command that reads its own environment
)

// helper runs the helper in mode and returns its exit code.
func helper(mode string) int {
	switch mode {
	case helperFacts:
		return report(event{Event: "facts", Facts: collectFacts()})
	case helperSignals:
		return waitSignals()
	case helperProgram:
		return passwordProgram()
	}
	return 2
}

// report appends e to the report file, as one write. It returns 0, or 3
// when it cannot.
func report(e event) int {
	b, err := json.Marshal(e)
	if err != nil {
		return 3
	}
	f, err := os.OpenFile(os.Getenv(reportVar), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G703: the report file that the test named.
	if err != nil {
		return 3
	}
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 3
	}
	return 0
}

// collectFacts finds out the facts of this process.
func collectFacts() *facts {
	f := &facts{PID: os.Getpid(), PPID: os.Getppid()}
	if _, _, pgrp, session, err := readStat("self"); err == nil {
		f.Pgrp, f.Session = pgrp, session
	}
	parent := strconv.Itoa(f.PPID)
	name, ppid, pgrp, session, err := readStat(parent)
	if err != nil {
		f.ParentStatErr = err.Error()
	}
	f.ParentName, f.ParentPPID, f.ParentPgrp, f.ParentSession = name, ppid, pgrp, session
	switch _, err := os.Readlink("/proc/" + parent + "/exe"); {
	case err == nil:
		f.ParentExe = "ok"
	case errors.Is(err, syscall.EACCES):
		f.ParentExe = "EACCES"
	default:
		f.ParentExe = err.Error()
	}
	if v, ok := os.LookupEnv(secretVar); ok {
		h := sha256.Sum256([]byte(v))
		f.EnvHash = hex.EncodeToString(h[:])
		f.EnvTry = strings.HasPrefix(v, "TRY-")
	}
	if b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096)); err == nil {
		f.Stdin = string(b)
	}
	if os.Getenv(fd3Var) == "1" {
		fd3 := os.NewFile(3, "fd3")
		if b, err := io.ReadAll(io.LimitReader(fd3, 4096)); err == nil {
			f.FD3 = string(b)
		}
	}
	f.Stdout, f.Stderr = kind(1), kind(2)
	return f
}

// readStat reads the name, the parent, the process group and the session
// of a process from /proc/PID/stat.
func readStat(pid string) (name string, ppid, pgrp, session int, err error) {
	b, err := os.ReadFile("/proc/" + pid + "/stat") //nolint:gosec // G304: a file of /proc.
	if err != nil {
		return "", 0, 0, 0, err
	}
	s := string(b)
	open, closing := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closing < open {
		return "", 0, 0, 0, errors.New("no name in /proc/PID/stat")
	}
	fields := strings.Fields(s[closing+1:])
	if len(fields) < 4 {
		return "", 0, 0, 0, errors.New("too few fields in /proc/PID/stat")
	}
	ppid, _ = strconv.Atoi(fields[1])
	pgrp, _ = strconv.Atoi(fields[2])
	session, _ = strconv.Atoi(fields[3])
	return s[open+1 : closing], ppid, pgrp, session, nil
}

// kind says what the file descriptor fd is: "terminal", "pipe" or "other".
func kind(fd int) string {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return "closed"
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFIFO {
		return "pipe"
	}
	var tio syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TCGETS, uintptr(unsafe.Pointer(&tio))); e == 0 { //nolint:gosec // G103: the ioctl needs the address.
		return "terminal"
	}
	return "other"
}

// signalNames are the signals that the helper catches.
var signalNames = map[os.Signal]string{
	syscall.SIGTERM: "TERM", syscall.SIGHUP: "HUP", syscall.SIGINT: "INT", syscall.SIGUSR1: "USR1",
}

// waitSignals reports "ready", then each signal that comes. On SIGTERM or
// SIGHUP it exits with 100 and the number of the signal.
func waitSignals() int {
	ch := make(chan os.Signal, 8)
	for s := range signalNames {
		signal.Notify(ch, s)
	}
	if code := report(event{Event: "ready"}); code != 0 {
		return code
	}
	timeout := time.After(waitLimit)
	for {
		select {
		case s := <-ch:
			if code := report(event{Event: "signal", Signal: signalNames[s]}); code != 0 {
				return code
			}
			if n, ok := s.(syscall.Signal); ok && (n == syscall.SIGTERM || n == syscall.SIGHUP) {
				return 100 + int(n)
			}
		case <-timeout:
			return 99
		}
	}
}

// passwordProgram is a program that reads a password from a command
// through a pipe, as a mail client does: the command prints the secret
// from the program's own environment (docs/setup.md, section 11). It
// reports the SHA-256 of what it read.
func passwordProgram() int {
	ctx, cancel := context.WithTimeout(context.Background(), waitLimit)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", "printenv "+secretVar).Output()
	if err != nil {
		return report(event{Event: "program", Error: "the password command failed"})
	}
	return report(event{Event: "program", Hash: hashOf([]byte(strings.TrimSuffix(string(out), "\n")))})
}
