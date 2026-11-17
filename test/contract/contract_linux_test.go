package contract

// The contract tests: each pins one pattern of a caller of nodkey run, as
// DESIGN.md section 5 ("What the command gets") and docs/setup.md section
// 11 ("Keep the mask on") document it. A change to a test here is a
// change in behavior for callers (README.md).

import (
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// secretHash returns the SHA-256 of the value of approvedSecret, as the
// command sees it in its environment. It never holds the value itself.
func secretHash(t *testing.T) string {
	t.Helper()
	r := run(t, call{mode: modes[0], helper: helperFacts})
	r.wantExit(0)
	f := r.facts()
	if f.EnvHash == "" || !f.EnvTry {
		t.Fatalf("the command did not get a value of nodkey try in %s", secretVar)
	}
	return f.EnvHash
}

// Pattern 1: a program reads the secret through a pipe from a password
// command. With the mask, it gets ***; this run never gets the value.
func TestPasswordCommandThroughPipeGetsMask(t *testing.T) {
	for _, m := range modes {
		if !m.masked || m.out == terminals {
			continue // stdout is not a pipe, or the value is not masked
		}
		t.Run(m.name, func(t *testing.T) {
			r := run(t, call{mode: m, argv: []string{"printenv", secretVar}})
			r.wantExit(0)
			// Never print the output, not even its length: it could be
			// the value.
			if r.stdout.String() != "***\n" {
				t.Error("the program did not read only \"***\\n\" through the pipe")
			}
		})
	}
}

// Pattern 1, the documented way: the program runs inside nodkey run, and
// its password command reads the program's own environment. It gets the
// value, on a pipe and on a terminal.
func TestPasswordCommandInsideRunGetsValue(t *testing.T) {
	want := secretHash(t)
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			r := run(t, call{mode: m, helper: helperProgram})
			r.wantExit(0)
			var got *event
			for _, e := range r.events() {
				if e.Event == "program" {
					got = &e
				}
			}
			switch {
			case got == nil:
				t.Fatal("the program did not run")
			case got.Error != "":
				t.Fatal(got.Error)
			case got.Hash == hashOf([]byte("***")):
				t.Error("the password command got *** in place of the value")
			case got.Hash != want:
				t.Error("the password command got another value than the secret")
			}
		})
	}
}

// Pattern 2: the parent of the command. Masked: a process named nodkey,
// not dumpable, whose parent is the caller, in the same process group and
// session. execve: the command has the process ID of nodkey run, and its
// parent is the caller.
func TestParentProcess(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			r := run(t, call{mode: m, helper: helperFacts})
			r.wantExit(0)
			f := r.facts()
			nodkeyPID, caller := r.cmd.Process.Pid, os.Getpid()
			if !m.masked {
				if f.PID != nodkeyPID {
					t.Errorf("execve: the command has process ID %d; want %d, the one of nodkey run", f.PID, nodkeyPID)
				}
				if f.PPID != caller {
					t.Errorf("execve: the parent of the command is %d; want the caller %d", f.PPID, caller)
				}
				return
			}
			if f.PPID != nodkeyPID {
				t.Errorf("masked: the parent of the command is %d; want nodkey run, %d", f.PPID, nodkeyPID)
			}
			if f.ParentStatErr != "" {
				t.Fatalf("masked: /proc/PID/stat of nodkey cannot be read: %s", f.ParentStatErr)
			}
			if f.ParentName != "nodkey" {
				t.Errorf("masked: the parent is named %q in /proc/PID/stat; want \"nodkey\"", f.ParentName)
			}
			if f.ParentPPID != caller {
				t.Errorf("masked: the parent of nodkey is %d; want the caller %d", f.ParentPPID, caller)
			}
			if f.Pgrp != f.ParentPgrp || f.Session != f.ParentSession {
				t.Errorf("masked: the command is in process group %d, session %d; nodkey in %d, %d",
					f.Pgrp, f.Session, f.ParentPgrp, f.ParentSession)
			}
			if os.Geteuid() == 0 {
				t.Log("the test runs as root: root can read /proc/PID/exe of nodkey, so that check is left out")
			} else if f.ParentExe != "EACCES" {
				t.Errorf("masked: readlink /proc/PID/exe of nodkey gave %q; want EACCES (nodkey is not dumpable)", f.ParentExe)
			}
		})
	}
}

// Pattern 3: the exit code of the command is the exit code of nodkey run.
func TestExitCode(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			r := run(t, call{mode: m, argv: []string{"/bin/sh", "-c", "exit 42"}})
			r.wantExit(42)
		})
	}
}

// Pattern 3: when the command dies of a signal. Masked: nodkey dies of
// the same signal for SIGTERM, SIGHUP, SIGINT and SIGKILL, and exits with
// 128 and the number for another one. execve: the command is nodkey run,
// so the caller sees its signal.
func TestDeathBySignal(t *testing.T) {
	for _, m := range modes {
		for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGKILL, syscall.SIGUSR1} {
			t.Run(m.name+"/"+sig.String(), func(t *testing.T) {
				// An ignored signal stays ignored in the children, so
				// the shell cannot die of it.
				needSignals(t, sig)
				name := strings.TrimPrefix(signalName(sig), "SIG")
				r := run(t, call{mode: m, argv: []string{"/bin/sh", "-c", "kill -s " + name + " $$"}})
				if m.masked && sig == syscall.SIGUSR1 {
					r.wantExit(128 + int(sig))
					return
				}
				r.wantSignal(sig)
			})
		}
	}
}

func signalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "TERM"
	case syscall.SIGHUP:
		return "HUP"
	case syscall.SIGINT:
		return "INT"
	case syscall.SIGKILL:
		return "KILL"
	case syscall.SIGUSR1:
		return "USR1"
	}
	return ""
}

// Pattern 3: SIGTERM and SIGHUP to nodkey run reach the command. Masked:
// nodkey does not pass SIGINT or SIGUSR1 on. execve: every signal goes to
// the command.
func TestSignalsReachCommand(t *testing.T) {
	for _, m := range modes {
		for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
			t.Run(m.name+"/"+sig.String(), func(t *testing.T) {
				// nodkey does not catch a signal that it got ignored
				// (DESIGN.md section 5), so it would not pass it on.
				needSignals(t, syscall.SIGINT, syscall.SIGUSR1, sig)
				r := start(t, call{mode: m, helper: helperSignals})
				r.waitEvent("ready from the command", func(e event) bool { return e.Event == "ready" })
				pid := r.cmd.Process.Pid
				var want []string
				for _, other := range []syscall.Signal{syscall.SIGINT, syscall.SIGUSR1} {
					if err := syscall.Kill(pid, other); err != nil {
						t.Fatal(err)
					}
					if !m.masked {
						// execve: wait until the command got it, so the
						// order of the signals is known.
						n := signalName(other)
						r.waitEvent("signal "+n+" at the command", func(e event) bool { return e.Event == "signal" && e.Signal == n })
						want = append(want, n)
					}
				}
				if m.masked {
					// A check that something does not come needs time.
					// Without it, a SIGINT that nodkey passes on could
					// still be on its way when the command exits on sig
					// (Linux delivers SIGHUP before SIGINT), and the test
					// would pass. nodkey passes a signal on at once, so
					// half a second is plenty.
					time.Sleep(500 * time.Millisecond)
				}
				if err := syscall.Kill(pid, sig); err != nil {
					t.Fatal(err)
				}
				r.wait()
				r.wantExit(100 + int(sig))
				want = append(want, signalName(sig))
				if got := r.signals(); !slices.Equal(got, want) {
					t.Errorf("the command got the signals %q; want %q", got, want)
				}
			})
		}
	}
}

// Pattern 4: the command reads the stdin of nodkey run, and a file
// descriptor that the caller passed to nodkey run (fd 3) reaches it.
// Masked, stdout and stderr of the command are pipes (to nodkey); with
// execve, they are those of the caller.
func TestStdinAndFileDescriptors(t *testing.T) {
	const stdin, fd3 = "data on stdin\n", "data on fd 3\n"
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			r := run(t, call{mode: m, helper: helperFacts, stdin: []byte(stdin), fd3: []byte(fd3)})
			r.wantExit(0)
			f := r.facts()
			if f.Stdin != stdin {
				t.Errorf("the command read %q on stdin; want %q", f.Stdin, stdin)
			}
			if f.FD3 != fd3 {
				t.Errorf("the command read %q on fd 3; want %q", f.FD3, fd3)
			}
			wantOut, wantErr := "pipe", "pipe"
			if !m.masked && m.out == terminals {
				wantOut, wantErr = "terminal", "terminal"
			}
			if f.Stdout != wantOut || f.Stderr != wantErr {
				t.Errorf("stdout and stderr of the command are %s and %s; want %s and %s", f.Stdout, f.Stderr, wantOut, wantErr)
			}
		})
	}
}

// A denied request: nodkey run exits with 77, its last line says so, and
// the command never runs. The first request gets a tap on Deny. After it,
// the broker denies the next requests for the same secret without a
// message, for 60 seconds (DESIGN.md section 8); they end in the same way.
func TestDenied(t *testing.T) {
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			r := run(t, call{mode: m, secret: deniedSecret, helper: helperFacts})
			r.wantExit(77)
			if setup.trial.denied.Load() == 0 {
				t.Error("the broker never asked, so the exit code 77 does not come from a tap on Deny")
			}
			if evs := r.events(); len(evs) > 0 {
				t.Errorf("the command ran after a deny: %d events", len(evs))
			}
			if m.out == pipes {
				if !strings.HasSuffix(r.stderr.String(), " (exit 77)\n") {
					// Do not print stderr: keep output of nodkey run out of
					// failures.
					t.Error("the last line on stderr does not end with \"(exit 77)\"")
				}
			} else {
				r.ptyOut.waitFor(t, " (exit 77)")
			}
		})
	}
}

// needSignals stops the test when the test process ignores one of sigs,
// as under nohup: then the children ignore it too, and the test cannot
// check what it should. In CI that is a failure, not a skip, so the check
// is never lost there.
func needSignals(t *testing.T, sigs ...syscall.Signal) {
	t.Helper()
	for _, sig := range sigs {
		if !signal.Ignored(sig) {
			continue
		}
		if os.Getenv("CI") != "" {
			t.Fatalf("the test process ignores %v, so this test cannot run; run it without that", sig)
		}
		t.Skipf("the test process ignores %v, so this test cannot run; run it without that", sig)
	}
}
