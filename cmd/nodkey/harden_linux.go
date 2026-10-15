package main

import (
	"errors"
	"fmt"
	"syscall"
)

// hardenProcess turns off core dumps, and fails if it cannot (DESIGN.md
// section 16):
//
//   - It sets the soft and the hard RLIMIT_CORE of the broker to 1. The
//     store programs inherit both, and cannot raise the soft limit above
//     the hard limit. With exactly 1 and a pipe or file core_pattern, such
//     as the default of systemd, the kernel writes no core file and starts
//     no core handler. A core handler such as systemd-coredump would copy
//     the environment of a crashed bws or bw, with the token or the
//     session key, into the journal. A limit of 0 does not stop a core
//     handler.
//   - It marks the broker not dumpable (PR_SET_DUMPABLE 0): no core dump
//     of the broker, and other processes of its user cannot attach to it
//     or read its memory.
//
// It reads both settings back.
func hardenProcess() error {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		return fmt.Errorf("cannot read the limit of core dumps: %w", err)
	}
	if lim.Max == 0 {
		return errors.New("the hard limit of core dumps is 0, so the soft limit cannot be 1; " +
			"set LimitCORE=1 in the systemd unit, or run ulimit -c 1 first")
	}
	// The hard limit only goes down: a process without privileges cannot
	// raise it again.
	lim.Cur, lim.Max = 1, 1
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		return fmt.Errorf("cannot set the limit of core dumps to 1: %w", err)
	}
	var got syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &got); err != nil || got.Cur != 1 || got.Max != 1 {
		return errors.New("the soft and the hard limit of core dumps are not 1 after setting them")
	}
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("cannot mark the process not dumpable: %w", errno)
	}
	dumpable, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if errno != 0 || dumpable != 0 {
		return errors.New("the process is still dumpable after PR_SET_DUMPABLE 0")
	}
	return nil
}
