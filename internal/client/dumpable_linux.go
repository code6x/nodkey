package client

import "syscall"

// notDumpable marks nodkey as not dumpable (prctl PR_SET_DUMPABLE 0): the
// kernel writes no core dump of it, and other processes of the same user
// cannot read its memory or its /proc files, such as with ptrace. execve
// makes the command dumpable again. RLIMIT_CORE is not used: the command
// would inherit it.
func notDumpable() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
