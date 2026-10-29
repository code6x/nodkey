//go:build unix

package client

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByUser reports whether the user of this process owns the file.
func ownedByUser(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// noFollow makes open refuse a symbolic link, and not wait on a named
// pipe that was put in place of the file.
const noFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
