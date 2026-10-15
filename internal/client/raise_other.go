//go:build !unix

package client

import "syscall"

// raise does nothing here: version 1 runs on Linux only (DESIGN.md section
// 3). nodkey exits with the status that a shell shows for the signal.
func raise(syscall.Signal) {}
