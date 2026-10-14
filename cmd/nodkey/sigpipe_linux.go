package main

import (
	"os/signal"
	"syscall"
)

// ignoreBrokenPipe makes a write to a closed pipe on stdout or stderr fail
// with an error. By default Go stops the program with SIGPIPE then, before
// keygen can remove the key file whose pin it could not print.
func ignoreBrokenPipe() {
	signal.Ignore(syscall.SIGPIPE)
}
