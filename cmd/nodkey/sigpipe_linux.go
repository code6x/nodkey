package main

import (
	"os"
	"os/signal"
	"syscall"
)

// ignoreBrokenPipe makes a write to a closed pipe on stdout or stderr fail
// with an error. By default Go stops the program with SIGPIPE then, before
// keygen can remove the key file whose pin it could not print.
func ignoreBrokenPipe() {
	signal.Ignore(syscall.SIGPIPE)
}

// catchBrokenPipe makes a write to a closed pipe on stdout or stderr fail
// with an error, as ignoreBrokenPipe does, but it catches SIGPIPE with
// signal.Notify instead of ignoring it. The broker needs this: a program
// that it starts, such as a store program, gets a caught signal back with
// its default action at execve, while an ignored signal stays ignored.
// Nothing reads the channel; Notify drops a signal that does not fit.
func catchBrokenPipe() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
}
