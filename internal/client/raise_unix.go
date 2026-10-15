//go:build unix

package client

import (
	"os/signal"
	"syscall"
	"time"
)

// raise ends nodkey with sig, as the signal ends a program that does not
// catch it, so that a shell sees it. nodkey no longer catches it, so Go's
// own handler ends the process with the signal. raise returns only if
// that does not happen in time; nodkey then exits with the status that a
// shell shows for the signal.
func raise(sig syscall.Signal) {
	signal.Reset(sig)
	if err := syscall.Kill(syscall.Getpid(), sig); err != nil {
		return
	}
	time.Sleep(time.Second)
}
