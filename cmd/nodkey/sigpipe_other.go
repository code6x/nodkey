//go:build !linux

package main

// ignoreBrokenPipe does nothing here: version 1 runs on Linux only, and
// keygen makes no key file elsewhere.
func ignoreBrokenPipe() {}
