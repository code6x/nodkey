//go:build !linux

package main

import "io"

// isTerminal reports false: nodkey version 1 runs on Linux only, so
// nodkey version asks GitHub only there.
func isTerminal(io.Writer) bool { return false }
