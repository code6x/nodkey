//go:build !linux

package client

// isTerminal reports false here: version 1 runs on Linux only (DESIGN.md
// section 3), so nodkey run masks the output on other systems.
func isTerminal(uintptr) bool { return false }
