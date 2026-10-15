//go:build !linux

package client

// notDumpable does nothing here: version 1 runs on Linux only (DESIGN.md
// section 3), and other systems have no prctl.
func notDumpable() error { return nil }
