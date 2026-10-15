//go:build !linux

package main

import "errors"

// hardenProcess fails: nodkey version 1 runs on Linux only, and it can
// turn off core dumps only there.
func hardenProcess() error {
	return errors.New("nodkey broker runs on Linux only; it cannot turn off core dumps here")
}
