//go:build !linux

package main

import (
	"errors"
	"io"
	"os"
)

// isTerminal reports false: nodkey version 1 runs on Linux only, so
// nodkey version asks GitHub only there.
func isTerminal(io.Writer) bool { return false }

// echoOff fails: hidden input needs Linux.
func echoOff(*os.File) (func(), error) { return nil, errors.New("hidden input works only on Linux") }
