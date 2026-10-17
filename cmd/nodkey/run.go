package main

import (
	"io"

	"github.com/code6x/nodkey/internal/client"
)

// runRun runs nodkey run (package client). When the person approves, the
// command replaces nodkey, and runRun does not return. It must never
// ignore SIGPIPE, as keygen does: an ignored signal stays ignored after
// execve, so the command would run with it ignored.
func runRun(args []string, stderr io.Writer) int {
	return client.Run(args, stderr, version)
}
