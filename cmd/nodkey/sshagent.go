package main

import (
	"io"
	"log"

	"github.com/code6x/nodkey/internal/client"
)

// runSSHAgent runs nodkey ssh-agent (package client) until SIGINT or
// SIGTERM.
//
// The agent serves the SSH agent protocol itself, and writes its own
// fixed lines. It does not use the agent server of golang.org/x/crypto,
// which writes the text of every error to Go's global logger, unescaped
// and without a limit. In case any library still writes to that logger,
// its lines go nowhere: they could hold text that a process on the agent
// machine sent.
func runSSHAgent(args []string, stderr io.Writer) int {
	log.SetOutput(io.Discard)
	return client.SSHAgent(args, stderr, version)
}
