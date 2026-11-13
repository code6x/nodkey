package main

import (
	"io"

	"github.com/code6x/nodkey/internal/client"
)

// runAgentBrowserPlugin runs nodkey agent-browser-plugin (package client):
// the credential plugin of agent-browser (DESIGN.md section 21.10).
func runAgentBrowserPlugin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ignoreBrokenPipe()
	return client.AgentBrowserPlugin(args, stdin, stdout, stderr, version)
}
