package main

import (
	"bytes"
	"io"
	"log"
	"strings"
	"testing"
)

// TestSSHAgentCommand: nodkey ssh-agent is a command of nodkey. -h prints
// its usage; wrong usage prints its usage, and the last line says why,
// with exit code 64. It sends Go's global logger nowhere, so that no
// library writes text that a process on the agent machine sent.
func TestSSHAgentCommand(t *testing.T) { // not parallel: it changes the global logger
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev) })
	var stdout, stderr bytes.Buffer
	if code := run([]string{"ssh-agent", "-h"}, strings.NewReader(""), &stdout, &stderr); code != exitOK ||
		!strings.HasPrefix(stderr.String(), "Usage: nodkey ssh-agent [--socket PATH]\n") || stdout.Len() != 0 {
		t.Errorf("nodkey ssh-agent -h: exit code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if log.Writer() != io.Discard {
		t.Error("the global logger still writes")
	}
	stderr.Reset()
	if code := run([]string{"ssh-agent", "--bogus"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage ||
		!strings.HasSuffix(stderr.String(), "(exit 64)\n") {
		t.Errorf("nodkey ssh-agent --bogus: exit code %d, stderr %q", code, stderr.String())
	}
	stdout.Reset()
	if run([]string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); !strings.Contains(stdout.String(), "\n  ssh-agent ") {
		t.Errorf("help does not list ssh-agent: %q", stdout.String())
	}
}
