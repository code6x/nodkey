package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunCommand: nodkey run is a command of nodkey. Wrong usage prints
// its usage, and the last line says why, with exit code 64.
func TestRunCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage {
		t.Errorf("nodkey run: exit code %d, want %d", code, exitUsage)
	}
	if !strings.HasPrefix(stderr.String(), "nodkey run: ") || !strings.HasSuffix(stderr.String(), `see "nodkey run --help" (exit 64)`+"\n") {
		t.Errorf("stderr = %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want it empty", stdout.String())
	}
	stdout.Reset()
	if run([]string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); !strings.Contains(stdout.String(), "\n  run ") {
		t.Errorf("help does not list run: %q", stdout.String())
	}
}
