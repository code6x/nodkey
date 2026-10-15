package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestSSHGrantCommand: nodkey ssh-grant is a command of nodkey. Wrong usage
// prints its usage, and the last line says why, with exit code 64. --help
// alone prints the usage and exits with 0. help lists the command. It
// never writes to stdout.
func TestSSHGrantCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"ssh-grant"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage {
		t.Errorf("nodkey ssh-grant: exit code %d, want %d", code, exitUsage)
	}
	if !strings.HasPrefix(stderr.String(), "Usage: nodkey ssh-grant ") ||
		!strings.HasSuffix(stderr.String(), "give the key with --key NAME (exit 64)\n") {
		t.Errorf("stderr = %q", stderr.String())
	}
	stderr.Reset()
	args := []string{"ssh-grant", "--key", "deploy", "--user", "deploy@web-1", "--host", "web-1", "--for", "15m"}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != exitUsage ||
		!strings.HasSuffix(stderr.String(), "must match [A-Za-z0-9._][A-Za-z0-9._-]{0,31} (exit 64)\n") {
		t.Errorf("a bad user name: exit code %d, stderr %q; want 64", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"ssh-grant", "--help"}, strings.NewReader(""), &stdout, &stderr); code != exitOK ||
		!strings.HasPrefix(stderr.String(), "Usage: nodkey ssh-grant ") {
		t.Errorf("nodkey ssh-grant --help: exit code %d, stderr %q; want 0 and the usage", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want it empty", stdout.String())
	}
	if run([]string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); !strings.Contains(stdout.String(),
		"\n  ssh-grant ") {
		t.Errorf("help does not list ssh-grant: %q", stdout.String())
	}
}
