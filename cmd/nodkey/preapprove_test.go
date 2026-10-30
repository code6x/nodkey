package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestPreapproveCommand: nodkey preapprove is a command of nodkey. Wrong
// usage prints its usage, and the last line says why, with exit code 64.
// --help alone prints the usage and exits with 0. help lists the command.
// It never writes to stdout, except for the ID of a grant.
func TestPreapproveCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"preapprove"}, strings.NewReader(""), &stdout, &stderr); code != exitUsage {
		t.Errorf("nodkey preapprove: exit code %d, want %d", code, exitUsage)
	}
	if !strings.HasPrefix(stderr.String(), "nodkey preapprove: give the secrets") ||
		!strings.HasSuffix(stderr.String(), `see "nodkey preapprove --help" (exit 64)`+"\n") {
		t.Errorf("stderr = %q", stderr.String())
	}
	stderr.Reset()
	args := []string{"preapprove", "--secret", "a", "--from", "tomorrow", "--until", "2026-10-28T04:00", "--uses", "1"}
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != exitUsage ||
		!strings.HasSuffix(stderr.String(), "(exit 64)\n") {
		t.Errorf("a bad time: exit code %d, stderr %q; want 64", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"preapprove", "--help"}, strings.NewReader(""), &stdout, &stderr); code != exitOK ||
		!strings.HasPrefix(stderr.String(), "Usage: nodkey preapprove ") {
		t.Errorf("nodkey preapprove --help: exit code %d, stderr %q; want 0 and the usage", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want it empty", stdout.String())
	}
	if run([]string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); !strings.Contains(stdout.String(),
		"\n  preapprove ") {
		t.Errorf("help does not list preapprove: %q", stdout.String())
	}
}
