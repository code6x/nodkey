package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string // a part of stderr; "" means stderr must be empty
	}{
		{name: "no arguments", args: nil, wantCode: exitUsage, wantStderr: `nodkey: give a command; see "nodkey --help"`},
		{name: "unknown command", args: []string{"bogus"}, wantCode: exitUsage, wantStderr: `unknown command "bogus"`},
		{name: "unknown flag", args: []string{"-bogus"}, wantCode: exitUsage, wantStderr: "unknown option"},
		{name: "-h", args: []string{"-h"}, wantCode: exitOK, wantStderr: usageText},
		{name: "help", args: []string{"help"}, wantCode: exitOK, wantStdout: usageText},
		{name: "version", args: []string{"version"}, wantCode: exitOK, wantStdout: "nodkey " + version + "\n"},
		{name: "--version", args: []string{"--version"}, wantCode: exitOK, wantStdout: "nodkey " + version + "\n"},
		{name: "-version", args: []string{"-version"}, wantCode: exitOK, wantStdout: "nodkey " + version + "\n"},
		{name: "--version with an argument", args: []string{"--version", "extra"}, wantCode: exitUsage, wantStderr: `nodkey version: unexpected argument "extra"; see "nodkey version --help"`},
		{name: "--version --offline", args: []string{"--version", "--offline"}, wantCode: exitOK, wantStdout: "nodkey " + version + "\n"},
		{name: "help --help", args: []string{"help", "--help"}, wantCode: exitOK, wantStdout: usageText},
		{name: "help help", args: []string{"help", "help"}, wantCode: exitOK, wantStdout: usageText},
		{name: "help of an unknown command", args: []string{"help", "bogus"}, wantCode: exitUsage, wantStderr: `unknown command "bogus"`},
		{name: "help with two commands", args: []string{"help", "run", "update"}, wantCode: exitUsage, wantStderr: `nodkey help: give at most one command; see "nodkey help --help"`},
		{name: "version with an argument", args: []string{"version", "extra"}, wantCode: exitUsage, wantStderr: `nodkey version: unexpected argument "extra"; see "nodkey version --help"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(""), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
			}
			got := stderr.String()
			if tt.wantStderr == "" && got != "" {
				t.Errorf("stderr = %q, want it empty", got)
			}
			if !strings.Contains(got, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", got, tt.wantStderr)
			}
		})
	}
}

// failingWriter fails every write, like a closed pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunReportsFailedOutput(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"help"}, {"help", "run"}} {
		var stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), failingWriter{}, &stderr); code != exitFailure {
			t.Errorf("run(%q) with a failing stdout: exit code = %d, want %d", args, code, exitFailure)
		}
	}
}

// TestHelpCommand: "nodkey help COMMAND" prints on stdout the same text
// that "nodkey COMMAND --help" prints, with exit code 0.
func TestHelpCommand(t *testing.T) {
	for _, name := range commands {
		t.Run(name, func(t *testing.T) {
			var want bytes.Buffer
			if code := run([]string{name, "--help"}, strings.NewReader(""), &want, &want); code != exitOK {
				t.Fatalf("nodkey %s --help: exit code %d, want %d", name, code, exitOK)
			}
			if !strings.HasPrefix(want.String(), "Usage: nodkey "+name) {
				t.Fatalf("nodkey %s --help printed %q", name, want.String())
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{"help", name}, strings.NewReader(""), &stdout, &stderr); code != exitOK {
				t.Errorf("nodkey help %s: exit code %d, want %d", name, code, exitOK)
			}
			if stdout.String() != want.String() {
				t.Errorf("nodkey help %s: stdout = %q, want %q", name, stdout.String(), want.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("nodkey help %s: stderr = %q, want it empty", name, stderr.String())
			}
		})
	}
}

// TestCommandsAreKnown: every name in commands is a command of run, so
// "nodkey help NAME" never gives the help of a name that run rejects.
func TestCommandsAreKnown(t *testing.T) {
	for _, name := range commands {
		var stderr bytes.Buffer
		run([]string{name, "--help"}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
		if strings.Contains(stderr.String(), "unknown command") {
			t.Errorf("%q is in commands, but run does not know it", name)
		}
	}
}
