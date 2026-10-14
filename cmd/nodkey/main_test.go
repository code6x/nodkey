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
		{name: "no arguments", args: nil, wantCode: exitUsage, wantStderr: usageText},
		{name: "unknown command", args: []string{"bogus"}, wantCode: exitUsage, wantStderr: `unknown command "bogus"`},
		{name: "unknown flag", args: []string{"-bogus"}, wantCode: exitUsage, wantStderr: "flag provided but not defined"},
		{name: "-h", args: []string{"-h"}, wantCode: exitOK, wantStderr: usageText},
		{name: "help", args: []string{"help"}, wantCode: exitOK, wantStdout: usageText},
		{name: "version", args: []string{"version"}, wantCode: exitOK, wantStdout: "nodkey " + version + "\n"},
		{name: "version with an argument", args: []string{"version", "extra"}, wantCode: exitUsage, wantStderr: "Usage: nodkey version"},
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
	for _, args := range [][]string{{"version"}, {"help"}} {
		var stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), failingWriter{}, &stderr); code != exitFailure {
			t.Errorf("run(%q) with a failing stdout: exit code = %d, want %d", args, code, exitFailure)
		}
	}
}
