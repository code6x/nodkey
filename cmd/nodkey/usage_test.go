package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestUsageErrorsAreOneLine: every command, given a bad argument, writes
// exactly one line to stderr, "nodkey CMD: REASON; see "nodkey CMD --help"
// (exit 64)", nothing on stdout, and exits with 64. No usage text comes
// before or after it (DESIGN.md section 15).
func TestUsageErrorsAreOneLine(t *testing.T) {
	for _, tt := range []struct {
		name string // the name in the line, "nodkey" for the top level
		args []string
	}{
		{"nodkey", nil},
		{"nodkey", []string{"bogus"}},
		{"nodkey", []string{"-bogus"}},
		{"nodkey broker", []string{"broker", "extra"}},
		{"nodkey broker", []string{"broker", "--bogus"}},
		{"nodkey keygen", []string{"keygen"}},
		{"nodkey keygen", []string{"keygen", "--out", "k", "extra"}},
		{"nodkey run", []string{"run"}},
		{"nodkey run", []string{"run", "--bogus"}},
		{"nodkey ssh-agent", []string{"ssh-agent", "extra"}},
		{"nodkey ssh-grant", []string{"ssh-grant"}},
		{"nodkey ssh-grant", []string{"ssh-grant", "--bogus"}},
		{"nodkey preapprove", []string{"preapprove"}},
		{"nodkey preapprove", []string{"preapprove", "--bogus"}},
		{"nodkey audit", []string{"audit"}},
		{"nodkey audit", []string{"audit", "bogus"}},
		{"nodkey audit verify", []string{"audit", "verify"}},
		{"nodkey audit verify", []string{"audit", "verify", "a", "b"}},
		{"nodkey audit verify", []string{"audit", "verify", "--bogus", "a"}},
		{"nodkey update", []string{"update", "extra"}},
		{"nodkey update", []string{"update", "--version", "1"}},
		{"nodkey changes", []string{"changes"}},
		{"nodkey changes", []string{"changes", "--since", "1"}},
		{"nodkey version", []string{"version", "extra"}},
		{"nodkey version", []string{"--version", "extra"}},
		{"nodkey help", []string{"help", "bogus"}},
		{"nodkey help", []string{"help", "run", "update"}},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(""), &stdout, &stderr)
			got := stderr.String()
			if code != exitUsage {
				t.Errorf("exit code %d, want %d; stderr %q", code, exitUsage, got)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want it empty", stdout.String())
			}
			if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
				t.Errorf("stderr = %q, want exactly one line", got)
			}
			if !strings.HasPrefix(got, tt.name+": ") {
				t.Errorf("stderr = %q, want it to start with %q", got, tt.name+": ")
			}
			if !strings.Contains(got, `see "`+tt.name+` --help"`) || !strings.HasSuffix(got, " (exit 64)\n") {
				t.Errorf(`stderr = %q, want it to say see "%s --help" and end with (exit 64)`, got, tt.name)
			}
		})
	}
}

// TestUsageErrorLineIsCapped: a long flag name, a long value, a long
// argument and a format character such as U+202E give one line that is
// capped and has no raw U+202E (DESIGN.md section 15).
func TestUsageErrorLineIsCapped(t *testing.T) {
	long := strings.Repeat("x", 200)
	for _, tt := range []struct {
		name string
		args []string
		want string // a text the line must hold, "" for none
	}{
		{"long flag name", []string{"broker", "--" + long}, `unknown option "` + strings.Repeat("x", 64) + `"`},
		{"long value", []string{"update", "--version", strings.Repeat("9", 150)}, "want X.Y.Z, such as 0.2.0"},
		{"long argument", []string{"broker", long}, ""},
		{"U+202E in a flag", []string{"broker", "--a\u202eb"}, "a\\u202eb"},
		{"U+202E in an argument", []string{"broker", "a\u202eb"}, "a\\u202eb"},
		{"long anchors path", []string{"audit", "verify", "f", "--anchors", "/nonexistent/" + long}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			run(tt.args, strings.NewReader(""), &bytes.Buffer{}, &stderr)
			got := stderr.String()
			if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
				t.Errorf("stderr = %q, want exactly one line", got)
			}
			if len(got) > 400 {
				t.Errorf("the line has %d bytes, want it capped", len(got))
			}
			if strings.ContainsRune(got, '\u202e') {
				t.Errorf("stderr = %q, want no raw U+202E", got)
			}
			if strings.Contains(got, strings.Repeat("x", 65)) || strings.Contains(got, strings.Repeat("9", 65)) {
				t.Errorf("stderr = %q, want the input cut to 64 characters", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("stderr = %q, want it to hold %q", got, tt.want)
			}
		})
	}
}
