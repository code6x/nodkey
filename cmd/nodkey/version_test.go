package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/release"
	nodkeyversion "github.com/code6x/nodkey/internal/version"
)

// fakeVersionCheck is a versionCheck with a fake terminal and a fake
// GitHub. It counts the lookups.
type fakeVersionCheck struct {
	terminal bool
	// notTerminal is a writer that is not a terminal, even when terminal
	// is true.
	notTerminal io.Writer
	newest      nodkeyversion.Release
	security    []release.Security
	err         error

	mu       sync.Mutex
	lookups  int
	own      nodkeyversion.Release // the version that the last lookup got
	timeLeft time.Duration         // the time that the context of the last lookup had left
}

func (f *fakeVersionCheck) check() versionCheck {
	return versionCheck{
		isTerminal: func(w io.Writer) bool { return f.terminal && w != f.notTerminal },
		lookup: func(ctx context.Context, own nodkeyversion.Release) (release.Info, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.lookups++
			f.own = own
			if dl, ok := ctx.Deadline(); ok {
				f.timeLeft = time.Until(dl)
			}
			return release.Info{Newest: f.newest, Security: f.security}, f.err
		},
	}
}

func (f *fakeVersionCheck) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups
}

// rel returns the release major.minor.patch.
func rel(major, minor, patch int) nodkeyversion.Release {
	return nodkeyversion.Release{Major: major, Minor: minor, Patch: patch}
}

// TestVersionCheck: on a terminal, a release asks GitHub, and prints one
// line on stderr: a newer release with its link and the command, or that
// this is the newest release, also when GitHub's newest is older, or why
// it could not check. stdout is the same in every case, and the exit code
// is 0, also after an error.
func TestVersionCheck(t *testing.T) {
	newer := "nodkey: a newer release is out: nodkey 0.3.0; to update, run nodkey update as root; " +
		"what is new: nodkey update --notes; release notes: https://github.com/code6x/nodkey/releases/tag/v0.3.0\n"
	for _, tt := range []struct {
		name   string
		newest nodkeyversion.Release
		err    error
		want   string
	}{
		{"newer", rel(0, 3, 0), nil, newer},
		{"newer by its numbers", rel(0, 10, 0), nil, "nodkey: a newer release is out: nodkey 0.10.0;"},
		{"the same", rel(0, 2, 0), nil, "nodkey: this is the newest release\n"},
		{"older", rel(0, 1, 9), nil, "nodkey: this is the newest release\n"},
		{"a rate limit", nodkeyversion.Release{}, fmt.Errorf("%w (HTTP 403); try again later", release.ErrRateLimit),
			"nodkey: cannot check for a newer release: GitHub limits the calls from this address for now (HTTP 403); " +
				"try again later\n"},
		{"a network error", nodkeyversion.Release{}, errors.New("cannot reach GitHub: the lookup timed out"),
			"nodkey: cannot check for a newer release: cannot reach GitHub: the lookup timed out\n"},
	} {
		f := &fakeVersionCheck{terminal: true, newest: tt.newest, err: tt.err}
		var stdout, stderr bytes.Buffer
		code := runVersion(nil, "0.2.0", &stdout, &stderr, f.check())
		if code != exitOK || stdout.String() != "nodkey 0.2.0\n" {
			t.Errorf("%s: exit code %d, stdout %q", tt.name, code, stdout.String())
		}
		if got := stderr.String(); !strings.HasPrefix(got, tt.want) || strings.Count(got, "\n") != 1 {
			t.Errorf("%s: stderr %q, want %q", tt.name, got, tt.want)
		}
		if f.count() != 1 || f.own != rel(0, 2, 0) {
			t.Errorf("%s: %d lookups, for %v; want 1, for 0.2.0", tt.name, f.count(), f.own)
		}
		if f.timeLeft <= 0 || f.timeLeft > 10*time.Second {
			t.Errorf("%s: the lookup had %s, want at most 10 seconds", tt.name, f.timeLeft)
		}
	}
}

// TestVersionNoCheck: no lookup, and nothing on stderr, when stdout is not
// a terminal, such as a pipe, a file or $(...) in the installer, with
// --offline, or for a build from the source. stdout is the same.
func TestVersionNoCheck(t *testing.T) {
	for _, tt := range []struct {
		name     string
		args     []string
		own      string
		terminal bool
	}{
		{"not a terminal", nil, "0.2.0", false},
		{"--offline", []string{"--offline"}, "0.2.0", true},
		{"-offline", []string{"-offline"}, "0.2.0", true},
		{"--offline=true", []string{"--offline=true"}, "0.2.0", true},
		{"--offline, not a terminal", []string{"--offline"}, "0.2.0", false},
		{"dev", nil, "dev", true},
		{"a commit", nil, "1a2b3c4", true},
		{"a release candidate", nil, "0.3.0-rc.1", true},
		{"a tag", nil, "v0.2.0", true},
	} {
		f := &fakeVersionCheck{terminal: tt.terminal, newest: rel(9, 0, 0)}
		var stdout, stderr bytes.Buffer
		code := runVersion(tt.args, tt.own, &stdout, &stderr, f.check())
		if code != exitOK || stdout.String() != "nodkey "+tt.own+"\n" || stderr.Len() != 0 || f.count() != 0 {
			t.Errorf("%s: exit code %d, stdout %q, stderr %q, %d lookups; want 0, the version, nothing, none",
				tt.name, code, stdout.String(), stderr.String(), f.count())
		}
	}
	// --offline=false checks.
	f := &fakeVersionCheck{terminal: true, newest: rel(0, 2, 0)}
	var stdout, stderr bytes.Buffer
	if code := runVersion([]string{"--offline=false"}, "0.2.0", &stdout, &stderr, f.check()); code != exitOK ||
		f.count() != 1 || stderr.String() != "nodkey: this is the newest release\n" {
		t.Errorf("--offline=false: exit code %d, %d lookups, stderr %q", code, f.count(), stderr.String())
	}
}

// TestVersionUsage: a wrong argument is wrong usage (64), with the usage
// on stderr, nothing on stdout, and no lookup; -h prints the usage and
// exits with 0. A stdout that cannot be written gives 1, and no lookup.
func TestVersionUsage(t *testing.T) {
	for _, tt := range []struct {
		args []string
		code int
	}{
		{[]string{"extra"}, exitUsage},
		{[]string{"--offline", "extra"}, exitUsage},
		{[]string{"--bogus"}, exitUsage},
		{[]string{"--offline=maybe"}, exitUsage},
		{[]string{"-h"}, exitOK},
		{[]string{"--help"}, exitOK},
	} {
		f := &fakeVersionCheck{terminal: true, newest: rel(0, 3, 0)}
		var stdout, stderr bytes.Buffer
		code := runVersion(tt.args, "0.2.0", &stdout, &stderr, f.check())
		if code != tt.code || stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage: nodkey version [--offline]") ||
			f.count() != 0 {
			t.Errorf("%q: exit code %d, stdout %q, stderr %q, %d lookups", tt.args, code, stdout.String(), stderr.String(),
				f.count())
		}
	}
	f := &fakeVersionCheck{terminal: true, newest: rel(0, 3, 0)}
	var stderr bytes.Buffer
	if code := runVersion(nil, "0.2.0", failingWriter{}, &stderr, f.check()); code != exitFailure || f.count() != 0 {
		t.Errorf("a stdout that fails: exit code %d, %d lookups; want %d, none", code, f.count(), exitFailure)
	}
}

// TestVersionRealCheck: nodkey version through run uses the real check,
// which looks at the real stdout: a buffer is not a terminal, so it never
// asks GitHub.
func TestVersionRealCheck(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runVersion(nil, "0.2.0", &stdout, &stderr, realVersionCheck); code != exitOK ||
		stdout.String() != "nodkey 0.2.0\n" || stderr.Len() != 0 {
		t.Errorf("exit code %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// TestVersionSecurity: a security release newer than this nodkey, also one
// older than the newest release, gives one red SECURITY UPDATE line. With
// NO_COLOR, or when stderr is not a terminal, it has no colour. A security release that is not newer gives
// the normal line.
func TestVersionSecurity(t *testing.T) {
	sec := func(vs ...nodkeyversion.Release) []release.Security {
		var out []release.Security
		for _, v := range vs {
			out = append(out, release.Security{Version: v})
		}
		return out
	}
	one := "SECURITY UPDATE: nodkey 0.3.1 fixes a security problem. This is nodkey 0.3.0. " +
		"Update now: run nodkey update as root. Checked notes: nodkey update --notes."
	for _, tt := range []struct {
		name     string
		noColor  string
		pipe     bool // stderr is not a terminal
		newest   nodkeyversion.Release
		security []release.Security
		want     string
	}{
		{"security", "", false, rel(0, 3, 1), sec(rel(0, 3, 1)), "\x1b[31m" + one + "\x1b[0m\n"},
		{"stderr not a terminal", "", true, rel(0, 3, 1), sec(rel(0, 3, 1)), one + "\n"},
		{"NO_COLOR", "1", false, rel(0, 3, 1), sec(rel(0, 3, 1)), one + "\n"},
		{"a skipped one", "1", false, rel(0, 3, 2), sec(rel(0, 3, 1)), one + "\n"},
		{"two", "1", false, rel(0, 4, 0), sec(rel(0, 3, 1), rel(0, 4, 0)),
			"SECURITY UPDATE: nodkey 0.3.1 and 0.4.0 fix security problems. This is nodkey 0.3.0. " +
				"Update now: run nodkey update as root. Checked notes: nodkey update --notes.\n"},
		{"not newer", "", false, rel(0, 3, 0), sec(rel(0, 2, 9), rel(0, 3, 0)), "nodkey: this is the newest release\n"},
		{"not newer, a normal newer one", "", false, rel(0, 3, 2), sec(rel(0, 3, 0)), "nodkey: a newer release is out: nodkey 0.3.2;"},
	} {
		t.Setenv("NO_COLOR", tt.noColor)
		var stdout, stderr bytes.Buffer
		f := &fakeVersionCheck{terminal: true, newest: tt.newest, security: tt.security}
		if tt.pipe {
			f.notTerminal = &stderr
		}
		if code := runVersion(nil, "0.3.0", &stdout, &stderr, f.check()); code != exitOK || stdout.String() != "nodkey 0.3.0\n" {
			t.Errorf("%s: exit code %d, stdout %q", tt.name, code, stdout.String())
		}
		if got := stderr.String(); !strings.HasPrefix(got, tt.want) || strings.Count(got, "\n") != 1 {
			t.Errorf("%s: stderr %q, want %q", tt.name, got, tt.want)
		}
	}
}
