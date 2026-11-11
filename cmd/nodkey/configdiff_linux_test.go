package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// The tests of nodkey broker config-diff run it in this process. It sets
// CREDENTIALS_DIRECTORY, so they are not parallel (see brokercheck).

func runDiff(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runBroker(append([]string{"config-diff"}, args...), &out, &errOut)
	return code, out.String(), errOut.String()
}

// diffDirs makes a directory "new" next to the config of e, with a copy
// of broker.toml and known_hosts, and returns the old and the new one.
func diffDirs(t *testing.T, e *brokerEnv) (oldDir, newDir string) {
	t.Helper()
	oldDir = filepath.Dir(e.cfgPath)
	newDir = filepath.Join(e.dir, "new")
	if err := os.Mkdir(newDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"broker.toml", "known_hosts"} {
		data, err := os.ReadFile(filepath.Join(oldDir, name)) //nolint:gosec // G304: the test's own file.
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(newDir, name), data, 0o600)
	}
	return oldDir, newDir
}

// TestConfigDiff: the exit codes and the lines of the full form, for
// directories and files. It runs as a user that is not root, without the
// credentials of the config.
func TestConfigDiff(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if os.Getuid() == 0 {
		t.Skip("runs as root; this test is for a user that is not root")
	}
	e := newBrokerEnv(t, brokerOptions{})
	oldDir, newDir := diffDirs(t, e)
	cfg := filepath.Join(newDir, "broker.toml")

	// Only a comment and spaces: no change.
	data, err := os.ReadFile(cfg) //nolint:gosec // G304: the test's own file.
	if err != nil {
		t.Fatal(err)
	}
	data0 := slices.Clone(data)
	writeTestFile(t, cfg, append([]byte("# a comment\n\n"), bytes.ReplaceAll(data, []byte(" = "), []byte("   =  "))...), 0o600)
	code, out, errOut := runDiff(t, oldDir, newDir)
	if code != exitOK || out != "no change\n" || errOut != "" {
		t.Fatalf("no change: exit %d, stdout %q, stderr %q", code, out, errOut)
	}

	// A change that widens and one that narrows.
	data = bytes.Replace(data, []byte("ask = \"always\"\nhosts = [\"web-1\"]"), []byte("ask = \"always\"\nhosts = []"), 1)
	data = bytes.Replace(data, []byte("[secret.db-password]"), []byte("[secret.gone]"), 1)
	data = bytes.Replace(data, []byte("ask = \"never\"\nnotify = false"), []byte("ask = \"always\""), 1)
	writeTestFile(t, cfg, data, 0o600)
	code, out, errOut = runDiff(t, oldDir, newDir)
	if code != exitFailure || errOut != "" {
		t.Fatalf("a change: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	for _, want := range []string{
		"⚠ SSH key \"deploy\": may now log in to every host in known_hosts\n",
		"  secret \"db-password\": removed\n",
		"⚠ secret \"gone\": new secret in store \"vault\", ask = \"always\"\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout %q has no %q", out, want)
		}
	}
	// A file for OLD and a directory for NEW: the same.
	if code, out2, _ := runDiff(t, e.cfgPath, newDir); code != exitFailure || out2 != out {
		t.Errorf("file and directory: exit %d, stdout %q, want %q", code, out2, out)
	}

	// Two files: each reads the known_hosts next to it, not the one at
	// the path in the config. A new host key in NEW's known_hosts shows.
	newKH := filepath.Join(newDir, "known_hosts")
	saved, err := os.ReadFile(newKH) //nolint:gosec // G304: the test's own file.
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, cfg, data0, 0o600)
	if code, out, _ := runDiff(t, e.cfgPath, cfg); code != exitOK || out != "no change\n" {
		t.Fatalf("two files, the same: exit %d, stdout %q", code, out)
	}
	host := newHostSigner(t)
	writeTestFile(t, newKH, append(slices.Clone(saved), []byte("db-9 "+string(ssh.MarshalAuthorizedKey(host.PublicKey())))...), 0o600)
	if code, out, _ := runDiff(t, e.cfgPath, cfg); code != exitFailure || !strings.Contains(out, "⚠ known_hosts: new host \"db-9\"") {
		t.Fatalf("two files, a new host next to NEW: exit %d, stdout %q", code, out)
	}
	writeTestFile(t, newKH, saved, 0o600)
	writeTestFile(t, cfg, data, 0o600)

	// A config that cannot be read, or is not valid: exit 2.
	for _, args := range [][]string{
		{filepath.Join(e.dir, "missing"), newDir},
		{oldDir, filepath.Join(newDir, "missing.toml")},
	} {
		if code, out, errOut := runDiff(t, args...); code != exitDiffUnreadable || out != "" ||
			strings.Count(errOut, "\n") != 1 || !strings.Contains(errOut, "that exists") {
			t.Errorf("config-diff %q: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	writeTestFile(t, cfg, append(data, "\n[client.bad]\npin = \"not-a-pin\"\n"...), 0o600)
	if code, _, errOut := runDiff(t, oldDir, newDir); code != exitDiffUnreadable || !strings.Contains(errOut, "NEW: config") ||
		!strings.Contains(errOut, "[client.bad] pin") || !strings.Contains(errOut, "nodkey broker check --files") {
		t.Errorf("an invalid NEW: exit %d, stderr %q", code, errOut)
	}
	// known_hosts of NEW comes from its directory.
	writeTestFile(t, cfg, data, 0o600)
	if err := os.Remove(filepath.Join(newDir, "known_hosts")); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runDiff(t, oldDir, newDir); code != exitDiffUnreadable || !strings.Contains(errOut, filepath.Join(newDir, "known_hosts")) {
		t.Errorf("NEW without known_hosts: exit %d, stderr %q", code, errOut)
	}
}

// TestConfigDiffUsage: wrong usage exits 64 with one line.
func TestConfigDiffUsage(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	for _, args := range [][]string{{}, {"a"}, {"a", "b", "c"}, {"--nope", "a", "b"}, {"--max-chars", "10", "a", "b"}} {
		code, out, errOut := runDiff(t, args...)
		if code != exitUsage || out != "" || strings.Count(errOut, "\n") != 1 ||
			!strings.HasPrefix(errOut, "nodkey broker config-diff: ") {
			t.Errorf("config-diff %q: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
	if code, out, _ := runDiff(t, "--help"); code != exitOK || !strings.HasPrefix(out, "Usage: nodkey broker config-diff") {
		t.Errorf("--help: exit %d, stdout %q", code, out)
	}
}

// TestConfigDiffShort: the short form keeps every line that widens when
// it cuts, or says that they do not fit, and is never longer than
// --max-chars.
func TestConfigDiffShort(t *testing.T) {
	lines := func(n int, wide bool) ([]string, []bool) {
		var l []string
		var w []bool
		for i := range n {
			if wide {
				l = append(l, fmt.Sprintf("⚠ change %d that widens access, with some more words to fill the line", i))
			} else {
				l = append(l, fmt.Sprintf("  change %d that narrows access, with some more words to fill the line", i))
			}
			w = append(w, wide)
		}
		return l, w
	}
	narrow, nw := lines(40, false)
	wide, ww := lines(5, true)
	// The narrowing lines come first in the input; the short form puts
	// the widening lines first.
	all, allW := append(narrow, wide...), append(nw, ww...)

	got := shortForm(all, allW, 100000)
	if len(got) != len(all) || got[0] != wide[0] {
		t.Fatalf("everything fits: %d lines, first %q", len(got), got[0])
	}
	got = shortForm(all, allW, 1000)
	if size(got) > 1000 {
		t.Errorf("size %d > 1000", size(got))
	}
	for i, w := range wide {
		if got[i] != w {
			t.Fatalf("line %d is %q, want the widening line %q", i, got[i], w)
		}
	}
	last := got[len(got)-1]
	if n := len(all) - (len(got) - 1); !strings.HasPrefix(last, fmt.Sprintf("and %d more;", n)) {
		t.Errorf("last line %q, want \"and %d more\"", last, n)
	}

	many, mw := lines(60, true)
	got = shortForm(append(many, narrow...), append(mw, nw...), 1000)
	if len(got) != 1 || !strings.HasPrefix(got[0], "⚠ 60 changes widen access, and they do not fit here") ||
		utf8.RuneCountInString(got[0]) > 1000 {
		t.Errorf("widening lines that do not fit: %q", got)
	}
	// At the smallest --max-chars, the line still fits.
	if got = shortForm(append(many, narrow...), append(mw, nw...), minShortChars); size(got) > minShortChars {
		t.Errorf("size %d > %d: %q", size(got), minShortChars, got)
	}
}
