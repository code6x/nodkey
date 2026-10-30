package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/code6x/nodkey"
)

// scriptRun is what nodkey update gave to the install script.
type scriptRun struct {
	calls  int
	script string
	args   []string
	env    []string
}

// fakeUpdate replaces the parts of nodkey update for one test: the
// effective user ID, the path of the program, and the run of the script,
// which returns code. It returns what the script got.
func fakeUpdate(t *testing.T, euid int, exe string, code int) *scriptRun {
	t.Helper()
	oldEuid, oldExe, oldRun := geteuid, executable, runInstallScript
	t.Cleanup(func() { geteuid, executable, runInstallScript = oldEuid, oldExe, oldRun })
	got := &scriptRun{}
	geteuid = func() int { return euid }
	executable = func() (string, error) { return exe, nil }
	runInstallScript = func(script string, args, env []string, _, _ io.Writer) int {
		got.calls++
		got.script, got.args, got.env = script, args, env
		return code
	}
	return got
}

// installedNodkey makes a file named nodkey in a directory of its own, and
// a link to it in another directory, as /usr/local/bin/nodkey could be.
// It returns the path of the link and the directory of the file.
func installedNodkey(t *testing.T) (link, dir string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(root, "opt")
	link = filepath.Join(root, "bin", "nodkey")
	for _, d := range []string{dir, filepath.Dir(link)} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "nodkey"), []byte("a made-up program\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nodkey"), link); err != nil {
		t.Fatal(err)
	}
	return link, dir
}

func TestUpdateUsage(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		code int
		want string // a part of stderr
	}{
		{"an argument", []string{"update", "0.2.0"}, exitUsage, ""},
		{"an unknown flag", []string{"update", "--bin-dir", "/tmp"}, exitUsage, `unknown option "bin-dir"`},
		{"no version", []string{"update", "--version"}, exitUsage, `option "version" needs a value`},
		{"an empty version", []string{"update", "--version="}, exitUsage, "want X.Y.Z, such as 0.2.0"},
		{"a version with two numbers", []string{"update", "--version", "0.2"}, exitUsage, "want X.Y.Z"},
		{"a version with a v", []string{"update", "--version", "v0.2.0"}, exitUsage, "want X.Y.Z"},
		{"a version with a leading zero", []string{"update", "--version", "0.02.0"}, exitUsage, "want X.Y.Z"},
		{"a version that is a flag", []string{"update", "--version", "--gh"}, exitUsage, "want X.Y.Z"},
		{"two versions", []string{"update", "--version", "0.2.0", "--version", "0.3.0"}, exitUsage, "give it once"},
		{"a gh that is not absolute", []string{"update", "--gh", "gh"}, exitUsage, "want an absolute path"},
		{"an empty gh", []string{"update", "--gh="}, exitUsage, "want an absolute path"},
		{"two gh", []string{"update", "--gh", "/usr/bin/gh", "--gh", "/usr/local/bin/gh"}, exitUsage, "give it once"},
		{"a value for --reinstall", []string{"update", "--reinstall=maybe"}, exitUsage, `bad value for option`},
		{"a value for --notes", []string{"update", "--notes=maybe"}, exitUsage, `bad value for option`},
		{"--notes with --reinstall", []string{"update", "--notes", "--reinstall"}, exitUsage, "does not go with --reinstall"},
		{"-h", []string{"update", "-h"}, exitOK, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := fakeUpdate(t, 0, "/usr/local/bin/nodkey", exitOK)
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, strings.NewReader(""), &stdout, &stderr); code != tt.code {
				t.Errorf("exit code %d, want %d", code, tt.code)
			}
			if tt.code == exitOK {
				if !strings.Contains(stderr.String(), "Usage: nodkey update [--version X.Y.Z] [--gh PATH] [--reinstall | --notes]") {
					t.Errorf("stderr = %q, want the usage", stderr.String())
				}
			} else if !strings.HasPrefix(stderr.String(), "nodkey update: ") || !strings.Contains(stderr.String(), tt.want) ||
				strings.Count(stderr.String(), "\n") != 1 {
				t.Errorf("stderr = %q, want one usage line with %q", stderr.String(), tt.want)
			}
			if stdout.Len() != 0 || got.calls != 0 {
				t.Errorf("stdout %q, %d runs of the script; want nothing", stdout.String(), got.calls)
			}
		})
	}
	var stdout bytes.Buffer
	if run([]string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); !strings.Contains(stdout.String(), "\n  update [--version X.Y.Z] [--gh PATH] [--reinstall | --notes]\n") {
		t.Errorf("help does not list update: %q", stdout.String())
	}
}

// TestUpdateNeedsRoot: as another user, nodkey update says to run it as root,
// and runs nothing.
func TestUpdateNeedsRoot(t *testing.T) {
	got := fakeUpdate(t, 1000, "/usr/local/bin/nodkey", exitOK)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"update"}, strings.NewReader(""), &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code %d, want %d", code, exitFailure)
	}
	if want := "nodkey: nodkey update must run as root: run it as root (exit 1)\n"; stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
	if stdout.Len() != 0 || got.calls != 0 {
		t.Errorf("stdout %q, %d runs of the script; want nothing", stdout.String(), got.calls)
	}
}

// TestUpdateRunsTheBuiltInScript: as root, nodkey update runs install.sh,
// as it is built in, with --bin-dir set to the directory of the file that
// the program runs from, behind links, with the flags that are given, and
// with a fixed environment.
func TestUpdateRunsTheBuiltInScript(t *testing.T) {
	file, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if nodkey.InstallScript != string(file) {
		t.Fatal("the built-in script is not install.sh")
	}
	// The files first: t.TempDir uses TMPDIR, which the test changes.
	link, dir := installedNodkey(t)
	// The environment of nodkey, as sudo -E could give it: only the
	// proxy variables reach the script.
	for name, value := range map[string]string{
		"TAR_OPTIONS": "--to-command=/nonexistent", "LD_PRELOAD": "/nonexistent/lib.so", "TMPDIR": "/nonexistent/tmp",
		"PATH": "/nonexistent/bin:/usr/bin", "HOME": "/nonexistent/home", "GH_TOKEN": "made-up-token",
		"HTTPS_PROXY": "http://192.0.2.1:3128", "no_proxy": "example.com",
	} {
		t.Setenv(name, value)
	}
	// Unset, and set back at the end of the test (t.Setenv).
	for _, name := range []string{"https_proxy", "NO_PROXY"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	wantEnv := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=/root",
		"HTTPS_PROXY=http://192.0.2.1:3128", "no_proxy=example.com"}

	for _, tt := range []struct {
		args []string
		want []string
	}{
		{nil, []string{"--bin-dir", dir}},
		{[]string{"--version", "0.2.0"}, []string{"--bin-dir", dir, "--version", "0.2.0"}},
		{[]string{"-version=1.10.0"}, []string{"--bin-dir", dir, "--version", "1.10.0"}},
		{[]string{"--version", "0.0.0"}, []string{"--bin-dir", dir, "--version", "0.0.0"}},
		{[]string{"--gh", "/usr/bin/gh"}, []string{"--bin-dir", dir, "--gh", "/usr/bin/gh"}},
		{[]string{"--reinstall"}, []string{"--bin-dir", dir, "--reinstall"}},
		{[]string{"--reinstall=false"}, []string{"--bin-dir", dir}},
		{[]string{"--reinstall", "--gh", "/usr/bin/gh", "--version", "0.2.0"},
			[]string{"--bin-dir", dir, "--version", "0.2.0", "--gh", "/usr/bin/gh", "--reinstall"}},
		{[]string{"--notes"}, []string{"--bin-dir", dir, "--notes"}},
		{[]string{"--notes", "--version", "0.3.0"}, []string{"--bin-dir", dir, "--version", "0.3.0", "--notes"}},
	} {
		got := fakeUpdate(t, 0, link, exitOK)
		var stdout, stderr bytes.Buffer
		if code := run(append([]string{"update"}, tt.args...), strings.NewReader(""), &stdout, &stderr); code != exitOK {
			t.Errorf("%q: exit code %d, want 0; stderr %q", tt.args, code, stderr.String())
		}
		if got.calls != 1 || got.script != string(file) {
			t.Errorf("%q: %d runs of the script; want 1, of install.sh", tt.args, got.calls)
		}
		if !slices.Equal(got.args, tt.want) {
			t.Errorf("%q: the script got %q, want %q", tt.args, got.args, tt.want)
		}
		if !slices.Equal(got.env, wantEnv) {
			t.Errorf("%q: the script got the environment %q, want %q", tt.args, got.env, wantEnv)
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Errorf("%q: stdout %q, stderr %q; want nothing", tt.args, stdout.String(), stderr.String())
		}
	}
}

// TestUpdatePassesTheExitCode: nodkey update exits with the exit code of
// the script.
func TestUpdatePassesTheExitCode(t *testing.T) {
	link, _ := installedNodkey(t)
	for _, code := range []int{exitOK, exitFailure, exitUsage, 3} {
		fakeUpdate(t, 0, link, code)
		if got := run([]string{"update"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); got != code {
			t.Errorf("exit code %d, want %d from the script", got, code)
		}
	}
}

// TestUpdateRefusesOtherFiles: nodkey update stops when it cannot find
// the file it runs from, or when that file is not named nodkey: the script
// would replace another file then.
func TestUpdateRefusesOtherFiles(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "nodkey-0.1.0")
	if err := os.WriteFile(other, []byte("a made-up program\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "nodkey")
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		exe  string
		want string
	}{
		{other, "nodkey update replaces only a file named nodkey, and this program is " + other + " (exit 1)\n"},
		{link, "nodkey update replaces only a file named nodkey, and this program is " + other + " (exit 1)\n"},
		{filepath.Join(root, "gone", "nodkey"), "cannot find the file of this program: "},
	} {
		got := fakeUpdate(t, 0, tt.exe, exitOK)
		var stderr bytes.Buffer
		if code := run([]string{"update"}, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != exitFailure {
			t.Errorf("%s: exit code %d, want %d", tt.exe, code, exitFailure)
		}
		if !strings.HasPrefix(stderr.String(), "nodkey: ") || !strings.Contains(stderr.String(), tt.want) {
			t.Errorf("%s: stderr = %q, want %q", tt.exe, stderr.String(), tt.want)
		}
		if got.calls != 0 {
			t.Errorf("%s: the script ran", tt.exe)
		}
	}
	got := fakeUpdate(t, 0, "", exitOK)
	executable = func() (string, error) { return "", errors.New("no /proc") }
	var stderr bytes.Buffer
	if code := run([]string{"update"}, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != exitFailure || got.calls != 0 {
		t.Errorf("exit code %d, %d runs; want %d and no run", code, got.calls, exitFailure)
	}
	if want := "nodkey: cannot find the file of this program: no /proc (exit 1)\n"; stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
}

// TestRunScript runs scripts with /bin/sh as nodkey update does: $0 is
// nodkey-install, the arguments come as they are, the environment is only
// the given one, stdin is /dev/null, stdout and stderr are those of
// nodkey, and the exit code comes back.
func TestRunScript(t *testing.T) {
	t.Setenv("TAR_OPTIONS", "--to-command=/nonexistent")
	var stdout, stderr bytes.Buffer
	code := runScript(`printf '%s|' "$0" "$@" "${A-unset}" "${TAR_OPTIONS-unset}"; echo to-stderr >&2; if read -r line; then exit 9; fi; exit 3`,
		[]string{"--bin-dir", "/a dir/with $HOME", "--version", "0.2.0"}, []string{"A=1"}, &stdout, &stderr)
	if code != 3 {
		t.Errorf("exit code %d, want 3 (9 means stdin was not empty)", code)
	}
	if want := "nodkey-install|--bin-dir|/a dir/with $HOME|--version|0.2.0|1|unset|"; stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
	if stderr.String() != "to-stderr\n" {
		t.Errorf("stderr = %q", stderr.String())
	}

	stderr.Reset()
	if code := runScript("exit 0", nil, scriptEnv(), &bytes.Buffer{}, &stderr); code != exitOK || stderr.Len() != 0 {
		t.Errorf("exit 0: exit code %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	if code := runScript("kill -TERM $$", nil, scriptEnv(), &bytes.Buffer{}, &stderr); code != exitFailure {
		t.Errorf("a script that a signal stops: exit code %d, want %d", code, exitFailure)
	}
	if want := "nodkey: a signal stopped the install script (exit 1)\n"; stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
}
