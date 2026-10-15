package client

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// checkedDir returns a new directory that passes the checks of the key
// files (DESIGN.md section 14), such as one in $XDG_RUNTIME_DIR. The
// system temporary directory does not pass: everyone can write to it. The
// test is skipped when there is no such directory.
func checkedDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		t.Skip("no XDG_RUNTIME_DIR, so no directory that passes the checks of the key files")
	}
	dir, err := os.MkdirTemp(base, "nodkey-test-")
	if err != nil {
		t.Skipf("cannot make a directory in XDG_RUNTIME_DIR: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G703: dir is the new directory that MkdirTemp made.
	if err := config.CheckParentDirs(filepath.Join(dir, "client.key")); err != nil {
		t.Skipf("XDG_RUNTIME_DIR does not pass the checks of the key files: %v", err)
	}
	return dir
}

// TestRunWithTheRealFiles runs Run as nodkey does, with the client config
// and the TLS key in ~/.config/nodkey/, read by config.LoadClient and
// transport.LoadKeyFile, and the client of transport.NewClient. The
// person denies, so no command starts. A key file that its group can read
// is refused, before any request.
func TestRunWithTheRealFiles(t *testing.T) { // not parallel: it sets HOME
	home := checkedDir(t)
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerDeny)
	dir := filepath.Join(home, ".config", "nodkey")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(keyFile, tb.laptop.file, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("broker = %q\nbroker_pin = %q\ntls_key = \"~/.config/nodkey/client.key\"\n",
		tb.addr, tb.key.pin.String())
	if err := os.WriteFile(filepath.Join(dir, "client.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	// Run marks the test process as not dumpable, as it marks nodkey;
	// make it dumpable again for the other tests.
	t.Cleanup(func() {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 1, 0); errno != 0 {
			t.Errorf("cannot make the test process dumpable again: %v", errno)
		}
	})
	var stderr strings.Builder
	code := Run([]string{"--secret", "GH_TOKEN=github-token", "--", self(t)}, &stderr)
	if d := dumpable(); d != 0 {
		t.Errorf("after Run asked the broker, the process is dumpable (%d)", d)
	}
	if code != exitDenied || len(waitingCodes(stderr.String())) != 1 ||
		lastLine(stderr.String()) != "nodkey: denied (exit 77)" {
		t.Errorf("exit code %d, stderr %q; want the waiting line and a deny", code, safe(stderr.String()))
	}
	if got := eventNames(tb.audit.waitFor(t, 3)); got != "request decision:deny denied:approver" {
		t.Errorf("audit entries: %s", got)
	}
	if err := os.Chmod(keyFile, 0o640); err != nil { //nolint:gosec // G302: the test needs a key file that its group can read.
		t.Fatal(err)
	}
	stderr.Reset()
	code = Run([]string{"--secret", "GH_TOKEN=github-token", "--", self(t)}, &stderr)
	if last := lastLine(stderr.String()); code != exitUnavailable || !strings.Contains(last, "tls_key") ||
		!strings.Contains(last, "group has access") {
		t.Errorf("with a key file that its group can read: exit code %d, stderr %q", code, safe(stderr.String()))
	}
	if n := len(tb.audit.all()); n != 3 {
		t.Errorf("the broker has %d audit entries, want 3: the refused key sent a request", n)
	}
}

// TestRunPhysicalWorkingDirectory: the working directory is a symbolic
// link, and $PWD names it through the link, as a shell sets it after
// "cd link". For "../tool", a shell and exec.LookPath use the parent of the
// real directory. nodkey run shows and runs that same file: it starts from
// the real working directory, and does not clean the path. (From the
// second security review of issue #12: filepath.Abs took the tool next to
// the link.)
func TestRunPhysicalWorkingDirectory(t *testing.T) { // not parallel: it changes the working directory
	sh := needProgram(t, "sh")
	base := t.TempDir()
	sub := filepath.Join(base, "real", "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	physical, logical := filepath.Join(base, "real", "tool"), filepath.Join(base, "tool")
	for path, text := range map[string]string{physical: "physical", logical: "logical"} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+text+"\n"), 0o700); err != nil { //nolint:gosec // G306: the file must look like a program.
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(sub, link); err != nil {
		t.Fatal(err)
	}
	// t.Chdir sets PWD to the path through the link, as a shell does.
	t.Chdir(link)
	out, err := exec.CommandContext(t.Context(), sh, "-c", "../tool").Output() //nolint:gosec // G204: the test runs sh, to see which tool a shell runs.
	if err != nil || strings.TrimSpace(string(out)) != "physical" {
		t.Fatalf("a shell runs ../tool as %q, %v; want the tool next to the real directory", out, err)
	}
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	fx := &fakeExec{}
	code, stderr := runIn(t.Context(), testRunner(tb.client(t), nil, fx), "--secret", "GH_TOKEN=github-token", "--",
		"../tool", "arg")
	calls := fx.ran()
	if code != exitOK || len(calls) != 1 {
		t.Fatalf("exit code %d, stderr %q", code, safe(stderr))
	}
	real, err := filepath.EvalSymlinks(sub)
	if err != nil {
		t.Fatal(err)
	}
	if want := real + "/../tool"; calls[0].path != want || !slices.Equal(calls[0].argv, []string{"../tool", "arg"}) {
		t.Errorf("runs %q with %q; want %q with the arguments as typed", calls[0].path, calls[0].argv, want)
	}
	runs, err := os.Stat(calls[0].path)
	if err != nil {
		t.Fatal(err)
	}
	if want, err := os.Stat(physical); err != nil || !os.SameFile(runs, want) {
		t.Errorf("nodkey run runs %q, which is not the tool that a shell runs (%v)", calls[0].path, err)
	}
	if got := tb.waitAsked(t, 1)[0].Prompt.Claim.Command; !strings.HasSuffix(got, "/real/sub/../tool arg") {
		t.Errorf("the message shows the command %q; want the path that runs, %s", got, calls[0].path)
	}
}
