package client

import (
	"bufio"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestClaimedContextRealProcess reads the claimed context of a real
// process from /proc: a sleep that a shell started, with NODKEY_REASON in
// its own environment. Its parents are the shell, the test, and the
// program that started the test. The reason of the shell and of the test
// does not count, and nothing else of the environment is returned.
func TestClaimedContextRealProcess(t *testing.T) {
	t.Parallel()
	sh, sleep := needProgram(t, "sh"), needProgram(t, "sleep")
	canary := madeUp("canary")
	script := `NODKEY_REASON="from the sleep" NODKEY_CANARY="$1" "$0" 60 & echo "$!"; wait`
	cmd := exec.CommandContext(t.Context(), sh, "-c", script, sleep, canary) //nolint:gosec // G204: the test runs sleep through sh.
	cmd.Env = append(withEnv(os.Environ(), nil), "NODKEY_REASON=from the shell", "OTHER="+canary)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})
	// The shell forks, and the child then runs sleep.
	waitFor(t, "the sleep to start", func() bool {
		argv := realCommandLine(t, pid)
		return len(argv) > 0 && argv[0] == sleep
	})
	proc := procFS{root: procDir}
	commands, reason := proc.claimedContext(int32(pid)) //nolint:gosec // G115: a process ID fits in an int32.
	want := [][]string{{sleep, "60"}, {sh, "-c", script, sleep, canary}, os.Args}
	if parent := realCommandLine(t, os.Getppid()); parent != nil {
		want = append(want, parent)
	}
	if !slices.EqualFunc(commands, want, slices.Equal) {
		t.Errorf("the command lines are %q\nwant %q", safe(strings.Join(flat(commands), " | ")),
			safe(strings.Join(flat(want), " | ")))
	}
	if reason != "from the sleep" {
		t.Errorf("the reason is %q, want the one of the sleep", safe(reason))
	}
}

// realCommandLine returns the command line of process pid, read here
// without procFS, or nil when there is none.
func realCommandLine(t *testing.T, pid int) []string {
	t.Helper()
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
}

// flat joins each command line with spaces.
func flat(commands [][]string) []string {
	out := make([]string, len(commands))
	for i, c := range commands {
		out[i] = strings.Join(c, " ")
	}
	return out
}

// TestRootPinsTheProcess: openProcess opens /proc/PID once, and the files
// come only from that process. The links of /proc/PID, such as cwd, exe
// and root, are never followed out of it. When the process ends, its
// files cannot be read any more, also not those of a new process with the
// same ID. (From the security review of issue #13.)
func TestRootPinsTheProcess(t *testing.T) {
	t.Parallel()
	sleep := needProgram(t, "sleep")
	cmd := exec.CommandContext(t.Context(), sleep, "60") //nolint:gosec // G204: the test runs sleep.
	cmd.Env = []string{"NODKEY_REASON=from the sleep"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended := false
	t.Cleanup(func() {
		if !ended {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	pid := cmd.Process.Pid
	waitFor(t, "the sleep to start", func() bool {
		argv := realCommandLine(t, pid)
		return len(argv) > 0 && argv[0] == sleep
	})
	pr, err := procFS{root: procDir}.openProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer pr.close()
	if argv, ok := pr.commandLine(); !ok || argv[0] != sleep {
		t.Fatalf("the command line is %q, %v", argv, ok)
	}
	if r := pr.reason(); r != "from the sleep" {
		t.Fatalf("the reason is %q", r)
	}
	// fd/0, fd/1 and map_files name files of the process itself; the
	// others lead out of /proc/PID.
	for _, name := range []string{"cwd", "exe", "root", "root/etc/hostname", "cwd/x", "../1/cmdline",
		"/etc/hostname", "task/" + strconv.Itoa(pid) + "/root/etc/hostname"} {
		if f, err := pr.dir.Open(name); err == nil {
			_ = f.Close()
			t.Errorf("%s: opened through the directory of the process", name)
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	ended = true
	argv, ok := pr.commandLine()
	_, hasParent := pr.parent()
	if reason := pr.reason(); ok || hasParent || reason != "" {
		t.Errorf("after the process ended: the command line %q (%v), a parent %v, the reason %q", argv, ok, hasParent,
			reason)
	}
}
