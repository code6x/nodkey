package main

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The environment of the child processes of the tests of nodkey try.
const (
	tryChildMode    = "NODKEY_TEST_TRY"         // "try" or "run"
	tryChildArgs    = "NODKEY_TEST_TRY_ARGS"    // the arguments of nodkey try run, split by tryArgSep
	tryChildTimeout = "NODKEY_TEST_TRY_TIMEOUT" // tryTimeout, as time.ParseDuration reads it
	tryArgSep       = "\x1f"
)

// TestTryChild runs nodkey try or nodkey try run as the child of a test.
func TestTryChild(t *testing.T) {
	switch os.Getenv(tryChildMode) {
	case "try":
		args := []string{"try"}
		if a := os.Getenv(tryChildArgs); a != "" {
			args = append(args, strings.Split(a, tryArgSep)...)
		}
		if s := os.Getenv(tryChildTimeout); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				t.Fatal(err)
			}
			tryTimeout = d
		}
		os.Exit(run(args, os.Stdin, os.Stdout, os.Stderr))
	case "run":
		args := strings.Split(os.Getenv(tryChildArgs), tryArgSep)
		os.Exit(run(append([]string{"try", "run"}, args...), os.Stdin, os.Stdout, os.Stderr))
	default:
		t.Skip("runs only as the child of the tests of nodkey try")
	}
}

// homeConfig is the client config in the home directory of the tests. It
// is not valid, so a run that read it would fail with a config error.
const homeConfig = "this is not the config of the trial\n"

// tryEnv is a trial in a child process, with its own home, runtime,
// temporary and working directories.
type tryEnv struct {
	t                        *testing.T
	home, runtime, tmp, work string
	out                      string // where the commands of the tests write the value they got
	cmd                      *exec.Cmd
	in                       io.WriteCloser
	log                      *lineLog
	exited                   chan struct{}
	waitErr                  error
	extra                    []string // more environment of nodkey try, such as the fake Telegram's proxy
}

// newTryEnv makes the directories of a trial, without starting it.
func newTryEnv(t *testing.T) *tryEnv {
	t.Helper()
	base := privateTestDir(t)
	e := &tryEnv{t: t, home: filepath.Join(base, "home"), runtime: filepath.Join(base, "run"),
		tmp: filepath.Join(base, "tmp"), work: filepath.Join(base, "work"), out: t.TempDir()}
	for _, d := range []string{e.home, e.runtime, e.tmp, e.work, filepath.Join(e.home, ".config", "nodkey")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(e.home, ".config", "nodkey", "client.toml"), []byte(homeConfig), 0o600)
	return e
}

// env is the environment of a child process: only the directories of
// the trial, and PATH for sh.
func (e *tryEnv) env(mode string, extra ...string) []string {
	env := []string{tryChildMode + "=" + mode, "HOME=" + e.home, "XDG_RUNTIME_DIR=" + e.runtime,
		"TMPDIR=" + e.tmp, "PATH=" + os.Getenv("PATH")}
	for _, name := range []string{"GORACE", "GOCOVERDIR"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return append(env, extra...)
}

// start starts nodkey try, and waits until it is ready.
func (e *tryEnv) start(timeout time.Duration) {
	t := e.t
	t.Helper()
	e.startNoWait(timeout)
	e.log.wait(t, "Press Ctrl-C to end the trial")
}

// startNoWait starts nodkey try.
func (e *tryEnv) startNoWait(timeout time.Duration) {
	t := e.t
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTryChild$") //nolint:gosec // G204: the test runs its own binary again.
	cmd.Env = e.env("try", append([]string{tryChildTimeout + "=" + timeout.String()}, e.extra...)...)
	cmd.Dir = e.work
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	e.cmd, e.in, e.log, e.exited = cmd, in, newLineLog(), make(chan struct{})
	go func() {
		e.log.readFrom(out)
		e.waitErr = cmd.Wait()
		close(e.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-e.exited
	})
}

// answer types line in the terminal of nodkey try.
func (e *tryEnv) answer(line string) {
	e.t.Helper()
	if _, err := io.WriteString(e.in, line+"\n"); err != nil {
		e.t.Fatal(err)
	}
}

// exitCode waits until nodkey try ends, and returns its exit code.
func (e *tryEnv) exitCode() int {
	e.t.Helper()
	select {
	case <-e.exited:
	case <-time.After(brokerWait):
		e.t.Fatalf("nodkey try did not end; its output:\n%s", e.log.text())
	}
	var ee *exec.ExitError
	if errors.As(e.waitErr, &ee) {
		return ee.ExitCode()
	}
	if e.waitErr != nil {
		e.t.Fatal(e.waitErr)
	}
	return 0
}

// tryRun is a nodkey try run in a child process.
type tryRun struct {
	stderr bytes.Buffer
	done   chan struct{}
	code   int
}

// run starts nodkey try run with args.
func (e *tryEnv) run(args ...string) *tryRun {
	t := e.t
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTryChild$") //nolint:gosec // G204: the test runs its own binary again.
	cmd.Env = e.env("run", tryChildArgs+"="+strings.Join(args, tryArgSep))
	cmd.Dir = e.work
	r := &tryRun{done: make(chan struct{})}
	cmd.Stderr = &r.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(r.done)
		err := cmd.Wait()
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			r.code = ee.ExitCode()
		case err != nil:
			r.code = -1
		}
	}()
	return r
}

// wait waits until the run ends, and returns its exit code and stderr.
func (r *tryRun) wait(t *testing.T) (int, string) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(brokerWait):
		t.Fatal("nodkey try run did not end")
	}
	return r.code, r.stderr.String()
}

// demoArgs are the arguments of a run that writes the value of demo-token
// to the file "value" in e.out.
func (e *tryEnv) demoArgs() []string {
	return []string{"--secret", "DEMO_TOKEN=demo-token", "--", "sh", "-c",
		`printf %s "$DEMO_TOKEN" > "$0"`, filepath.Join(e.out, "value")}
}

// value returns the value that the command of demoArgs got.
func (e *tryEnv) value() string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.out, "value"))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

// checkClientLines checks that each line of nodkey try run says TRY MODE.
func checkClientLines(t *testing.T, stderr string) {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSuffix(stderr, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, "TRY MODE ") {
			t.Errorf("a line of nodkey try run does not say TRY MODE: %q", line)
		}
	}
}

// stopAndCheck sends sig to nodkey try, and checks that it ended with
// exit code 0, removed its directory, wrote nothing outside of it, and
// said what a real setup adds.
func (e *tryEnv) stopAndCheck(sig syscall.Signal) {
	t := e.t
	t.Helper()
	if err := e.cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	if code := e.exitCode(); code != exitOK {
		t.Fatalf("exit code %d after %v, want 0; output:\n%s", code, sig, e.log.text())
	}
	e.checkClean()
	if !e.log.has("docs/setup.md") {
		t.Errorf("the last lines do not point to docs/setup.md:\n%s", e.log.text())
	}
}

// checkClean checks that the trial's directory is gone, and that nothing
// was written in the home, temporary or working directory.
func (e *tryEnv) checkClean() {
	t := e.t
	t.Helper()
	for _, d := range []string{e.runtime, e.tmp, e.work} {
		if names := dirNames(t, d); len(names) > 0 {
			t.Errorf("%s holds %q after the trial, want nothing", d, names)
		}
	}
	if names := dirNames(t, e.home); !slices.Equal(names, []string{".config", ".config/nodkey", ".config/nodkey/client.toml"}) {
		t.Errorf("the home directory holds %q after the trial", names)
	}
	if b, err := os.ReadFile(filepath.Join(e.home, ".config", "nodkey", "client.toml")); err != nil || string(b) != homeConfig {
		t.Errorf("the client config in the home directory changed: %q, %v", b, err)
	}
}

// dirNames returns the paths of everything under dir, relative to dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir {
			rel, _ := filepath.Rel(dir, path)
			names = append(names, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// checkValue checks that the command got a TRY- value, and that nodkey
// try and nodkey try run never printed it.
func (e *tryEnv) checkValue(stderr string) {
	t := e.t
	t.Helper()
	v := e.value()
	if !strings.HasPrefix(v, tryValuePrefix) || len(v) < len(tryValuePrefix)+16 {
		t.Fatalf("the command got a value of %d bytes that is not a TRY- value", len(v))
	}
	if strings.Contains(e.log.text(), v) || strings.Contains(stderr, v) {
		t.Fatal("nodkey try or nodkey try run printed the value")
	}
}

func TestTryApproveOnce(t *testing.T) {
	e := newTryEnv(t)
	e.start(time.Minute)
	r := e.run(e.demoArgs()...)
	e.log.wait(t, "1 = Approve once, 2 = Approve 5 min, 3 = Deny")
	if !e.log.has("TRY MODE: request ") || !e.log.has("secrets: demo-token") {
		t.Fatalf("the message does not say TRY MODE or the secret:\n%s", e.log.text())
	}
	e.answer("1")
	code, stderr := r.wait(t)
	if code != 0 {
		t.Fatalf("nodkey try run: exit code %d, want 0; stderr:\n%s", code, stderr)
	}
	checkClientLines(t, stderr)
	e.checkValue(stderr)
	e.log.wait(t, ": approved once")

	// Once means once: the next run asks again, and Deny ends it.
	r = e.run(e.demoArgs()...)
	e.log.waitCount(t, "1 = Approve once", 2)
	e.answer("3")
	if code, stderr := r.wait(t); code != 77 {
		t.Fatalf("nodkey try run after Deny: exit code %d, want 77; stderr:\n%s", code, stderr)
	}
	e.stopAndCheck(syscall.SIGINT)
}

func TestTryApproveWindow(t *testing.T) {
	e := newTryEnv(t)
	e.start(time.Minute)
	r := e.run(e.demoArgs()...)
	e.log.wait(t, "2 = Approve 5 min")
	e.answer("2")
	code, stderr := r.wait(t)
	if code != 0 {
		t.Fatalf("nodkey try run: exit code %d, want 0; stderr:\n%s", code, stderr)
	}
	e.checkValue(stderr)
	e.log.wait(t, ": approved for 5 min")
	// In the window, the next run needs no answer.
	code, stderr = e.run(e.demoArgs()...).wait(t)
	if code != 0 {
		t.Fatalf("nodkey try run in the window: exit code %d, want 0; stderr:\n%s", code, stderr)
	}
	checkClientLines(t, stderr)
	if n := e.log.count("1 = Approve once"); n != 1 {
		t.Fatalf("%d messages, want 1: the window did not count", n)
	}
	e.stopAndCheck(syscall.SIGTERM)
}

func TestTryStopsOnHangup(t *testing.T) {
	e := newTryEnv(t)
	e.start(time.Minute)
	e.stopAndCheck(syscall.SIGHUP)
}

func TestTryDeny(t *testing.T) {
	e := newTryEnv(t)
	e.start(time.Minute)
	r := e.run(e.demoArgs()...)
	e.log.wait(t, "3 = Deny")
	e.answer("9") // not an answer: the request still waits
	e.log.wait(t, "type 1 (Approve once)")
	e.answer("3")
	code, stderr := r.wait(t)
	if code != 77 {
		t.Fatalf("nodkey try run: exit code %d, want 77; stderr:\n%s", code, stderr)
	}
	checkClientLines(t, stderr)
	e.log.wait(t, ": denied")
	if _, err := os.Stat(filepath.Join(e.out, "value")); err == nil {
		t.Fatal("the command ran after Deny")
	}
	e.stopAndCheck(syscall.SIGINT)
}

func TestTryExpiry(t *testing.T) {
	e := newTryEnv(t)
	e.start(2 * time.Second)
	code, stderr := e.run(e.demoArgs()...).wait(t)
	if code != 77 {
		t.Fatalf("nodkey try run: exit code %d, want 77; stderr:\n%s", code, stderr)
	}
	checkClientLines(t, stderr)
	e.log.wait(t, "expired without an answer, so denied")
	if _, err := os.Stat(filepath.Join(e.out, "value")); err == nil {
		t.Fatal("the command ran without an answer")
	}
	// A late answer does not count.
	e.answer("1")
	e.log.wait(t, "no such request")
	e.stopAndCheck(syscall.SIGTERM)
}

// When the input of the terminal ends, no answer can come: the trial
// stops, and still removes its directory.
func TestTryStopsWhenTheInputEnds(t *testing.T) {
	e := newTryEnv(t)
	e.start(time.Minute)
	_ = e.in.Close()
	if code := e.exitCode(); code != exitFailure {
		t.Fatalf("exit code %d, want 1; output:\n%s", code, e.log.text())
	}
	e.checkClean()
}

// A second trial does not start while one runs, and does not harm it.
func TestTryOnlyOneTrial(t *testing.T) {
	e := newTryEnv(t)
	e.start(time.Minute)
	second := &tryEnv{t: t, home: e.home, runtime: e.runtime, tmp: e.tmp, work: e.work}
	second.startNoWait(time.Minute)
	if code := second.exitCode(); code != exitFailure || !second.log.has("a trial runs already") {
		t.Fatalf("second trial: exit code %d, want 1; output:\n%s", code, second.log.text())
	}
	r := e.run(e.demoArgs()...)
	e.log.wait(t, "3 = Deny")
	e.answer("1")
	if code, stderr := r.wait(t); code != 0 {
		t.Fatalf("the first trial no longer works: exit code %d; stderr:\n%s", code, stderr)
	}
	e.stopAndCheck(syscall.SIGINT)
}

// A directory of a trial that was killed is removed by the next start.
func TestTryRemovesAStaleDirectory(t *testing.T) {
	e := newTryEnv(t)
	e.start(time.Minute)
	_ = e.cmd.Process.Kill()
	<-e.exited
	if _, err := os.Stat(filepath.Join(e.runtime, tryDirName, tryClientConf)); err != nil {
		t.Fatalf("the killed trial left no directory: %v", err)
	}
	e.start(time.Minute)
	e.stopAndCheck(syscall.SIGINT)
}

// nodkey try run without a trial fails, and does not fall back to the
// client config in the home directory.
func TestTryRunWithoutATrial(t *testing.T) {
	e := newTryEnv(t)
	code, stderr := e.run(e.demoArgs()...).wait(t)
	if code != 69 || !strings.Contains(stderr, "no trial runs") {
		t.Fatalf("exit code %d, want 69 and \"no trial runs\"; stderr:\n%s", code, stderr)
	}
	checkClientLines(t, stderr)
	e.checkClean()
}

// newTryTelegramEnv is a trial with --telegram, and the fake Telegram.
func newTryTelegramEnv(t *testing.T, opts brokerOptions) (*tryEnv, *fakeTelegram) {
	t.Helper()
	f := newFakeTelegram(t, opts)
	e := newTryEnv(t)
	e.extra = []string{tryChildArgs + "=--telegram", "HTTPS_PROXY=http://" + f.proxyAddr,
		"SSL_CERT_FILE=" + f.caFile, "SSL_CERT_DIR=" + f.caDir}
	return e, f
}

// pairTry types the token, sends /start with the code of the link, and
// answers the question of the name with confirm.
func (e *tryEnv) pairTry(f *fakeTelegram, confirm string) {
	t := e.t
	t.Helper()
	e.answer(f.token)
	e.log.wait(t, "https://t.me/try_test_bot?start=")
	m := regexp.MustCompile(`start=([A-Za-z0-9_-]{16,64})$`).FindStringSubmatch(strings.TrimSpace(e.log.text()))
	if m == nil {
		t.Fatalf("no code in the link:\n%s", e.log.text())
	}
	f.sendStart(m[1])
	e.log.wait(t, "sent the code.")
	if !e.log.has("Test (@test_user) (ID 7000001)") {
		t.Fatalf("the name is not shown:\n%s", e.log.text())
	}
	e.answer(confirm)
}

func TestTryTelegram(t *testing.T) {
	e, f := newTryTelegramEnv(t, brokerOptions{})
	e.startNoWait(time.Minute)
	e.pairTry(f, "yes")
	e.log.wait(t, "The request shows up in Telegram")
	if strings.Contains(e.log.text(), f.token) {
		t.Fatal("nodkey try printed the bot token")
	}
	r := e.run(e.demoArgs()...)
	msgID, requestID := f.waitAsk(1)
	if body := f.bodies(); !strings.Contains(body, "TRY MODE · ") {
		t.Fatalf("the message does not say TRY MODE:\n%s", body)
	}
	f.waitTapAnswer(f.tap(msgID, "o:"+requestID))
	code, stderr := r.wait(t)
	if code != 0 {
		t.Fatalf("nodkey try run: exit code %d, want 0; stderr:\n%s", code, stderr)
	}
	checkClientLines(t, stderr)
	e.checkValue(stderr)
	e.stopAndCheck(syscall.SIGTERM)
}

// Without "yes", the trial does not start.
func TestTryTelegramNotConfirmed(t *testing.T) {
	e, f := newTryTelegramEnv(t, brokerOptions{})
	e.startNoWait(time.Minute)
	e.pairTry(f, "no")
	if code := e.exitCode(); code != exitFailure || !e.log.has("not confirmed") {
		t.Fatalf("exit code %d, want 1; output:\n%s", code, e.log.text())
	}
	e.checkClean()
}

// A conflict from Telegram stops the trial and says to use a new bot.
func TestTryTelegramConflict(t *testing.T) {
	e, f := newTryTelegramEnv(t, brokerOptions{refusePolls: http.StatusConflict})
	e.startNoWait(time.Minute)
	e.answer(f.token)
	if code := e.exitCode(); code != exitFailure || !e.log.has("never the broker's bot") {
		t.Fatalf("exit code %d, want 1; output:\n%s", code, e.log.text())
	}
	e.checkClean()
}

// A token that Telegram does not accept stops the trial.
func TestTryTelegramBadToken(t *testing.T) {
	e, _ := newTryTelegramEnv(t, brokerOptions{})
	e.startNoWait(time.Minute)
	e.answer(newBotToken())
	if code := e.exitCode(); code != exitFailure || !e.log.has("does not accept the bot token") {
		t.Fatalf("exit code %d, want 1; output:\n%s", code, e.log.text())
	}
	e.checkClean()
}
