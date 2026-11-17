package contract

// The harness of the contract tests: it builds nodkey, starts a trial
// broker with "nodkey try", answers its requests, and runs "nodkey run"
// with the test binary itself as the command (the helper, see
// helper_linux_test.go). See README.md.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The environment variables between the test and its helper. nodkey run
// passes its environment on to the command.
const (
	helperVar = "NODKEY_CONTRACT_HELPER" // the mode of the helper
	reportVar = "NODKEY_CONTRACT_REPORT" // the file that the helper writes its events to
	fd3Var    = "NODKEY_CONTRACT_FD3"    // "1": the helper reads fd 3
	secretVar = "CONTRACT_SECRET"        // the variable of the secret
)

// The secrets of the trial broker. The harness approves each request for
// approvedSecret for some minutes, and denies every other request.
const (
	approvedSecret = "demo-token"
	deniedSecret   = "demo-password"
)

// waitLimit caps each wait of the tests.
const waitLimit = 30 * time.Second

// setup is what TestMain made.
var setup struct {
	nodkey string // the built nodkey binary
	home   string // HOME of nodkey run: its client config is in it
	self   string // the test binary, the helper
	trial  *trial
}

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperVar); mode != "" {
		os.Exit(helper(mode))
	}
	os.Exit(runTests(m))
}

// runTests builds nodkey, starts the trial broker, runs the tests, and
// removes what it made.
func runTests(m *testing.M) int {
	stderr := os.Stderr //nolint:forbidigo // TestMain reports on stderr, as the testing package does.
	var err error
	if setup.self, err = os.Executable(); err != nil {
		_, _ = fmt.Fprintln(stderr, "contract: cannot find the test binary:", err)
		return 1
	}
	build, err := os.MkdirTemp("", "nodkey-contract-")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "contract: cannot make a temporary directory:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(build) }()
	setup.nodkey = filepath.Join(build, "nodkey")
	if err := buildNodkey(setup.nodkey); err != nil {
		_, _ = fmt.Fprintln(stderr, "contract: cannot build nodkey:", err)
		return 1
	}
	tr, err := startTrialSomewhere()
	setup.trial = tr
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "contract: cannot start the trial broker (nodkey try):", err)
		return 1
	}
	code := m.Run()
	if err := tr.stop(); err != nil {
		_, _ = fmt.Fprintln(stderr, "contract: the trial broker did not stop cleanly:", err)
		code = 1
	}
	_ = os.RemoveAll(tr.dir)
	return code
}

// startTrialSomewhere starts the trial broker in a new private directory.
// Every directory on the way to its files must pass the file checks of
// nodkey (DESIGN.md section 14), and the system temporary directory fails
// them. So the directory is in XDG_RUNTIME_DIR or in the cache directory
// of the user, as in the tests of cmd/nodkey.
func startTrialSomewhere() (*trial, error) {
	var bases []string
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		bases = append(bases, d)
	}
	if d, err := os.UserCacheDir(); err == nil {
		bases = append(bases, d)
	}
	var errs []error
	for _, base := range bases {
		if err := os.MkdirAll(base, 0o700); err != nil { //nolint:gosec // G703: a base directory of the user.
			errs = append(errs, err)
			continue
		}
		dir, err := os.MkdirTemp(base, "nodkey-contract-")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		tr, err := startTrial(dir)
		if err == nil {
			return tr, nil
		}
		_ = os.RemoveAll(dir) //nolint:gosec // G703: the test's own new directory.
		errs = append(errs, fmt.Errorf("in %s: %w", base, err))
	}
	return nil, fmt.Errorf("no directory works for it: %w", errors.Join(errs...))
}

// buildNodkey builds ./cmd/nodkey of this repository as bin, with the Go
// that built the test.
func buildNodkey(bin string) error {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return err
	}
	goTool := "go"
	//nolint:staticcheck // SA1019: the root of the toolchain that built this test binary is what is wanted here.
	if r := runtime.GOROOT(); r != "" {
		if p := filepath.Join(r, "bin", "go"); fileExists(p) {
			goTool = p
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, "build", "-o", bin, "./cmd/nodkey") //nolint:gosec // G204: the test builds nodkey with its own arguments.
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build: %w\n%s", err, out)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// trial is the trial broker: "nodkey try" in a child process. It reads
// the answers on its stdin, and shows each request on its stdout.
type trial struct {
	dir   string // its files, and the home directory of nodkey run
	cmd   *exec.Cmd
	in    io.WriteCloser
	ready chan struct{}
	done  chan struct{} // the answers ended: the stdout of nodkey try is closed

	denied atomic.Int64 // the requests that the harness denied

	mu  sync.Mutex
	out bytes.Buffer // what nodkey try wrote: names and short codes, no values
}

// startTrial starts nodkey try with its files in dir, and puts its client
// config into setup.home.
func startTrial(dir string) (*trial, error) {
	run := filepath.Join(dir, "run")
	setup.home = filepath.Join(dir, "home")
	conf := filepath.Join(setup.home, ".config", "nodkey")
	for _, d := range []string{run, conf} {
		if err := os.MkdirAll(d, 0o700); err != nil { //nolint:gosec // G703: in the test's own new directory.
			return nil, err
		}
	}
	tr := &trial{dir: dir, ready: make(chan struct{}), done: make(chan struct{})}
	// Not with the context of a test: the trial lives for all of them.
	tr.cmd = exec.CommandContext(context.Background(), setup.nodkey, "try") //nolint:gosec // G204: the nodkey binary of the test.
	tr.cmd.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+run)
	in, err := tr.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	tr.in = in
	out, err := tr.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	tr.cmd.Stderr = &lockedWriter{mu: &tr.mu, w: &tr.out}
	if err := tr.cmd.Start(); err != nil {
		return nil, err
	}
	go tr.answer(out)
	select {
	case <-tr.ready:
	case <-tr.done:
		_ = tr.stop()
		return nil, fmt.Errorf("nodkey try stopped; it wrote:\n%s", tr.output())
	case <-time.After(waitLimit):
		_ = tr.stop()
		return nil, fmt.Errorf("nodkey try is not ready after %s; it wrote:\n%s", waitLimit, tr.output())
	}
	b, err := os.ReadFile(filepath.Join(run, "nodkey-try", "client.toml")) //nolint:gosec // G304: the client config of the trial.
	if err != nil {
		_ = tr.stop()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(conf, "client.toml"), b, 0o600); err != nil { //nolint:gosec // G703: in the test's own new directory.
		_ = tr.stop()
		return nil, err
	}
	return tr, nil
}

// answer reads the stdout of nodkey try. It answers each request: "Approve
// N min" when it asks only for approvedSecret, else Deny.
func (tr *trial) answer(out io.Reader) {
	defer close(tr.done)
	sc := bufio.NewScanner(out)
	var code, secrets string
	for sc.Scan() {
		line := sc.Text()
		tr.mu.Lock()
		tr.out.WriteString(line + "\n")
		tr.mu.Unlock()
		const prefix = "nodkey try: TRY MODE: "
		switch {
		case strings.HasPrefix(line, prefix+"a trial broker listens on "):
			close(tr.ready)
		case strings.HasPrefix(line, prefix+"request ") && strings.Contains(line, " from client "):
			code, secrets = strings.Fields(strings.TrimPrefix(line, prefix+"request "))[0], ""
		case strings.HasPrefix(line, "  secrets: "):
			secrets = strings.TrimPrefix(line, "  secrets: ")
		case strings.HasPrefix(line, "  type:") && code != "":
			choice := "3" // Deny
			if secrets == approvedSecret {
				choice = "2" // Approve N min
			} else {
				tr.denied.Add(1)
			}
			_, _ = fmt.Fprintf(tr.in, "%s %s\n", code, choice)
			code = ""
		}
	}
}

func (tr *trial) output() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.out.String()
}

// stop ends nodkey try with SIGTERM: it removes its files.
func (tr *trial) stop() error {
	// No more answers: a request that comes now expires.
	_ = tr.in.Close()
	_ = tr.cmd.Process.Signal(syscall.SIGTERM)
	waited := make(chan error, 1)
	go func() { waited <- tr.cmd.Wait() }()
	select {
	case err := <-waited:
		return err
	case <-time.After(waitLimit):
		_ = tr.cmd.Process.Kill()
		return errors.New("nodkey try did not end after SIGTERM")
	}
}

// lockedWriter writes to w under mu.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// output is where stdout and stderr of nodkey run go.
type output int

const (
	pipes          output = iota // both pipes
	terminals                    // both one pseudo-terminal
	stdoutPipeOnly               // stdout a pipe, stderr a pseudo-terminal
)

// mode is one way to call nodkey run: where its output goes, and its flags.
type mode struct {
	name   string
	out    output
	flags  []string
	masked bool // the documented form: masked, or execve
}

// modes are the ways to call nodkey run that the tests check (pattern 5).
// Masked is the default when stdout or stderr is not a terminal, or with
// --mask; execve when both are a terminal, or with --no-mask.
var modes = []mode{
	{name: "pipe", out: pipes, masked: true},
	{name: "stdout pipe, stderr terminal", out: stdoutPipeOnly, masked: true},
	{name: "terminal --mask", out: terminals, flags: []string{"--mask"}, masked: true},
	{name: "terminal", out: terminals, masked: false},
	{name: "pipe --no-mask", out: pipes, flags: []string{"--no-mask"}, masked: false},
}

// call is one nodkey run.
type call struct {
	mode   mode
	secret string   // the secret NAME; approvedSecret when empty
	helper string   // the mode of the helper as the command, or ""
	argv   []string // the command when helper is ""
	stdin  []byte   // nil: stdin is /dev/null
	fd3    []byte   // nil: no fd 3
}

// running is a nodkey run that has started.
type running struct {
	t      *testing.T
	cmd    *exec.Cmd
	report string
	stdout bytes.Buffer // only when stdout is a pipe
	stderr bytes.Buffer // only when stderr is a pipe
	pty    *os.File     // the master side, or nil
	ptyOut *ptyReader
}

// start starts nodkey run for c. The test fails when it cannot.
func start(t *testing.T, c call) *running {
	t.Helper()
	r := &running{t: t, report: filepath.Join(t.TempDir(), "report")}
	secret := c.secret
	if secret == "" {
		secret = approvedSecret
	}
	args := append([]string{"run"}, c.mode.flags...)
	args = append(args, "--secret", secretVar+"="+secret, "--reason", "contract test", "--")
	if c.helper != "" {
		args = append(args, setup.self)
	} else {
		args = append(args, c.argv...)
	}
	// Not the test's context: a test that ends must not kill nodkey run
	// with SIGKILL before it checks how nodkey run ended.
	r.cmd = exec.CommandContext(context.Background(), setup.nodkey, args...) //nolint:gosec // G204: the nodkey binary of the test.
	// GORACE: a helper built with -race waits a second when it exits, unless
	// told not to.
	r.cmd.Env = append(os.Environ(), "HOME="+setup.home, helperVar+"="+c.helper, reportVar+"="+r.report,
		"GORACE=atexit_sleep_ms=0")
	if c.stdin != nil {
		r.cmd.Stdin = bytes.NewReader(c.stdin)
	}
	if c.fd3 != nil {
		path := filepath.Join(t.TempDir(), "fd3")
		if err := os.WriteFile(path, c.fd3, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path) //nolint:gosec // G304: a file of the test.
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		r.cmd.ExtraFiles = []*os.File{f}
		r.cmd.Env = append(r.cmd.Env, fd3Var+"=1")
	}
	var pts *os.File
	if c.mode.out != pipes {
		r.pty, pts = openPty(t)
		defer func() { _ = pts.Close() }()
		r.ptyOut = readPty(r.pty)
	}
	switch c.mode.out {
	case pipes:
		r.cmd.Stdout, r.cmd.Stderr = &r.stdout, &r.stderr
	case terminals:
		r.cmd.Stdout, r.cmd.Stderr = pts, pts
	case stdoutPipeOnly:
		r.cmd.Stdout, r.cmd.Stderr = &r.stdout, pts
	}
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if r.cmd.ProcessState == nil {
			_ = r.cmd.Process.Kill()
			_ = r.cmd.Wait()
		}
		if r.pty != nil {
			_ = r.pty.Close()
		}
	})
	return r
}

// run starts nodkey run for c and waits until it ends.
func run(t *testing.T, c call) *running {
	t.Helper()
	r := start(t, c)
	r.wait()
	return r
}

// wait waits until nodkey run ends.
func (r *running) wait() syscall.WaitStatus {
	r.t.Helper()
	waited := make(chan error, 1)
	go func() { waited <- r.cmd.Wait() }()
	select {
	case <-waited:
	case <-time.After(waitLimit):
		_ = r.cmd.Process.Kill()
		<-waited
		r.t.Fatalf("nodkey run did not end after %s", waitLimit)
	}
	return r.status()
}

// status is how nodkey run ended.
func (r *running) status() syscall.WaitStatus {
	ws, ok := r.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		r.t.Fatal("no wait status")
	}
	return ws
}

// wantExit checks that nodkey run exited with code.
func (r *running) wantExit(code int) {
	r.t.Helper()
	ws := r.status()
	if !ws.Exited() || ws.ExitStatus() != code {
		r.t.Errorf("nodkey run ended with %s; want exit code %d", describe(ws), code)
	}
}

// wantSignal checks that nodkey run died of sig.
func (r *running) wantSignal(sig syscall.Signal) {
	r.t.Helper()
	ws := r.status()
	if !ws.Signaled() || ws.Signal() != sig {
		r.t.Errorf("nodkey run ended with %s; want death by signal %d (%v)", describe(ws), int(sig), sig)
	}
}

func describe(ws syscall.WaitStatus) string {
	switch {
	case ws.Exited():
		return "exit code " + strconv.Itoa(ws.ExitStatus())
	case ws.Signaled():
		return fmt.Sprintf("death by signal %d (%v)", int(ws.Signal()), ws.Signal())
	}
	return fmt.Sprintf("wait status %#x", uint32(ws))
}

// event is one line that the helper writes to its report. It never holds
// a value: only facts, and a SHA-256 of a value.
type event struct {
	Event  string `json:"event"`            // "facts", "ready", "signal", "program"
	Facts  *facts `json:"facts,omitempty"`  // for "facts"
	Signal string `json:"signal,omitempty"` // for "signal": TERM, HUP, INT or USR1
	Hash   string `json:"hash,omitempty"`   // for "program": the SHA-256 of what the password command printed
	Error  string `json:"error,omitempty"`  // for "program"
}

// facts is what the command found out about its process.
type facts struct {
	PID           int    `json:"pid"`
	PPID          int    `json:"ppid"`
	Pgrp          int    `json:"pgrp"`
	Session       int    `json:"session"`
	ParentName    string `json:"parent_name"`     // the name in /proc/PPID/stat
	ParentStatErr string `json:"parent_stat_err"` // "" when /proc/PPID/stat could be read
	ParentPPID    int    `json:"parent_ppid"`
	ParentPgrp    int    `json:"parent_pgrp"`
	ParentSession int    `json:"parent_session"`
	ParentExe     string `json:"parent_exe"` // "ok", "EACCES", or another error of readlink /proc/PPID/exe
	EnvHash       string `json:"env_hash"`   // the SHA-256 of the secret in its environment
	EnvTry        bool   `json:"env_try"`    // the value starts with TRY-, as each value of nodkey try
	Stdin         string `json:"stdin"`
	FD3           string `json:"fd3"`
	Stdout        string `json:"stdout"` // "terminal", "pipe" or "other"
	Stderr        string `json:"stderr"`
}

// events reads the report of the helper. A missing report has no events.
func (r *running) events() []event {
	r.t.Helper()
	b, err := os.ReadFile(r.report)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		r.t.Fatal(err)
	}
	var evs []event
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			r.t.Fatalf("a line of the report is not JSON: %v", err)
		}
		evs = append(evs, e)
	}
	return evs
}

// waitEvent waits until the report has an event that ok accepts.
func (r *running) waitEvent(what string, ok func(event) bool) {
	r.t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		for _, e := range r.events() {
			if ok(e) {
				return
			}
		}
		if r.cmd.ProcessState != nil {
			r.t.Fatalf("nodkey run ended before %s", what)
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("no %s after %s", what, waitLimit)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// facts returns the facts that the helper reported.
func (r *running) facts() facts {
	r.t.Helper()
	for _, e := range r.events() {
		if e.Event == "facts" && e.Facts != nil {
			return *e.Facts
		}
	}
	r.t.Fatal("the command reported no facts: did it run?")
	return facts{}
}

// signals returns the signals that the helper got, in order.
func (r *running) signals() []string {
	var s []string
	for _, e := range r.events() {
		if e.Event == "signal" {
			s = append(s, e.Signal)
		}
	}
	return s
}

// hashOf is the SHA-256 of b, in hex.
func hashOf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// openPty opens a new pseudo-terminal, with no controlling terminal.
func openPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("no pseudo-terminal: %v", err)
		}
		t.Skipf("no pseudo-terminal: %v", err)
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 { //nolint:gosec // G103: the ioctl needs the address.
		_ = ptmx.Close()
		t.Fatalf("unlockpt: %v", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, ptmx.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 { //nolint:gosec // G103: the same.
		_ = ptmx.Close()
		t.Fatalf("ptsname: %v", e)
	}
	pts, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = ptmx.Close()
		t.Fatal(err)
	}
	return ptmx, pts
}

// ptyReader reads the master side of a pseudo-terminal, so that writes to
// it never block.
type ptyReader struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func readPty(master *os.File) *ptyReader {
	p := &ptyReader{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := master.Read(b)
			p.mu.Lock()
			if p.buf.Len() < 1<<16 {
				p.buf.Write(b[:n])
			}
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return p
}

// waitFor waits until the pseudo-terminal showed text.
func (p *ptyReader) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(waitLimit)
	for {
		p.mu.Lock()
		found := bytes.Contains(p.buf.Bytes(), []byte(text))
		p.mu.Unlock()
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the terminal did not show %q after %s", text, waitLimit)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
