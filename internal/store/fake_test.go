package store

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The fake store programs. The tests make a symbolic link named bws or bw
// to the test binary, and give its path to the store as the program. When
// the store runs it, TestMain sees the name and acts as that program.
//
// The fake gets only what the store gives a real program: its arguments,
// HOME, PATH and the token or session variable. So it reads what to do
// from fakeScenarioFile in HOME, and appends a fakeCall for each run to
// fakeCallsFile there. The fake bw keeps its state in fakeBWStateFile.

// The files of the fake programs in the store's home directory.
const (
	fakeScenarioFile = "fake-scenario.gob"
	fakeCallsFile    = "fake-calls.jsonl"
	fakeBWStateFile  = "fake-bw-state.json"
	fakePIDsFile     = "fake-pids"
	fakeRunningDir   = "fake-running"
)

// The fake programs write their answers and errors to stdout and stderr,
// as bws and bw do. Only the fakes use these; the tests never print.
var (
	fakeStdout = os.Stdout //nolint:forbidigo // the fake program answers on stdout, as bws and bw do.
	fakeStderr = os.Stderr //nolint:forbidigo // the fake program writes errors to stderr, as bws and bw do.
)

// fakeSleeper is the name under which the test binary only sleeps. The
// fake programs start it as a child, to test that a store stops the whole
// process group.
const fakeSleeper = "fake-sleeper"

// TestMain runs the fake programs, or else the tests.
//
// A fake ends with syscall.Exit, not os.Exit: with the race detector, a
// program that exits with 0 through os.Exit first sleeps for a second
// (GORACE atexit_sleep_ms), and the fake gets no GORACE to turn it off.
// The fake writes to stdout and stderr without a buffer, so nothing is
// lost.
func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "bws":
		syscall.Exit(runFake("bws"))
	case "bw":
		syscall.Exit(runFake("bw"))
	case fakeSleeper:
		time.Sleep(time.Hour)
		syscall.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeScenario says what a fake program does.
type fakeScenario struct {
	Token    string              `json:"token"`    // bws: the access token that works
	Password string              `json:"password"` // bw: the master password, the first line of the password file
	Session  string              `json:"session"`  // bw: the session key that unlock makes; random if empty
	Items    map[string]string   `json:"items"`    // the answer for each item ID, in lower case
	Steps    map[string]fakeStep `json:"steps"`    // what a step does instead of its usual work
	Pause    time.Duration       `json:"pause"`    // each run waits this long first
}

// fakeStep is what a step does instead of its usual work. The steps are
// "secret get" for bws, and "unlock", "sync", "get item" and "status" for
// bw.
type fakeStep struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Exit   int    `json:"exit"`
	// Hang starts a child that sleeps, writes both process IDs to
	// fakePIDsFile, writes Stdout, and sleeps.
	Hang bool `json:"hang"`
	// Flood writes Stdout, then writes to "stdout" or "stderr" without end.
	Flood string `json:"flood"`
	// Leave starts a child that sleeps with the same stdout, writes both
	// process IDs to fakePIDsFile, writes Stdout, and exits with Exit.
	Leave bool `json:"leave"`
}

// fakeBWState is the state of the fake bw: its account and its session.
type fakeBWState struct {
	LoggedOut bool   `json:"loggedOut"`
	Session   string `json:"session"` // the session key that works; empty when the vault is locked
}

// fakeCall is what a fake program got in one run.
type fakeCall struct {
	Program string   `json:"program"`
	Args    []string `json:"args"`
	Env     []string `json:"env"`
	Dir     string   `json:"dir"`
	Stdin   string   `json:"stdin"`   // what stdin is, such as /dev/null
	Leader  bool     `json:"leader"`  // the run leads its own process group
	Running int      `json:"running"` // runs of fakes in this home at that moment, this one too
}

// runFake is the main function of a fake program. It returns the exit
// code.
func runFake(program string) int {
	home := os.Getenv("HOME")
	if home == "" {
		_, _ = fakeStderr.WriteString("fake: no HOME\n")
		return 99
	}
	var sc fakeScenario
	if err := readGob(filepath.Join(home, fakeScenarioFile), &sc); err != nil {
		_, _ = fakeStderr.WriteString("fake: no scenario\n")
		return 99
	}
	running := filepath.Join(home, fakeRunningDir, strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(filepath.Dir(running), 0o700); err != nil { //nolint:gosec // G703: the fake writes only in the home directory that its test made.
		return 99
	}
	if err := os.WriteFile(running, nil, 0o600); err != nil { //nolint:gosec // G703: the fake writes only in the home directory that its test made.
		return 99
	}
	entries, _ := os.ReadDir(filepath.Dir(running))
	stdin, _ := os.Readlink("/proc/self/fd/0")
	dir, _ := os.Getwd()
	call := fakeCall{
		Program: program,
		Args:    os.Args[1:],
		Env:     os.Environ(),
		Dir:     dir,
		Stdin:   stdin,
		Leader:  syscall.Getpgrp() == os.Getpid(),
		Running: len(entries),
	}
	if err := appendJSONLine(filepath.Join(home, fakeCallsFile), call); err != nil {
		return 99
	}
	time.Sleep(sc.Pause)
	var code int
	if program == "bws" {
		code = fakeBWS(home, &sc)
	} else {
		code = fakeBW(home, &sc)
	}
	_ = os.Remove(running) //nolint:gosec // G703: the fake removes only its own file in the home directory that its test made.
	return code
}

// fakeBWS acts as bws.
func fakeBWS(home string, sc *fakeScenario) int {
	args := os.Args[1:]
	if len(args) < 3 || args[0] != "secret" || args[1] != "get" {
		return fakeFail("error: unexpected arguments", 2)
	}
	if step, ok := sc.Steps["secret get"]; ok {
		return fakeOverride(home, step)
	}
	if os.Getenv("BWS_ACCESS_TOKEN") != sc.Token || sc.Token == "" {
		return fakeFail("Error: \n   0: Access token is not in a valid format", 1)
	}
	item, ok := sc.Items[strings.ToLower(args[2])]
	if !ok {
		return fakeFail("Error: \n   0: Received error message from server: [404 Not Found]", 1)
	}
	_, _ = fakeStdout.WriteString(item)
	return 0
}

// fakeBW acts as bw.
func fakeBW(home string, sc *fakeScenario) int {
	args := os.Args[1:]
	step := ""
	switch {
	case len(args) > 0 && slices.Contains([]string{"unlock", "sync", "status"}, args[0]):
		step = args[0]
	case len(args) > 2 && args[0] == "get" && args[1] == "item":
		step = "get item"
	default:
		return fakeFail("Invalid command: "+strings.Join(args, " "), 1)
	}
	if o, ok := sc.Steps[step]; ok {
		return fakeOverride(home, o)
	}
	var st fakeBWState
	if err := readJSON(filepath.Join(home, fakeBWStateFile), &st); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 99
	}
	session := os.Getenv("BW_SESSION")
	unlocked := st.Session != "" && session == st.Session
	switch step {
	case "status":
		status := "locked"
		switch {
		case st.LoggedOut:
			status = "unauthenticated"
		case unlocked:
			status = "unlocked"
		}
		out, _ := json.Marshal(map[string]any{
			"serverUrl": "https://bitwarden.example.com", "lastSync": "2026-10-14T12:00:00.000Z",
			"userEmail": "nodkey@example.com", "userId": "00000000-0000-0000-0000-000000000000", "status": status,
		})
		_, _ = fakeStdout.Write(out)
		return 0
	case "unlock":
		if st.LoggedOut {
			return fakeFail("You are not logged in.", 1)
		}
		i := slices.Index(args, "--passwordfile")
		if i < 0 || i+1 >= len(args) {
			return fakeFail("Master password is required.", 1)
		}
		password, err := firstLine(args[i+1])
		if err != nil || password != sc.Password {
			return fakeFail("Invalid master password.", 1)
		}
		st.Session = sc.Session
		if st.Session == "" {
			key := make([]byte, 64)
			_, _ = rand.Read(key)
			st.Session = base64.StdEncoding.EncodeToString(key)
		}
		if err := writeJSON(filepath.Join(home, fakeBWStateFile), st); err != nil {
			return 99
		}
		if !slices.Contains(args, "--raw") {
			_, _ = fakeStdout.WriteString("Your vault is now unlocked!\n\n$ export BW_SESSION=\"" + st.Session + "\"\n")
			return 0
		}
		_, _ = fakeStdout.WriteString(st.Session)
		return 0
	case "sync":
		if st.LoggedOut {
			return fakeFail("You are not logged in.", 1)
		}
		_, _ = fakeStdout.WriteString("Syncing complete.")
		return 0
	}
	// get item
	switch {
	case st.LoggedOut:
		return fakeFail("You are not logged in.", 1)
	case !unlocked:
		return fakeFail("Vault is locked.", 1)
	}
	item, ok := sc.Items[strings.ToLower(args[2])]
	if !ok {
		return fakeFail("Not found.", 1)
	}
	_, _ = fakeStdout.WriteString(item)
	return 0
}

// fakeOverride does what step says.
func fakeOverride(home string, step fakeStep) int {
	if step.Hang || step.Leave {
		exe, err := os.Executable()
		if err != nil {
			return 99
		}
		child := exec.Cmd{Path: exe, Args: []string{fakeSleeper}}
		if step.Leave {
			child.Stdout = fakeStdout
		}
		if err := child.Start(); err != nil {
			return 99
		}
		pids := strconv.Itoa(os.Getpid()) + " " + strconv.Itoa(child.Process.Pid) + "\n"
		if err := os.WriteFile(filepath.Join(home, fakePIDsFile), []byte(pids), 0o600); err != nil { //nolint:gosec // G703: the fake writes only in the home directory that its test made.
			return 99
		}
	}
	_, _ = fakeStdout.WriteString(step.Stdout)
	_, _ = fakeStderr.WriteString(step.Stderr)
	switch {
	case step.Hang:
		time.Sleep(time.Hour)
	case step.Flood != "":
		w := fakeStdout
		if step.Flood == "stderr" {
			w = fakeStderr
		}
		chunk := []byte(strings.Repeat("flood ", 1000))
		for {
			if _, err := w.Write(chunk); err != nil {
				return 98
			}
		}
	}
	return step.Exit
}

// fakeFail writes msg to stderr, as bws and bw write their errors, and
// returns code.
func fakeFail(msg string, code int) int {
	_, _ = fakeStderr.WriteString(msg)
	return code
}

// firstLine returns the first line of a file, as bw reads its password
// file.
func firstLine(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the fake reads the password file that its test made.
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	s := bufio.NewScanner(f)
	if !s.Scan() {
		return "", errors.New("empty")
	}
	return strings.TrimSuffix(s.Text(), "\r"), nil
}

// readGob reads a gob file into v. The scenario is a gob, not JSON:
// encoding/json would change invalid UTF-8 in an answer that a test wants
// the fake to print as it is.
func readGob(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: tests read only files in their own temporary directory.
	if err != nil {
		return err
	}
	return gob.NewDecoder(bytes.NewReader(data)).Decode(v) //nolint:gosec // G709: the fake reads the scenario that its own test wrote.
}

// writeGob writes v to a gob file.
func writeGob(path string, v any) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// readJSON reads a JSON file into v.
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: tests read only files in their own temporary directory.
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// writeJSON writes v to a JSON file.
func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600) //nolint:gosec // G703: tests and fakes write only in their own temporary directory.
}

// appendJSONLine appends v to a file as one line, with one write.
func appendJSONLine(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G304: tests write only files in their own temporary directory.
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
