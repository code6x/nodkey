package store

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// testItemID is the item of most tests.
const testItemID = "6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b"

// testDeps returns deps for tests. The checks of the config package refuse
// every path below the system temporary directory, which everyone can
// write to; TestNewMakesTheRealChecks shows that New makes them. The check
// of node does nothing either, so that a node on the test machine does
// not change the tests; TestBWPathNodeIsCheckedLikeTheProgram runs it.
func testDeps() deps {
	return deps{
		readPrivateFile: func(path string) ([]byte, error) {
			return os.ReadFile(path) //nolint:gosec // G304: tests read only files in their own temporary directory.
		},
		checkPrivateFile: func(path string) error {
			_, err := os.Stat(path) //nolint:gosec // G703: tests check only files in their own temporary directory.
			return err
		},
		checkParentDirs: func(string) error { return nil },
		checkProgram:    func(string) error { return nil },
		path:            bwPath,
		timeout:         20 * time.Second,
		waitDelay:       2 * time.Second,
	}
}

// madeUp returns a new made-up secret with the label at its start, such
// as "token-0f1e...". It is made when the test runs, so the source holds no
// text that looks like a real token. It has no spaces, so it can be a
// token or a session key too.
func madeUp(label string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return label + "-" + hex.EncodeToString(b)
}

// testFake is a store under test, with its fake program.
type testFake struct {
	t     *testing.T
	store Store
	cfg   config.Store
	dir   string // the state directory
	home  string // the store's home directory: dir/NAME
}

// newTestFake makes a store of type typ whose program is the fake. The
// token or password file holds sc.Token or sc.Password and a newline.
func newTestFake(t *testing.T, typ config.StoreType, sc fakeScenario, d deps) *testFake {
	t.Helper()
	f := setupFake(t, typ, sc)
	s, err := newStore(f.cfg, f.dir, d)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	f.store = s
	t.Cleanup(s.Close)
	return f
}

// setupFake makes the files of a store with a fake program: the link to
// the fake, the token or password file, and the home directory with the
// scenario. It does not make the store.
func setupFake(t *testing.T, typ config.StoreType, sc fakeScenario) *testFake {
	t.Helper()
	base := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil { //nolint:gosec // G301: a test directory for the link to the fake program.
		t.Fatal(err)
	}
	f := &testFake{t: t, dir: filepath.Join(base, "state")}
	f.cfg = config.Store{Name: "main", Type: typ, Program: filepath.Join(bin, string(typ))}
	if typ == config.StoreBW {
		f.cfg.Name = "vault"
	}
	if err := os.Symlink(exe, f.cfg.Program); err != nil {
		t.Fatal(err)
	}
	switch typ {
	case config.StoreBWS:
		f.cfg.TokenFile = filepath.Join(base, "bws-token")
		writeFile(t, f.cfg.TokenFile, sc.Token+"\n")
	case config.StoreBW:
		f.cfg.PasswordFile = filepath.Join(base, "bw-password")
		writeFile(t, f.cfg.PasswordFile, sc.Password+"\n")
	}
	f.home = filepath.Join(f.dir, f.cfg.Name)
	if err := os.MkdirAll(f.home, 0o700); err != nil {
		t.Fatal(err)
	}
	f.setScenario(sc)
	return f
}

// writeFile writes a test file with mode 0600.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// setScenario tells the fake what to do from now on.
func (f *testFake) setScenario(sc fakeScenario) {
	f.t.Helper()
	if err := writeGob(filepath.Join(f.home, fakeScenarioFile), sc); err != nil {
		f.t.Fatal(err)
	}
}

// bwState returns the state of the fake bw.
func (f *testFake) bwState() fakeBWState {
	f.t.Helper()
	var st fakeBWState
	if err := readJSON(filepath.Join(f.home, fakeBWStateFile), &st); err != nil {
		f.t.Fatal(err)
	}
	return st
}

// setBWState sets the state of the fake bw.
func (f *testFake) setBWState(st fakeBWState) {
	f.t.Helper()
	if err := writeJSON(filepath.Join(f.home, fakeBWStateFile), st); err != nil {
		f.t.Fatal(err)
	}
}

// calls returns the runs of the fake so far.
func (f *testFake) calls() []fakeCall {
	f.t.Helper()
	file, err := os.Open(filepath.Join(f.home, fakeCallsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var calls []fakeCall
	s := bufio.NewScanner(file)
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		var c fakeCall
		if err := json.Unmarshal(s.Bytes(), &c); err != nil {
			f.t.Fatal(err)
		}
		calls = append(calls, c)
	}
	if err := s.Err(); err != nil {
		f.t.Fatal(err)
	}
	return calls
}

// steps returns the step of each run of the fake so far, such as
// "unlock" or "get item".
func (f *testFake) steps() []string {
	f.t.Helper()
	var steps []string
	for _, c := range f.calls() {
		switch {
		case len(c.Args) >= 2 && (c.Args[0] == "secret" || c.Args[0] == "get"):
			steps = append(steps, c.Args[0]+" "+c.Args[1])
		case len(c.Args) >= 1:
			steps = append(steps, c.Args[0])
		default:
			steps = append(steps, "")
		}
	}
	return steps
}

// pids returns the process IDs that a hanging or leaving fake wrote.
func (f *testFake) pids() []int {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.home, fakePIDsFile))
	if err != nil {
		f.t.Fatalf("the fake wrote no process IDs: %v", err)
	}
	var pids []int
	for _, w := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(w)
		if err != nil || pid <= 1 {
			f.t.Fatalf("bad process ID %q", w)
		}
		pids = append(pids, pid)
	}
	if len(pids) != 2 {
		f.t.Fatalf("got %d process IDs, want 2", len(pids))
	}
	return pids
}

// waitGone waits until each process is gone or a zombie, and fails the
// test if one still runs after 10 seconds.
func waitGone(t *testing.T, pids []int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for _, pid := range pids {
		for alive(pid) {
			if time.Now().After(deadline) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("process %d still runs", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// alive reports whether a process runs: it exists and is not a zombie.
func alive(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// The state is the first field after the ")" that ends the name.
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return false
	}
	return data[i+2] != 'Z' && data[i+2] != 'X'
}

// envNames returns the sorted names of the variables in env.
func envNames(env []string) []string {
	var names []string
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// envValue returns the value of the variable name in env.
func envValue(env []string, name string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}
	return ""
}

// noCanary fails the test if text holds the canary. The message never
// shows the text, which may hold a secret.
func noCanary(t *testing.T, where, text, canary string) {
	t.Helper()
	if canary == "" {
		t.Fatal("empty canary")
	}
	if strings.Contains(text, canary) {
		t.Errorf("%s holds the made-up secret (%d bytes of text, not shown)", where, len(text))
	}
}

// checkValue fails the test if v is not want. The message shows only the
// lengths.
func checkValue(t *testing.T, v Value, want string) {
	t.Helper()
	if !bytes.Equal(v.Bytes(), []byte(want)) {
		t.Errorf("the value is wrong: got %d bytes, want %d bytes (the values are not shown)", len(v.Bytes()), len(want))
	}
}

// checkErr fails the test unless err wraps want.
func checkErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want %v", err, want)
	}
}

// bwsSecretJSON returns an answer of "bws secret get ID --output json" in
// the form of bws 2.1.0: serde_json's pretty print and a newline.
func bwsSecretJSON(id, value string) string {
	out, err := json.MarshalIndent(map[string]any{
		"id":             id,
		"organizationId": "0a1b2c3d-0000-4000-8000-000000000001",
		"projectId":      "0a1b2c3d-0000-4000-8000-000000000002",
		"key":            "GITHUB_TOKEN",
		"value":          value,
		"note":           "",
		"creationDate":   "2026-10-14T12:00:00.000000Z",
		"revisionDate":   "2026-10-14T12:00:00.000000Z",
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(out) + "\n"
}

// bwItemJSON returns an answer of "bw get item ID" for a login item, in
// the form of bw 2026.9.1: compact JSON without a newline. A normal item
// has no "deletedDate" and no "archivedDate" at all: bw leaves them
// undefined, and JSON.stringify drops them. deletedDate, if not nil, is
// the date the item went to the trash. secrets fills other fields that
// hold secrets, which nodkey must not read.
func bwItemJSON(id string, password any, deletedDate any, secrets string) string {
	item := map[string]any{
		"passwordHistory": []any{map[string]any{"lastUsedDate": "2026-10-01T12:00:00.000Z", "password": secrets}},
		"revisionDate":    "2026-10-14T12:00:00.000Z",
		"creationDate":    "2026-10-01T12:00:00.000Z",
		"object":          "item",
		"id":              id,
		"organizationId":  nil,
		"folderId":        nil,
		"type":            1,
		"reprompt":        0,
		"name":            "deploy token",
		"notes":           "notes: " + secrets,
		"favorite":        false,
		"fields":          []any{map[string]any{"name": "api", "value": secrets, "type": 1, "linkedId": nil}},
		"login": map[string]any{
			"uris":                 []any{map[string]any{"match": nil, "uri": "https://example.com"}},
			"username":             "deploy",
			"password":             password,
			"totp":                 secrets,
			"passwordRevisionDate": nil,
			"fido2Credentials":     []any{},
		},
		"collectionIds": []any{},
		"attachments":   nil,
	}
	if deletedDate != nil {
		item["deletedDate"] = deletedDate
	}
	out, err := json.Marshal(item)
	if err != nil {
		panic(err)
	}
	return string(out)
}

// String makes test failures show the scenario's steps, not its secrets.
func (sc fakeScenario) String() string {
	return fmt.Sprintf("scenario with %d items and %d steps", len(sc.Items), len(sc.Steps))
}
