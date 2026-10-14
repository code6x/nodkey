package store

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// TestBWChecksItsPathDirectories shows that New checks each directory in
// bw's PATH like the directories on the way to a program, and that a
// directory that is not there passes when the way to it passes.
func TestBWChecksItsPathDirectories(t *testing.T) {
	t.Parallel()
	f := setupFake(t, config.StoreBW, fakeScenario{Password: madeUp("password")})
	missing := filepath.Join(t.TempDir(), "missing")
	d := testDeps()
	d.path = "/usr/local/bin:" + missing
	var checked []string
	bad := errors.New("made-up: group or others can write to this directory")
	d.checkParentDirs = func(path string) error {
		checked = append(checked, path)
		switch path {
		case filepath.Join(missing, "node"):
			return &fs.PathError{Op: "lstat", Path: missing, Err: fs.ErrNotExist}
		case "/usr/local/bin/node":
			if len(checked) > 4 { // the second store below
				return bad
			}
		}
		return nil
	}
	s, err := newStore(f.cfg, f.dir, d)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	s.Close()
	want := []string{f.home, "/usr/local/bin/node", filepath.Join(missing, "node"), missing}
	if !slices.Equal(checked, want) {
		t.Errorf("checked %q, want %q", checked, want)
	}
	// A PATH directory that fails the check stops New.
	_, err = newStore(f.cfg, f.dir, d)
	checkErr(t, err, bad)
	if err != nil && !strings.Contains(err.Error(), `store "vault": PATH directory /usr/local/bin: `) {
		t.Errorf("error = %v", err)
	}
	// bws gets no PATH, so its PATH is not checked.
	checked = nil
	b := setupFake(t, config.StoreBWS, fakeScenario{Token: madeUp("token")})
	s, err = newStore(b.cfg, b.dir, d)
	if err != nil {
		t.Fatalf("newStore of bws: %v", err)
	}
	s.Close()
	if !slices.Equal(checked, []string{b.home}) {
		t.Errorf("bws checked %q, want only its home", checked)
	}
	// A PATH directory must be a clean absolute path.
	for _, path := range []string{"bin", "/usr/bin:", "/usr//bin", "/usr/bin/../bin"} {
		none := func(string) error { return nil }
		if err := checkPathDirs(path, none, none); err == nil {
			t.Errorf("checkPathDirs(%q) took it", path)
		}
	}
}

// TestPathDirectoriesRealCheck runs checkPathDirs with the real check of
// the config package on a directory that everyone can write to.
func TestPathDirectoriesRealCheck(t *testing.T) {
	t.Parallel()
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // G302: the test needs a directory that others can write to.
		t.Fatal(err)
	}
	for _, path := range []string{open, filepath.Join(open, "missing")} {
		err := checkPathDirs(path, config.CheckParentDirs, config.CheckProgram)
		if err == nil || !strings.Contains(err.Error(), "group or others can write to this directory") {
			t.Errorf("checkPathDirs(%s): %v", path, err)
		}
	}
}

// TestBWPathNodeIsCheckedLikeTheProgram comes from the second security
// review of issue #8. The node that bw's PATH gives a bw script reads the
// master password file and gets the session key, like the program itself.
// So it must pass the checks of a program: owned by root or the broker
// user, not writable by group or others, also after its links, and the
// way to its target too. config.TestCheckProgram tests the check itself.
func TestBWPathNodeIsCheckedLikeTheProgram(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]func(t *testing.T, dir string){
		"a node that others can write": func(t *testing.T, dir string) {
			node := filepath.Join(dir, "node")
			writeFile(t, node, "")
			if err := os.Chmod(node, 0o777); err != nil { //nolint:gosec // G302: the test needs a file that others can write to.
				t.Fatal(err)
			}
		},
		"a node that links to a file that others can write": func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "node")
			writeFile(t, target, "")
			if err := os.Chmod(target, 0o777); err != nil { //nolint:gosec // G302: the test needs a file that others can write to.
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "node")); err != nil {
				t.Fatal(err)
			}
		},
		"a node that links to a missing file": func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "node"), filepath.Join(dir, "node")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := setupFake(t, config.StoreBW, fakeScenario{Password: madeUp("password")})
			dir := t.TempDir()
			setup(t, dir)
			d := testDeps()
			d.path = dir
			d.checkProgram = config.CheckProgram // the real check
			s, err := newStore(f.cfg, f.dir, d)
			if err == nil {
				s.Close()
				t.Fatal("newStore took it")
			}
			if !strings.Contains(err.Error(), `store "vault": PATH directory `+dir+": node: ") {
				t.Errorf("error = %v", err)
			}
		})
	}
	// Each node is checked, by its path in PATH: the check follows the
	// links and checks the way to the target. A directory without node
	// has nothing to check.
	f := setupFake(t, config.StoreBW, fakeScenario{Password: madeUp("password")})
	dir, empty, target := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "node")
	writeFile(t, target, "")
	if err := os.Symlink(target, filepath.Join(dir, "node")); err != nil {
		t.Fatal(err)
	}
	d := testDeps()
	d.path = empty + ":" + dir
	var checked []string
	d.checkProgram = func(p string) error { checked = append(checked, p); return nil }
	s, err := newStore(f.cfg, f.dir, d)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	s.Close()
	if want := []string{filepath.Join(dir, "node")}; !slices.Equal(checked, want) {
		t.Errorf("checked %q, want %q", checked, want)
	}
	// A failed check stops New.
	bad := errors.New("made-up: group or others can write to it")
	d.checkProgram = func(string) error { return bad }
	if _, err := newStore(f.cfg, f.dir, d); !errors.Is(err, bad) {
		t.Errorf("newStore with a bad node: %v", err)
	}
}

// TestBWDataIsRefused shows that New refuses a bw-data directory next to
// bw's executable, where bw would keep its state instead of in its home.
func TestBWDataIsRefused(t *testing.T) {
	t.Parallel()
	makeDir := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tests := map[string]func(t *testing.T, f *testFake, d *deps){
		"next to the program": func(t *testing.T, f *testFake, _ *deps) {
			makeDir(t, filepath.Join(filepath.Dir(f.cfg.Program), bwDataDir))
		},
		"a file next to the program": func(t *testing.T, f *testFake, _ *deps) {
			writeFile(t, filepath.Join(filepath.Dir(f.cfg.Program), bwDataDir), "")
		},
		"next to the file that the program links to": func(t *testing.T, f *testFake, _ *deps) {
			real := filepath.Join(t.TempDir(), "real", "bw")
			makeDir(t, filepath.Dir(real))
			writeFile(t, real, "")
			makeDir(t, filepath.Join(filepath.Dir(real), bwDataDir))
			if err := os.Remove(f.cfg.Program); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, f.cfg.Program); err != nil {
				t.Fatal(err)
			}
		},
		"next to node in PATH": func(t *testing.T, _ *testFake, d *deps) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "node"), "")
			makeDir(t, filepath.Join(dir, bwDataDir))
			d.path = "/usr/local/bin:" + dir
		},
		"next to the file that node links to": func(t *testing.T, _ *testFake, d *deps) {
			dir, real := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(real, "node"), "")
			makeDir(t, filepath.Join(real, bwDataDir))
			if err := os.Symlink(filepath.Join(real, "node"), filepath.Join(dir, "node")); err != nil {
				t.Fatal(err)
			}
			d.path = dir
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := setupFake(t, config.StoreBW, fakeScenario{Password: madeUp("password")})
			d := testDeps()
			setup(t, f, &d)
			_, err := newStore(f.cfg, f.dir, d)
			if err == nil || !strings.Contains(err.Error(), "/bw-data: bw would keep its state there") {
				t.Errorf("newStore: %v", err)
			}
		})
	}
	// A program that is not there cannot be checked.
	f := setupFake(t, config.StoreBW, fakeScenario{Password: madeUp("password")})
	if err := os.Remove(f.cfg.Program); err != nil {
		t.Fatal(err)
	}
	if _, err := newStore(f.cfg, f.dir, testDeps()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("newStore without the program: %v", err)
	}
	// bws does not use bw-data.
	b := setupFake(t, config.StoreBWS, fakeScenario{Token: madeUp("token")})
	makeDir(t, filepath.Join(filepath.Dir(b.cfg.Program), bwDataDir))
	s, err := newStore(b.cfg, b.dir, testDeps())
	if err != nil {
		t.Fatalf("newStore of bws: %v", err)
	}
	s.Close()
}

// TestBWPasswordFileSize shows that the password file must hold 1 byte to
// 1 MiB, at New and before each unlock.
func TestBWPasswordFileSize(t *testing.T) {
	t.Parallel()
	password := madeUp("password")
	for name, tc := range map[string]struct {
		content string
		want    string
	}{
		"empty":    {"", "is empty"},
		"too big":  {password + "\n" + strings.Repeat("x", maxPasswordFileSize), "is larger than 1 MiB"},
		"a folder": {"", "is not a regular file"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := setupFake(t, config.StoreBW, bwScenario(password, "", madeUp("value"), madeUp("other")))
			setFile := func() {
				if name == "a folder" {
					if err := os.RemoveAll(f.cfg.PasswordFile); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(f.cfg.PasswordFile, 0o700); err != nil {
						t.Fatal(err)
					}
					return
				}
				writeFile(t, f.cfg.PasswordFile, tc.content)
			}
			setFile()
			_, err := newStore(f.cfg, f.dir, testDeps())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("newStore: %v, want an error with %q", err, tc.want)
			}
			// The file was good at New, and then changed.
			if err := os.RemoveAll(f.cfg.PasswordFile); err != nil {
				t.Fatal(err)
			}
			writeFile(t, f.cfg.PasswordFile, password+"\n")
			s, err := newStore(f.cfg, f.dir, testDeps())
			if err != nil {
				t.Fatalf("newStore: %v", err)
			}
			defer s.Close()
			setFile()
			err = s.Start(t.Context())
			if err == nil || !strings.Contains(err.Error(), `bw unlock: password_file: `) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Start: %v, want an error with %q", err, tc.want)
			}
			if calls := f.calls(); len(calls) != 0 {
				t.Errorf("bw ran %d times, want 0", len(calls))
			}
		})
	}
}

// brokerHomeVar names the home directory of a store, in a child process
// of TestProgramDiesWithTheBroker that acts as the broker.
const brokerHomeVar = "NODKEY_TEST_BROKER_STORE"

// TestProgramDiesWithTheBroker starts a child process that acts as the
// broker and runs a store program that hangs. Then it kills the child with
// SIGKILL, so the broker cannot clean up. The program must die too
// (Pdeathsig).
func TestProgramDiesWithTheBroker(t *testing.T) {
	if dir := os.Getenv(brokerHomeVar); dir != "" {
		// The child: a bws store whose program hangs. Fetch never returns.
		cfg := config.Store{
			Name: "main", Type: config.StoreBWS, Program: filepath.Join(dir, "bin", "bws"),
			TokenFile: filepath.Join(dir, "bws-token"),
		}
		s, err := newStore(cfg, filepath.Join(dir, "state"), testDeps())
		if err != nil {
			t.Fatalf("newStore: %v", err)
		}
		_, err = s.Fetch(t.Context(), testItemID)
		t.Fatalf("Fetch returned: %v", err)
	}
	t.Parallel()
	sc := bwsScenario(madeUp("token"), madeUp("value"))
	sc.Steps = map[string]fakeStep{"secret get": {Hang: true}}
	f := setupFake(t, config.StoreBWS, sc)
	broker := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProgramDiesWithTheBroker$") //nolint:gosec // G204: the test runs its own binary again.
	broker.Env = append(os.Environ(), brokerHomeVar+"="+filepath.Dir(f.dir))
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- broker.Wait() }()
	// Wait until the program runs: it writes its process IDs.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(f.home, fakePIDsFile)); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the broker ended early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the program did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	pids := f.pids()
	// The program's own child is in its process group, which only the
	// broker kills. Kill it when the test ends.
	t.Cleanup(func() { _ = syscall.Kill(pids[1], syscall.SIGKILL) })
	if err := broker.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	<-done
	waitGone(t, pids[:1])
}
