package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

// TestNewMakesTheRealChecks shows that New uses the checks of the config
// package. The other tests replace them (testDeps), because those checks
// refuse every path below the system temporary directory.
func TestNewMakesTheRealChecks(t *testing.T) {
	t.Parallel()
	for _, typ := range []config.StoreType{config.StoreBWS, config.StoreBW} {
		f := setupFake(t, typ, fakeScenario{Token: madeUp("token"), Password: madeUp("password")})
		// A directory that everyone can write to, on the way to the home.
		open := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(open, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // G302: the test needs a directory that others can write to.
			t.Fatal(err)
		}
		dir := filepath.Join(open, "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := New(f.cfg, dir)
		if err == nil || !strings.Contains(err.Error(), "group or others can write to this directory") {
			t.Errorf("%s: New below a directory that others can write to: %v", typ, err)
		}
		// The token or password file is checked too.
		key := filepath.Join(open, "key")
		writeFile(t, key, madeUp("key")+"\n")
		f.cfg.TokenFile, f.cfg.PasswordFile = "", ""
		if typ == config.StoreBWS {
			f.cfg.TokenFile = key
		} else {
			f.cfg.PasswordFile = key
		}
		_, err = newStore(f.cfg, f.dir, deps{
			readPrivateFile:  config.ReadPrivateFile,
			checkPrivateFile: config.CheckPrivateFile,
			checkParentDirs:  func(string) error { return nil },
		})
		if err == nil {
			t.Errorf("%s: newStore took a key file below a directory that others can write to", typ)
		}
		if calls := f.calls(); len(calls) != 0 {
			t.Errorf("%s ran %d times, want 0", typ, len(calls))
		}
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	t.Parallel()
	f := setupFake(t, config.StoreBWS, fakeScenario{Token: madeUp("token")})
	tests := map[string]struct {
		change func(cfg *config.Store, dir *string)
		want   string
	}{
		"relative program":    {func(c *config.Store, _ *string) { c.Program = "bws" }, "program: must be an absolute path"},
		"program with ..":     {func(c *config.Store, _ *string) { c.Program = "/usr/local/../local/bin/bws" }, "program: must be an absolute path without"},
		"program with //":     {func(c *config.Store, _ *string) { c.Program = "/usr/local//bin/bws" }, "program: must be an absolute path without"},
		"relative token file": {func(c *config.Store, _ *string) { c.TokenFile = "bws-token" }, "token_file: must be an absolute path"},
		"token file with .":   {func(c *config.Store, _ *string) { c.TokenFile = "/etc/nodkey/./bws-token" }, "token_file: must be an absolute path without"},
		"no token file":       {func(c *config.Store, _ *string) { c.TokenFile = "" }, "token_file: must be an absolute path"},
		"bw, relative password file": {func(c *config.Store, _ *string) {
			c.Type, c.PasswordFile = config.StoreBW, "-password"
		}, "password_file: must be an absolute path"},
		"bw, password file with ..": {func(c *config.Store, _ *string) {
			c.Type, c.PasswordFile = config.StoreBW, "/etc/nodkey/../nodkey/password"
		}, "password_file: must be an absolute path without"},
		"bw, no password file": {func(c *config.Store, _ *string) { c.Type = config.StoreBW }, "password_file: must be an absolute path"},
		"unknown type":         {func(c *config.Store, _ *string) { c.Type = "sops" }, "unknown store type"},
		"no type":              {func(c *config.Store, _ *string) { c.Type = "" }, "unknown store type"},
		"name ..":              {func(c *config.Store, _ *string) { c.Name = ".." }, "cannot be the name of a directory"},
		"name .":               {func(c *config.Store, _ *string) { c.Name = "." }, "cannot be the name of a directory"},
		"name with /":          {func(c *config.Store, _ *string) { c.Name = "a/b" }, "cannot be the name of a directory"},
		"empty name":           {func(c *config.Store, _ *string) { c.Name = "" }, "cannot be the name of a directory"},
		"relative dir":         {func(_ *config.Store, d *string) { *d = "state" }, "state directory: must be an absolute path"},
		"dir with ..":          {func(_ *config.Store, d *string) { *d += "/../state" }, "state directory: must be an absolute path without"},
		"missing dir":          {func(_ *config.Store, d *string) { *d += "/missing" }, "no such file or directory"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg, dir := f.cfg, f.dir
			tc.change(&cfg, &dir)
			_, err := newStore(cfg, dir, testDeps())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("newStore: %v, want an error with %q", err, tc.want)
			}
		})
	}
}

// TestNewPreparesTheHome is not parallel: it changes the umask of the
// whole process.
func TestNewPreparesTheHome(t *testing.T) {
	f := setupFake(t, config.StoreBWS, fakeScenario{Token: madeUp("token")})
	if err := os.RemoveAll(f.home); err != nil {
		t.Fatal(err)
	}
	// A missing home is made with mode 0700, whatever the umask.
	old := syscall.Umask(0o277)
	s, err := newStore(f.cfg, f.dir, testDeps())
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	s.Close()
	fi, err := os.Lstat(f.home)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("home mode = %v, want a directory with 0700", fi.Mode())
	}
	// The directories on the way are checked.
	d := testDeps()
	bad := errors.New("made-up: a directory that others can write to")
	var checked []string
	d.checkParentDirs = func(path string) error {
		checked = append(checked, path)
		return bad
	}
	if _, err := newStore(f.cfg, f.dir, d); !errors.Is(err, bad) {
		t.Errorf("newStore with a bad directory on the way: %v", err)
	}
	if !slices.Equal(checked, []string{f.home}) {
		t.Errorf("checked %q, want the home %q", checked, f.home)
	}
}

func TestNewRefusesABadHome(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		make func(t *testing.T, home string)
		want string
	}{
		"group can read":     {func(t *testing.T, home string) { chmod(t, home, 0o750) }, "has mode 0750"},
		"others can read":    {func(t *testing.T, home string) { chmod(t, home, 0o705) }, "has mode 0705"},
		"owner cannot write": {func(t *testing.T, home string) { chmod(t, home, 0o500) }, "has mode 0500"},
		"a file": {func(t *testing.T, home string) {
			if err := os.RemoveAll(home); err != nil {
				t.Fatal(err)
			}
			writeFile(t, home, "")
		}, "is not a directory"},
		"a link": {func(t *testing.T, home string) {
			if err := os.Rename(home, home+"-real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(home+"-real", home); err != nil {
				t.Fatal(err)
			}
		}, "is a symbolic link"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := setupFake(t, config.StoreBWS, fakeScenario{Token: madeUp("token")})
			tc.make(t, f.home)
			t.Cleanup(func() { chmod(t, f.home, 0o700) }) // so t.TempDir can remove it
			_, err := newStore(f.cfg, f.dir, testDeps())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("newStore: %v, want an error with %q", err, tc.want)
			}
		})
	}
}

// chmod sets the mode of a test file, if it is not a link.
func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		return
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestNoInheritedEnvironment shows that a program gets nothing from the
// broker's own environment. Variables such as NODE_OPTIONS, LD_PRELOAD or
// BW_CLEANEXIT (which makes bw exit with 0 on errors) would change what
// the program does.
func TestNoInheritedEnvironment(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "--require=/made-up/module.js")
	t.Setenv("BW_CLEANEXIT", "true")
	t.Setenv("BWS_SERVER_URL", "https://made-up.example.com")
	t.Setenv("NODKEY_TEST_MADE_UP", "x")
	for _, typ := range []config.StoreType{config.StoreBWS, config.StoreBW} {
		value := madeUp("value")
		sc := bwsScenario(madeUp("token"), value)
		if typ == config.StoreBW {
			sc = bwScenario(madeUp("password"), "", value, madeUp("other"))
		}
		f := newTestFake(t, typ, sc, testDeps())
		v, err := f.store.Fetch(t.Context(), testItemID)
		if err != nil {
			t.Fatalf("%s: Fetch: %v", typ, err)
		}
		checkValue(t, v, value)
		for _, c := range f.calls() {
			for _, name := range envNames(c.Env) {
				if !slices.Contains([]string{"HOME", "PATH", "BWS_ACCESS_TOKEN", "BW_SESSION"}, name) {
					t.Errorf("%s %q got the variable %s", typ, c.Args, name)
				}
			}
		}
	}
}

func TestMissingProgram(t *testing.T) {
	t.Parallel()
	f := newTestFake(t, config.StoreBWS, bwsScenario(madeUp("token"), madeUp("value")), testDeps())
	if err := os.Remove(f.cfg.Program); err != nil {
		t.Fatal(err)
	}
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrStart)
	checkErr(t, err, syscall.ENOENT)
	if err != nil && err.Error() != `store "main": bws secret get: cannot start the program: no such file or directory` {
		t.Errorf("error = %v", err)
	}
}

func TestIsUUID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{testItemID, strings.ToUpper(testItemID), "00000000-0000-0000-0000-000000000000"} {
		if !isUUID(id) {
			t.Errorf("isUUID(%q) = false", id)
		}
	}
	for _, id := range []string{"", "-", testItemID + "\n", "{" + testItemID + "}", "6f1e2d3c4b5a49878a6b5c4d3e2f1a0b"} {
		if isUUID(id) {
			t.Errorf("isUUID(%q) = true", id)
		}
	}
}
