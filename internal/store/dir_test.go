package store

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestPrepareDir: the store directory follows the rules of a store's home
// directory. A missing one is made with mode 0700; one with another mode,
// a file or a link is refused; the directories on the way are checked, and
// PrepareDir itself makes the real check of the config package.
func TestPrepareDir(t *testing.T) {
	t.Parallel()
	pass := func(string) error { return nil }

	dir := filepath.Join(t.TempDir(), "stores")
	if err := prepareDir(dir, pass); err != nil {
		t.Fatalf("a missing store directory: %v", err)
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != homePerm {
		t.Fatalf("the store directory: %v, %v; want a directory with mode 0700", fi, err)
	}
	if err := prepareDir(dir, pass); err != nil {
		t.Errorf("a store directory that is there: %v", err)
	}

	bad := errors.New("made-up: a directory that others can write to")
	var checked []string
	check := func(p string) error {
		checked = append(checked, p)
		return bad
	}
	if err := prepareDir(dir, check); !errors.Is(err, bad) {
		t.Errorf("with a bad directory on the way: %v", err)
	}
	if !slices.Equal(checked, []string{dir}) {
		t.Errorf("checked %q, want %q", checked, dir)
	}

	chmod(t, dir, 0o750)
	if err := prepareDir(dir, pass); err == nil || !strings.Contains(err.Error(), "has mode 0750") {
		t.Errorf("a store directory with mode 0750: %v", err)
	}
	chmod(t, dir, 0o700)

	link := filepath.Join(filepath.Dir(dir), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareDir(link, pass); err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Errorf("a link: %v", err)
	}

	for _, p := range []string{"stores", dir + "/", dir + "/../stores", ""} {
		if err := prepareDir(p, pass); err == nil || !strings.Contains(err.Error(), cleanAbsRule) {
			t.Errorf("%q: %v, want an error about the path", p, err)
		}
	}

	// The real check refuses the system temporary directory, which
	// everyone can write to.
	if err := PrepareDir(filepath.Join(t.TempDir(), "stores")); err == nil ||
		!strings.Contains(err.Error(), "group or others can write") {
		t.Errorf("PrepareDir below the system temporary directory: %v", err)
	}
}
