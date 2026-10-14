package store

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
)

// homePerm is the mode of a store's home directory: only its owner may
// read, write or enter it.
const homePerm fs.FileMode = 0o700

// prepareHome makes sure that home is a private directory for the
// program's state files. bws keeps its login state there, and bw keeps a
// copy of the vault and its login.
//
//   - Every directory on the way to home must pass checkParentDirs
//     (config.CheckParentDirs): owned by root or by the user that runs
//     nodkey, and not writable by group or others. So nobody else can
//     swap home.
//   - If home is missing, it is made with mode 0700. Its parent must
//     exist.
//   - home must be a directory, not a symbolic link, owned by the user
//     that runs nodkey, with mode 0700.
//
// An error can name the path.
func prepareHome(home string, checkParentDirs func(string) error) error {
	if err := checkParentDirs(home); err != nil {
		return err // the error names the path
	}
	made := false
	switch err := os.Mkdir(home, homePerm); { //nolint:gosec // G703: home is the broker's state directory and a checked store name; checkParentDirs checked the way to it.
	case err == nil:
		made = true
	case !errors.Is(err, fs.ErrExist):
		return err // a *fs.PathError names the path
	}
	if made {
		// The umask may have taken bits away; set the mode exactly. Only
		// root and this user can change the directories on the way.
		if err := os.Chmod(home, homePerm); err != nil { //nolint:gosec // G703: the directory that Mkdir just made.
			return err
		}
	}
	fi, err := os.Lstat(home) //nolint:gosec // G703: Lstat only looks at home; the checks below refuse anything but a private directory.
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s: is a symbolic link; use the path of the directory itself", home)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: is not a directory", home)
	}
	owner, ok := fileOwner(fi)
	if !ok {
		return fmt.Errorf("%s: cannot check the owner on this system", home)
	}
	euid := os.Geteuid()
	if euid < 0 || uint64(euid) > math.MaxUint32 || owner != uint32(euid) {
		return fmt.Errorf("%s: is owned by user ID %d; it must be owned by the user that runs nodkey (ID %d)",
			home, owner, euid)
	}
	if perm := fi.Mode().Perm(); perm != homePerm {
		return fmt.Errorf("%s: has mode %04o; it must be private to its owner, with mode 0700", home, perm)
	}
	return nil
}
