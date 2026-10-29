package client

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/code6x/nodkey/internal/grantkey"
)

// The token file of a standing grant (DESIGN.md sections 8 and 15) holds
// one token and a line feed. Only its owner may read and write it. These
// helpers are for nodkey preapprove, which writes the first token, and for
// nodkey run, which writes each new token.

// ErrTokenFile is returned for a token file that the client refuses, or
// cannot save. Errors that wrap it never hold the token.
var ErrTokenFile = errors.New("grant token file")

// CheckGrantTokenFile checks that path is free to use as a token file:
// either nothing is there, or a regular file that the user owns, with no
// permission for the group and for others (mode 0600 at most). A symbolic
// link is refused. It does not read the file.
func CheckGrantTokenFile(path string) error {
	if path == "" {
		return fmt.Errorf("%w: the path is empty", ErrTokenFile)
	}
	fi, err := os.Lstat(path) //nolint:gosec // G703: the path is the one that the person gave.
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%w: cannot look at %q: %s", ErrTokenFile, path, errText(err))
	}
	return checkTokenFileInfo(path, fi)
}

// checkTokenFileInfo checks the Lstat result fi of the file path.
func checkTokenFileInfo(path string, fi fs.FileInfo) error {
	switch {
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%w: %q is not a regular file", ErrTokenFile, path)
	case !ownedByUser(fi):
		return fmt.Errorf("%w: %q is not owned by this user", ErrTokenFile, path)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%w: %q can be read or written by other users; use mode 0600", ErrTokenFile, path)
	}
	return nil
}

// SaveGrantToken writes tok to the file path so that a reader sees the old
// token or the new one, never a part. It checks the file as
// CheckGrantTokenFile does, makes a new file with mode 0600 in the same
// directory (it never follows a link and never reuses a name), writes
// and syncs it, renames it over path, and syncs the directory. On an error
// no new file is left. Its errors never hold the token.
func SaveGrantToken(path string, tok grantkey.Token) (err error) {
	if err := CheckGrantTokenFile(path); err != nil {
		return err
	}
	if _, perr := grantkey.Parse(tok.Reveal()); perr != nil {
		return fmt.Errorf("%w: not a token", ErrTokenFile)
	}
	dir := filepath.Dir(path)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("%w: no random bytes", ErrTokenFile)
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600) //nolint:gosec // G304: the path is the one that the person gave.
	if err != nil {
		return fmt.Errorf("%w: cannot make a file in %q: %s", ErrTokenFile, dir, errText(err))
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err == nil {
		_, err = f.WriteString(tok.Reveal() + "\n")
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%w: cannot write the file in %q: %s", ErrTokenFile, dir, errText(err))
	}
	// The file may have changed while the broker was asked.
	if err = CheckGrantTokenFile(path); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("%w: cannot replace %q: %s", ErrTokenFile, path, errText(err))
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the directory of the path that the person gave.
	if err == nil {
		err = d.Sync()
		_ = d.Close()
	}
	if err != nil {
		// The new file is in place; do not remove it.
		return fmt.Errorf("%w: cannot sync the directory %q: %s", ErrTokenFile, dir, errText(err))
	}
	return nil
}

// errText is the reason of an operating system error, without the path.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return err.Error()
}
