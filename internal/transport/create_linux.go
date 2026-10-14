package transport

import (
	"os"
	"syscall"
)

// createFlags make a new file for writing. With O_EXCL the file must not
// exist, also not as a symbolic link: open(2) then fails with EEXIST.
// O_NOFOLLOW says the same once more.
const createFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL | syscall.O_NOFOLLOW

// createKeyFile makes a new, empty key file at path with mode 0600. The
// umask can only take bits away; fillKeyFile sets the mode exactly.
func createKeyFile(path string) (*os.File, error) {
	return os.OpenFile(path, createFlags, keyFilePerm) //nolint:gosec // G304: the person who runs nodkey keygen chooses the path; generateKeyFile checks the directories first.
}
