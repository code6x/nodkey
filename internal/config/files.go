package config

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// maxFileSize is the largest file that ReadPrivateFile and ReadConfigFile
// read.
const maxFileSize = 1 << 20

// maxLinks is the largest number of symbolic links that walkPath follows
// for one path. Linux has the same limit.
const maxLinks = 40

// trustedDir is the top of the checks of walkPath: it checks trustedDir and
// the directories below it, but not the directories above it. It is "/",
// so every directory is checked. Only tests change it: the system temporary
// directory (/tmp) is writable by everyone, so the check would refuse every
// test file.
var trustedDir = string(filepath.Separator)

// credentialsRef is the one variable that ExpandPath knows.
const credentialsRef = "${CREDENTIALS_DIRECTORY}"

// ExpandPath expands a path from a config file.
//
//   - "${CREDENTIALS_DIRECTORY}/" at the start becomes the directory where
//     systemd puts the credentials of the service. It is an error if that
//     variable is not set or not an absolute path.
//   - "~/" at the start becomes the home directory.
//
// Any other "$", and a "~" at the start that is not "~/", is an error, so a
// typo in a variable name does not go unnoticed. Errors do not repeat the
// path.
func ExpandPath(p string) (string, error) {
	var base, rest string
	switch {
	case strings.HasPrefix(p, credentialsRef+"/"):
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return "", errors.New("uses ${CREDENTIALS_DIRECTORY}, but it is not set; " +
				"systemd sets it for a unit with LoadCredential= or LoadCredentialEncrypted=")
		}
		if !filepath.IsAbs(dir) {
			return "", errors.New("uses ${CREDENTIALS_DIRECTORY}, but it is not an absolute path")
		}
		base, rest = dir, p[len(credentialsRef):]
	case strings.HasPrefix(p, "~/"):
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", errors.New("starts with ~/, but the home directory is not known")
		}
		base, rest = home, p[1:]
	case strings.HasPrefix(p, "~"):
		return "", errors.New(`only "~/" is expanded at the start of a path`)
	default:
		rest = p
	}
	if strings.Contains(rest, "$") {
		return "", errors.New(`only "${CREDENTIALS_DIRECTORY}/" at the start of a path is expanded; no other "$" is allowed`)
	}
	return base + rest, nil
}

// ReadPrivateFile reads a file that holds a key, a token or a password.
// nodkey reads such files only through it (DESIGN.md sections 11 and 14).
//
// It opens the file once, checks the open file, and reads from that same
// open file, so the file cannot be swapped between the check and the read.
// The checks:
//
//   - Every directory on the way to the file must be owned by root or by
//     the user that runs nodkey, and group and others must not be able to
//     write to it. Otherwise someone else could swap the file. This holds
//     for the directories that hold a symbolic link on the way, too (see
//     walkPath). The credentials directory of a systemd service passes:
//     root owns it and it is read only.
//   - The file must not be a symbolic link, even one that points to a
//     private file. It is opened with O_NOFOLLOW.
//   - It must be a regular file, owned by root or by the user that runs
//     nodkey, and group and others must have no access: no read, write or
//     execute bit.
//   - POSIX ACLs: systemd gives a service its credentials as files owned
//     by root, mode 0400, with an ACL entry that lets the service's user
//     read them. The group bits of the mode then show the ACL mask, as in
//     0440. So when the group bits are set, the ACL of the open file is
//     read, and the file passes only if no entry gives access to anyone but
//     the owner and the user that runs nodkey. If the ACL cannot be read,
//     the file does not pass.
//   - It must be on a local file system that nodkey knows: ext2, ext3,
//     ext4, xfs, btrfs, zfs, tmpfs, ramfs, f2fs, bcachefs, overlayfs or
//     ecryptfs. Any other file system is refused, such as NFS, SMB/CIFS,
//     9p, Ceph or FUSE. There the mode bits may not show who can read the
//     file.
//   - It must not be larger than 1 MiB.
func ReadPrivateFile(path string) ([]byte, error) {
	f, _, err := openPrivateFile(path)
	if err != nil {
		return nil, err
	}
	return readAndClose(f, path)
}

// CheckPrivateFile makes the checks of ReadPrivateFile without reading the
// file. It tells early that a file is wrong; read the file with
// ReadPrivateFile, never by its path after this check.
func CheckPrivateFile(path string) error {
	_, err := checkPrivateFile(path)
	return err
}

// checkPrivateFile makes the checks of ReadPrivateFile and returns the
// information of the open file.
func checkPrivateFile(path string) (fs.FileInfo, error) {
	f, fi, err := openPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err // a *fs.PathError names the path
	}
	return fi, nil
}

// openPrivateFile opens a file and makes the checks of ReadPrivateFile. It
// returns the open file and its information.
func openPrivateFile(path string) (*os.File, fs.FileInfo, error) {
	self, err := currentUser()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	name, lfi, err := walkPath(path, self, lastLstat)
	if err != nil {
		return nil, nil, err
	}
	if lfi.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s: is a symbolic link; use the path of the file itself", path)
	}
	f, err := openRegular(name, lfi, path)
	if err != nil {
		return nil, nil, err
	}
	fi, err := checkOpenPrivateFile(f, self)
	if err != nil {
		_ = f.Close() // the check failed; a close error adds nothing
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, fi, nil
}

// checkOpenPrivateFile makes the checks of ReadPrivateFile on the open
// file itself, and returns its information.
func checkOpenPrivateFile(f *os.File, self uint32) (fs.FileInfo, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkFileOwner(fi, self); err != nil {
		return nil, err
	}
	if err := checkFileSystem(f); err != nil {
		return nil, err
	}
	if err := checkPrivatePerm(fi.Mode().Perm(), func() ([]byte, error) { return fileACL(f) }, self); err != nil {
		return nil, err
	}
	return fi, nil
}

// checkPrivatePerm checks the mode bits of a private file. When the group
// bits are set, it reads the file's ACL with readACL. No ACL, or an error
// while reading it, means the group bits are the group's own rights.
func checkPrivatePerm(perm fs.FileMode, readACL func() ([]byte, error), self uint32) error {
	if perm&0o007 != 0 {
		return fmt.Errorf("others have access (mode %04o); it must be private to its owner, such as mode 0600", perm)
	}
	if perm&0o070 == 0 {
		return nil
	}
	acl, err := readACL()
	if err != nil || acl == nil {
		return fmt.Errorf("its group has access (mode %04o); it must be private to its owner, such as mode 0600", perm)
	}
	return checkACL(acl, self)
}

// ReadConfigFile reads a file that decides what the broker allows: the
// config file or known_hosts. It follows symbolic links. Every directory on
// the way must pass the checks of ReadPrivateFile. The file must be a
// regular file owned by root or by the user that runs nodkey, and group and
// others must not be able to write to it; anyone may read it. It must not
// be larger than 1 MiB. Like ReadPrivateFile, it opens the file once,
// checks the open file, and reads from that same open file.
//
// Mode bits are enough here: with an ACL, the group bits show the ACL
// mask, which covers every ACL entry that could give write access.
func ReadConfigFile(path string) ([]byte, error) {
	self, err := currentUser()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	name, lfi, err := walkPath(path, self, lastFollow)
	if err != nil {
		return nil, err
	}
	f, err := openRegular(name, lfi, path)
	if err != nil {
		return nil, err
	}
	if err := checkOpenConfigFile(f, self); err != nil {
		_ = f.Close() // the check failed; a close error adds nothing
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return readAndClose(f, path)
}

// checkOpenConfigFile makes the checks of ReadConfigFile on the open file
// itself.
func checkOpenConfigFile(f *os.File, self uint32) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := checkFileOwner(fi, self); err != nil {
		return err
	}
	return checkNotWritable(fi.Mode().Perm())
}

// CheckParentDirs checks the directories on the way to path, with the same
// walk as ReadPrivateFile: each directory must be owned by root or by the
// user that runs nodkey, and group and others must not be able to write to
// it. Otherwise someone else could swap the file at path, or a symbolic
// link on the way. Symbolic links in the directories are followed, and the
// directory that holds each link is checked too.
//
// It checks only the owner and the write bits of the directories. Who can
// read or enter them is not checked, so a directory with mode 0755 passes.
// It does not look at the last part of path: that part may be missing, a
// symbolic link, or a file that anyone can read or write.
//
// So CheckParentDirs is only the first step before nodkey makes or opens a
// file that is not read with ReadPrivateFile or ReadConfigFile:
//
//   - The audit log: open it with O_NOFOLLOW, and check the open file.
//   - The ssh-agent socket: O_NOFOLLOW does not apply to bind(2), and a
//     directory that passes here may let other users reach the socket. So
//     the caller must still make the socket's directory with mode 0700,
//     and check the user of each peer that connects (DESIGN.md section 15).
//
// A path that ends in "/", "." or ".." is an error, because it names a
// directory. An error can name the path and the directory that failed.
func CheckParentDirs(path string) error {
	self, err := currentUser()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	_, _, err = walkPath(path, self, lastSkip)
	return err
}

// checkAuditLog checks the audit log before the broker opens it. Every
// directory on the way must pass CheckParentDirs. The file may be missing;
// the broker makes it. If it is there, it must be a regular file, not a
// symbolic link, owned by self, and its mode may give only read and write
// to its owner, such as 0600. The broker opens it later with O_NOFOLLOW and
// checks the open file again.
//
// It returns the Lstat information of the file, or nil when the file is
// missing, so that CheckFiles can compare it with the private files.
func checkAuditLog(path string, self uint32) (fs.FileInfo, error) {
	name, _, err := walkPath(path, self, lastSkip)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err // a *fs.PathError names the path
	}
	if err := checkAuditLogFile(fi, self); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return fi, nil
}

// checkAuditLogFile checks the Lstat information fi of an audit log that
// is there, for checkAuditLog.
func checkAuditLogFile(fi fs.FileInfo, self uint32) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return errors.New("is a symbolic link; use the path of the file itself")
	}
	if !fi.Mode().IsRegular() {
		return errors.New("is not a regular file")
	}
	owner, ok := fileOwner(fi)
	if !ok {
		return errors.New("cannot check the owner on this system")
	}
	if owner != self {
		return fmt.Errorf("is owned by user ID %d; it must be owned by the user that runs nodkey (ID %d)", owner, self)
	}
	// Only read and write for the owner: 0600 and less. A bit for group or
	// others, or an execute bit, points to a file that is not an audit log.
	switch perm := fi.Mode().Perm(); {
	case perm&0o077 != 0:
		return fmt.Errorf("group or others have access (mode %04o); it must be private to its owner, such as mode 0600", perm)
	case perm&0o100 != 0:
		return fmt.Errorf("its owner may run it as a program (mode %04o); the audit log must allow only read and "+
			"write, such as mode 0600", perm)
	}
	return nil
}

// checkProgram checks a program that the broker runs and gives a token to.
// It follows symbolic links. Every directory on the way must pass the
// checks of ReadPrivateFile. The program must be a regular file owned by
// root or by the user that runs nodkey, and group and others must not be
// able to write to it. It returns the Lstat information of the program,
// after the links.
func checkProgram(path string) (fs.FileInfo, error) {
	self, err := currentUser()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	name, fi, err := walkPath(path, self, lastFollow)
	if err != nil {
		return nil, err
	}
	if err := checkFileOwner(fi, self); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := checkNotWritable(fi.Mode().Perm()); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return fi, nil
}

// checkNotWritable checks the mode bits of a file that others must not
// change.
func checkNotWritable(perm fs.FileMode) error {
	if perm&0o022 != 0 {
		return fmt.Errorf("group or others can write to it (mode %04o); remove that, such as with chmod go-w", perm)
	}
	return nil
}

// lastPart says what walkPath does with the last part of a path.
type lastPart int

const (
	lastLstat  lastPart = iota // Lstat it; a symbolic link there is not followed
	lastFollow                 // follow a symbolic link there, then Lstat the target
	lastSkip                   // do not look at it; it may be missing
)

// walkPath finds the file that path names, the way the kernel does, and
// checks each directory on the way: it must be owned by root or by self,
// and group and others must not be able to write to it. Otherwise someone
// else could swap the file, or a symbolic link on the way. The directories
// above trustedDir are not checked.
//
// Symbolic links on the way are followed, at most maxLinks of them. last
// says what happens to the last part of the path. walkPath returns the path
// of the file, with no links in its directories, and the file's Lstat
// information; with lastSkip, the information is nil. Path errors name the
// part that failed.
func walkPath(path string, self uint32, last lastPart) (string, fs.FileInfo, error) {
	if path == "" {
		return "", nil, errors.New("the path is empty")
	}
	sep := string(filepath.Separator)
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return "", nil, err
		}
		path = wd + sep + path
	}
	// dir is a directory with no links in its path. It and every directory
	// above it have been checked.
	dir := sep
	if err := checkDir(dir, self); err != nil {
		return "", nil, err
	}
	parts := strings.Split(path, sep)
	links := 0
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			dir = filepath.Dir(dir) // dir has no links, so this is its real parent
			continue
		}
		name := filepath.Join(dir, part)
		// The last part is the file. A path that ends in "/" or "/." names
		// a directory, so its last part must be one.
		isLast := len(parts) == 0
		if isLast && last == lastSkip {
			return name, nil, nil
		}
		fi, err := os.Lstat(name)
		if err != nil {
			return "", nil, err // a *fs.PathError names the path
		}
		if fi.Mode()&fs.ModeSymlink != 0 && (!isLast || last == lastFollow) {
			if links++; links > maxLinks {
				return "", nil, fmt.Errorf("%s: more than %d symbolic links on the way", path, maxLinks)
			}
			target, err := os.Readlink(name)
			if err != nil {
				return "", nil, err
			}
			if filepath.IsAbs(target) {
				dir = sep // already checked
			}
			// The link is in dir, and dir is checked, so nobody else can
			// change where it points.
			parts = append(strings.Split(target, sep), parts...)
			continue
		}
		if isLast {
			return name, fi, nil
		}
		if !fi.IsDir() {
			return "", nil, fmt.Errorf("%s: is not a directory", name)
		}
		if err := checkDir(name, self); err != nil {
			return "", nil, err
		}
		dir = name
	}
	return "", nil, fmt.Errorf("%s: is a directory, not a file", path)
}

// checkDir checks one directory for walkPath, unless it is above
// trustedDir.
func checkDir(dir string, self uint32) error {
	prefix := dir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if dir != trustedDir && strings.HasPrefix(trustedDir, prefix) {
		return nil
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		// A link here means the path changed after it was walked.
		return fmt.Errorf("%s: is not a directory", dir)
	}
	owner, ok := fileOwner(fi)
	if !ok {
		return fmt.Errorf("%s: cannot check the owner on this system", dir)
	}
	if err := checkOwner(owner, self); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s: group or others can write to this directory (mode %04o), "+
			"so they could swap the files in it; remove that, such as with chmod go-w", dir, perm)
	}
	return nil
}

// openRegular opens the file at name, which walkPath returned with its
// Lstat information lfi, for reading. It opens only a regular file:
// opening a device can have side effects, and opening a FIFO can wait.
// The flags also refuse a symbolic link and do not wait on a FIFO, in case
// the file changed after the walk.
func openRegular(name string, lfi fs.FileInfo, path string) (*os.File, error) {
	if !lfi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: is not a regular file", path)
	}
	return os.OpenFile(name, openFlags, 0) //nolint:gosec // G304: the path comes from the config or the command line; walkPath checked the way to it, and the open file is checked next.
}

// readAndClose reads all of f, up to maxFileSize, and closes f. A close
// error is an error too.
func readAndClose(f io.ReadCloser, path string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err // a *fs.PathError names the path
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%s: is larger than 1 MiB", path)
	}
	return data, nil
}

// currentUser returns the user ID that runs nodkey.
func currentUser() (uint32, error) {
	euid := os.Geteuid()
	if euid < 0 || uint64(euid) > math.MaxUint32 {
		return 0, errors.New("cannot get the user ID on this system")
	}
	return uint32(euid), nil
}

// checkFileOwner checks that fi is a regular file owned by root or self.
func checkFileOwner(fi fs.FileInfo, self uint32) error {
	if !fi.Mode().IsRegular() {
		return errors.New("is not a regular file")
	}
	owner, ok := fileOwner(fi)
	if !ok {
		return errors.New("cannot check the owner on this system")
	}
	return checkOwner(owner, self)
}

// checkOwner checks that a file owned by user ID owner is safe for the
// user self: root or self must own it. Another owner can change it.
func checkOwner(owner, self uint32) error {
	if owner != 0 && owner != self {
		return fmt.Errorf("is owned by user ID %d; it must be owned by the user that runs nodkey (ID %d) or by root",
			owner, self)
	}
	return nil
}

// The parts of a Linux POSIX ACL in the system.posix_acl_access extended
// attribute: a version, then entries of tag, permissions and ID (see
// include/uapi/linux/posix_acl_xattr.h). All are little endian.
const (
	aclVersion   = 2
	aclHeader    = 4
	aclEntrySize = 8

	aclUserObj  = 0x01 // the owner
	aclUser     = 0x02 // a named user
	aclGroupObj = 0x04 // the owning group
	aclGroup    = 0x08 // a named group
	aclMask     = 0x10 // the most that named users and all groups get
	aclOther    = 0x20 // everyone else
)

// checkACL returns an error unless the ACL gives access only to the owner
// and to the user self. The mask limits named users and all groups, as
// the kernel does.
func checkACL(acl []byte, self uint32) error {
	if len(acl) < aclHeader || (len(acl)-aclHeader)%aclEntrySize != 0 ||
		binary.LittleEndian.Uint32(acl) != aclVersion {
		return errors.New("has an access control list (ACL) in a form nodkey does not know")
	}
	entries := acl[aclHeader:]
	mask := uint16(0o7)
	for i := 0; i < len(entries); i += aclEntrySize {
		if binary.LittleEndian.Uint16(entries[i:]) == aclMask {
			mask = binary.LittleEndian.Uint16(entries[i+2:])
		}
	}
	for i := 0; i < len(entries); i += aclEntrySize {
		tag := binary.LittleEndian.Uint16(entries[i:])
		perm := binary.LittleEndian.Uint16(entries[i+2:]) & 0o7
		id := binary.LittleEndian.Uint32(entries[i+4:])
		switch tag {
		case aclUserObj, aclMask:
			// The owner is checked apart. The mask only limits others.
		case aclUser:
			if id != self && perm&mask != 0 {
				return fmt.Errorf("its access control list (ACL) gives user ID %d access", id)
			}
		case aclGroupObj, aclGroup:
			if perm&mask != 0 {
				return errors.New("its access control list (ACL) gives a group access")
			}
		case aclOther:
			if perm != 0 {
				return errors.New("its access control list (ACL) gives others access")
			}
		default:
			return errors.New("has an access control list (ACL) entry nodkey does not know")
		}
	}
	return nil
}
