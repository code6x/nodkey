package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
)

// openFlags open a file for reading without following a symbolic link,
// and without waiting on a FIFO.
const openFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// fileOwner returns the user ID that owns the file.
func fileOwner(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// Magic numbers of the local file systems where the mode bits and the ACL
// show who can read a file (see statfs(2) and include/uapi/linux/magic.h;
// zfs comes from OpenZFS). overlayfs and ecryptfs are layers over another
// file system; the kernel still checks the mode bits and the ACL of the
// file you name. On overlayfs those are the bits of the top copy only: a
// lower copy of the file can have others (DESIGN.md section 14). Every
// other file system is refused: on a network file system another machine
// also decides who can read a file, on FUSE a program decides, and nodkey
// does not know the rest.
const (
	extMagic       = 0xEF53 // ext2, ext3 and ext4
	xfsMagic       = 0x58465342
	btrfsMagic     = 0x9123683E
	zfsMagic       = 0x2FC12FC1
	tmpfsMagic     = 0x01021994
	ramfsMagic     = 0x858458F6
	f2fsMagic      = 0xF2F52010
	bcachefsMagic  = 0xCA451A4E
	overlayfsMagic = 0x794C7630
	ecryptfsMagic  = 0xF15F
)

// localFileSystems names the file systems above, for error messages.
const localFileSystems = "ext2, ext3, ext4, xfs, btrfs, zfs, tmpfs, ramfs, f2fs, bcachefs, overlayfs or ecryptfs"

// refusedFileSystems names some file systems that are refused, so that an
// error can say which one a file is on. The magic numbers come from
// include/uapi/linux/magic.h, or else from the file system's own source
// code (gfs2, lustre, orangefs, gpfs, vboxsf and beegfs). An error shows
// any other type as a number.
var refusedFileSystems = map[uint32]string{
	0x6969:     "nfs",
	0x517B:     "smb",
	0xFF534D42: "cifs",
	0xFE534D42: "smb2",
	0x01021997: "9p",
	0x5346414F: "afs",
	0x6B414653: "afs",
	0x00C36400: "ceph",
	0x65735546: "fuse",
	0x73757245: "coda",
	0x7461636F: "ocfs2",
	0x01161970: "gfs2",
	0x00C0FFEE: "hostfs",
	0x0BD00BD0: "lustre",
	0x20030528: "orangefs",
	0x47504653: "gpfs",
	0x786F4256: "vboxsf",
	0x19830326: "beegfs",
	0x4D44:     "vfat",
	0x2011BAB0: "exfat",
}

// checkFileSystem refuses an open file that is not on one of the local
// file systems above.
func checkFileSystem(f *os.File) error {
	magic, err := fileSystemType(f)
	if err != nil {
		return err
	}
	return checkFileSystemType(magic)
}

// fileSystemType returns the magic number of the file system that holds
// the open file f. It is a variable only so that a test can act as if the
// file were on another file system.
var fileSystemType = func(f *os.File) (uint32, error) {
	var st syscall.Statfs_t
	err := control(f, func(fd uintptr) error {
		return syscall.Fstatfs(int(fd), &st)
	})
	if err != nil {
		return 0, err
	}
	// f_type is a 32-bit magic number; its Go type differs between
	// architectures.
	return uint32(st.Type), nil
}

// checkFileSystemType allows only the local file systems above. It is an
// allow list: a file system that nodkey does not know is refused. The error
// names the type, such as nfs, or gives its number if it has no name here.
func checkFileSystemType(magic uint32) error {
	switch magic {
	case extMagic, xfsMagic, btrfsMagic, zfsMagic, tmpfsMagic, ramfsMagic, f2fsMagic, bcachefsMagic,
		overlayfsMagic, ecryptfsMagic:
		return nil
	}
	kind := fmt.Sprintf("of unknown type %#x", magic)
	if name, ok := refusedFileSystems[magic]; ok {
		kind = "of type " + name
	}
	return fmt.Errorf("is on a file system %s, where the mode bits may not show who can read it; "+
		"keep it on a local file system: %s", kind, localFileSystems)
}

// fileACL returns the POSIX access ACL of the open file f, or nil if it has
// none. A file has none when its ACL says no more than its mode, or when
// its file system does not support ACLs.
func fileACL(f *os.File) ([]byte, error) {
	buf := make([]byte, 64<<10) // XATTR_SIZE_MAX, the largest value Linux allows
	var n int
	err := control(f, func(fd uintptr) error {
		var err error
		n, err = fgetxattr(fd, "system.posix_acl_access", buf)
		return err
	})
	switch {
	case errors.Is(err, syscall.ENODATA), errors.Is(err, syscall.EOPNOTSUPP):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return buf[:n], nil
}

// control runs fn with the file descriptor of f.
func control(f *os.File, fn func(fd uintptr) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var fnErr error
	if err := rc.Control(func(fd uintptr) { fnErr = fn(fd) }); err != nil {
		return err
	}
	return fnErr
}

// fgetxattr calls fgetxattr(2). The syscall package has no wrapper for it,
// and nodkey adds no dependency for one call.
func fgetxattr(fd uintptr, attr string, dest []byte) (int, error) {
	name, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return 0, err
	}
	if len(dest) == 0 {
		return 0, syscall.ERANGE
	}
	// The pointers are passed straight to the system call, as the rules
	// of package unsafe allow.
	n, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, fd,
		uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&dest[0])), uintptr(len(dest)), 0, 0) //nolint:gosec // G103: fgetxattr(2) needs pointers to the name and the buffer.
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
