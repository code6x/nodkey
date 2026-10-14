package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCheckProgram checks CheckProgram, the check of a store's program,
// which the store package also uses for the node that a bw script starts.
// CheckFiles tests the same check in more cases.
func TestCheckProgram(t *testing.T) {
	dir := privateTempDir(t)
	bin := mkdir(t, dir, "bin", 0o755)
	open := mkdir(t, dir, "open", 0o777)
	good := writeFile(t, bin, "node", "", 0o755)
	for _, path := range []string{good, symlink(t, good, filepath.Join(bin, "node-link"))} {
		if err := CheckProgram(path); err != nil {
			t.Errorf("CheckProgram(%s): %v", path, err)
		}
	}
	writable := writeFile(t, bin, "node-0777", "", 0o777)
	inOpen := writeFile(t, open, "node", "", 0o755)
	hop := symlink(t, good, filepath.Join(open, "hop"))
	tests := []struct{ name, path, want string }{
		{"others can write it", writable, writable + ": group or others can write to it (mode 0777)"},
		{"a link to a file that others can write", symlink(t, writable, filepath.Join(bin, "link-0777")),
			writable + ": group or others can write to it (mode 0777)"},
		{"a link into a directory that others can write", symlink(t, inOpen, filepath.Join(bin, "link-open")),
			open + ": group or others can write to this directory (mode 0777)"},
		{"a link held in a directory that others can write", symlink(t, hop, filepath.Join(bin, "link-hop")),
			open + ": group or others can write to this directory (mode 0777)"},
		{"a directory", mkdir(t, bin, "node-dir", 0o755), "is not a regular file"},
		{"missing", filepath.Join(bin, "missing"), "no such file or directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkError(t, CheckProgram(tc.path), tc.want, "")
		})
	}
	if err := CheckProgram(filepath.Join(bin, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("CheckProgram(missing) = %v, want an error that is fs.ErrNotExist", err)
	}
}

// TestCheckPrivateFileWithACL sets a real POSIX ACL on a file, like the one
// systemd puts on a credential, and checks that the group bits it shows in
// the mode do not count as group access.
func TestCheckPrivateFileWithACL(t *testing.T) {
	self, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		acl   []byte
		group os.FileMode // the group bits that the ACL mask gives the mode
		want  string      // "" means no error
	}{
		{name: "read for the user that runs nodkey", acl: systemdACL(self, 0), group: 0o040},
		{name: "read for another user", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 4, noID}, aclEntry{aclUser, 4, self + 1}, aclEntry{aclGroupObj, 0, noID},
			aclEntry{aclMask, 4, noID}, aclEntry{aclOther, 0, noID}),
			group: 0o040, want: "gives user ID"},
		{name: "read for the owning group", acl: systemdACL(self, 4), group: 0o040, want: "gives a group access"},
		{name: "read for another user, turned off by the mask", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 4, noID}, aclEntry{aclUser, 4, self + 1}, aclEntry{aclGroupObj, 0, noID},
			aclEntry{aclMask, 0, noID}, aclEntry{aclOther, 0, noID}),
			group: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeFile(t, privateTempDir(t), "credential", "made-up token\n", 0o400)
			err := syscall.Setxattr(p, "system.posix_acl_access", tt.acl, 0)
			if errors.Is(err, syscall.EOPNOTSUPP) {
				t.Skip("the file system of the test directory does not support ACLs")
			}
			if err != nil {
				t.Fatalf("setting the ACL: %v", err)
			}
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if perm := fi.Mode().Perm(); perm&0o070 != tt.group {
				t.Fatalf("mode = %04o, want group bits %04o from the ACL mask", perm, tt.group)
			}
			err = CheckPrivateFile(p)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("CheckPrivateFile: %v", err)
				}
				return
			}
			checkError(t, err, tt.want, "made-up")
		})
	}
}

func TestCheckPrivateFile(t *testing.T) {
	dir := privateTempDir(t)
	regular := func(mode os.FileMode) func(t *testing.T) string {
		return func(t *testing.T) string {
			return writeFile(t, dir, "key-"+mode.String(), "made-up key\n", mode)
		}
	}
	tests := []struct {
		name string
		make func(t *testing.T) string
		want string // "" means no error
	}{
		{name: "0600", make: regular(0o600)},
		{name: "0400", make: regular(0o400)},
		{name: "0700", make: regular(0o700)},
		{name: "0640", make: regular(0o640), want: "its group has access (mode 0640)"},
		{name: "0644", make: regular(0o644), want: "others have access (mode 0644)"},
		{name: "0604", make: regular(0o604), want: "others have access (mode 0604)"},
		{name: "0620", make: regular(0o620), want: "its group has access (mode 0620)"},
		{name: "0602", make: regular(0o602), want: "others have access (mode 0602)"},
		{name: "0610", make: regular(0o610), want: "its group has access (mode 0610)"},
		{name: "0601", make: regular(0o601), want: "others have access (mode 0601)"},
		{name: "a directory", want: "is not a regular file", make: func(t *testing.T) string {
			return mkdir(t, dir, "a-directory", 0o700)
		}},
		{name: "a FIFO", want: "is not a regular file", make: func(t *testing.T) string {
			p := filepath.Join(dir, "a-fifo")
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{name: "a symbolic link to a 0600 file", want: "is a symbolic link", make: func(t *testing.T) string {
			target := writeFile(t, dir, "link-target", "made-up key\n", 0o600)
			return symlink(t, target, filepath.Join(dir, "a-link"))
		}},
		{name: "a hard link to a 0600 file", make: func(t *testing.T) string {
			target := writeFile(t, dir, "hard-link-target", "made-up key\n", 0o600)
			p := filepath.Join(dir, "a-hard-link")
			if err := os.Link(target, p); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{name: "a missing file", want: "no such file or directory", make: func(t *testing.T) string {
			return filepath.Join(dir, "no-such-file")
		}},
		{name: "a path that ends in a slash", want: "slash-key: is not a directory", make: func(t *testing.T) string {
			return writeFile(t, dir, "slash-key", "made-up key\n", 0o600) + "/"
		}},
		{name: "in a directory writable by group", want: "/shared: group or others can write to this directory (mode 0770)", make: func(t *testing.T) string {
			sub := mkdir(t, dir, "shared", 0o700)
			p := writeFile(t, sub, "key", "made-up key\n", 0o600)
			chmod(t, sub, 0o770)
			return p
		}},
		{name: "below a directory writable by others", want: "/open: group or others can write to this directory (mode 0777)", make: func(t *testing.T) string {
			sub := mkdir(t, mkdir(t, dir, "open", 0o777), "private", 0o700)
			return writeFile(t, sub, "key", "made-up key\n", 0o600)
		}},
		{name: "through a linked directory to a safe one", make: func(t *testing.T) string {
			sub := mkdir(t, dir, "real-dir", 0o700)
			writeFile(t, sub, "key", "made-up key\n", 0o600)
			return filepath.Join(symlink(t, sub, filepath.Join(dir, "linked-dir")), "key")
		}},
		{name: "through a linked directory to an open one", want: "/open-dir: group or others can write to this directory", make: func(t *testing.T) string {
			sub := mkdir(t, dir, "open-dir", 0o777)
			writeFile(t, sub, "key", "made-up key\n", 0o600)
			return filepath.Join(symlink(t, sub, filepath.Join(dir, "safe-looking-dir")), "key")
		}},
		{name: "through a link that is in an open directory", want: "/open-links: group or others can write to this directory", make: func(t *testing.T) string {
			// The directory the link points to is safe, but anyone can
			// change where the link points.
			sub := mkdir(t, dir, "real-keys", 0o700)
			writeFile(t, sub, "key", "made-up key\n", 0o600)
			links := mkdir(t, dir, "open-links", 0o777)
			return filepath.Join(symlink(t, sub, filepath.Join(links, "keys")), "key")
		}},
		{name: "through a chain of links to a safe directory", make: func(t *testing.T) string {
			sub := mkdir(t, dir, "chain-real", 0o700)
			writeFile(t, sub, "key", "made-up key\n", 0o600)
			first := symlink(t, "chain-real", filepath.Join(dir, "chain-1")) // a relative link
			return filepath.Join(symlink(t, first, filepath.Join(dir, "chain-2")), "key")
		}},
		{name: "through a link loop", want: "more than 40 symbolic links on the way", make: func(t *testing.T) string {
			a, b := filepath.Join(dir, "loop-a"), filepath.Join(dir, "loop-b")
			symlink(t, b, a)
			symlink(t, a, b)
			return filepath.Join(a, "key")
		}},
		{name: "dot-dot after a linked directory", make: func(t *testing.T) string {
			// As in the kernel, ".." after a link goes up from the link's
			// target: dot-link/../key is dot-parent/key, not dir/key.
			parent := mkdir(t, dir, "dot-parent", 0o700)
			writeFile(t, parent, "key", "made-up key\n", 0o600)
			symlink(t, mkdir(t, parent, "child", 0o700), filepath.Join(dir, "dot-link"))
			return dir + "/dot-link/../key"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.make(t)
			err := CheckPrivateFile(p)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("CheckPrivateFile: %v", err)
				}
				return
			}
			checkError(t, err, tt.want, "made-up")
		})
	}
}

func TestWalkPath(t *testing.T) {
	dir := privateTempDir(t)
	self, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	sub := mkdir(t, dir, "real", 0o700)
	file := writeFile(t, sub, "file", "made-up\n", 0o600)
	fileLink := symlink(t, file, filepath.Join(dir, "file-link"))
	dirLink := symlink(t, "real", filepath.Join(dir, "dir-link"))
	tests := []struct {
		path string
		last lastPart
		want string // the path walkPath returns
		link bool   // it is a symbolic link
	}{
		{path: file, want: file},
		{path: file, last: lastFollow, want: file},
		{path: dir + "//real/./file", want: file},
		{path: dirLink + "/file", want: file},
		{path: dir + "/real/../real/file", want: file},
		{path: dir + "/dir-link/../real/file", want: file},
		{path: fileLink, want: fileLink, link: true},
		{path: fileLink, last: lastFollow, want: file},
	}
	for _, tt := range tests {
		name, fi, err := walkPath(tt.path, self, tt.last)
		if err != nil {
			t.Errorf("walkPath(%q, %v): %v", tt.path, tt.last, err)
			continue
		}
		if name != tt.want || (fi.Mode()&os.ModeSymlink != 0) != tt.link {
			t.Errorf("walkPath(%q, %v) = %q, mode %v; want %q, link %v", tt.path, tt.last, name, fi.Mode(), tt.want, tt.link)
		}
	}

	// With lastSkip, the last part is not looked at: it may be missing,
	// and a link there is not followed. The directories are still walked.
	for path, want := range map[string]string{
		file:                          file,
		fileLink:                      fileLink,
		sub + "/missing":              sub + "/missing",
		dirLink + "/missing":          sub + "/missing",
		dir + "/dir-link/../real/new": sub + "/new",
	} {
		name, fi, err := walkPath(path, self, lastSkip)
		if err != nil || name != want || fi != nil {
			t.Errorf("walkPath(%q, lastSkip) = %q, %v, %v; want %q, no information, no error", path, name, fi, err, want)
		}
	}

	// A relative path starts at the working directory.
	t.Chdir(dir)
	if name, _, err := walkPath("real/file", self, lastLstat); err != nil || name != file {
		t.Errorf("walkPath(real/file) in %s = %q, %v; want %q", dir, name, err, file)
	}

	for path, want := range map[string]string{
		"":           "the path is empty",
		"/":          "/: is a directory, not a file",
		dir + "/":    dir + "/: is a directory, not a file",
		sub + "/.":   sub + "/.: is a directory, not a file",
		sub + "/..":  sub + "/..: is a directory, not a file",
		file + "/":   file + ": is not a directory",
		file + "/x":  file + ": is not a directory",
		dir + "/nil": "lstat " + dir + "/nil: no such file or directory",
	} {
		for _, last := range []lastPart{lastLstat, lastFollow, lastSkip} {
			if last == lastSkip && path == dir+"/nil" {
				continue // the last part may be missing
			}
			_, _, err := walkPath(path, self, last)
			checkError(t, err, want, "")
		}
	}
	// With lastSkip, a missing directory on the way is still an error.
	_, _, err = walkPath(dir+"/nil/x", self, lastSkip)
	checkError(t, err, "lstat "+dir+"/nil: no such file or directory", "")
}

func TestCheckParentDirs(t *testing.T) {
	dir := privateTempDir(t)
	sub := mkdir(t, dir, "sub", 0o700)
	writeFile(t, sub, "file", "made-up\n", 0o600)
	symlink(t, filepath.Join(dir, "nowhere"), filepath.Join(sub, "dangling"))
	linked := symlink(t, sub, filepath.Join(dir, "linked"))
	open := mkdir(t, dir, "open", 0o777)
	writeFile(t, open, "file", "made-up\n", 0o600)

	// The last part is not looked at: a missing file, a file, a directory,
	// a link that points nowhere, a file anyone can write to, a link to a
	// file in a directory anyone can write to, and a link to a directory
	// all pass.
	writeFile(t, sub, "open-file", "made-up\n", 0o666)
	symlink(t, filepath.Join(open, "file"), filepath.Join(sub, "link-to-open"))
	// Only the write bits count: a directory that others can read and
	// enter passes. So the ssh-agent socket needs its own 0700 directory.
	readable := mkdir(t, dir, "readable", 0o755)
	for _, p := range []string{
		sub + "/missing", sub + "/file", dir + "/sub", sub + "/dangling", sub + "/open-file",
		linked + "/missing", dir + "/sub/../sub/missing", dir + "/open", sub + "/link-to-open", linked,
		readable + "/agent.sock",
	} {
		if err := CheckParentDirs(p); err != nil {
			t.Errorf("CheckParentDirs(%q): %v", p, err)
		}
	}
	// A relative path starts at the working directory, and ".." in it
	// goes up from there.
	t.Chdir(sub)
	if err := CheckParentDirs("../sub/missing"); err != nil {
		t.Errorf("CheckParentDirs(../sub/missing) in %s: %v", sub, err)
	}

	tests := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"empty", func(*testing.T) string { return "" }, "the path is empty"},
		{"ends in a slash", func(*testing.T) string { return sub + "/" }, sub + "/: is a directory, not a file"},
		{"ends in a dot", func(*testing.T) string { return sub + "/." }, "is a directory, not a file"},
		{"ends in two dots", func(*testing.T) string { return sub + "/.." }, "is a directory, not a file"},
		{"a missing directory", func(*testing.T) string { return dir + "/nil/file" },
			"lstat " + dir + "/nil: no such file or directory"},
		{"a file as a directory", func(*testing.T) string { return sub + "/file/x" }, sub + "/file: is not a directory"},
		{"in a directory writable by others", func(*testing.T) string { return open + "/file" },
			open + ": group or others can write to this directory (mode 0777)"},
		{"in a directory writable by group", func(t *testing.T) string {
			return filepath.Join(mkdir(t, dir, "shared", 0o770), "audit.jsonl")
		}, "/shared: group or others can write to this directory (mode 0770)"},
		{"below a directory writable by others", func(t *testing.T) string {
			return filepath.Join(mkdir(t, open, "private", 0o700), "audit.jsonl")
		}, open + ": group or others can write to this directory (mode 0777)"},
		{"through a link to a directory writable by others", func(t *testing.T) string {
			return filepath.Join(symlink(t, open, filepath.Join(dir, "safe-looking")), "audit.jsonl")
		}, open + ": group or others can write to this directory (mode 0777)"},
		{"through a link that is in a directory writable by others", func(t *testing.T) string {
			return filepath.Join(symlink(t, sub, filepath.Join(open, "sub-link")), "audit.jsonl")
		}, open + ": group or others can write to this directory (mode 0777)"},
		{"through a link loop", func(t *testing.T) string {
			a, b := filepath.Join(dir, "loop-a"), filepath.Join(dir, "loop-b")
			symlink(t, b, a)
			symlink(t, a, b)
			return filepath.Join(a, "audit.jsonl")
		}, "more than 40 symbolic links on the way"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkError(t, CheckParentDirs(tt.path(t)), tt.want, "")
		})
	}
}

// TestCheckAuditLogFile checks the audit log that is there, by its Lstat
// information. TestLoadBrokerAuditLog checks the whole path.
func TestCheckAuditLogFile(t *testing.T) {
	self, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTempDir(t)
	lstat := func(t *testing.T, p string) os.FileInfo {
		t.Helper()
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi
	}
	for _, mode := range []os.FileMode{0o600, 0o400, 0o200} {
		p := writeFile(t, dir, "ok-"+mode.String(), "", mode)
		if err := checkAuditLogFile(lstat(t, p), self); err != nil {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o666, 0o755} {
		p := writeFile(t, dir, "open-"+mode.String(), "", mode)
		checkError(t, checkAuditLogFile(lstat(t, p), self),
			fmt.Sprintf("group or others have access (mode %04o); it must be private to its owner", mode), "")
	}
	// Only read and write for the owner: an execute bit points to a
	// program, such as a store's program.
	for _, mode := range []os.FileMode{0o700, 0o500, 0o300, 0o100} {
		p := writeFile(t, dir, "run-"+mode.String(), "", mode)
		checkError(t, checkAuditLogFile(lstat(t, p), self),
			fmt.Sprintf("its owner may run it as a program (mode %04o); the audit log must allow only read and write", mode), "")
	}
	private := writeFile(t, dir, "private", "", 0o600)
	checkError(t, checkAuditLogFile(lstat(t, symlink(t, private, filepath.Join(dir, "link"))), self),
		"is a symbolic link", "")
	checkError(t, checkAuditLogFile(lstat(t, mkdir(t, dir, "a-directory", 0o700)), self), "is not a regular file", "")
	fifo := filepath.Join(dir, "a-fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	checkError(t, checkAuditLogFile(lstat(t, fifo), self), "is not a regular file", "")
	// Another owner is refused, root too: the broker writes the file. Tests
	// cannot make a file that another user owns, so they ask for another
	// user instead.
	checkError(t, checkAuditLogFile(lstat(t, private), self+1), fmt.Sprintf("is owned by user ID %d; "+
		"it must be owned by the user that runs nodkey (ID %d)", self, self+1), "")
}

// TestCheckAuditLog checks the audit log by its path. CheckParentDirs lets
// any last part through; checkAuditLog checks it, and returns its
// information for CheckFiles.
func TestCheckAuditLog(t *testing.T) {
	self, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTempDir(t)
	if fi, err := checkAuditLog(filepath.Join(dir, "missing.jsonl"), self); fi != nil || err != nil {
		t.Errorf("checkAuditLog of a missing file = %v, %v; want no information and no error", fi, err)
	}
	log := writeFile(t, dir, "audit.jsonl", "{}\n", 0o600)
	want, err := os.Lstat(log)
	if err != nil {
		t.Fatal(err)
	}
	// Through a linked directory, checkAuditLog finds the same file.
	for _, p := range []string{log, filepath.Join(symlink(t, dir, filepath.Join(dir, "linked")), "audit.jsonl")} {
		fi, err := checkAuditLog(p, self)
		if err != nil || fi == nil || !os.SameFile(fi, want) {
			t.Errorf("checkAuditLog(%q) = %v, %v; want the information of %s", p, fi, err, log)
		}
	}

	// What CheckParentDirs lets through, checkAuditLog refuses.
	key := writeFile(t, dir, "key", "made-up key\n", 0o600)
	fifo := filepath.Join(dir, "fifo.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		symlink(t, key, filepath.Join(dir, "link.jsonl")): "is a symbolic link",
		fifo: "is not a regular file",
		writeFile(t, dir, "open.jsonl", "{}\n", 0o644): "group or others have access (mode 0644)",
		writeFile(t, dir, "run.jsonl", "{}\n", 0o700):  "its owner may run it as a program (mode 0700)",
		mkdir(t, dir, "dir.jsonl", 0o700):              "is not a regular file",
	} {
		if err := CheckParentDirs(p); err != nil {
			t.Errorf("CheckParentDirs(%q): %v", p, err)
		}
		fi, err := checkAuditLog(p, self)
		checkError(t, err, p+": "+want, "made-up")
		if fi != nil {
			t.Errorf("checkAuditLog(%q) returned file information with the error", p)
		}
	}
	// A hard link to a key file passes here: it is a private regular file.
	// CheckFiles refuses it (TestCheckFilesAuditLogIsAnotherFile).
	hard := filepath.Join(dir, "hard.jsonl")
	if err := os.Link(key, hard); err != nil {
		t.Fatal(err)
	}
	if fi, err := checkAuditLog(hard, self); err != nil || fi == nil {
		t.Errorf("checkAuditLog of a hard link to a private file = %v, %v; want its information", fi, err)
	}
}

// TestWalkPathChecksEveryDirectory checks the default: outside tests, the
// check starts at "/".
func TestWalkPathChecksEveryDirectory(t *testing.T) {
	if trustedDir != "/" {
		t.Fatalf("trustedDir = %q, want /", trustedDir)
	}
	// The walk refuses the first bad directory on the way: the system
	// temporary directory, or else the test's own "open" directory.
	open := mkdir(t, t.TempDir(), "open", 0o777)
	p := writeFile(t, mkdir(t, open, "private", 0o700), "key", "made-up key\n", 0o600)
	checkError(t, CheckPrivateFile(p), "group or others can write to this directory", "made-up")
	checkError(t, CheckParentDirs(filepath.Join(filepath.Dir(p), "audit.jsonl")),
		"group or others can write to this directory", "")
}

func TestCheckDir(t *testing.T) {
	self, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTempDir(t)
	trusted := trustedDir
	if trusted != filepath.Dir(dir) {
		t.Fatalf("trustedDir = %q, want the test's temporary root", trusted)
	}
	// The directories above trustedDir are not checked; the system
	// temporary directory is writable by everyone.
	for d := filepath.Dir(trusted); ; d = filepath.Dir(d) {
		if err := checkDir(d, self); err != nil {
			t.Errorf("checkDir(%q) above trustedDir: %v", d, err)
		}
		if d == "/" {
			break
		}
	}
	// trustedDir itself and the directories below it are checked.
	if err := checkDir(trusted, self); err != nil {
		t.Errorf("checkDir(trustedDir): %v", err)
	}
	chmod(t, trusted, 0o770)
	checkError(t, checkDir(trusted, self), trusted+": group or others can write to this directory (mode 0770)", "")
	chmod(t, dir, 0o707)
	checkError(t, checkDir(dir, self), dir+": group or others can write to this directory (mode 0707)", "")
	// A directory owned by another user is refused. (Root may own any.)
	if self != 0 {
		checkError(t, checkDir(dir, self+1), fmt.Sprintf("%s: is owned by user ID %d; "+
			"it must be owned by the user that runs nodkey (ID %d) or by root", dir, self, self+1), "")
	}
	// A name next to trustedDir that starts with its name is not above it.
	checkError(t, checkDir(trusted+"-other", self), "no such file or directory", "")
	// A link where a directory is expected means the path changed.
	link := symlink(t, dir, filepath.Join(dir, "link"))
	checkError(t, checkDir(link, self), link+": is not a directory", "")
}

func TestReadPrivateFile(t *testing.T) {
	dir := privateTempDir(t)
	p := writeFile(t, dir, "token", "made-up token\n", 0o600)
	got, err := ReadPrivateFile(p)
	if err != nil {
		t.Fatalf("ReadPrivateFile: %v", err)
	}
	if string(got) != "made-up token\n" {
		t.Errorf("ReadPrivateFile = %q, want the file content", got)
	}

	open := writeFile(t, dir, "open-token", "made-up token\n", 0o644)
	_, err = ReadPrivateFile(open)
	checkError(t, err, open+": others have access", "made-up")

	big := writeFile(t, dir, "big", strings.Repeat("x", maxFileSize+1), 0o600)
	_, err = ReadPrivateFile(big)
	checkError(t, err, big+": is larger than 1 MiB", "xxx")

	exact := writeFile(t, dir, "exact", strings.Repeat("x", maxFileSize), 0o600)
	if got, err := ReadPrivateFile(exact); err != nil || len(got) != maxFileSize {
		t.Errorf("ReadPrivateFile of exactly 1 MiB: %d bytes, %v", len(got), err)
	}

	link := symlink(t, p, filepath.Join(dir, "token-link"))
	_, err = ReadPrivateFile(link)
	checkError(t, err, link+": is a symbolic link", "made-up")
}

// TestCheckOpenFileOwner checks the owner of open files. Tests cannot make
// a file that another user owns, so they ask for another user instead.
func TestCheckOpenFileOwner(t *testing.T) {
	self, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	if self == 0 {
		t.Skip("root owns the test files, and root may own any file")
	}
	f, err := openFile(t, writeFile(t, privateTempDir(t), "token", "made-up token\n", 0o600), os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("is owned by user ID %d; it must be owned by the user that runs nodkey (ID %d) or by root", self, self+1)
	_, err = checkOpenPrivateFile(f, self+1)
	checkError(t, err, want, "made-up")
	checkError(t, checkOpenConfigFile(f, self+1), want, "made-up")
	if _, err := checkOpenPrivateFile(f, self); err != nil {
		t.Errorf("checkOpenPrivateFile for the owner: %v", err)
	}
	if err := checkOpenConfigFile(f, self); err != nil {
		t.Errorf("checkOpenConfigFile for the owner: %v", err)
	}
	// The walk checks the owner of each directory, in every mode.
	for _, last := range []lastPart{lastLstat, lastFollow, lastSkip} {
		_, _, err = walkPath(f.Name(), self+1, last)
		checkError(t, err, fmt.Sprintf("is owned by user ID %d", self), "")
	}
	fi, err := checkAuditLog(f.Name(), self+1)
	checkError(t, err, fmt.Sprintf("is owned by user ID %d", self), "")
	if fi != nil {
		t.Error("checkAuditLog returned file information with the error")
	}
}

// TestReadPrivateFileReadsTheCheckedFile swaps the file between the check
// and the read. The read gets the file that was checked.
func TestReadPrivateFileReadsTheCheckedFile(t *testing.T) {
	dir := privateTempDir(t)
	p := writeFile(t, dir, "token", "made-up token\n", 0o600)
	f, _, err := openPrivateFile(p)
	if err != nil {
		t.Fatalf("openPrivateFile: %v", err)
	}
	other := writeFile(t, dir, "other", "made-up other\n", 0o644)
	if err := os.Rename(other, p); err != nil {
		t.Fatal(err)
	}
	got, err := readAndClose(f, p)
	if err != nil {
		t.Fatalf("readAndClose: %v", err)
	}
	if string(got) != "made-up token\n" {
		t.Errorf("read %q, want the checked file's content", got)
	}
	// The new file fails its own check.
	_, err = ReadPrivateFile(p)
	checkError(t, err, "others have access", "made-up")
	// A file that cannot be read gives an error, not data.
	if got, err := readAndClose(f, p); err == nil {
		t.Errorf("readAndClose of a closed file = %q, nil; want an error", got)
	}
	// So does a file that does not close cleanly.
	got, err = readAndClose(closeError{strings.NewReader("made-up token\n")}, p)
	if !errors.Is(err, syscall.EIO) || got != nil {
		t.Errorf("readAndClose with a close error = %q, %v; want no data and the error", got, err)
	}
}

// closeError is a file that reads well, but fails to close.
type closeError struct{ *strings.Reader }

func (closeError) Close() error { return syscall.EIO }

func TestReadConfigFile(t *testing.T) {
	dir := privateTempDir(t)
	const content = "listen = \"192.0.2.10:7743\"\n"
	n := 0
	file := func(t *testing.T, dir string, mode os.FileMode) string {
		t.Helper()
		n++
		return writeFile(t, dir, "file-"+strconv.Itoa(n), content, mode)
	}
	tests := []struct {
		name string
		make func(t *testing.T) string
		want string // "" means no error
	}{
		{name: "0644", make: func(t *testing.T) string { return file(t, dir, 0o644) }},
		{name: "0444", make: func(t *testing.T) string { return file(t, dir, 0o444) }},
		{name: "0600", make: func(t *testing.T) string { return file(t, dir, 0o600) }},
		{name: "0664", want: ": group or others can write to it (mode 0664)", make: func(t *testing.T) string {
			return file(t, dir, 0o664)
		}},
		{name: "0646", want: ": group or others can write to it (mode 0646)", make: func(t *testing.T) string {
			return file(t, dir, 0o646)
		}},
		{name: "a link to a 0644 file", make: func(t *testing.T) string {
			return symlink(t, file(t, dir, 0o644), filepath.Join(dir, "link-to-0644"))
		}},
		{name: "a link to a 0666 file", want: "link-to-0666: group or others can write to it (mode 0666)", make: func(t *testing.T) string {
			return symlink(t, file(t, dir, 0o666), filepath.Join(dir, "link-to-0666"))
		}},
		{name: "in a directory writable by group", want: "/shared: group or others can write to this directory (mode 0770)", make: func(t *testing.T) string {
			return file(t, mkdir(t, dir, "shared", 0o770), 0o644)
		}},
		{name: "a link to a file in a directory writable by others", want: "/open-target: group or others can write to this directory", make: func(t *testing.T) string {
			target := file(t, mkdir(t, dir, "open-target", 0o777), 0o644)
			return symlink(t, target, filepath.Join(dir, "link-to-open"))
		}},
		{name: "a link in a directory writable by others", want: "/open-link-dir: group or others can write to this directory", make: func(t *testing.T) string {
			return symlink(t, file(t, dir, 0o644), filepath.Join(mkdir(t, dir, "open-link-dir", 0o777), "link"))
		}},
		{name: "a link loop", want: "more than 40 symbolic links on the way", make: func(t *testing.T) string {
			a, b := filepath.Join(dir, "loop-a"), filepath.Join(dir, "loop-b")
			symlink(t, b, a)
			return symlink(t, a, b)
		}},
		{name: "a FIFO", want: "a-fifo: is not a regular file", make: func(t *testing.T) string {
			p := filepath.Join(dir, "a-fifo")
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{name: "a directory", want: "a-directory: is not a regular file", make: func(t *testing.T) string {
			return mkdir(t, dir, "a-directory", 0o755)
		}},
		{name: "a missing file", want: "no-such-file: no such file or directory", make: func(t *testing.T) string {
			return filepath.Join(dir, "no-such-file")
		}},
		{name: "larger than 1 MiB", want: "big: is larger than 1 MiB", make: func(t *testing.T) string {
			return writeFile(t, dir, "big", strings.Repeat("#", maxFileSize+1), 0o644)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.make(t)
			got, err := ReadConfigFile(p)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("ReadConfigFile: %v", err)
				}
				if string(got) != content {
					t.Errorf("ReadConfigFile = %q, want the file content", got)
				}
				return
			}
			checkError(t, err, tt.want, "")
		})
	}
}

func TestCheckFileSystemType(t *testing.T) {
	// Only these local file systems are allowed. overlayfs and ecryptfs are
	// layers over another file system; the kernel checks the file you name.
	allowed := map[string]uint32{
		"ext2, ext3 and ext4": 0xEF53, "xfs": 0x58465342, "btrfs": 0x9123683E, "zfs": 0x2FC12FC1,
		"tmpfs": 0x01021994, "ramfs": 0x858458F6, "f2fs": 0xF2F52010, "bcachefs": 0xCA451A4E,
		"overlayfs": 0x794C7630, "ecryptfs": 0xF15F,
	}
	for name, magic := range allowed {
		if err := checkFileSystemType(magic); err != nil {
			t.Errorf("%s (%#x): %v", name, magic, err)
		}
	}
	// Everything else is refused: network and cluster file systems, FUSE,
	// and file systems that nodkey does not know. The error names a type
	// that nodkey has a name for, and gives the number of any other.
	const after = " where the mode bits may not show who can read it; keep it on a local file system: " +
		"ext2, ext3, ext4, xfs, btrfs, zfs, tmpfs, ramfs, f2fs, bcachefs, overlayfs or ecryptfs"
	named := map[uint32]string{
		0x6969: "nfs", 0x517B: "smb", 0xFF534D42: "cifs", 0xFE534D42: "smb2", 0x01021997: "9p",
		0x5346414F: "afs", 0x6B414653: "afs", 0x00C36400: "ceph", 0x65735546: "fuse", 0x73757245: "coda",
		0x7461636F: "ocfs2", 0x01161970: "gfs2", 0x00C0FFEE: "hostfs", 0x0BD00BD0: "lustre",
		0x20030528: "orangefs", 0x47504653: "gpfs", 0x786F4256: "vboxsf", 0x19830326: "beegfs",
		0x4D44: "vfat", 0x2011BAB0: "exfat",
	}
	for magic, name := range named {
		// A name, never the number.
		checkError(t, checkFileSystemType(magic), "is on a file system of type "+name+","+after, "0x")
	}
	if len(refusedFileSystems) != len(named) {
		t.Errorf("refusedFileSystems has %d names, the test knows %d", len(refusedFileSystems), len(named))
	}
	for magic := range refusedFileSystems {
		if _, ok := named[magic]; !ok {
			t.Errorf("refusedFileSystems names %#x, which this test does not check", magic)
		}
	}
	// squashfs, the number 0 and all bits set have no name here.
	for _, magic := range []uint32{0x73717368, 0, 0xFFFFFFFF} {
		checkError(t, checkFileSystemType(magic), fmt.Sprintf("is on a file system of unknown type %#x,", magic)+after, "")
	}
	// The open file of a test is on a local file system, also when the
	// temporary directory is on overlayfs, as in many containers.
	f, err := openFile(t, writeFile(t, t.TempDir(), "local", "x", 0o600), os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFileSystem(f); err != nil {
		t.Errorf("checkFileSystem on the test directory: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// A file that cannot be checked is refused.
	if err := checkFileSystem(f); err == nil {
		t.Error("checkFileSystem on a closed file: got no error")
	}
}

// TestCheckPrivateFileOnOtherFileSystem acts as if the file were on another
// file system, such as NFS or FUSE: tests cannot mount one.
func TestCheckPrivateFileOnOtherFileSystem(t *testing.T) {
	p := writeFile(t, privateTempDir(t), "token", "made-up token\n", 0o600)
	old := fileSystemType
	t.Cleanup(func() { fileSystemType = old })
	// NFS, CIFS, SMB2, 9p, Ceph, FUSE, Lustre, and a type with no name.
	for magic, kind := range map[uint32]string{
		0x6969: "of type nfs", 0xFF534D42: "of type cifs", 0xFE534D42: "of type smb2", 0x01021997: "of type 9p",
		0x00C36400: "of type ceph", 0x65735546: "of type fuse", 0x0BD00BD0: "of type lustre",
		0x12345678: "of unknown type 0x12345678",
	} {
		fileSystemType = func(*os.File) (uint32, error) { return magic, nil }
		want := p + ": is on a file system " + kind + ", where the mode bits may not show who can read it"
		checkError(t, CheckPrivateFile(p), want, "made-up")
		got, err := ReadPrivateFile(p)
		checkError(t, err, want, "made-up")
		if got != nil {
			t.Errorf("ReadPrivateFile returned data with the error")
		}
	}
	// A local file system on the list passes; so do overlayfs and ecryptfs.
	for name, magic := range map[string]uint32{"zfs": zfsMagic, "overlayfs": overlayfsMagic, "ecryptfs": ecryptfsMagic} {
		fileSystemType = func(*os.File) (uint32, error) { return magic, nil }
		if err := CheckPrivateFile(p); err != nil {
			t.Errorf("CheckPrivateFile on %s: %v", name, err)
		}
		if got, err := ReadPrivateFile(p); err != nil || string(got) != "made-up token\n" {
			t.Errorf("ReadPrivateFile on %s: %d bytes, %v; want the file content", name, len(got), err)
		}
	}
	// An error while asking for the file system is an error too.
	fileSystemType = func(*os.File) (uint32, error) { return 0, syscall.EIO }
	checkError(t, CheckPrivateFile(p), p+": input/output error", "made-up")
	// Config files may be on any file system: only who can write counts.
	fileSystemType = func(*os.File) (uint32, error) { return 0x6969, nil }
	if _, err := ReadConfigFile(writeFile(t, filepath.Dir(p), "config", "made-up\n", 0o644)); err != nil {
		t.Errorf("ReadConfigFile: %v", err)
	}
}

// TestFileACL reads ACLs with fgetxattr(2). An error while reading must be
// an error, never "no ACL": with no ACL, the group bits count as the
// group's own rights.
func TestFileACL(t *testing.T) {
	self, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTempDir(t)
	open := func(t *testing.T, p string) *os.File {
		t.Helper()
		f, err := openFile(t, p, os.O_RDONLY)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	plain := open(t, writeFile(t, dir, "plain", "made-up\n", 0o600))
	if acl, err := fileACL(plain); acl != nil || err != nil {
		t.Errorf("fileACL of a file without an ACL = %v, %v; want nil, nil", acl, err)
	}

	p := writeFile(t, dir, "with-acl", "made-up\n", 0o400)
	want := systemdACL(self, 0)
	switch err := syscall.Setxattr(p, "system.posix_acl_access", want, 0); {
	case errors.Is(err, syscall.EOPNOTSUPP):
		t.Log("the file system of the test directory does not support ACLs")
	case err != nil:
		t.Fatalf("setting the ACL: %v", err)
	default:
		if got, err := fileACL(open(t, p)); err != nil || !bytes.Equal(got, want) {
			t.Errorf("fileACL = %v, %v; want %v", got, err, want)
		}
	}

	closed := open(t, writeFile(t, dir, "closed", "made-up\n", 0o640))
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if acl, err := fileACL(closed); err == nil {
		t.Errorf("fileACL of a closed file = %v, nil; want an error", acl)
	}
	buf := make([]byte, 64)
	if _, err := fgetxattr(^uintptr(0), "system.posix_acl_access", buf); !errors.Is(err, syscall.EBADF) {
		t.Errorf("fgetxattr with a bad file descriptor: %v, want EBADF", err)
	}
	if _, err := fgetxattr(0, "system.posix_acl_access", nil); !errors.Is(err, syscall.ERANGE) {
		t.Errorf("fgetxattr with no buffer: %v, want ERANGE", err)
	}
	if _, err := fgetxattr(0, "system.\x00", buf); err == nil {
		t.Error("fgetxattr with a NUL in the name: got no error")
	}
}

// TestOpenFlags checks that openFlags refuse a symbolic link and do not
// wait on a FIFO, in case a file changes after walkPath.
func TestOpenFlags(t *testing.T) {
	dir := privateTempDir(t)
	link := symlink(t, writeFile(t, dir, "target", "made-up\n", 0o600), filepath.Join(dir, "link"))
	if _, err := openFile(t, link, openFlags); err == nil {
		t.Error("opening a symbolic link worked; want ELOOP (O_NOFOLLOW)")
	} else if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("opening a symbolic link: %v, want ELOOP", err)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openFile(t, fifo, openFlags)
		if err == nil {
			err = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("opening a FIFO: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("opening a FIFO with no writer waits; want it to return at once (O_NONBLOCK)")
	}
}
