package client

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/code6x/nodkey/internal/api"
)

// The claimed context of an SSH login (DESIGN.md section 6, step 5): the
// command lines of the ssh process and of at most 3 of its parents, and
// NODKEY_REASON from the environment of ssh. nodkey ssh-agent reads them
// from /proc, for the process that connected to the agent (SO_PEERCRED).
// They are claims: the agent machine can write anything there, and a
// process ID can be used again by a new process. The broker shows them
// under the "claimed by the agent" line, after it masked them.

// procDir is where Linux shows its processes.
const procDir = "/proc"

// Limits of what the agent reads from /proc.
const (
	// maxParents is the most parent processes whose command lines go with
	// a sign request, after the one of ssh (DESIGN.md section 6).
	maxParents = 3
	// maxCmdline is the most bytes of a command line in /proc that the
	// agent sends: api.MaxText bytes of arguments, and a NUL byte after
	// each of at most api.MaxArgs arguments. A longer one is sent as
	// "[hidden: too long]".
	maxCmdline = api.MaxText + api.MaxArgs
	// maxStat is the most bytes of /proc/PID/stat that the agent reads.
	// The line is far shorter.
	maxStat = 4 << 10
	// maxEnviron is the most bytes of /proc/PID/environ that the agent
	// reads. Linux allows at most 6 MiB of arguments and environment for
	// a new program.
	maxEnviron = 8 << 20
)

// procFS reads processes from a /proc tree. Its root is procDir; tests
// give it a tree of their own.
type procFS struct {
	root string
}

// claimedContext returns the claimed context of a sign request from the
// process pid: the command lines of pid and of at most maxParents of its
// parents, pid first, and NODKEY_REASON from the environment of pid. It
// returns nothing when pid is 0 (not known, such as a process in another
// PID namespace) or its command line cannot be read. The chain of parents
// stops at the first one that cannot be read, has no command line, such
// as a kernel thread, or is there twice.
//
// Each command line and the reason are as nodkey run sends them: a field
// that is too long becomes "[hidden: too long]" (claimedCommand,
// claimedText). Nothing else of the environment is kept or sent.
//
// A read of /proc can block, such as on a mapping of a stuck FUSE or NFS
// file system; sshAgent.claimed waits for claimedContext only for a short
// time.
func (p procFS) claimedContext(pid int32) (commands [][]string, reason string) {
	commands = [][]string{}
	pr, err := p.openProcess(int(pid))
	if err != nil {
		return commands, ""
	}
	argv, ok := pr.commandLine()
	if !ok {
		pr.close()
		return commands, ""
	}
	commands = append(commands, argv)
	reason = pr.reason()
	parent, hasParent := pr.parent()
	pr.close()
	seen := map[int]bool{int(pid): true}
	for range maxParents {
		if !hasParent || seen[parent] {
			break
		}
		seen[parent] = true
		pr, err := p.openProcess(parent)
		if err != nil {
			break
		}
		argv, ok := pr.commandLine()
		parent, hasParent = pr.parent()
		pr.close()
		if !ok {
			break
		}
		commands = append(commands, argv)
	}
	return commands, reason
}

// process is the open directory of one process in /proc. Its files are
// read through it (openat), so that they all come from that one process:
// when the process ends and a new process gets its ID, a read fails
// instead of reading the new process.
type process struct {
	dir *os.Root
}

// openProcess opens the directory of process pid.
func (p procFS) openProcess(pid int) (*process, error) {
	if pid <= 0 {
		return nil, errors.New("client: no such process")
	}
	dir, err := os.OpenRoot(filepath.Join(p.root, strconv.Itoa(pid)))
	if err != nil {
		return nil, err
	}
	return &process{dir: dir}, nil
}

// close closes the directory.
func (pr *process) close() { _ = pr.dir.Close() }

// read reads the file name of the process, at most limit bytes. over is
// true, and data nil, when the file has more.
func (pr *process) read(name string, limit int) (data []byte, over bool, err error) {
	f, err := pr.dir.Open(name)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	data, err = io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > limit {
		return nil, true, nil
	}
	return data, false, nil
}

// commandLine returns the command line of the process, from
// /proc/PID/cmdline: the arguments, each followed by a NUL byte. ok is
// false when it cannot be read, or is empty, as for a kernel thread or a
// process that ended.
func (pr *process) commandLine() ([]string, bool) {
	data, over, err := pr.read("cmdline", maxCmdline)
	switch {
	case err != nil:
		return nil, false
	case over:
		return []string{tooLong}, true
	case len(data) == 0:
		return nil, false
	}
	// The NUL after the last argument ends it; it does not start another
	// one.
	s := strings.TrimSuffix(string(data), "\x00")
	return claimedCommand(strings.Split(s, "\x00")), true
}

// parent returns the parent of the process, from /proc/PID/stat:
// "PID (NAME) STATE PPID ...". NAME can hold any byte, also ")" and
// spaces, so the fields after it start after the last ")". ok is false
// when there is no parent, as for process 1, or it cannot be read.
func (pr *process) parent() (int, bool) {
	data, over, err := pr.read("stat", maxStat)
	if err != nil || over {
		return 0, false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid <= 0 {
		return 0, false
	}
	return ppid, true
}

// reason returns NODKEY_REASON from the environment of the process, from
// /proc/PID/environ, as claimedText makes it: "" when it is not set or
// cannot be read, and "[hidden: too long]" when it is longer than
// api.MaxText bytes.
func (pr *process) reason() string {
	f, err := pr.dir.Open("environ")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	value, found, long := envValue(io.LimitReader(f, maxEnviron), reasonVar, api.MaxText)
	switch {
	case !found:
		return ""
	case long:
		return tooLong
	}
	return value
}

// envValue returns the value of the first variable called name in r, an
// environment as /proc/PID/environ holds it: entries "NAME=VALUE", each
// followed by a NUL byte. The first one counts, as for getenv(3) of the C
// library, which ssh uses. A value longer than limit bytes is not
// returned: long is true then.
//
// envValue keeps no other entry. It reads r in small pieces, looks at one
// byte at a time, and clears each piece after use. So no other variable of
// the environment, which may hold a secret, stays in memory.
func envValue(r io.Reader, name string, limit int) (value string, found, long bool) {
	prefix := name + "="
	buf := make([]byte, 4<<10)
	defer clear(buf)
	var val []byte
	defer func() { clear(val) }()
	const (
		inName   = iota // in the name of an entry; matched bytes of prefix so far
		inValue         // in the value of the variable
		skipping        // in another entry, up to its NUL
	)
	state, matched := inName, 0
	for {
		n, err := r.Read(buf)
		for _, c := range buf[:n] {
			switch state {
			case inName:
				switch c {
				case 0:
					matched = 0 // the entry ended; the next one starts
				case prefix[matched]:
					if matched++; matched == len(prefix) {
						state = inValue
					}
				default:
					state = skipping
				}
			case inValue:
				if c == 0 {
					return string(val), true, long
				}
				if len(val) < limit {
					val = append(val, c)
				} else {
					long = true
				}
			case skipping:
				if c == 0 {
					state, matched = inName, 0
				}
			}
		}
		if err != nil {
			break
		}
	}
	// The last entry may end without a NUL byte.
	if state == inValue {
		return string(val), true, long
	}
	return "", false, false
}
