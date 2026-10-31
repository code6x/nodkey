// Package store gets secret values from the secret stores: Bitwarden
// Secrets Manager (bws), the Bitwarden Password Manager (bw), 1Password
// with a service account (1password) and Infisical with a machine identity
// (infisical). See DESIGN.md sections 5, 11 and 16, and THREAT-MODEL.md
// T18 and T29.
//
// nodkey does not link the Bitwarden SDK. A bws or bw store runs the
// store's own program instead (a 1password store calls the 1Password SDK
// in the process, see opStore; an infisical store calls Infisical's API,
// see infStore):
//
//   - by the absolute path from the config, without a shell;
//   - with stdin from /dev/null, in its own process group, and with its
//     home directory as the working directory;
//   - with only the environment it needs: HOME (a private directory for
//     this store alone), the bws token or the bw session key in a
//     variable, never in an argument, and for bw a fixed PATH of system
//     directories, which New checks;
//   - with a time limit and a cap on its output. On a timeout, too much
//     output, or a cancelled request, the whole process group is killed.
//     If the broker ends during a run, the kernel kills the program.
//
// The program's output is never logged. An error gives the store's name,
// the step (such as "bw sync"), a fixed text and the exit code, never the
// program's output.
package store

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// Store gets secret values from one [store.*] section of the broker
// config. The methods are safe for many goroutines.
type Store interface {
	// Start prepares the store when the broker starts. For bw it unlocks
	// the vault with the master password file and keeps the session key
	// in memory. An error means that the store cannot hand out values
	// now; Fetch tries again. For bws it does nothing.
	Start(ctx context.Context) error
	// Fetch gets the value of the item with the ID id, the id of a
	// [secret.*] section. For a 1password store, id is "ITEM_ID/FIELD",
	// with the field of the section; for an infisical store, it is from
	// InfisicalRef. The caller must Clear the value when
	// it is sent.
	// Any error means deny.
	Fetch(ctx context.Context, id string) (Value, error)
	// Close clears the token or the session key that the store holds.
	// Fetch and Start fail after Close.
	Close()
}

// The reasons of the errors of a store. An error of Start or Fetch wraps
// one of them, a context error, or the error of a file check. Test them
// with errors.Is.
var (
	ErrClosed        = errors.New("the store is closed")
	ErrBadID         = errors.New("the item ID is not a UUID")
	ErrStart         = errors.New("cannot start the program")
	ErrFailed        = errors.New("the program failed")
	ErrTimeout       = errors.New("the program took too long and was stopped")
	ErrTooMuchOutput = errors.New("the program wrote too much output and was stopped")
	ErrLeftRunning   = errors.New("the program left a process running, which was stopped")
	ErrBadAnswer     = errors.New("the program's answer is not in the expected form")
	ErrNoValue       = errors.New("the item has no value to hand out")
	ErrBadValue      = errors.New("the value holds a NUL byte, which a command's environment cannot hold")
	ErrTrashed       = errors.New("the item is in the trash")
	ErrArchived      = errors.New("the item is archived")
	ErrLoggedOut     = errors.New("bw is logged out; a person must log in again in the store's home directory")
	ErrLocked        = errors.New("the bw vault is locked; the next request unlocks it again")
)

// DefaultTimeout is the time limit of one run of a store program.
const DefaultTimeout = 30 * time.Second

// deps are the parts of a store that tests replace.
type deps struct {
	// readPrivateFile reads the bws token file: config.ReadPrivateFile.
	readPrivateFile func(path string) ([]byte, error)
	// checkPrivateFile checks the bw password file before bw reads it:
	// config.CheckPrivateFile.
	checkPrivateFile func(path string) error
	// checkParentDirs checks the directories on the way to a store's home
	// directory, and the directories in path: config.CheckParentDirs.
	checkParentDirs func(path string) error
	// checkProgram checks the node in each directory in path, as a
	// store's program is checked: config.CheckProgram.
	checkProgram func(path string) error
	// path is the PATH of bw: bwPath.
	path string
	// timeout limits each run of the program.
	timeout time.Duration
	// opConnect logs in to 1Password: sdkConnect when nil.
	opConnect opConnect
	// infTransport sends the requests to Infisical: newInfTransport when
	// nil.
	infTransport http.RoundTripper
	// now is the clock of the infisical store: time.Now when nil.
	now func() time.Time
	// waitDelay is how long a run waits for the program's output after
	// the program ended. A process that the program left behind can hold
	// the output open; after this time the run fails.
	waitDelay time.Duration
}

// realDeps are the deps that New uses.
func realDeps() deps {
	return deps{
		readPrivateFile:  config.ReadPrivateFile,
		checkPrivateFile: config.CheckPrivateFile,
		checkParentDirs:  config.CheckParentDirs,
		checkProgram:     config.CheckProgram,
		path:             bwPath,
		timeout:          DefaultTimeout,
		waitDelay:        2 * time.Second,
	}
}

// New makes the store of one [store.*] section. dir is the directory for
// the programs' state; it must exist. The store's program gets its own
// home directory in it, dir/NAME, where NAME is the name of the section.
// So two stores never share one: bw keeps the state of one account there.
//
// The program, the token file and the password file must be clean
// absolute paths. The config package already makes them absolute, but New
// does not rely on it: bw reads the password file from its home directory,
// and a relative path would name another file there than the one that
// nodkey checked.
//
// New checks the home directory, and makes it if it is missing (see
// prepareHome). For bws, it reads the token file with
// config.ReadPrivateFile. For bw, it checks the master password file with
// config.CheckPrivateFile and its size, the directories in bw's PATH and
// the node in them (checkPathDirs), and that bw would not keep its state
// in a bw-data directory (checkNoBWData); bw reads the password file
// itself when it unlocks. New does not run the program; call Start.
func New(cfg config.Store, dir string) (Store, error) {
	return newStore(cfg, dir, realDeps())
}

// newStore is New with deps.
func newStore(cfg config.Store, dir string, d deps) (Store, error) {
	if !validName(cfg.Name) {
		return nil, errors.New("store: the name of the store cannot be the name of a directory")
	}
	name := cfg.Name
	switch cfg.Type {
	case config.StoreOnePassword:
		return newOP(cfg, d)
	case config.StoreInfisical:
		return newInfisical(cfg, d)
	}
	files := []struct{ key, path string }{{"program", cfg.Program}}
	switch cfg.Type {
	case config.StoreBWS:
		files = append(files, struct{ key, path string }{"token_file", cfg.TokenFile})
	case config.StoreBW:
		files = append(files, struct{ key, path string }{"password_file", cfg.PasswordFile})
	default:
		return nil, fmt.Errorf("store %q: unknown store type", name)
	}
	for _, f := range files {
		if !cleanAbs(f.path) {
			return nil, fmt.Errorf("store %q: %s: %s", name, f.key, cleanAbsRule)
		}
	}
	if !cleanAbs(dir) {
		return nil, fmt.Errorf("store %q: the state directory: %s", name, cleanAbsRule)
	}
	home := filepath.Join(dir, name)
	if err := prepareHome(home, d.checkParentDirs); err != nil {
		return nil, fmt.Errorf("store %q: home directory: %w", name, err)
	}
	r := runner{
		store:     name,
		program:   cfg.Program,
		home:      home,
		timeout:   d.timeout,
		waitDelay: d.waitDelay,
	}
	if cfg.Type == config.StoreBWS {
		return newBWS(cfg, r, d)
	}
	r.bwPath = d.path
	return newBW(cfg, r, d)
}

// cleanAbsRule says what cleanAbs allows, for errors.
const cleanAbsRule = `must be an absolute path without "//", "." or ".." parts`

// cleanAbs reports whether p is an absolute path that filepath.Clean
// leaves as it is. Clean would change what ".." means after a symbolic
// link, so a path that is not clean is refused, not cleaned.
func cleanAbs(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p
}

// validName reports whether name can be one directory in the state
// directory. The config allows only such names (DESIGN.md section 14);
// this checks again, because the name becomes part of a path.
func validName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00") && len(name) <= 64
}

// isUUID reports whether id is a UUID in the form
// 00000000-0000-0000-0000-000000000000, in upper or lower case. An ID
// goes into the program's arguments, so it must never start with "-",
// and bw must never search items by name.
func isUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

// isHex reports whether c is a hex digit, in upper or lower case.
func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// stepError returns an error of one step of a store, such as
// `store "vault": bw sync: the program failed`.
func stepError(store, step string, err error) error {
	return fmt.Errorf("store %q: %s: %w", store, step, err)
}

// acquire takes a place in slots, or returns an error when ctx ends first.
func acquire(ctx context.Context, slots chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
