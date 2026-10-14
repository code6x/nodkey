package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/code6x/nodkey/internal/config"
)

// bwPath is the PATH of bw. A bw that npm installed is a script that
// starts with "#!/usr/bin/env node", and env finds node through PATH. Only
// directories that root manages on most systems are in it, and New checks
// each of them, and the node in it (checkPathDirs).
const bwPath = "/usr/local/bin:/usr/bin:/bin"

// maxPasswordFileSize is the largest bw password file: 1 MiB, as for every
// key, token and password file (DESIGN.md section 14).
const maxPasswordFileSize = 1 << 20

// bwDataDir is the name of a directory that bw uses for its state instead
// of its home directory, when the directory is next to bw's executable.
const bwDataDir = "bw-data"

// The steps of a bw store, for errors.
const (
	stepUnlock  = "bw unlock"
	stepSync    = "bw sync"
	stepGetItem = "bw get item"
	stepStatus  = "bw status"
)

// bwStore gets values from the Bitwarden Password Manager with bw.
//
// bw keeps the state of its account in one file in its home directory,
// and each "bw unlock" makes a new session key that ends the old one. So
// only one bw program runs at a time for one store: a run holds lock, and
// lock also guards session and closed. A second request waits for its
// turn, or until its context ends.
type bwStore struct {
	run              runner
	path             string             // the PATH of bw
	passwordFile     string             // the master password; bw reads it itself
	checkPrivateFile func(string) error // checks passwordFile before each unlock

	lock    chan struct{} // one place: held during every run of bw
	session Value         // the session key; zero when the vault must be unlocked
	closed  bool
}

// newBW checks the directories in bw's PATH, that bw would keep its state
// in its home directory, and the master password file of a bw store, and
// returns the store. It does not run bw; Start unlocks.
func newBW(cfg config.Store, r runner, d deps) (*bwStore, error) {
	if err := checkPathDirs(d.path, d.checkParentDirs, d.checkProgram); err != nil {
		return nil, fmt.Errorf("store %q: %w", cfg.Name, err) // the error names the directory
	}
	if err := checkNoBWData(cfg.Program, d.path); err != nil {
		return nil, fmt.Errorf("store %q: %w", cfg.Name, err) // the error names the directory
	}
	if err := checkPasswordFile(cfg.PasswordFile, d.checkPrivateFile); err != nil {
		return nil, fmt.Errorf("store %q: password_file: %w", cfg.Name, err) // the error names the path
	}
	return &bwStore{
		run:              r,
		path:             d.path,
		passwordFile:     cfg.PasswordFile,
		checkPrivateFile: d.checkPrivateFile,
		lock:             make(chan struct{}, 1),
	}, nil
}

// checkPathDirs checks the directories in path, the PATH of bw, and the
// node in each of them. The node that a bw script starts through PATH
// reads the master password file and gets the session key, and so does
// any program that someone puts in such a directory.
//
//   - Each directory must pass checkDirs (config.CheckParentDirs), like
//     the directories on the way to a store's program: owned by root or by
//     the user that runs nodkey, and not writable by group or others. A
//     directory that is not there passes when the directories on the way
//     to it pass: then only root or that user can make it.
//   - A node in a directory, also a link, must pass checkProgram
//     (config.CheckProgram), as a store's program does: after its links,
//     it is a regular file owned by root or by that user, not writable by
//     group or others, and every directory on the way to it passes the
//     checks too. A link whose target is missing fails: someone could put
//     a file there later.
func checkPathDirs(path string, checkDirs, checkProgram func(string) error) error {
	for _, dir := range filepath.SplitList(path) {
		if !cleanAbs(dir) {
			return fmt.Errorf("PATH directory %q: %s", dir, cleanAbsRule)
		}
		node := filepath.Join(dir, "node")
		err := checkDirs(node) // checks dir and the way to it
		if errors.Is(err, fs.ErrNotExist) {
			err = checkDirs(dir) // checks only the way to dir
		}
		if err != nil {
			return fmt.Errorf("PATH directory %s: %w", dir, err)
		}
		switch _, err := os.Lstat(node); {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return fmt.Errorf("PATH directory %s: %w", dir, err) // a *fs.PathError names the path
		default:
			if err := checkProgram(node); err != nil {
				return fmt.Errorf("PATH directory %s: node: %w", dir, err)
			}
		}
	}
	return nil
}

// checkNoBWData refuses a directory named bw-data next to bw's
// executable. bw keeps its state there when it is there, and ignores HOME
// (see bw's service-container.ts): then the state is not in the store's
// private home, and two stores could share it. bw's executable is the
// program, after its links, for the standalone bw; for a bw from npm, it
// is node, which env finds through PATH. So checkNoBWData looks next to
// the program, next to the file that it links to, and next to node in
// each directory in path, before and after its links.
func checkNoBWData(program, path string) error {
	target, err := filepath.EvalSymlinks(program)
	if err != nil {
		return fmt.Errorf("program: %w", err) // a *fs.PathError names the path
	}
	dirs := []string{filepath.Dir(program), filepath.Dir(target)}
	for _, dir := range filepath.SplitList(path) {
		node, err := filepath.EvalSymlinks(filepath.Join(dir, "node"))
		switch {
		case err == nil:
			dirs = append(dirs, dir, filepath.Dir(node))
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("PATH directory %s: %w", dir, err)
		}
	}
	for _, dir := range dirs {
		p := filepath.Join(dir, bwDataDir)
		switch _, err := os.Lstat(p); {
		case err == nil:
			return fmt.Errorf("%s: bw would keep its state there, not in the store's home directory; "+
				"move it away", p)
		case !errors.Is(err, fs.ErrNotExist):
			return err // a *fs.PathError names the path
		}
	}
	return nil
}

// checkPasswordFile checks the bw password file with check
// (config.CheckPrivateFile), then that it is a regular file of 1 byte to
// 1 MiB. bw reads it by its path, so nodkey checks only the file there,
// without reading it.
func checkPasswordFile(path string, check func(string) error) error {
	if err := check(path); err != nil {
		return err // the error names the path
	}
	fi, err := os.Lstat(path)
	switch {
	case err != nil:
		return err // a *fs.PathError names the path
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s: is not a regular file", path)
	case fi.Size() == 0:
		return fmt.Errorf("%s: is empty; it must hold the master password", path)
	case fi.Size() > maxPasswordFileSize:
		return fmt.Errorf("%s: is larger than 1 MiB", path)
	}
	return nil
}

// Start unlocks the vault, unless the store has a session key already.
func (s *bwStore) Start(ctx context.Context) error {
	if err := acquire(ctx, s.lock); err != nil {
		return stepError(s.run.store, stepUnlock, err)
	}
	defer s.release()
	if s.closed {
		return stepError(s.run.store, stepUnlock, ErrClosed)
	}
	if s.session.Bytes() != nil {
		return nil
	}
	return s.unlock(ctx)
}

// Fetch unlocks the vault if the store has no session key, runs
// "bw sync --force", then runs "bw get item ID" and returns the item's
// password. The session key goes in BW_SESSION. If any step fails, Fetch
// fails: it never hands out a value from bw's old copy of the vault.
//
// The sync is forced. Without --force, bw downloads the vault only when
// the server's revision date of the account is later than bw's last sync,
// and bw takes the time of each sync from the broker's clock. With that
// clock ahead, bw would never download again, and an item that a person
// changed, moved to the trash or archived would still be handed out.
func (s *bwStore) Fetch(ctx context.Context, id string) (Value, error) {
	if !isUUID(id) {
		return Value{}, stepError(s.run.store, stepGetItem, ErrBadID)
	}
	if err := acquire(ctx, s.lock); err != nil {
		return Value{}, stepError(s.run.store, stepGetItem, err)
	}
	defer s.release()
	if s.closed {
		return Value{}, stepError(s.run.store, stepGetItem, ErrClosed)
	}
	if s.session.Bytes() == nil {
		if err := s.unlock(ctx); err != nil {
			return Value{}, err
		}
	}
	out, err := s.runWithSession(ctx, stepSync, "sync", "--force")
	if err != nil {
		return Value{}, err
	}
	clear(out) // "Syncing complete."
	out, err = s.runWithSession(ctx, stepGetItem, "get", "item", id)
	if err != nil {
		return Value{}, err
	}
	defer clear(out)
	v, err := parseBWItem(out, id)
	if err != nil {
		return Value{}, stepError(s.run.store, stepGetItem, err)
	}
	return v, nil
}

// unlock runs "bw unlock --passwordfile FILE --raw" and keeps the session
// key that it prints. bw reads the password file itself, so the password
// never passes through nodkey. The file is checked right before, as at
// start. The caller holds lock.
func (s *bwStore) unlock(ctx context.Context) error {
	if err := checkPasswordFile(s.passwordFile, s.checkPrivateFile); err != nil {
		return stepError(s.run.store, stepUnlock, fmt.Errorf("password_file: %w", err)) // names the path
	}
	out, err := s.run.run(ctx, stepUnlock, []string{"unlock", "--passwordfile", s.passwordFile, "--raw", "--nointeraction"},
		[]string{"PATH=" + s.path})
	if err != nil {
		return s.failed(ctx, stepUnlock, err)
	}
	defer clear(out)
	session, ok := parseKey(out, maxSessionLen)
	if !ok {
		return stepError(s.run.store, stepUnlock, ErrBadAnswer)
	}
	s.session = session
	return nil
}

// runWithSession runs bw with args and the session key in BW_SESSION. The
// caller holds lock and has a session key.
func (s *bwStore) runWithSession(ctx context.Context, step string, args ...string) ([]byte, error) {
	out, err := s.run.run(ctx, step, append(args, "--nointeraction"), s.sessionEnv())
	if err != nil {
		return nil, s.failed(ctx, step, err)
	}
	return out, nil
}

// failed handles a run of bw that failed. When bw exited with an error,
// failed asks bw status why:
//
//   - unauthenticated: bw is logged out. The error is ErrLoggedOut, and
//     every request fails until a person logs in again.
//   - locked: the session key does not work any more, for example after
//     someone ran "bw lock" or "bw unlock" in the store's home directory.
//     The error is ErrLocked (for unlock itself, its own error), and the
//     next request unlocks again.
//   - unlocked: the step failed for another reason, such as a network
//     error or an unknown item. The error is the step's own.
//
// The store forgets the session key in the first two cases, and when bw
// status fails too. The caller holds lock.
func (s *bwStore) failed(ctx context.Context, step string, err error) error {
	if !errors.Is(err, ErrFailed) {
		return err // a timeout, too much output, or the end of ctx
	}
	state, serr := s.status(ctx)
	switch {
	case serr != nil:
		s.forget()
		return err
	case state == bwUnauthenticated:
		s.forget()
		return stepError(s.run.store, step, ErrLoggedOut)
	case state == bwLocked:
		s.forget()
		if step == stepUnlock {
			return err
		}
		return stepError(s.run.store, step, ErrLocked)
	}
	return err
}

// status runs "bw status" and returns the state of bw, with the session
// key if the store has one. The caller holds lock.
func (s *bwStore) status(ctx context.Context) (string, error) {
	out, err := s.run.run(ctx, stepStatus, []string{"status", "--nointeraction"}, s.sessionEnv())
	if err != nil {
		return "", err
	}
	defer clear(out) // it holds the account's email address
	state, err := parseBWStatus(out)
	if err != nil {
		return "", stepError(s.run.store, stepStatus, err)
	}
	return state, nil
}

// sessionEnv returns the environment of a run of bw: PATH, and the
// session key when the store has one. The string with the key is a copy
// that cannot be cleared; so is the copy that os/exec makes for the system
// call.
func (s *bwStore) sessionEnv() []string {
	env := []string{"PATH=" + s.path}
	if s.session.Bytes() == nil {
		return env
	}
	return append(env, "BW_SESSION="+string(s.session.Bytes()))
}

// forget clears the session key, so the next request unlocks again.
func (s *bwStore) forget() {
	s.session.Clear()
	s.session = Value{}
}

// release gives lock back.
func (s *bwStore) release() { <-s.lock }

// Close clears the session key. It waits for a run of bw to end.
func (s *bwStore) Close() {
	s.lock <- struct{}{}
	defer s.release()
	s.forget()
	s.closed = true
}

// String names the store, without its session key.
func (s *bwStore) String() string { return fmt.Sprintf("bw store %q", s.run.store) }

// GoString names the store, without its session key.
func (s *bwStore) GoString() string { return s.String() }

// Format writes String for every verb.
func (s *bwStore) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
