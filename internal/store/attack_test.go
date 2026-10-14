package store

// Attack tests from the security review of issue #8. Each test runs a small
// /bin/sh script as the store program.
//
//   - TestSetsidChild...: what happens for a risk that the threat model
//     accepts (T29). If the behavior changes, update THREAT-MODEL.md.
//   - The others: what the store must do, also against a program that
//     misbehaves.
//
// None of them is parallel: a script file that another test's fork still
// holds open fails exec with ETXTBSY.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// scriptStore makes a store of type typ whose program is the /bin/sh
// script body. It returns the store, its home directory and its config.
func scriptStore(t *testing.T, typ config.StoreType, body string, d deps) (Store, string, config.Store) {
	t.Helper()
	base := t.TempDir()
	prog := filepath.Join(base, string(typ))
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // a test script.
		t.Fatal(err)
	}
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Store{Name: "main", Type: typ, Program: prog}
	switch typ {
	case config.StoreBWS:
		cfg.TokenFile = filepath.Join(base, "token")
		writeFile(t, cfg.TokenFile, madeUp("token")+"\n")
	case config.StoreBW:
		cfg.PasswordFile = filepath.Join(base, "password")
		writeFile(t, cfg.PasswordFile, madeUp("password")+"\n")
	}
	s, err := newStore(cfg, dir, d)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	t.Cleanup(s.Close)
	return s, filepath.Join(dir, cfg.Name), cfg
}

// readPID reads a process ID that a script wrote to name in home.
func readPID(t *testing.T, home, name string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(filepath.Join(home, name)) //nolint:gosec // test file.
		if err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the script wrote no process ID to %s", name)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// killLater kills pid when the test ends.
func killLater(t *testing.T, pid int) {
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
}

// A child that leaves the process group with setsid, and keeps stdout open.
// The run fails after waitDelay, but the child survives the group kill, with
// the token in its environment. THREAT-MODEL T29 accepts this.
func TestSetsidChildThatHoldsTheOutput(t *testing.T) {
	d := testDeps()
	d.waitDelay = 300 * time.Millisecond
	s, home, _ := scriptStore(t, config.StoreBWS, `setsid sh -c 'echo $$ > "$HOME/escaped.pid"; exec sleep 300' &
sleep 0.3
printf '{"value":"x"}'
`, d)
	start := time.Now()
	v, err := s.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrLeftRunning)
	if v.Bytes() != nil {
		t.Error("a value with an error")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("Fetch took %v", took)
	}
	pid := readPID(t, home, "escaped.pid")
	killLater(t, pid)
	if !alive(pid) {
		t.Fatal("the escaped child is gone; T29 says it survives (update the threat model)")
	}
	env, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(env, []byte("BWS_ACCESS_TOKEN=")) {
		t.Error("the escaped child has no token in its environment")
	}
}

// The same, but the child does not hold the output: the fetch works, and
// the child keeps running with the token. THREAT-MODEL T29 accepts this.
func TestSetsidChildThatLetsGoOfTheOutput(t *testing.T) {
	s, home, _ := scriptStore(t, config.StoreBWS, `setsid sh -c 'echo $$ > "$HOME/escaped.pid"; exec sleep 300' >/dev/null 2>&1 &
sleep 0.3
printf '{"id":"`+testItemID+`","value":"x"}'
`, testDeps())
	v, err := s.Fetch(t.Context(), testItemID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	v.Clear()
	pid := readPID(t, home, "escaped.pid")
	killLater(t, pid)
	if !alive(pid) {
		t.Fatal("the escaped child is gone; T29 says it survives (update the threat model)")
	}
}

// A child that stays in the group, and does not hold the output: the fetch
// works, and the group kill after the run stops the child.
func TestGroupChildKilledAfterSuccess(t *testing.T) {
	s, home, _ := scriptStore(t, config.StoreBWS, `sleep 300 >/dev/null 2>&1 &
echo $! > "$HOME/child.pid"
printf '{"id":"`+testItemID+`","value":"x"}'
`, testDeps())
	v, err := s.Fetch(t.Context(), testItemID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	v.Clear()
	pid := readPID(t, home, "child.pid")
	killLater(t, pid)
	waitGone(t, []int{pid})
}

// A program that stops itself (SIGSTOP) is still killed at the time limit.
func TestStoppedProgramTimesOut(t *testing.T) {
	d := testDeps()
	d.timeout = 2 * time.Second
	s, home, _ := scriptStore(t, config.StoreBWS, `echo $$ > "$HOME/self.pid"
kill -STOP $$
printf '{"value":"x"}'
`, d)
	start := time.Now()
	_, err := s.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrTimeout)
	if took := time.Since(start); took > 6*time.Second {
		t.Errorf("Fetch took %v", took)
	}
	pid := readPID(t, home, "self.pid")
	killLater(t, pid)
	waitGone(t, []int{pid})
}

// A program that closes stdout and stderr and keeps running is killed at
// the time limit.
func TestProgramThatClosesItsOutputTimesOut(t *testing.T) {
	d := testDeps()
	d.timeout = 2 * time.Second
	s, home, _ := scriptStore(t, config.StoreBWS, `echo $$ > "$HOME/self.pid"
exec >&- 2>&-
exec sleep 300
`, d)
	start := time.Now()
	_, err := s.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrTimeout)
	if took := time.Since(start); took > 6*time.Second {
		t.Errorf("Fetch took %v", took)
	}
	pid := readPID(t, home, "self.pid")
	killLater(t, pid)
	waitGone(t, []int{pid})
}

// /proc/PID/environ of a store program, which holds the token, is readable
// only by its own user (and root). cmdline has no token.
func TestEnvironmentIsPrivate(t *testing.T) {
	s, home, _ := scriptStore(t, config.StoreBWS, `echo $$ > "$HOME/self.pid"
sleep 1
printf '{"id":"`+testItemID+`","value":"x"}'
`, testDeps())
	done := make(chan error, 1)
	go func() {
		v, err := s.Fetch(context.Background(), testItemID)
		v.Clear()
		done <- err
	}()
	pid := readPID(t, home, "self.pid")
	fi, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o400 {
		t.Errorf("environ has mode %04o, want 0400", perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		t.Errorf("environ is not owned by the broker user")
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cmdline, []byte("token-")) {
		t.Error("the token is in the command line")
	}
	if err := <-done; err != nil {
		t.Fatalf("Fetch: %v", err)
	}
}

// bw: Close waits until a running Fetch ends, and that Fetch still hands
// out its value. The broker must cancel requests before it closes a store.
func TestBWCloseWaitsForAFetch(t *testing.T) {
	s, _, _ := scriptStore(t, config.StoreBW, `case "$1" in
unlock) printf 'c2Vzc2lvbi1rZXk=' ;;
sync) sleep 2; printf 'Syncing complete.' ;;
get) printf '{"id":"`+testItemID+`","login":{"password":"x"}}' ;;
status) printf '{"status":"unlocked"}' ;;
esac
`, testDeps())
	type result struct {
		v   Value
		err error
		at  time.Time
	}
	done := make(chan result, 1)
	go func() {
		v, err := s.Fetch(t.Context(), testItemID)
		done <- result{v, err, time.Now()}
	}()
	time.Sleep(500 * time.Millisecond)
	s.Close()
	closed := time.Now()
	r := <-done
	if r.err != nil {
		t.Fatalf("Fetch: %v", r.err)
	}
	r.v.Clear()
	if closed.Before(r.at) {
		t.Error("Close returned before the Fetch ended")
	}
}

// newStore refuses a relative password_file. CheckPrivateFile would check
// it relative to the broker's working directory, but bw runs in the
// store's home and reads it relative to that. The config package refuses
// relative paths, so this needs a config.Store that did not come from
// LoadBroker; newStore checks program for the same reason.
func TestNewRefusesRelativeFiles(t *testing.T) {
	d := testDeps()
	d.checkPrivateFile = func(string) error { return nil } // a check that passed for another file
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{"password", "-password", "../password"} {
		cfg := config.Store{Name: "vault", Type: config.StoreBW, Program: "/bin/false", PasswordFile: pw}
		s, err := newStore(cfg, dir, d)
		if err == nil {
			s.Close()
			t.Errorf("newStore took password_file %q, a relative path", pw)
		} else if !strings.Contains(err.Error(), "password_file: must be an absolute path") {
			t.Errorf("newStore with password_file %q: %v", pw, err)
		}
	}
	cfg := config.Store{Name: "main", Type: config.StoreBWS, Program: "/bin/false", TokenFile: "token"}
	d.readPrivateFile = func(string) ([]byte, error) { return []byte(madeUp("token")), nil }
	if s, err := newStore(cfg, dir, d); err == nil {
		s.Close()
		t.Error("newStore took a relative token_file")
	} else if !strings.Contains(err.Error(), "token_file: must be an absolute path") {
		t.Errorf("newStore with a relative token_file: %v", err)
	}
}

// A value with a NUL byte can never go into an environment variable
// (execve ends each one at a NUL), so the broker denies it before the
// value leaves the broker.
func TestValueWithNULIsRefused(t *testing.T) {
	s, _, _ := scriptStore(t, config.StoreBWS, `printf '{"id":"`+testItemID+`","value":"a\\u0000b"}'
`, testDeps())
	v, err := s.Fetch(t.Context(), testItemID)
	if err == nil {
		t.Errorf("Fetch handed out a value with a NUL byte (%d bytes)", len(v.Bytes()))
		v.Clear()
	}
	checkErr(t, err, ErrBadValue)
}

// An answer for another item is refused. Checking "id" against the asked
// ID costs nothing, and turns a CLI bug or a future fallback to a search
// into a deny.
func TestAnswerForAnotherItemIsRefused(t *testing.T) {
	const other = "00000000-0000-4000-8000-0000000000aa"
	for _, typ := range []config.StoreType{config.StoreBWS, config.StoreBW} {
		s, _, _ := scriptStore(t, typ, `case "$1" in
secret) printf '{"id":"`+other+`","value":"x"}' ;;
unlock) printf 'c2Vzc2lvbi1rZXk=' ;;
sync) printf 'Syncing complete.' ;;
get) printf '{"object":"item","id":"`+other+`","type":1,"login":{"password":"x"}}' ;;
status) printf '{"status":"unlocked"}' ;;
esac
`, testDeps())
		v, err := s.Fetch(t.Context(), testItemID)
		if err == nil {
			t.Errorf("%s: Fetch handed out the value of item %s for item %s", typ, other, testItemID)
			v.Clear()
		}
		checkErr(t, err, ErrBadAnswer)
	}
}

// bw get item by ID returns archived items too, as it does items in the
// trash; bw's own search skips both. A person who archives an item to
// retire it expects nodkey to stop handing it out.
func TestBWArchivedItemIsRefused(t *testing.T) {
	s, _, _ := scriptStore(t, config.StoreBW, `case "$1" in
unlock) printf 'c2Vzc2lvbi1rZXk=' ;;
sync) printf 'Syncing complete.' ;;
get) printf '{"object":"item","id":"`+testItemID+`","type":1,"archivedDate":"2026-10-13T12:00:00.000Z","login":{"password":"x"}}' ;;
status) printf '{"status":"unlocked"}' ;;
esac
`, testDeps())
	v, err := s.Fetch(t.Context(), testItemID)
	if err == nil {
		t.Error("Fetch handed out an archived item")
		v.Clear()
	}
	checkErr(t, err, ErrArchived)
}

// Real bw 2026.9.1 leaves "deletedDate" out of a normal item (CipherView
// has it undefined, and JSON.stringify drops it). Such an answer must work.
func TestBWItemWithoutDeletedDate(t *testing.T) {
	s, _, _ := scriptStore(t, config.StoreBW, `case "$1" in
unlock) printf 'c2Vzc2lvbi1rZXk=' ;;
sync) printf 'Syncing complete.' ;;
get) printf '{"object":"item","id":"`+testItemID+`","type":1,"name":"n","login":{"username":"u","password":"x"}}' ;;
status) printf '{"status":"unlocked"}' ;;
esac
`, testDeps())
	v, err := s.Fetch(t.Context(), testItemID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	checkValue(t, v, "x")
	v.Clear()
}
