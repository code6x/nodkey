package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// bwScenario returns a scenario where bw knows one login item with the
// password value. Its other fields hold the made-up secret other.
func bwScenario(password, session, value, other string) fakeScenario {
	return fakeScenario{
		Password: password,
		Session:  session,
		Items:    map[string]string{testItemID: bwItemJSON(testItemID, value, nil, other)},
	}
}

func TestBWStartAndFetch(t *testing.T) {
	t.Parallel()
	password, session, value := madeUp("password"), madeUp("session"), madeUp("value")
	f := newTestFake(t, config.StoreBW, bwScenario(password, session, value, madeUp("other")), testDeps())
	if err := f.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := f.steps(); !slices.Equal(got, []string{"unlock"}) {
		t.Errorf("Start ran %q, want unlock", got)
	}
	// A second Start keeps the session key.
	if err := f.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for range 2 {
		v, err := f.store.Fetch(t.Context(), testItemID)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		checkValue(t, v, value)
		v.Clear()
	}
	if got, want := f.steps(), []string{"unlock", "sync", "get item", "sync", "get item"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
	calls := f.calls()
	unlock := calls[0]
	if want := []string{"unlock", "--passwordfile", f.cfg.PasswordFile, "--raw", "--nointeraction"}; !slices.Equal(unlock.Args, want) {
		t.Errorf("unlock arguments = %q, want %q", unlock.Args, want)
	}
	if got, want := envNames(unlock.Env), []string{"HOME", "PATH"}; !slices.Equal(got, want) {
		t.Errorf("unlock environment names = %q, want %q", got, want)
	}
	// The sync is forced: bw would compare the server's time with the
	// broker's clock otherwise.
	if want := []string{"sync", "--force", "--nointeraction"}; !slices.Equal(calls[1].Args, want) {
		t.Errorf("sync arguments = %q, want %q", calls[1].Args, want)
	}
	if want := []string{"get", "item", testItemID, "--nointeraction"}; !slices.Equal(calls[2].Args, want) {
		t.Errorf("get item arguments = %q, want %q", calls[2].Args, want)
	}
	for _, c := range calls {
		if c.Dir != f.home || envValue(c.Env, "HOME") != f.home || envValue(c.Env, "PATH") != bwPath {
			t.Errorf("%q: working directory %q, HOME %q, PATH %q", c.Args, c.Dir, envValue(c.Env, "HOME"),
				envValue(c.Env, "PATH"))
		}
		if !c.Leader {
			t.Errorf("%q: bw does not lead its own process group", c.Args)
		}
		if c.Running != 1 {
			t.Errorf("%q: %d runs of bw at once, want 1", c.Args, c.Running)
		}
		if c.Args[0] == "unlock" {
			continue
		}
		if got, want := envNames(c.Env), []string{"BW_SESSION", "HOME", "PATH"}; !slices.Equal(got, want) {
			t.Errorf("%q: environment names = %q, want %q", c.Args, got, want)
		}
		if envValue(c.Env, "BW_SESSION") != session {
			t.Errorf("%q: BW_SESSION is not the session key from bw unlock", c.Args)
		}
	}
}

func TestBWFetchUnlocksWithoutStart(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", value, madeUp("other")), testDeps())
	v, err := f.store.Fetch(t.Context(), testItemID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	checkValue(t, v, value)
	if got, want := f.steps(), []string{"unlock", "sync", "get item"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
}

func TestBWLoggedOut(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", value, madeUp("other")), testDeps())
	f.setBWState(fakeBWState{LoggedOut: true})
	checkErr(t, f.store.Start(t.Context()), ErrLoggedOut)
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrLoggedOut)
	if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw unlock: bw is logged out`) {
		t.Errorf("error = %v", err)
	}
	if got, want := f.steps(), []string{"unlock", "status", "unlock", "status"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
	// A person logs in again: the next request works.
	f.setBWState(fakeBWState{})
	v, err := f.store.Fetch(t.Context(), testItemID)
	if err != nil {
		t.Fatalf("Fetch after a new login: %v", err)
	}
	checkValue(t, v, value)
}

func TestBWLoggedOutLater(t *testing.T) {
	t.Parallel()
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other")), testDeps())
	if err := f.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	st := f.bwState()
	st.LoggedOut = true
	f.setBWState(st)
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrLoggedOut)
	if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw sync: bw is logged out`) {
		t.Errorf("error = %v", err)
	}
	// After a failed sync, bw get item never runs.
	if got, want := f.steps(), []string{"unlock", "sync", "status"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
	if f.store.(*bwStore).session.Bytes() != nil {
		t.Error("the store kept the session key")
	}
}

func TestBWLockedUnlocksAgain(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", value, madeUp("other")), testDeps())
	if err := f.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	old := f.bwState().Session
	// Someone ran bw unlock in the store's home: the old key is no good.
	f.setBWState(fakeBWState{Session: madeUp("someone-else")})
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrLocked)
	if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw get item: the bw vault is locked`) {
		t.Errorf("error = %v", err)
	}
	// The next request unlocks again, with a new session key.
	v, err := f.store.Fetch(t.Context(), testItemID)
	if err != nil {
		t.Fatalf("Fetch after a lock: %v", err)
	}
	checkValue(t, v, value)
	if f.bwState().Session == old {
		t.Error("the store did not unlock again")
	}
	want := []string{"unlock", "sync", "get item", "status", "unlock", "sync", "get item"}
	if got := f.steps(); !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
}

func TestBWSyncFails(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	sc := bwScenario(madeUp("password"), "", value, madeUp("other"))
	sc.Steps = map[string]fakeStep{"sync": {Stderr: "Syncing failed: fetch failed", Exit: 1}}
	f := newTestFake(t, config.StoreBW, sc, testDeps())
	v, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrFailed)
	if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw sync: the program failed (exit code 1); to see why, run /`) ||
		!strings.Contains(err.Error(), " by hand as the broker's user, with HOME set to /") {
		t.Errorf("error = %v", err)
	}
	if v.Bytes() != nil {
		t.Error("Fetch returned a value with its error")
	}
	// The value is never read from bw's old copy of the vault.
	if got, want := f.steps(), []string{"unlock", "sync", "status"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
	// bw is still unlocked, so the store keeps the session key.
	if f.store.(*bwStore).session.Bytes() == nil {
		t.Error("the store dropped a session key that works")
	}
}

func TestBWGetItemFails(t *testing.T) {
	t.Parallel()
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other")), testDeps())
	_, err := f.store.Fetch(t.Context(), "00000000-0000-4000-8000-0000000000ff") // not found
	checkErr(t, err, ErrFailed)
	if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw get item: the program failed (exit code 1); to see why, run /`) {
		t.Errorf("error = %v", err)
	}
	if f.store.(*bwStore).session.Bytes() == nil {
		t.Error("the store dropped a session key that works")
	}
}

func TestBWWrongPassword(t *testing.T) {
	t.Parallel()
	password := madeUp("password")
	f := newTestFake(t, config.StoreBW, bwScenario(password, "", madeUp("value"), madeUp("other")), testDeps())
	writeFile(t, f.cfg.PasswordFile, madeUp("wrong")+"\n")
	err := f.store.Start(t.Context())
	checkErr(t, err, ErrFailed)
	if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw unlock: the program failed (exit code 1); to see why, run /`) {
		t.Errorf("error = %v", err)
	}
	if errors.Is(err, ErrLocked) {
		t.Error("a failed unlock says that the vault is locked")
	}
	_, err = f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrFailed)
	if got, want := f.steps(), []string{"unlock", "status", "unlock", "status"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
}

func TestBWUnlockBadAnswer(t *testing.T) {
	t.Parallel()
	session := madeUp("session")
	for name, stdout := range map[string]string{
		// bw unlock with an empty password file ends without output.
		"nothing":     "",
		"a message":   "Your vault is now unlocked!\n\n$ export BW_SESSION=\"" + session + "\"\n",
		"two words":   session + " " + session,
		"color":       "\x1b[32m" + session,
		"too long":    strings.Repeat("s", maxSessionLen+1),
		"only spaces": " \n ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other"))
			sc.Steps = map[string]fakeStep{"unlock": {Stdout: stdout}}
			f := newTestFake(t, config.StoreBW, sc, testDeps())
			err := f.store.Start(t.Context())
			checkErr(t, err, ErrBadAnswer)
			if err != nil {
				noCanary(t, "the error", err.Error(), session)
			}
			if f.store.(*bwStore).session.Bytes() != nil {
				t.Error("the store kept a session key from a bad answer")
			}
		})
	}
}

func TestBWStatusFails(t *testing.T) {
	t.Parallel()
	sc := bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other"))
	sc.Steps = map[string]fakeStep{"status": {Stdout: "not JSON"}}
	f := newTestFake(t, config.StoreBW, sc, testDeps())
	if err := f.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, err := f.store.Fetch(t.Context(), "00000000-0000-4000-8000-0000000000ff") // not found
	checkErr(t, err, ErrFailed)
	// The store cannot tell why bw failed, so it unlocks again next time.
	if f.store.(*bwStore).session.Bytes() != nil {
		t.Error("the store kept the session key")
	}
}

func TestBWTimeoutKillsTheProcessGroup(t *testing.T) {
	t.Parallel()
	for _, step := range []string{"unlock", "sync", "get item"} {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			value := madeUp("value")
			sc := bwScenario(madeUp("password"), "", value, madeUp("other"))
			sc.Steps = map[string]fakeStep{step: {Hang: true, Stdout: value}}
			d := testDeps()
			d.timeout = 5 * time.Second
			f := newTestFake(t, config.StoreBW, sc, d)
			v, err := f.store.Fetch(t.Context(), testItemID)
			checkErr(t, err, ErrTimeout)
			if v.Bytes() != nil {
				t.Error("Fetch returned a value with its error")
			}
			if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw `+step+": the program took too long") {
				t.Errorf("error = %v", err)
			}
			waitGone(t, f.pids())
			// A timeout says nothing about bw's state: no bw status.
			if got := f.steps(); slices.Contains(got, "status") {
				t.Errorf("steps = %q, want no status", got)
			}
		})
	}
}

func TestBWTooMuchOutput(t *testing.T) {
	t.Parallel()
	for _, step := range []string{"unlock", "sync", "get item", "status"} {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			sc := bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other"))
			sc.Steps = map[string]fakeStep{step: {Flood: "stdout"}}
			if step == "status" {
				// bw status runs only after a failed step.
				sc.Steps["sync"] = fakeStep{Exit: 1}
			}
			f := newTestFake(t, config.StoreBW, sc, testDeps())
			_, err := f.store.Fetch(t.Context(), testItemID)
			want := ErrTooMuchOutput
			if step == "status" {
				want = ErrFailed // the error of bw sync
			}
			checkErr(t, err, want)
		})
	}
}

func TestBWItemAnswers(t *testing.T) {
	t.Parallel()
	value, other := madeUp("value"), madeUp("other")
	tests := map[string]struct {
		item string
		want error
	}{
		"in the trash":     {bwItemJSON(testItemID, value, "2026-10-13T12:00:00.000Z", other), ErrTrashed},
		"null password":    {bwItemJSON(testItemID, nil, nil, other), ErrNoValue},
		"empty password":   {bwItemJSON(testItemID, "", nil, other), ErrNoValue},
		"no login":         {`{"object":"item","id":"` + testItemID + `","type":2,"notes":"` + other + `","deletedDate":null}`, ErrNoValue},
		"null login":       {`{"id":"` + testItemID + `","login":null}`, ErrNoValue},
		"password number":  {`{"login":{"password":7}}`, ErrBadAnswer},
		"deletedDate true": {`{"login":{"password":"` + value + `"},"deletedDate":true}`, ErrBadAnswer},
		"two passwords":    {`{"login":{"password":"` + value + `","password":"` + value + `"}}`, ErrBadAnswer},
		"two logins":       {`{"login":{"password":"` + value + `"},"login":{"password":"` + value + `"}}`, ErrBadAnswer},
		"Password":         {`{"id":"` + testItemID + `","login":{"Password":"` + value + `"}}`, ErrNoValue},
		"cut short":        {`{"login":{"password":"` + value + `"}`, ErrBadAnswer},
		"a list":           {`[` + bwItemJSON(testItemID, value, nil, other) + `]`, ErrBadAnswer},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwScenario(madeUp("password"), "", value, other)
			sc.Items[testItemID] = tc.item
			f := newTestFake(t, config.StoreBW, sc, testDeps())
			v, err := f.store.Fetch(t.Context(), testItemID)
			checkErr(t, err, tc.want)
			if v.Bytes() != nil {
				t.Error("Fetch returned a value with its error")
			}
			if err != nil {
				noCanary(t, "the error", err.Error(), value)
				noCanary(t, "the error", err.Error(), other)
			}
		})
	}
}

func TestBWConcurrentFetches(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	sc := bwScenario(madeUp("password"), "", value, madeUp("other"))
	sc.Pause = 30 * time.Millisecond
	f := newTestFake(t, config.StoreBW, sc, testDeps())
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			v, err := f.store.Fetch(t.Context(), testItemID)
			if err == nil && string(v.Bytes()) != value {
				err = errors.New("wrong value")
			}
			v.Clear()
			errs[i] = err
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Errorf("Fetch: %v", err)
		}
	}
	// One unlock, then a sync and a get for each request, one bw at a
	// time.
	steps := f.steps()
	if len(steps) != 1+2*n || steps[0] != "unlock" {
		t.Errorf("steps = %q, want one unlock and %d of sync and get item", steps, n)
	}
	for _, c := range f.calls() {
		if c.Running != 1 {
			t.Errorf("%d runs of bw at once, want 1", c.Running)
		}
	}
}

func TestBWFetchWaitsForItsTurn(t *testing.T) {
	t.Parallel()
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other")), testDeps())
	s := f.store.(*bwStore)
	s.lock <- struct{}{} // another request runs bw
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := s.Fetch(ctx, testItemID)
	checkErr(t, err, context.DeadlineExceeded)
	checkErr(t, s.Start(ctx), context.DeadlineExceeded)
	s.release()
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("bw ran %d times, want 0", len(calls))
	}
}

func TestBWChecksThePasswordFileBeforeEachUnlock(t *testing.T) {
	t.Parallel()
	f := setupFake(t, config.StoreBW, bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other")))
	d := testDeps()
	bad := errors.New("made-up: others can read it")
	var mu sync.Mutex
	checks, fail := 0, false
	d.checkPrivateFile = func(path string) error {
		mu.Lock()
		defer mu.Unlock()
		if path != f.cfg.PasswordFile {
			t.Errorf("checked %q, want the password file", path)
		}
		checks++
		if fail {
			return bad
		}
		return nil
	}
	s, err := newStore(f.cfg, f.dir, d)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	defer s.Close()
	mu.Lock()
	fail = true
	mu.Unlock()
	err = s.Start(t.Context())
	checkErr(t, err, bad)
	if err != nil && !strings.HasPrefix(err.Error(), `store "vault": bw unlock: password_file: `) {
		t.Errorf("error = %v", err)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("bw ran %d times, want 0", len(calls))
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	if err := s.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	mu.Lock()
	if checks != 3 { // newStore, and each unlock
		t.Errorf("the password file was checked %d times, want 3", checks)
	}
	// newStore refuses a password file that fails the check.
	fail = true
	mu.Unlock()
	if _, err := newStore(f.cfg, f.dir, d); !errors.Is(err, bad) {
		t.Errorf("newStore with a bad password file: %v", err)
	}
}

func TestBWClose(t *testing.T) {
	t.Parallel()
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", madeUp("value"), madeUp("other")), testDeps())
	if err := f.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	session := f.store.(*bwStore).session
	f.store.Close()
	if session.Bytes() != nil {
		t.Error("Close left the session key")
	}
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrClosed)
	checkErr(t, f.store.Start(t.Context()), ErrClosed)
	if got := f.steps(); !slices.Equal(got, []string{"unlock"}) {
		t.Errorf("steps = %q, want only the first unlock", got)
	}
	f.store.Close()
}
