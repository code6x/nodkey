package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// bwsScenario returns a scenario where bws knows one item with value.
func bwsScenario(token, value string) fakeScenario {
	return fakeScenario{Token: token, Items: map[string]string{testItemID: bwsSecretJSON(testItemID, value)}}
}

func TestBWSFetch(t *testing.T) {
	t.Parallel()
	token, value := madeUp("token"), madeUp("value")
	f := newTestFake(t, config.StoreBWS, bwsScenario(token, value), testDeps())
	if err := f.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("Start ran bws %d times, want 0", len(calls))
	}
	// An ID in upper case works too; bws takes both.
	for _, id := range []string{testItemID, strings.ToUpper(testItemID)} {
		v, err := f.store.Fetch(t.Context(), id)
		if err != nil {
			t.Fatalf("Fetch(%s): %v", id, err)
		}
		checkValue(t, v, value)
		v.Clear()
		if v.Bytes() != nil {
			t.Error("Clear left the value")
		}
	}
	calls := f.calls()
	if len(calls) != 2 {
		t.Fatalf("bws ran %d times, want 2", len(calls))
	}
	c := calls[0]
	if want := []string{"secret", "get", testItemID, "--output", "json", "--color", "no"}; !slices.Equal(c.Args, want) {
		t.Errorf("arguments = %q, want %q", c.Args, want)
	}
	// bws starts no other program, so it gets no PATH.
	if got, want := envNames(c.Env), []string{"BWS_ACCESS_TOKEN", "HOME"}; !slices.Equal(got, want) {
		t.Errorf("environment names = %q, want %q", got, want)
	}
	if envValue(c.Env, "BWS_ACCESS_TOKEN") != token {
		t.Error("BWS_ACCESS_TOKEN is not the token from the token file")
	}
	if got := envValue(c.Env, "HOME"); got != f.home {
		t.Errorf("HOME = %q, want %q", got, f.home)
	}
	if c.Dir != f.home {
		t.Errorf("working directory = %q, want %q", c.Dir, f.home)
	}
	if c.Stdin != os.DevNull {
		t.Errorf("stdin = %q, want %q", c.Stdin, os.DevNull)
	}
	if !c.Leader {
		t.Error("bws does not lead its own process group")
	}
}

func TestBWSErrorExit(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	for _, code := range []int{1, 2, 77} {
		sc := bwsScenario(madeUp("token"), value)
		sc.Steps = map[string]fakeStep{"secret get": {
			Stdout: bwsSecretJSON(testItemID, value), Stderr: "Error: " + value, Exit: code,
		}}
		f := newTestFake(t, config.StoreBWS, sc, testDeps())
		v, err := f.store.Fetch(t.Context(), testItemID)
		checkErr(t, err, ErrFailed)
		if v.Bytes() != nil {
			t.Error("Fetch returned a value with its error")
		}
		want := `store "main": bws secret get: the program failed (exit code ` + strconv.Itoa(code) + ")"
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q", err, want)
		}
		noCanary(t, "the error", err.Error(), value)
	}
}

func TestBWSWrongToken(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	sc := bwsScenario(madeUp("token"), value)
	f := newTestFake(t, config.StoreBWS, sc, testDeps())
	sc.Token = madeUp("other-token") // bws now refuses the token in the file
	f.setScenario(sc)
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrFailed)
}

func TestBWSUnknownItem(t *testing.T) {
	t.Parallel()
	f := newTestFake(t, config.StoreBWS, bwsScenario(madeUp("token"), madeUp("value")), testDeps())
	_, err := f.store.Fetch(t.Context(), "00000000-0000-4000-8000-0000000000ff")
	checkErr(t, err, ErrFailed)
}

func TestBWSTimeoutKillsTheProcessGroup(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	sc := bwsScenario(madeUp("token"), value)
	sc.Steps = map[string]fakeStep{"secret get": {Hang: true, Stdout: bwsSecretJSON(testItemID, value)}}
	d := testDeps()
	d.timeout = 5 * time.Second
	f := newTestFake(t, config.StoreBWS, sc, d)
	start := time.Now()
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrTimeout)
	if err != nil && !strings.Contains(err.Error(), "(after 5s)") {
		t.Errorf("error = %v, want the time limit in it", err)
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("Fetch took %v", took)
	}
	// The fake and the child it started are both gone.
	waitGone(t, f.pids())
}

func TestCancelKillsTheProcessGroup(t *testing.T) {
	t.Parallel()
	sc := bwsScenario(madeUp("token"), madeUp("value"))
	sc.Steps = map[string]fakeStep{"secret get": {Hang: true}}
	f := newTestFake(t, config.StoreBWS, sc, testDeps())
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := f.store.Fetch(ctx, testItemID)
		done <- err
	}()
	// Wait until the fake has started its child.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(f.home, fakePIDsFile)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	err := <-done
	checkErr(t, err, context.Canceled)
	waitGone(t, f.pids())
}

func TestBWSTooMuchOutput(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			t.Parallel()
			sc := bwsScenario(madeUp("token"), value)
			sc.Steps = map[string]fakeStep{"secret get": {Flood: stream, Stdout: bwsSecretJSON(testItemID, value)}}
			f := newTestFake(t, config.StoreBWS, sc, testDeps())
			start := time.Now()
			v, err := f.store.Fetch(t.Context(), testItemID)
			checkErr(t, err, ErrTooMuchOutput)
			if v.Bytes() != nil {
				t.Error("Fetch returned a value with its error")
			}
			// The cap stops the program, long before the time limit.
			if took := time.Since(start); took > 10*time.Second {
				t.Errorf("Fetch took %v", took)
			}
			if err != nil {
				noCanary(t, "the error", err.Error(), value)
			}
		})
	}
}

func TestBWSLeftRunning(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	sc := bwsScenario(madeUp("token"), value)
	// bws prints a good answer and exits with 0, but leaves a child that
	// holds its stdout open.
	sc.Steps = map[string]fakeStep{"secret get": {Leave: true, Stdout: bwsSecretJSON(testItemID, value)}}
	d := testDeps()
	d.waitDelay = 300 * time.Millisecond
	f := newTestFake(t, config.StoreBWS, sc, d)
	v, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrLeftRunning)
	if v.Bytes() != nil {
		t.Error("Fetch returned a value with its error")
	}
	waitGone(t, f.pids())
}

func TestBWSMissingValue(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		stdout string
		want   error
	}{
		"empty value":  {bwsSecretJSON(testItemID, ""), ErrNoValue},
		"null value":   {`{"id":"` + testItemID + `","value":null}`, ErrNoValue},
		"no value":     {`{"id":"` + testItemID + `","key":"GITHUB_TOKEN","note":""}`, ErrNoValue},
		"empty object": {"{}\n", ErrBadAnswer}, // no id
		// bws with a token of no organization logs an error and exits
		// with 0, with nothing on stdout.
		"no output": {"", ErrBadAnswer},
		// encoding/json would match these keys to "value".
		"Value":        {`{"id":"` + testItemID + `","Value":"x"}`, ErrNoValue},
		"VALUE":        {`{"id":"` + testItemID + `","VALUE":"x"}`, ErrNoValue},
		"value number": {`{"value":7}`, ErrBadAnswer},
		"value object": {`{"value":{"x":"y"}}`, ErrBadAnswer},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwsScenario(madeUp("token"), "")
			sc.Steps = map[string]fakeStep{"secret get": {Stdout: tc.stdout}}
			f := newTestFake(t, config.StoreBWS, sc, testDeps())
			v, err := f.store.Fetch(t.Context(), testItemID)
			checkErr(t, err, tc.want)
			if v.Bytes() != nil {
				t.Error("Fetch returned a value with its error")
			}
		})
	}
}

func TestBWSBadJSON(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	good := bwsSecretJSON(testItemID, value)
	tests := map[string]string{
		"two answers":    good + good,
		"text after":     good + "done\n",
		"cut short":      good[:len(good)/2],
		"an array":       "[" + good + "]",
		"a string":       `"` + value + `"`,
		"two values":     `{"value":"` + value + `","value":"` + value + `"}`,
		"color":          "\x1b[38;5;231m" + good,
		"bad escape":     `{"value":"` + value + `\x"}`,
		"lone surrogate": `{"value":"` + value + esc("d800") + `"}`,
		"invalid UTF-8":  `{"value":"` + value + "\xff\"}",
		"control":        "{\"value\":\"" + value + "\x01\"}",
		"single quotes":  `{'value':'` + value + `'}`,
		"trailing comma": `{"value":"` + value + `",}`,
	}
	for name, stdout := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwsScenario(madeUp("token"), value)
			sc.Steps = map[string]fakeStep{"secret get": {Stdout: stdout}}
			f := newTestFake(t, config.StoreBWS, sc, testDeps())
			v, err := f.store.Fetch(t.Context(), testItemID)
			checkErr(t, err, ErrBadAnswer)
			if v.Bytes() != nil {
				t.Error("Fetch returned a value with its error")
			}
			if err != nil {
				noCanary(t, "the error", err.Error(), value)
			}
		})
	}
}

func TestFetchRefusesBadIDs(t *testing.T) {
	t.Parallel()
	for _, typ := range []config.StoreType{config.StoreBWS, config.StoreBW} {
		f := newTestFake(t, typ, fakeScenario{Token: madeUp("token"), Password: madeUp("password")}, testDeps())
		for _, id := range []string{
			"", "-h", "--help", "--session", "github-token", testItemID + " ", " " + testItemID,
			testItemID[:35], testItemID + "0", strings.ReplaceAll(testItemID, "-", "_"),
			"6f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0g", "-f1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0b",
		} {
			_, err := f.store.Fetch(t.Context(), id)
			checkErr(t, err, ErrBadID)
		}
		if calls := f.calls(); len(calls) != 0 {
			t.Errorf("%s ran %d times, want 0", typ, len(calls))
		}
	}
}

func TestBWSConcurrentFetches(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	sc := bwsScenario(madeUp("token"), value)
	sc.Pause = 100 * time.Millisecond
	f := newTestFake(t, config.StoreBWS, sc, testDeps())
	const n = 12
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
	calls := f.calls()
	if len(calls) != n {
		t.Errorf("bws ran %d times, want %d", len(calls), n)
	}
	for _, c := range calls {
		if c.Running > bwsParallel {
			t.Errorf("%d runs of bws at once, want at most %d", c.Running, bwsParallel)
		}
	}
}

func TestBWSTokenFile(t *testing.T) {
	t.Parallel()
	token := madeUp("token")
	for name, content := range map[string]string{
		"newline":     token + "\n",
		"CRLF":        token + "\r\n",
		"spaces":      "  " + token + " \n",
		"no newline":  token,
		"blank lines": "\n" + token + "\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwsScenario(token, madeUp("value"))
			f := setupFake(t, config.StoreBWS, sc)
			writeFile(t, f.cfg.TokenFile, content)
			s, err := newStore(f.cfg, f.dir, testDeps())
			if err != nil {
				t.Fatalf("newStore: %v", err)
			}
			defer s.Close()
			if _, err := s.Fetch(t.Context(), testItemID); err != nil {
				t.Errorf("Fetch: %v", err)
			}
		})
	}
	for name, content := range map[string]string{
		"empty":         "",
		"only a space":  " \n",
		"two lines":     token + "\n" + token + "\n",
		"a space in it": token + " " + token,
		"a control":     token + "\x00",
		"not ASCII":     token + "é",
		"too long":      strings.Repeat("t", maxTokenLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := setupFake(t, config.StoreBWS, bwsScenario(token, madeUp("value")))
			writeFile(t, f.cfg.TokenFile, content)
			_, err := newStore(f.cfg, f.dir, testDeps())
			if err == nil {
				t.Fatal("newStore took a bad token file")
			}
			if !strings.Contains(err.Error(), "it holds no access token") {
				t.Errorf("error = %v", err)
			}
			noCanary(t, "the error", err.Error(), token)
		})
	}
	// A token file that cannot be read.
	f := setupFake(t, config.StoreBWS, bwsScenario(token, madeUp("value")))
	f.cfg.TokenFile = filepath.Join(t.TempDir(), "missing")
	if _, err := newStore(f.cfg, f.dir, testDeps()); err == nil || !strings.Contains(err.Error(), "token_file") {
		t.Errorf("newStore with a missing token file: %v", err)
	}
}

func TestBWSClose(t *testing.T) {
	t.Parallel()
	f := newTestFake(t, config.StoreBWS, bwsScenario(madeUp("token"), madeUp("value")), testDeps())
	s := f.store.(*bwsStore)
	token := s.token
	f.store.Close()
	if token.Bytes() != nil {
		t.Error("Close left the token")
	}
	_, err := f.store.Fetch(t.Context(), testItemID)
	checkErr(t, err, ErrClosed)
	checkErr(t, f.store.Start(t.Context()), ErrClosed)
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("bws ran %d times after Close, want 0", len(calls))
	}
	f.store.Close() // a second Close does nothing
}

func TestBWSFetchWaitsForAPlace(t *testing.T) {
	t.Parallel()
	sc := bwsScenario(madeUp("token"), madeUp("value"))
	f := newTestFake(t, config.StoreBWS, sc, testDeps())
	s := f.store.(*bwsStore)
	for range bwsParallel {
		s.slots <- struct{}{} // every place is taken
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := s.Fetch(ctx, testItemID)
	checkErr(t, err, context.DeadlineExceeded)
	for range bwsParallel {
		<-s.slots
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Errorf("bws ran %d times, want 0", len(calls))
	}
}
