package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// canaries are the made-up secrets of one canary test: they must never
// appear in an error, a log line, a printed store or value, or a program's
// arguments.
type canaries struct {
	token, password, session, value, other string
}

func newCanaries() canaries {
	return canaries{
		token:    madeUp("token"),
		password: madeUp("password"),
		session:  madeUp("session"),
		value:    madeUp("value"),
		other:    madeUp("other"),
	}
}

func (c canaries) all() []string {
	return []string{c.token, c.password, c.session, c.value, c.other}
}

// check fails the test if text holds any canary.
func (c canaries) check(t *testing.T, where, text string) {
	t.Helper()
	for _, s := range c.all() {
		noCanary(t, where, text, s)
	}
}

// checkCalls checks what the fake programs got: no canary in an
// argument; the token only in BWS_ACCESS_TOKEN and the session key only in
// BW_SESSION; the password, the value and the other secrets in no
// variable.
func (c canaries) checkCalls(t *testing.T, f *testFake) {
	t.Helper()
	calls := f.calls()
	if len(calls) == 0 {
		t.Fatal("no program ran")
	}
	for _, call := range calls {
		for _, arg := range call.Args {
			c.check(t, "an argument", arg)
		}
		for _, kv := range call.Env {
			name, val, _ := strings.Cut(kv, "=")
			noCanary(t, "the name of a variable", name, c.token)
			for _, s := range []string{c.password, c.value, c.other} {
				noCanary(t, "variable "+name, val, s)
			}
			if name != "BWS_ACCESS_TOKEN" {
				noCanary(t, "variable "+name, val, c.token)
			}
			if name != "BW_SESSION" {
				noCanary(t, "variable "+name, val, c.session)
			}
		}
	}
}

// TestCanaries runs both stores through success and many failures with
// made-up secrets: the bws token, the bw master password and session key,
// the value, and other secrets in the same item. In every case, no error,
// log line, printed value or printed store holds any of them, and the
// programs get them only where they must.
func TestCanaries(t *testing.T) {
	t.Parallel()
	type result struct {
		where string
		value Value
		err   error
	}
	type check struct {
		name  string
		typ   config.StoreType
		setup func(c canaries, sc *fakeScenario, f *testFake)
		want  error // nil: Fetch must work
	}
	bwsAnswer := func(c canaries) string {
		out, _ := json.MarshalIndent(map[string]any{"id": testItemID, "key": c.other, "value": c.value, "note": c.other}, "", "  ")
		return string(out) + "\n"
	}
	checks := []check{
		{name: "bws works", typ: config.StoreBWS},
		{"bws exits with 1", config.StoreBWS, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{"secret get": {Stdout: bwsAnswer(c), Stderr: "Error: " + c.token + c.value, Exit: 1}}
		}, ErrFailed},
		{"bws answers twice", config.StoreBWS, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{"secret get": {Stdout: bwsAnswer(c) + bwsAnswer(c)}}
		}, ErrBadAnswer},
		{"bws repeats value", config.StoreBWS, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{"secret get": {Stdout: `{"value":"` + c.value + `","value":"` + c.other + `"}`}}
		}, ErrBadAnswer},
		{"bws floods", config.StoreBWS, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{"secret get": {Stdout: bwsAnswer(c), Flood: "stdout"}}
		}, ErrTooMuchOutput},
		{"bws hangs", config.StoreBWS, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{"secret get": {Stdout: bwsAnswer(c), Hang: true}}
		}, ErrTimeout},
		{name: "bw works", typ: config.StoreBW},
		{"bw get item exits with 1", config.StoreBW, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{"get item": {
				Stdout: bwItemJSON(testItemID, c.value, nil, c.other), Stderr: c.session + c.password, Exit: 1,
			}}
		}, ErrFailed},
		{"bw item in the trash", config.StoreBW, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Items[testItemID] = bwItemJSON(testItemID, c.value, "2026-10-13T12:00:00.000Z", c.other)
		}, ErrTrashed},
		{"bw unlock talks", config.StoreBW, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{"unlock": {Stdout: "Your vault is now unlocked!\n$ export BW_SESSION=\"" + c.session + "\"\n"}}
		}, ErrBadAnswer},
		{"bw is locked", config.StoreBW, func(c canaries, _ *fakeScenario, f *testFake) {
			if err := f.store.Start(t.Context()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			f.setBWState(fakeBWState{Session: c.other})
		}, ErrLocked},
		{"bw is logged out", config.StoreBW, func(_ canaries, _ *fakeScenario, f *testFake) {
			f.setBWState(fakeBWState{LoggedOut: true})
		}, ErrLoggedOut},
		{"bw status floods", config.StoreBW, func(c canaries, sc *fakeScenario, _ *testFake) {
			sc.Steps = map[string]fakeStep{
				"sync":   {Stderr: c.session, Exit: 1},
				"status": {Stdout: c.session + c.password, Flood: "stdout"},
			}
		}, ErrFailed},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newCanaries()
			sc := bwsScenario(c.token, c.value)
			sc.Items[testItemID] = bwsAnswer(c)
			if tc.typ == config.StoreBW {
				sc = bwScenario(c.password, c.session, c.value, c.other)
			}
			d := testDeps()
			d.timeout = 5 * time.Second
			f := newTestFake(t, tc.typ, sc, d)
			if tc.setup != nil {
				tc.setup(c, &sc, f)
				f.setScenario(sc)
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			jsonLogger := slog.New(slog.NewJSONHandler(&logs, nil))
			startErr := f.store.Start(t.Context())
			v, err := f.store.Fetch(t.Context(), testItemID)
			results := []result{{"Start", Value{}, startErr}, {"Fetch", v, err}}
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Fetch: %v", err)
				}
				checkValue(t, v, c.value)
			} else {
				checkErr(t, err, tc.want)
			}
			for _, r := range results {
				logger.Error(r.where, "err", r.err, "value", r.value)
				jsonLogger.Error(r.where, "err", r.err, "value", r.value)
				logger.Info(r.where, slog.Any("value", r.value), slog.Any("store", f.store))
				var texts []string
				if r.err != nil {
					texts = append(texts, r.err.Error(), fmt.Sprintf("%v %+v %#v", r.err, r.err, r.err))
				}
				texts = append(texts, fmt.Sprintf("%v %+v %#v %s %x", r.value, r.value, r.value, r.value, r.value))
				for _, text := range texts {
					c.check(t, r.where, text)
				}
			}
			c.check(t, "the logs", logs.String())
			c.check(t, "the printed store", fmt.Sprintf("%v %+v %#v %s", f.store, f.store, f.store, f.store))
			c.checkCalls(t, f)
			v.Clear()
		})
	}
}
