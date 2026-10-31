package main

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
)

// tryFiles are the files of nodkey try. Only they may use its parts.
var tryFiles = map[string]bool{"try.go": true, "tryapprover.go": true, "trystore.go": true}

// tryOnly are the names of the parts of nodkey try: the terminal
// approver, the test store, the config without a file, and the trial.
var tryOnly = map[string]bool{
	"tryApprover": true, "newTryApprover": true, "tryStore": true, "newTryStore": true, "tryConfig": true,
	"trial": true, "serveTry": true, "runTryRun": true, "tryUserID": true,
}

// nodkey broker has no way to turn on the approval in the terminal, or
// the test store: no file outside of nodkey try uses their names, main.go
// reaches nodkey try only by its command, and the one approval core of
// nodkey broker takes the Telegram approver.
func TestBrokerHasNoTerminalApproval(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	cores := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || tryFiles[path] {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if tryOnly[n.Name] || (n.Name == "runTry" && path != "main.go") {
					t.Errorf("%s uses %s, a part of nodkey try", path, n.Name)
				}
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, isIdent := sel.X.(*ast.Ident); isIdent && pkg.Name == "approval" && sel.Sel.Name == "New" {
					cores++
					if arg, ok := n.Args[1].(*ast.Ident); path != "broker.go" || !ok || arg.Name != "tg" {
						t.Errorf("%s makes an approval core with another approver than Telegram", path)
					}
				}
			}
			return true
		})
	}
	if cores != 1 {
		t.Errorf("%d approval cores outside of nodkey try, want 1: the one of nodkey broker", cores)
	}
	var stderr bytes.Buffer
	if code := run([]string{"broker", "--terminal"}, strings.NewReader(""), io.Discard, &stderr); code != exitUsage {
		t.Errorf("nodkey broker --terminal: exit code %d, want 64", code)
	}
}

// The trial's config has only the trial store, with no type, so no real
// store can serve it, and nodkey broker cannot make it from a file.
func TestTryConfigHasOnlyTheTrialStore(t *testing.T) {
	cfg := tryConfig("/nonexistent", config.Pin{})
	if len(cfg.Stores) != 1 || cfg.Stores[tryStoreName].Type != "" {
		t.Fatalf("stores %v, want only %q with no type", cfg.Stores, tryStoreName)
	}
	if _, err := store.New(cfg.Stores[tryStoreName], t.TempDir()); err == nil {
		t.Fatal("store.New made a store for the trial store")
	}
	if len(cfg.Keys) != 0 || cfg.KnownHosts != nil || cfg.Telegram.TokenFile != "" || cfg.Updates.Check {
		t.Fatal("the trial's config has keys, known hosts, a bot token or the release check")
	}
	if len(cfg.Secrets) != len(trySecretNames) {
		t.Fatalf("%d secrets, want %d", len(cfg.Secrets), len(trySecretNames))
	}
	for name, s := range cfg.Secrets {
		if s.Store != tryStoreName || s.ID != name || s.Rule.Ask != config.AskWindow {
			t.Errorf("secret %q: store %q, ID %q, ask %q", name, s.Store, s.ID, s.Rule.Ask)
		}
	}
	if !strings.HasPrefix(cfg.AuditLog, "/nonexistent/") || !strings.HasPrefix(cfg.TLSKey, "/nonexistent/") {
		t.Fatal("a file of the trial's config is outside of its directory")
	}
}

func TestTryStore(t *testing.T) {
	s := newTryStore()
	seen := map[string]bool{}
	for _, name := range trySecretNames {
		v, err := s.Fetch(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		got := string(v.Bytes())
		if !strings.HasPrefix(got, tryValuePrefix) || len(got) < len(tryValuePrefix)+16 || seen[got] {
			t.Fatalf("%s: not a new random TRY- value", name)
		}
		seen[got] = true
		v.Clear()
	}
	if _, err := s.Fetch(t.Context(), "real-token"); !errors.Is(err, errTryUnknown) {
		t.Fatalf("unknown item: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Fetch(ctx, trySecretNames[0]); err == nil {
		t.Fatal("Fetch with a cancelled context worked")
	}
	s.Close()
	if _, err := s.Fetch(t.Context(), trySecretNames[0]); !errors.Is(err, store.ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
}

func TestTryLines(t *testing.T) {
	var b bytes.Buffer
	w := &tryLines{w: &b, start: true}
	for _, s := range []string{"nodkey: one", "\nnodkey: two\n", "three\n"} {
		if _, err := io.WriteString(w, s); err != nil {
			t.Fatal(err)
		}
	}
	if want := "TRY MODE nodkey: one\nTRY MODE nodkey: two\nTRY MODE three\n"; b.String() != want {
		t.Fatalf("got %q, want %q", b.String(), want)
	}
}

func TestTryClean(t *testing.T) {
	if got := tryClean("a\x1b[2Jb\nc\u202ed\u00e9"); got != "a?[2Jb?c?d\u00e9" {
		t.Fatalf("got %q", got)
	}
}

// With more than one request waiting, an answer without a short code
// counts for none of them; an answer that did not count says so.
func TestTryApproverAnswers(t *testing.T) {
	var out bytes.Buffer
	a := newTryApprover(strings.NewReader(""), &out)
	p1 := approval.Prompt{RequestID: "id-1", ShortCode: "aaaa", Once: true, WindowMinutes: 5}
	p2 := approval.Prompt{RequestID: "id-2", ShortCode: "bbbb", Once: true}
	for _, p := range []approval.Prompt{p1, p2} {
		if _, err := a.Ask(t.Context(), p); err != nil {
			t.Fatal(err)
		}
	}
	var got []approval.Answer
	answer := func(an approval.Answer) error {
		got = append(got, an)
		if an.RequestID == "id-2" {
			return approval.ErrNotAllowed
		}
		return nil
	}
	a.answerLine("1", answer)
	a.answerLine("cccc 1", answer)
	a.answerLine("aaaa x", answer)
	if len(got) != 0 {
		t.Fatalf("answers counted: %v", got)
	}
	a.answerLine("bbbb 2", answer)
	a.answerLine("aaaa 2", answer)
	if len(got) != 2 || got[1] != (approval.Answer{RequestID: "id-1", Action: audit.AnswerApproveWindow,
		Message: "try-id-1", UserID: tryUserID}) {
		t.Fatalf("answers %v", got)
	}
	for _, want := range []string{"TRY MODE: request aaaa", "no such request", "type 1 (Approve once)",
		"does not offer that answer"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output does not hold %q:\n%s", want, out.String())
		}
	}
	// The input ended: no answer can come, so Run stops.
	if err := a.Run(t.Context(), answer); !errors.Is(err, errTryInputClosed) {
		t.Fatalf("Run: %v", err)
	}
}

// An answer that comes before the broker knows the message is tried
// again; when it stays too early, the terminal says to type it again.
func TestTryApproverTooEarly(t *testing.T) {
	var out bytes.Buffer
	a := newTryApprover(strings.NewReader(""), &out)
	if _, err := a.Ask(t.Context(), approval.Prompt{RequestID: "id-1", ShortCode: "aaaa", Once: true}); err != nil {
		t.Fatal(err)
	}
	calls, early := 0, 2
	answer := func(approval.Answer) error {
		calls++
		if calls <= early {
			return approval.ErrTooEarly
		}
		return nil
	}
	a.answerLine("1", answer)
	if calls != 3 || strings.Contains(out.String(), "not ready yet") {
		t.Fatalf("calls %d, want 3; output:\n%s", calls, out.String())
	}
	calls, early = 0, tryEarlyRetries+1
	a.answerLine("1", answer)
	if calls != tryEarlyRetries+1 || !strings.Contains(out.String(), "not ready yet") {
		t.Fatalf("calls %d, want %d; output:\n%s", calls, tryEarlyRetries+1, out.String())
	}
}

// The trial allows no scheduled and no standing grant.
func TestTryConfigAllowsNoScheduledOrStandingGrants(t *testing.T) {
	cfg := tryConfig("/nonexistent", config.Pin{})
	if cfg.Preapprove != (config.PreapproveLimits{}) {
		t.Errorf("preapprove limits %+v, want none", cfg.Preapprove)
	}
	if cfg.Standing != (config.StandingLimits{}) {
		t.Errorf("standing limits %+v, want none", cfg.Standing)
	}
	for name, s := range cfg.Secrets {
		if s.Rule.Preapprove {
			t.Errorf("secret %q allows preapprove", name)
		}
	}
}

// Write is safe to call from several goroutines.
func TestTryLinesConcurrent(t *testing.T) {
	var b bytes.Buffer
	w := &tryLines{w: &b, start: true}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_, _ = io.WriteString(w, "line\n")
			}
		}()
	}
	wg.Wait()
	if want := strings.Repeat("TRY MODE line\n", 400); b.String() != want {
		t.Fatal("lines are mixed")
	}
}
