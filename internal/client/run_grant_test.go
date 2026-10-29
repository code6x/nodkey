package client

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
)

// grantRunBroker answers a secrets request with one value and the token
// newTok ("" for none), and keeps the token header of each request.
type grantRunBroker struct {
	*fakeBroker
	mu      sync.Mutex
	headers []string
}

func newGrantRunBroker(t *testing.T, newTok string) *grantRunBroker {
	t.Helper()
	gb := &grantRunBroker{}
	gb.fakeBroker = newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		gb.mu.Lock()
		gb.headers = append(gb.headers, r.Header.Get(api.GrantTokenHeader))
		gb.mu.Unlock()
		a := api.SecretsAnswer{Secrets: []api.SecretValue{{Var: "GH_TOKEN", Value: []byte("made-up-value")}}, GrantToken: newTok}
		body, err := a.Encode()
		if err != nil {
			t.Error(err)
			return
		}
		answer(http.StatusOK, string(body))(w, r)
	})
	return gb
}

func (gb *grantRunBroker) seen() []string {
	gb.mu.Lock()
	defer gb.mu.Unlock()
	return append([]string(nil), gb.headers...)
}

func writeToken(t *testing.T, dir, tok string) string {
	t.Helper()
	f := filepath.Join(dir, "grant")
	if err := os.WriteFile(f, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func runGrant(t *testing.T, gb *grantRunBroker, fx *fakeExec, args ...string) (int, string) {
	t.Helper()
	var b *Broker
	if gb != nil {
		b = gb.b
	}
	return runIn(t.Context(), testRunner(b, nil, fx),
		append(append([]string{"--secret", "GH_TOKEN=github-token"}, args...), "--", self(t))...)
}

// TestRunGrantToken: the header carries the token, and the new token is in
// the file before the command starts.
func TestRunGrantToken(t *testing.T) {
	t.Parallel()
	oldTok, newTok := newToken(t).Reveal(), newToken(t).Reveal()
	f := writeToken(t, t.TempDir(), oldTok)
	gb := newGrantRunBroker(t, newTok)
	fx := &fakeExec{}
	var inFile string
	r := testRunner(gb.b, nil, fx)
	r.exec = func(path string, argv, envv []string) error {
		data, _ := os.ReadFile(f) //nolint:gosec // G304: the test's own file.
		inFile = string(data)
		return fx.exec(path, argv, envv)
	}
	code, stderr := runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--grant-token", f, "--", self(t))
	if code != exitOK {
		t.Fatalf("exit %d; stderr %q", code, safe(stderr))
	}
	if h := gb.seen(); len(h) != 1 || h[0] != oldTok {
		t.Errorf("the request had %d token headers, or a wrong one", len(h))
	}
	if inFile != newTok+"\n" {
		t.Error("the file did not hold the new token when the command started")
	}
	mustNotLeak(t, oldTok, stderr)
	mustNotLeak(t, newTok, stderr)
	if len(fx.ran()) != 1 {
		t.Error("the command did not start")
	}
}

// TestRunGrantTokenDeny: every failure runs no command.
func TestRunGrantTokenDeny(t *testing.T) {
	t.Parallel()
	oldTok := newToken(t).Reveal()
	for _, tt := range []struct {
		name  string
		newTk func() string
		setup func(t *testing.T, dir, f string)
		want  int
	}{
		{"no new token", func() string { return "" }, nil, exitUnavailable},
		{"bad new token", func() string { return "nkg_" + strings.Repeat("a", 10) }, nil, exitUnavailable},
		{"save fails", func() string { return newToken(t).Reveal() }, func(t *testing.T, dir, f string) {
			// The directory cannot take a new file; reading still works.
			if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: a directory that cannot take a new file.
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: a directory.
		}, exitDenied},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			f := writeToken(t, dir, oldTok)
			if tt.setup != nil {
				tt.setup(t, dir, f)
			}
			nt := tt.newTk()
			gb := newGrantRunBroker(t, nt)
			fx := &fakeExec{}
			code, stderr := runGrant(t, gb, fx, "--grant-token", f)
			if code != tt.want {
				t.Errorf("exit %d, want %d; stderr %q", code, tt.want, safe(stderr))
			}
			if len(fx.ran()) != 0 {
				t.Error("the command started")
			}
			if n := len(gb.seen()); n != 1 {
				t.Errorf("%d requests, want 1 (no retry)", n)
			}
			mustNotLeak(t, oldTok, stderr)
			if nt != "" {
				mustNotLeak(t, nt, stderr)
			}
			if data, _ := os.ReadFile(f); string(data) != oldTok+"\n" { //nolint:gosec // G304: the test's own file.
				t.Error("the token file changed")
			}
		})
	}
}

// TestRunGrantTokenBadFile: a bad file makes no request.
func TestRunGrantTokenBadFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	open := filepath.Join(dir, "open")
	if err := os.WriteFile(open, []byte(newToken(t).Reveal()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o640); err != nil { //nolint:gosec // G302: the test needs a file that the group can read.
		t.Fatal(err)
	}
	junk := writeToken(t, dir, "not a token")
	if err := os.Rename(junk, filepath.Join(dir, "junk")); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]string{"missing": filepath.Join(dir, "none"), "mode 0640": open,
		"not a token": filepath.Join(dir, "junk"), "a directory": dir} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gb := newGrantRunBroker(t, newToken(t).Reveal())
			fx := &fakeExec{}
			code, stderr := runGrant(t, gb, fx, "--grant-token", f)
			if code == exitOK || len(fx.ran()) != 0 || len(gb.seen()) != 0 {
				t.Errorf("exit %d, %d requests, %d commands; stderr %q", code, len(gb.seen()), len(fx.ran()), safe(stderr))
			}
		})
	}
}

// TestRunTokenWithoutFlag: an answer with a token, for a request without
// one, is refused.
func TestRunTokenWithoutFlag(t *testing.T) {
	t.Parallel()
	gb := newGrantRunBroker(t, newToken(t).Reveal())
	fx := &fakeExec{}
	code, stderr := runGrant(t, gb, fx)
	if code != exitUnavailable || len(fx.ran()) != 0 {
		t.Errorf("exit %d, %d commands; stderr %q", code, len(fx.ran()), safe(stderr))
	}
	if h := gb.seen(); len(h) != 1 || h[0] != "" {
		t.Error("the request had a token header, or was sent again")
	}
}

// TestRunGrantTokenCancel: a SIGINT while the broker works on a request with
// a token. The broker may have rotated the token already, but the client
// has no answer, so it keeps its token file as it is, starts no command,
// and never sends the request again (the broker gives the use back when the
// client hangs up).
func TestRunGrantTokenCancel(t *testing.T) {
	t.Parallel()
	oldTok := newToken(t).Reveal()
	f := writeToken(t, t.TempDir(), oldTok)
	entered := make(chan struct{}, 1)
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done() // the broker works until the client hangs up
	})
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	fx := &fakeExec{}
	done := make(chan int, 1)
	var stderr string
	go func() {
		var code int
		code, stderr = runIn(ctx, testRunner(fb.b, nil, fx),
			"--secret", "GH_TOKEN=github-token", "--grant-token", f, "--", self(t))
		done <- code
	}()
	select {
	case <-entered:
	case <-time.After(waitLimit):
		t.Fatal("the broker got no request")
	}
	cancel(interrupted{sig: syscall.SIGINT})
	if code := <-done; code != 130 || lastLine(stderr) != "nodkey: cancelled by SIGINT (exit 130)" {
		t.Errorf("exit code %d, stderr %q", code, safe(stderr))
	}
	if len(fx.ran()) != 0 {
		t.Error("the command started")
	}
	if n := fb.requests.Load(); n != 1 {
		t.Errorf("%d requests, want 1 (no retry)", n)
	}
	if data, _ := os.ReadFile(f); string(data) != oldTok+"\n" { //nolint:gosec // G304: the test's own file.
		t.Error("the token file changed")
	}
	mustNotLeak(t, oldTok, stderr)
}

// TestRunGrantTokenSymlink: a symbolic link is not read, even when the file
// it points to is a good token file. Nothing is sent and no command runs.
func TestRunGrantTokenSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := writeToken(t, dir, newToken(t).Reveal())
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	gb := newGrantRunBroker(t, newToken(t).Reveal())
	fx := &fakeExec{}
	code, stderr := runGrant(t, gb, fx, "--grant-token", link)
	if code == exitOK || len(fx.ran()) != 0 || len(gb.seen()) != 0 {
		t.Errorf("exit %d, %d requests, %d commands; stderr %q", code, len(gb.seen()), len(fx.ran()), safe(stderr))
	}
	if _, err := readGrantToken(link); err == nil {
		t.Error("readGrantToken read through a link")
	}
	// The open itself refuses a link, with no check before it.
	if f, err := os.OpenFile(link, os.O_RDONLY|noFollow, 0); err == nil { //nolint:gosec,forbidigo // G304: the test's own link.
		_ = f.Close()
		t.Error("the open followed a link")
	}
}
