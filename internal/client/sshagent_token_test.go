package client

// Tests of nodkey ssh-agent --grant-token: each signature sends the token
// of the standing grant and saves the new one before ssh gets the
// signature (DESIGN.md section 8, "An SSH key").

import (
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/grantkey"
	"github.com/code6x/nodkey/internal/transport"
)

// tokenBroker is a fake broker that signs with signer when the request
// has the current token, and answers with a new one. answer, if set,
// replaces the token of the answer.
type tokenBroker struct {
	*fakeBroker
	mu      sync.Mutex
	current grantkey.Token
	seen    []string // the tokens that came, in order
	busy    bool
	overlap bool // two requests with a token ran at the same time
}

func newTokenBroker(t *testing.T, signer ssh.AlgorithmSigner, first grantkey.Token, answer func(grantkey.Token) string) *tokenBroker {
	t.Helper()
	tb := &tokenBroker{current: first}
	tb.fakeBroker = newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == api.PathKeys {
			_, _ = transport.ReadJSON[api.KeysRequest](w, r)
			_ = transport.WriteJSON(w, http.StatusOK, api.KeysAnswer{Keys: []api.Key{{Name: "deploy", PublicKey: signer.PublicKey().Marshal()}}})
			return
		}
		req, err := transport.ReadJSON[api.SignRequest](w, r)
		if err != nil {
			return
		}
		got := r.Header.Values(api.GrantTokenHeader)
		tb.mu.Lock()
		if tb.busy {
			tb.overlap = true
		}
		tb.busy = true
		tb.seen = append(tb.seen, strings.Join(got, ","))
		ok := len(got) == 1 && got[0] == tb.current.Reveal()
		next, _ := grantkey.New()
		if ok {
			tb.current = next
		}
		tb.mu.Unlock()
		defer func() { tb.mu.Lock(); tb.busy = false; tb.mu.Unlock() }()
		if !ok {
			transport.WriteError(w, http.StatusForbidden)
			return
		}
		sig, err := signer.SignWithAlgorithm(rand.Reader, req.Data, "")
		if err != nil {
			transport.WriteError(w, http.StatusInternalServerError)
			return
		}
		raw := next.Reveal()
		if answer != nil {
			raw = answer(next)
		}
		_ = transport.WriteJSON(w, http.StatusOK, api.SignAnswer{Format: sig.Format, Blob: sig.Blob, GrantToken: api.HiddenToken(raw)})
	})
	return tb
}

func tokenFileWith(t *testing.T, tok grantkey.Token) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "token")
	if err := SaveGrantToken(file, tok); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestAgentGrantTokenRotates: logins one after the other and at the same
// time each send the current token once, and the file ends with the last
// token. No line holds a token.
func TestAgentGrantTokenRotates(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	first := newToken(t)
	file := tokenFileWith(t, first)
	tb := newTokenBroker(t, deploy, first, nil)
	au := startAgent(t, tb.b, agentOptions{tokenFile: file})
	for range 2 {
		data := []byte("data " + rand.Text())
		if sig := signOnce(t, au, deploy.PublicKey(), data, 0); sig == nil || deploy.PublicKey().Verify(data, sig) != nil {
			t.Fatalf("no valid signature; lines %q", au.lines())
		}
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if sig := signOnce(t, au, deploy.PublicKey(), []byte("data "+rand.Text()), 0); sig == nil {
				t.Errorf("no signature; lines %q", au.lines())
			}
		})
	}
	wg.Wait()
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.overlap || len(tb.seen) != 6 {
		t.Fatalf("overlap %v, %d requests, want 6 one after the other", tb.overlap, len(tb.seen))
	}
	if tb.seen[0] != first.Reveal() {
		t.Error("the first request did not send the token of the file")
	}
	got, err := readGrantToken(file)
	if err != nil || got != tb.current {
		t.Errorf("the file does not hold the last token: %v", err)
	}
	for _, s := range append(tb.seen, tb.current.Reveal()) {
		if strings.Contains(au.log.String(), s) {
			t.Error("a line holds a token")
		}
	}
}

// TestAgentGrantTokenBadAnswer: an answer without a valid new token gives
// ssh no signature, and the file keeps its token.
func TestAgentGrantTokenBadAnswer(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		answer func(grantkey.Token) string
		want   string
	}{
		{"no token", func(grantkey.Token) string { return "" }, "it has no new token"},
		{"not a token", func(grantkey.Token) string { return "nkg_x" }, "its new token is not a token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deploy, _ := newSSHKey(t)
			first := newToken(t)
			file := tokenFileWith(t, first)
			tb := newTokenBroker(t, deploy, first, tt.answer)
			au := startAgent(t, tb.b, agentOptions{tokenFile: file})
			if sig := signOnce(t, au, deploy.PublicKey(), []byte("data"), 0); sig != nil {
				t.Fatal("the agent gave ssh a signature")
			}
			if lines := au.lines(); len(lines) != 1 || !strings.Contains(lines[0], tt.want) {
				t.Errorf("the agent wrote %q; want %q", lines, tt.want)
			}
			if got, err := readGrantToken(file); err != nil || got != first {
				t.Errorf("the file changed: %v", err)
			}
		})
	}
}

// TestAgentGrantTokenSaveFails: when the new token cannot be saved, ssh
// gets no signature, and the line says why.
func TestAgentGrantTokenSaveFails(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can write to a folder without the write bit")
	}
	deploy, _ := newSSHKey(t)
	first := newToken(t)
	file := tokenFileWith(t, first)
	tb := newTokenBroker(t, deploy, first, nil)
	au := startAgent(t, tb.b, agentOptions{tokenFile: file})
	dir := filepath.Dir(file)
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: a test folder without the write bit.
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: the test folder of the token file.
	if sig := signOnce(t, au, deploy.PublicKey(), []byte("data"), 0); sig != nil {
		t.Fatal("the agent gave ssh a signature without saving the new token")
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if strings.Contains(au.log.String(), tb.current.Reveal()) || strings.Contains(au.log.String(), first.Reveal()) {
		t.Fatal("a line holds a token")
	}
	if lines := au.lines(); len(lines) != 1 || !strings.Contains(lines[0], "cannot make a file") {
		t.Errorf("the agent wrote %q", lines)
	}
}

// TestAgentRotateToken: the checks of the new token of a sign answer.
func TestAgentRotateToken(t *testing.T) {
	t.Parallel()
	a := &sshAgent{}
	if err := a.rotateToken(newToken(t).Reveal()); err == nil {
		t.Error("a token for an agent without a file passed")
	}
	if err := a.rotateToken(""); err != nil {
		t.Error(err)
	}
	a.tokenFile = filepath.Join(t.TempDir(), "token")
	tok := newToken(t)
	if err := a.rotateToken(tok.Reveal()); err != nil {
		t.Fatal(err)
	}
	if got, err := readGrantToken(a.tokenFile); err != nil || got != tok {
		t.Errorf("the token was not saved: %v", err)
	}
}

// TestAgentGrantTokenArgs: --grant-token is read once, needs a value, and
// a token file that is not safe stops the agent before it serves.
func TestAgentGrantTokenArgs(t *testing.T) {
	t.Parallel()
	sock, file, err := parseAgentArgs([]string{"--socket", "/run/a.sock", "--grant-token=/x/token"})
	if err != nil || sock != "/run/a.sock" || file != "/x/token" {
		t.Errorf("got %q %q %v", sock, file, err)
	}
	for _, args := range [][]string{
		{"--grant-token"}, {"--grant-token", ""}, {"--grant-token", "a", "--grant-token", "b"},
	} {
		if _, _, err := parseAgentArgs(args); err == nil {
			t.Errorf("%q passed", args)
		}
	}
	bad := filepath.Join(t.TempDir(), "token")
	if err := SaveGrantToken(bad, newToken(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o644); err != nil { //nolint:gosec // G302: the test makes a bad mode.
		t.Fatal(err)
	}
	var out syncBuffer
	r := agentRunner{getenv: func(string) string { return "" }}
	code := r.run(t.Context(), []string{"--socket", filepath.Join(shortTempDir(t), "a.sock"), "--grant-token", bad}, &out)
	if code != exitUsage || !strings.Contains(out.String(), "token") {
		t.Errorf("exit %d, %q; want exit 64 for a token file that others can read", code, out.String())
	}
}
