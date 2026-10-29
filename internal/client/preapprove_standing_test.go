package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/grantkey"
)

const testGrantID = "AAAAAAAAAAAAAAAAAAAAAA"

// standingArgs are the arguments of a standing grant that writes its token
// to file, and then extra.
func standingArgs(file string, extra ...string) []string {
	return append([]string{"--secret", "backup-token", "--daily", "03:00-05:00", "--until", "2026-12-28T00:00",
		"--grant-token", file}, extra...)
}

func newToken(t testing.TB) grantkey.Token {
	t.Helper()
	tok, err := grantkey.New()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// standingBroker answers a preapprove request with a grant that has the
// token field token ("" for none), and a cancel with the ID.
type standingBroker struct {
	*fakeBroker
	mu        sync.Mutex
	preBodies []string
	cancels   []string
}

func newStandingBroker(t *testing.T, token string) *standingBroker {
	t.Helper()
	sb := &standingBroker{}
	sb.fakeBroker = newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sb.mu.Lock()
		defer sb.mu.Unlock()
		if r.URL.Path == api.PathPreapproveCancel {
			sb.cancels = append(sb.cancels, string(body))
			answer(http.StatusOK, `{"id":"`+testGrantID+`"}`)(w, r)
			return
		}
		sb.preBodies = append(sb.preBodies, string(body))
		a := `{"id":"` + testGrantID + `","from":"2026-10-15T12:00:00Z","until":"2026-12-28T00:00:00Z"`
		if token != "" {
			a += `,"grant_token":"` + token + `"`
		}
		answer(http.StatusOK, a+"}")(w, r)
	})
	return sb
}

func (sb *standingBroker) bodies() ([]string, []string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	return append([]string(nil), sb.preBodies...), append([]string(nil), sb.cancels...)
}

// TestPreapproveStanding: the token goes to the file with mode 0600, is
// never printed, and the request has the window and the defaults.
func TestPreapproveStanding(t *testing.T) {
	t.Parallel()
	tok := newToken(t)
	sb := newStandingBroker(t, tok.Reveal())
	file := filepath.Join(t.TempDir(), "grant.token")
	code, stdout, stderr := preIn(t.Context(), testGranter(sb.b, nil), standingArgs(file)...)
	mustNotLeak(t, tok.Reveal(), stdout, stderr)
	if code != exitOK || stdout != testGrantID+"\n" {
		t.Fatalf("exit code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	got, err := os.ReadFile(file) //nolint:gosec // G304: a test path.
	if err != nil || string(got) != tok.Reveal()+"\n" {
		t.Errorf("token file: %v (content matches: %v)", err, string(got) == tok.Reveal()+"\n")
	}
	if fi, _ := os.Stat(file); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v, want 0600", fi)
	}
	bodies, cancels := sb.bodies()
	if len(bodies) != 1 || len(cancels) != 0 {
		t.Fatalf("%d requests, %d cancels", len(bodies), len(cancels))
	}
	var req api.PreapproveRequest
	if err := json.Unmarshal([]byte(bodies[0]), &req); err != nil {
		t.Fatal(err)
	}
	w := req.Windows
	if len(w) != 1 || w[0].Kind != "daily" || w[0].From != "03:00" || w[0].To != "05:00" || req.Uses != 1 ||
		req.From != noon.Format("2006-01-02T15:04:05Z07:00") || req.Until != "2026-12-28T00:00" ||
		len(req.Secrets) != 1 || req.Secrets[0] != "backup-token" {
		t.Errorf("request %+v", req)
	}
	if entries, _ := os.ReadDir(filepath.Dir(file)); len(entries) != 1 {
		t.Errorf("%d files in the directory, want only the token file", len(entries))
	}
}

// TestPreapproveStandingWeeklyOwnFile: weekly days are sorted; the old
// token file of the user (mode 0600) is replaced.
func TestPreapproveStandingWeeklyOwnFile(t *testing.T) {
	t.Parallel()
	tok := newToken(t)
	sb := newStandingBroker(t, tok.Reveal())
	file := filepath.Join(t.TempDir(), "grant.token")
	if err := os.WriteFile(file, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := preIn(t.Context(), testGranter(sb.b, nil),
		"--secret", "s", "--weekly", "thu,mon", "03:00-05:00", "--from", "2026-10-16T00:00", "--until", "2026-12-28T00:00",
		"--uses", "3", "--grant-token", file)
	if code != exitOK {
		t.Fatalf("exit code %d, stderr %q", code, stderr)
	}
	if got, _ := os.ReadFile(file); string(got) != tok.Reveal()+"\n" { //nolint:gosec // G304: a test path.
		t.Error("the token file was not replaced")
	}
	bodies, _ := sb.bodies()
	var req api.PreapproveRequest
	if err := json.Unmarshal([]byte(bodies[0]), &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Windows) != 1 || req.Windows[0].Kind != "weekly" || strings.Join(req.Windows[0].Days, ",") != "mon,thu" ||
		req.Uses != 3 || req.From != "2026-10-16T00:00" {
		t.Errorf("request %+v", req)
	}
}

// TestPreapproveStandingBadAnswers: no token, a bad token, a token for a
// scheduled grant, and a file that cannot be saved all fail, cancel the
// grant, and never print the token.
func TestPreapproveStandingBadAnswers(t *testing.T) {
	t.Parallel()
	good := newToken(t).Reveal()
	for _, tt := range []struct {
		name, token string
		dirGone     bool
	}{
		{"no token", "", false},
		{"bad checksum", good[:len(good)-1] + map[bool]string{true: "0", false: "1"}[good[len(good)-1] == '1'], false},
		{"not a token", "hello", false},
		{"cannot write", good, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sb := newStandingBroker(t, tt.token)
			dir := t.TempDir()
			file := filepath.Join(dir, "grant.token")
			args := standingArgs(file)
			if tt.dirGone {
				// The directory is there for the check before the request,
				// and gone for the save.
				file = filepath.Join(dir, "sub", "grant.token")
				args = standingArgs(file)
				if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
					t.Fatal(err)
				}
				sb2 := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == api.PathPreapproveCancel {
						answer(http.StatusOK, `{"id":"`+testGrantID+`"}`)(w, r)
						return
					}
					_ = os.RemoveAll(filepath.Join(dir, "sub"))
					answer(http.StatusOK, `{"id":"`+testGrantID+`","from":"2026-10-15T12:00:00Z","until":"2026-12-28T00:00:00Z","grant_token":"`+tt.token+`"}`)(w, r)
				})
				sb.fakeBroker = sb2
			}
			code, stdout, stderr := preIn(t.Context(), testGranter(sb.b, nil), args...)
			mustNotLeak(t, good, stdout, stderr)
			if tt.token != "" {
				mustNotLeak(t, tt.token, stdout, stderr)
			}
			if code != exitUnavailable || stdout != "" || !strings.Contains(stderr, testGrantID) ||
				!strings.HasSuffix(stderr, "(exit 69)\n") {
				t.Errorf("exit code %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if _, err := os.Stat(file); err == nil {
				t.Error("a token file exists")
			}
			if tt.dirGone {
				return
			}
			if _, cancels := sb.bodies(); len(cancels) != 1 || !strings.Contains(cancels[0], testGrantID) {
				t.Errorf("cancels %q, want one", cancels)
			}
		})
	}
}

// TestPreapproveScheduledRefusesToken: without --daily or --weekly an
// answer with a token fails closed, and the grant is cancelled.
func TestPreapproveScheduledRefusesToken(t *testing.T) {
	t.Parallel()
	tok := newToken(t)
	sb := newStandingBroker(t, tok.Reveal())
	code, stdout, stderr := preIn(t.Context(), testGranter(sb.b, nil),
		"--secret", "s", "--from", "2026-10-15T12:00:00Z", "--until", "2026-10-15T13:00:00Z", "--uses", "1")
	mustNotLeak(t, tok.Reveal(), stdout, stderr)
	if code != exitUnavailable || stdout != "" {
		t.Errorf("exit code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, cancels := sb.bodies(); len(cancels) != 1 {
		t.Errorf("%d cancels, want 1", len(cancels))
	}
}

// TestPreapproveScheduledUnchanged: the request of a scheduled grant has no
// windows, and an answer without a token passes.
func TestPreapproveScheduledUnchanged(t *testing.T) {
	t.Parallel()
	sb := newStandingBroker(t, "")
	code, stdout, stderr := preIn(t.Context(), testGranter(sb.b, nil),
		"--secret", "s", "--from", "2026-10-15T12:00:00Z", "--until", "2026-10-15T13:00:00Z", "--uses", "2")
	if code != exitOK || stdout != testGrantID+"\n" {
		t.Fatalf("exit code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	bodies, _ := sb.bodies()
	if strings.Contains(bodies[0], "windows") {
		t.Errorf("request %s has windows", bodies[0])
	}
}

// TestPreapproveStandingBadFile: a bad token file is refused before the
// broker is asked.
func TestPreapproveStandingBadFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o640); err != nil { //nolint:gosec // G302: the test makes a loose file.
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{loose, link, dir} {
		sb := newStandingBroker(t, newToken(t).Reveal())
		code, stdout, stderr := preIn(t.Context(), testGranter(sb.b, nil), standingArgs(file)...)
		if code != exitUsage || stdout != "" || sb.requests.Load() != 0 || !strings.Contains(stderr, "grant token file") {
			t.Errorf("%s: exit code %d, stdout %q, stderr %q, %d requests", filepath.Base(file), code, stdout, stderr, sb.requests.Load())
		}
	}
}

// TestPreapproveStandingFlags: the flags of a standing grant.
func TestPreapproveStandingFlags(t *testing.T) {
	t.Parallel()
	ok := func(extra ...string) []string {
		return append([]string{"--secret", "s", "--grant-token", "f", "--until", "2026-12-28T00:00"}, extra...)
	}
	for _, tt := range []struct {
		name string
		args []string
		ok   bool
		uses int
	}{
		{"daily", ok("--daily", "03:00-05:00"), true, 1},
		{"weekly", ok("--weekly", "mon,thu", "03:00-05:00"), true, 1},
		{"weekly equals", ok("--weekly=sun", "03:00-05:00", "--uses", "4"), true, 4},
		{"both", ok("--daily", "03:00-05:00", "--weekly", "mon", "03:00-05:00"), false, 0},
		{"both reverse", ok("--weekly", "mon", "03:00-05:00", "--daily", "03:00-05:00"), false, 0},
		{"daily twice", ok("--daily", "03:00-05:00", "--daily", "03:00-05:00"), false, 0},
		{"bad time", ok("--daily", "3:00-05:00"), false, 0},
		{"reversed", ok("--daily", "05:00-03:00"), false, 0},
		{"midnight", ok("--daily", "23:00-24:00"), false, 0},
		{"no dash", ok("--daily", "03:00"), false, 0},
		{"seconds", ok("--daily", "03:00:00-05:00:00"), false, 0},
		{"bad day", ok("--weekly", "monday", "03:00-05:00"), false, 0},
		{"upper day", ok("--weekly", "Mon", "03:00-05:00"), false, 0},
		{"day twice", ok("--weekly", "mon,mon", "03:00-05:00"), false, 0},
		{"empty day", ok("--weekly", "mon,", "03:00-05:00"), false, 0},
		{"weekly without window", ok("--weekly", "mon"), false, 0},
		{"weekly window is an option", ok("--weekly", "mon", "--uses", "2"), false, 0},
		{"no until", []string{"--secret", "s", "--grant-token", "f", "--daily", "03:00-05:00"}, false, 0},
		{"no grant-token", []string{"--secret", "s", "--until", "2026-12-28T00:00", "--daily", "03:00-05:00"}, false, 0},
		{"no secret", []string{"--grant-token", "f", "--until", "2026-12-28T00:00", "--daily", "03:00-05:00"}, false, 0},
		{"key", []string{"--key", "k", "--user", "u", "--host", "h", "--grant-token", "f", "--until", "2026-12-28T00:00", "--daily", "03:00-05:00"}, false, 0},
		{"bad until", append([]string{"--daily", "03:00-05:00", "--secret", "s", "--grant-token", "f"}, "--until", "soon"), false, 0},
		{"zero uses", ok("--daily", "03:00-05:00", "--uses", "0"), false, 0},
		{"empty token path", []string{"--secret", "s", "--grant-token", "", "--until", "2026-12-28T00:00", "--daily", "03:00-05:00"}, false, 0},
		{"token twice", ok("--daily", "03:00-05:00", "--grant-token", "g"), false, 0},
		{"cancel mixed", []string{"--cancel", testGrantID, "--daily", "03:00-05:00"}, false, 0},
		{"token without window", []string{"--secret", "s", "--from", "2026-10-15T12:00", "--until", "2026-12-28T00:00", "--uses", "1", "--grant-token", "f"}, false, 0},
	} {
		o, err := parsePreapproveArgs(tt.args)
		if (err == nil) != tt.ok {
			t.Errorf("%s: error %v, want ok=%v", tt.name, err, tt.ok)
			continue
		}
		if err == nil && (o.uses != tt.uses || len(o.windows) != 1) {
			t.Errorf("%s: uses %d windows %v", tt.name, o.uses, o.windows)
		}
	}
	// A scheduled request is as before: --from and --uses are a must.
	if _, err := parsePreapproveArgs([]string{"--secret", "s", "--until", "2026-12-28T00:00"}); err == nil {
		t.Error("a scheduled grant without --from and --uses passes")
	}
}

// TestSaveGrantToken: the helper writes with mode 0600, replaces its own
// file, refuses files that are not safe, and never follows a link.
func TestSaveGrantToken(t *testing.T) {
	t.Parallel()
	tok := newToken(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "t")
	if err := SaveGrantToken(file, tok); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	tok2 := newToken(t)
	if err := SaveGrantToken(file, tok2); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(file); string(got) != tok2.Reveal()+"\n" { //nolint:gosec // test path or test file mode.
		t.Error("not replaced")
	}
	// Bad modes of an existing file.
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o666, 0o602} {
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		err := SaveGrantToken(file, tok)
		if !errors.Is(err, ErrTokenFile) {
			t.Errorf("mode %v: error %v", mode, err)
		}
		if got, _ := os.ReadFile(file); string(got) != tok2.Reveal()+"\n" { //nolint:gosec // test path or test file mode.
			t.Errorf("mode %v: the file changed", mode)
		}
	}
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := SaveGrantToken(file, tok); err != nil {
		t.Errorf("mode 0400: %v", err)
	}
	// A link is never followed and never replaced.
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := SaveGrantToken(link, tok); !errors.Is(err, ErrTokenFile) {
		t.Errorf("link: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "keep" { //nolint:gosec // test path or test file mode.
		t.Error("the target of the link changed")
	}
	// A directory, a missing directory, an empty path, a bad token.
	if err := SaveGrantToken(dir, tok); !errors.Is(err, ErrTokenFile) {
		t.Errorf("directory: %v", err)
	}
	if err := SaveGrantToken(filepath.Join(dir, "no", "t"), tok); !errors.Is(err, ErrTokenFile) {
		t.Errorf("missing directory: %v", err)
	}
	if err := SaveGrantToken("", tok); !errors.Is(err, ErrTokenFile) {
		t.Errorf("empty path: %v", err)
	}
	if err := SaveGrantToken(filepath.Join(dir, "x"), grantkey.Token{}); !errors.Is(err, ErrTokenFile) {
		t.Errorf("zero token: %v", err)
	}
	// No temporary file is left.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("left over: %s", e.Name())
		}
	}
}

// TestSaveGrantTokenNoLeak: an error never holds the token.
func TestSaveGrantTokenNoLeak(t *testing.T) {
	t.Parallel()
	tok := newToken(t)
	err := SaveGrantToken(filepath.Join(t.TempDir(), "no", "t"), tok)
	if err == nil || strings.Contains(err.Error(), tok.Reveal()) {
		t.Errorf("the error is nil, or holds the token: %v", err == nil)
	}
}

// TestPreapproveStandingBadTimeCancels: a standing grant whose answer has a
// bad time is cancelled, and no file is written.
func TestPreapproveStandingBadTimeCancels(t *testing.T) {
	t.Parallel()
	tok := newToken(t)
	var mu sync.Mutex
	cancels := 0
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == api.PathPreapproveCancel {
			mu.Lock()
			cancels++
			mu.Unlock()
			answer(http.StatusOK, `{"id":"`+testGrantID+`"}`)(w, r)
			return
		}
		answer(http.StatusOK, `{"id":"`+testGrantID+`","from":"x","until":"y","grant_token":"`+tok.Reveal()+`"}`)(w, r)
	})
	file := filepath.Join(t.TempDir(), "grant.token")
	code, stdout, stderr := preIn(t.Context(), testGranter(fb.b, nil), standingArgs(file)...)
	mustNotLeak(t, tok.Reveal(), stdout, stderr)
	mu.Lock()
	defer mu.Unlock()
	if code != exitUnavailable || cancels != 1 {
		t.Errorf("exit code %d, %d cancels, stderr %q", code, cancels, stderr)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("a token file exists")
	}
}
