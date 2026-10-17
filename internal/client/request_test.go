package client

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/transport"
)

// TestRunUsage: wrong usage exits with 64, prints the usage, and asks no
// one; -h and --help print the usage and exit with 0.
func TestRunUsage(t *testing.T) {
	t.Parallel()
	thirtyThree := []string{}
	for i := range api.MaxSecrets + 1 {
		thirtyThree = append(thirtyThree, "--secret", "V"+itoa(i)+"=github-token")
	}
	tests := []struct {
		name string
		args []string
		want string // the last line, without "nodkey: " and " (exit 64)"; "" for help
	}{
		{"nothing", nil, `put "--" before the command`},
		{"no --", []string{"--secret", "GH_TOKEN=github-token", "gh"}, `put "--" before the command`},
		{"options only", []string{"--secret", "GH_TOKEN=github-token"}, `put "--" before the command`},
		{"no command", []string{"--secret", "GH_TOKEN=github-token", "--"}, `no command after "--"`},
		{"no secret", []string{"--", "gh"}, "give at least one --secret VAR=NAME"},
		{"no value", []string{"--secret"}, "--secret needs a value"},
		{"no reason", []string{"--secret", "GH_TOKEN=github-token", "--reason"}, "--reason needs a value"},
		{"no =", []string{"--secret", "GH_TOKEN", "--", "gh"}, "--secret needs VAR=NAME"},
		{"lower case", []string{"--secret", "gh_token=github-token", "--", "gh"}, `the variable name "gh_token" must match`},
		{"digit first", []string{"--secret", "1TOKEN=github-token", "--", "gh"}, `the variable name "1TOKEN" must match`},
		{"variable too long", []string{"--secret", strings.Repeat("A", 65) + "=x", "--", "gh"}, "must match"},
		{"no secret name", []string{"--secret", "GH_TOKEN=", "--", "gh"}, "the secret name must have 1 to 64 bytes"},
		{"secret name too long", []string{"--secret", "GH_TOKEN=" + strings.Repeat("n", 65), "--", "gh"},
			"the secret name must have 1 to 64 bytes"},
		{"a variable twice", []string{"--secret", "GH_TOKEN=a", "--secret", "GH_TOKEN=b", "--", "gh"},
			"the variable GH_TOKEN is given twice"},
		{"too many", append(thirtyThree, "--", "gh"), "at most 32 --secret options"},
		{"two reasons", []string{"--reason", "a", "--reason=b", "--secret", "A=b", "--", "gh"}, "--reason is given twice"},
		{"unknown option", []string{"--secret", "A=b", "--bogus", "--", "gh"}, `unknown option "--bogus"`},
		{"one dash", []string{"-", "--", "gh"}, `unknown option "-"`},
		{"a line break", []string{"--secret", "A\nB=c", "--", "gh"}, `the variable name "A\nB" must match`},
		{"help", []string{"-h"}, ""},
		{"help with a command", []string{"--secret", "A=b", "--help", "--", "gh"}, "--help must be the only argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fx := &fakeExec{}
			code, stderr := runIn(t.Context(), testRunner(nil, nil, fx), tt.args...)
			if !strings.HasPrefix(stderr, runUsage) {
				t.Errorf("stderr = %q; want the usage first", safe(stderr))
			}
			if tt.want == "" {
				if code != exitOK || stderr != runUsage {
					t.Errorf("exit code %d, stderr %q; want 0 and only the usage", code, safe(stderr))
				}
				return
			}
			if last := lastLine(stderr); code != exitUsage || !strings.HasPrefix(last, "nodkey: ") ||
				!strings.Contains(last, tt.want) || !strings.HasSuffix(last, " (exit 64)") {
				t.Errorf("exit code %d, last line %q; want 64 and %q", code, safe(last), tt.want)
			}
			if len(fx.ran()) != 0 {
				t.Error("the command started")
			}
		})
	}
}

// TestRunDeniedVars: nodkey run refuses every variable on the deny list,
// and every variable that starts with a prefix on it (DESIGN.md section
// 5), before it asks anyone: it prints the usage and a clear last line,
// exits with 64, sends no request and starts nothing. Names that hold
// secrets on purpose, or only look like an entry, pass.
func TestRunDeniedVars(t *testing.T) {
	t.Parallel()
	fb := newFakeBroker(t, func(http.ResponseWriter, *http.Request) {
		t.Error("a request reached the broker")
	})
	type test struct{ name, want string }
	var tests []test
	names, prefixes := api.DenyList()
	for _, name := range names {
		tests = append(tests, test{name, "nodkey refuses the variable " + name +
			", because programs show or run its value"})
	}
	for _, p := range prefixes {
		want := "nodkey refuses variables that start with " + p + ", because programs show or run their values"
		tests = append(tests, test{p, want}, test{p + "X", want})
	}
	for _, tt := range tests {
		fx := &fakeExec{}
		code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token",
			"--secret", tt.name+"=npm-token", "--", self(t))
		want := "nodkey: --secret " + tt.name + "=...: " + tt.want + " (exit 64)"
		if last := lastLine(stderr); code != exitUsage || last != want || !strings.HasPrefix(stderr, runUsage) {
			t.Errorf("%s: exit code %d, last line %q; want 64, the usage and %q", tt.name, code, safe(last), want)
		}
		if len(fx.ran()) != 0 {
			t.Errorf("%s: the command started", tt.name)
		}
	}
	if n := fb.requests.Load(); n != 0 {
		t.Errorf("%d requests reached the broker, want none", n)
	}
	for _, ok := range []string{"GH_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "LDAP_PASSWORD", "NODE_AUTH_TOKEN",
		"NPM_TOKEN", "DOCKER_PASSWORD", "CARGO_REGISTRY_TOKEN", "TF_TOKEN_EXAMPLE_COM", "GOPROXY", "HTTPS_PROXY"} {
		if _, err := parseArgs([]string{"--secret", ok + "=github-token", "--", "gh"}); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

// TestParseArgs: the forms of the options, as the flag package reads
// them. Everything after "--" is the command, also its own options.
func TestParseArgs(t *testing.T) {
	t.Parallel()
	o, err := parseArgs([]string{"-secret", "A=a", "--secret=B=b=c", "-reason=why", "--", "gh", "--secret", "--", "x"})
	if err != nil {
		t.Fatal(err)
	}
	want := []api.SecretRef{{Var: "A", Name: "a"}, {Var: "B", Name: "b=c"}}
	if !slices.Equal(o.secrets, want) || o.reason != "why" || !o.reasonSet ||
		!slices.Equal(o.command, []string{"gh", "--secret", "--", "x"}) {
		t.Errorf("parseArgs = %+v", o)
	}
	o, err = parseArgs([]string{"--reason", "--", "--secret", "A=a", "--", "gh"})
	if err != nil || o.reason != "--" || len(o.secrets) != 1 || !slices.Equal(o.command, []string{"gh"}) {
		t.Errorf("a reason that is \"--\": %+v, %v", o, err)
	}
	var max []string
	for i := range api.MaxSecrets {
		max = append(max, "--secret", "V"+itoa(i)+"="+strings.Repeat("n", api.MaxName))
	}
	if o, err := parseArgs(append(max, "--", "gh")); err != nil || len(o.secrets) != api.MaxSecrets {
		t.Errorf("%d secrets with names of %d bytes: %v", api.MaxSecrets, api.MaxName, err)
	}
}

// TestNewRequest: a claimed field over 64 KiB, and a command line with
// more than 4096 arguments or more than 64 KiB in all, become "[hidden:
// too long]" (DESIGN.md section 10). Fields at the limit stay.
func TestNewRequest(t *testing.T) {
	t.Parallel()
	args := func(n, size int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat("a", size)
		}
		return out
	}
	full := strings.Repeat("x", api.MaxText)
	tests := []struct {
		name    string
		command []string
		text    string
		hidden  bool
	}{
		{"short", []string{"gh", "release"}, "why", false},
		{"at the limits", args(api.MaxArgs, api.MaxText/api.MaxArgs), full, false},
		{"too many arguments", args(api.MaxArgs+1, 1), full + "x", true},
		{"too long", append(args(1, api.MaxText), "a"), full + "x", true},
		{"one long argument", args(1, 1900<<10), strings.Repeat("y", 1900<<10), true},
	}
	for _, tt := range tests {
		req := newRequest([]api.SecretRef{{Var: "A", Name: "a"}}, tt.command, tt.text, tt.text)
		wantCommand, wantText := tt.command, tt.text
		if tt.hidden {
			wantCommand, wantText = []string{tooLong}, tooLong
		}
		if !slices.Equal(req.Command, wantCommand) || req.Dir != wantText || req.Reason != wantText {
			t.Errorf("%s: the request has %d arguments, a directory of %d bytes and a reason of %d bytes",
				tt.name, len(req.Command), len(req.Dir), len(req.Reason))
		}
		if _, err := encodeRequest(req); err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

// TestLargestRequestFits: the largest request that nodkey run sends fits
// in the broker's cap (transport.MaxRequestBody): 32 variables with the
// longest names, and a command line, a directory and a reason at their
// limits, of characters that take the most bytes in JSON.
func TestLargestRequestFits(t *testing.T) {
	t.Parallel()
	var secrets []api.SecretRef
	for i := range api.MaxSecrets {
		v := strings.Repeat("V", api.MaxName-2) + string(rune('A'+i/26)) + string(rune('A'+i%26))
		secrets = append(secrets, api.SecretRef{Var: v, Name: strings.Repeat("\x01", api.MaxName)})
	}
	command := make([]string, api.MaxArgs)
	for i := range command {
		command[i] = strings.Repeat("\x01", api.MaxText/api.MaxArgs)
	}
	text := strings.Repeat("\x01", api.MaxText)
	body, err := encodeRequest(newRequest(secrets, command, text, text))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > transport.MaxRequestBody {
		t.Errorf("the largest request has %d bytes, more than %d", len(body), transport.MaxRequestBody)
	}
	t.Logf("the largest request for secrets has %d bytes", len(body))
	// Without the replacement, a long field would be over the cap.
	if _, err := encodeRequest(api.SecretsRequest{Secrets: secrets, Command: []string{"gh"},
		Reason: strings.Repeat("\x01", transport.MaxRequestBody/6+1)}); err == nil {
		t.Error("encodeRequest took a request over the broker's cap")
	}
	if _, err := encodeRequest(api.SecretsRequest{Secrets: append(secrets, secrets[0])}); err == nil {
		t.Errorf("encodeRequest took %d variables", api.MaxSecrets+1)
	}
}

// TestTooLongIsTheBrokersText: the client's "[hidden: too long]" is the
// text that the broker shows for a field over its limit, and the limits
// are the same.
func TestTooLongIsTheBrokersText(t *testing.T) {
	t.Parallel()
	if api.MaxText != claim.MaxInput {
		t.Errorf("api.MaxText is %d, claim.MaxInput %d", api.MaxText, claim.MaxInput)
	}
	if got := claim.Line(strings.Repeat("x", claim.MaxInput+1), 100); got != tooLong {
		t.Errorf("the broker shows %q for a long field, the client sends %q", got, tooLong)
	}
}

// TestCommandEnv: the values replace the variables of the same names, and
// come last, in the order of the request. Other variables keep their
// place.
func TestCommandEnv(t *testing.T) {
	t.Parallel()
	one, two := madeUp("one"), madeUp("two")
	env := []string{"A=1", "GH_TOKEN=old", "B=2", "NPM_TOKEN", "GH_TOKEN=older", "GH_TOKEN_X=3", "=4"}
	secrets := []api.SecretRef{{Var: "NPM_TOKEN", Name: "npm-token"}, {Var: "GH_TOKEN", Name: "github-token"}}
	ans := &api.SecretsAnswer{Secrets: []api.SecretValue{
		{Var: "NPM_TOKEN", Value: []byte(one)}, {Var: "GH_TOKEN", Value: []byte(two)},
	}}
	got, err := commandEnv(env, secrets, ans)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"A=1", "B=2", "GH_TOKEN_X=3", "=4", "NPM_TOKEN=" + one, "GH_TOKEN=" + two}
	if !slices.Equal(got, want) {
		t.Errorf("the environment has %q, want %q", names(got), names(want))
	}
	// A value at the limits passes; one byte more does not.
	big := strings.Repeat("v", api.MaxValue)
	ans = &api.SecretsAnswer{Secrets: []api.SecretValue{{Var: "GH_TOKEN", Value: []byte(big)}}}
	if _, err := commandEnv(nil, secrets[1:], ans); err != nil {
		t.Errorf("a value of %d bytes: %v", api.MaxValue, err)
	}
	ans.Secrets[0].Value = []byte(big + "v")
	if _, err := commandEnv(nil, secrets[1:], ans); err == nil {
		t.Errorf("commandEnv took a value of %d bytes", api.MaxValue+1)
	}
}

// TestOneLine: the last line of nodkey run is one line, whatever the
// reason holds.
func TestOneLine(t *testing.T) {
	t.Parallel()
	if got := oneLine("a\nb\rc\x00d\u2028e\u0085f\u2029g"); got != "a b c d e f g" {
		t.Errorf("oneLine = %q", got)
	}
}

// TestBrokerHasNoTimeout: the HTTP client has no time limit that ends the
// wait for the person (http.Client.Timeout, ResponseHeaderTimeout). The
// deadline of each request is the broker's longest timeout and a margin.
func TestBrokerHasNoTimeout(t *testing.T) {
	t.Parallel()
	b := newFakeBroker(t, answer(http.StatusForbidden, `{"error":"Forbidden"}`)).b
	tr, ok := b.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the transport is %T", b.client.Transport)
	}
	if b.client.Timeout != 0 || tr.ResponseHeaderTimeout != 0 {
		t.Errorf("Timeout %s, ResponseHeaderTimeout %s; want none", b.client.Timeout, tr.ResponseHeaderTimeout)
	}
	if b.timeout != RequestTimeout || RequestTimeout.Minutes() != 15 {
		t.Errorf("the deadline is %s, RequestTimeout %s; want 15m", b.timeout, RequestTimeout)
	}
}

// TestLoad: Load reads the client config with config.LoadClient, which
// checks the config file, the TLS key file and the directories on the way
// to them as the broker checks its files (DESIGN.md section 14). Here the
// system temporary directory, which everyone can write to, or else the key
// file that others can read, is refused. TestRunWithTheRealFiles loads a
// config that passes.
func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "client.key")
	if err := os.WriteFile(keyFile, newTLSKey(t).file, 0o644); err != nil { //nolint:gosec // G306: the test needs a key file that others can read.
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o644); err != nil { //nolint:gosec // G302: the same; the umask may have taken bits away.
		t.Fatal(err)
	}
	path := filepath.Join(dir, "client.toml")
	cfg := "broker = \"192.0.2.10:7743\"\nbroker_pin = \"" + newTLSKey(t).pin.String() + "\"\ntls_key = \"" +
		keyFile + "\"\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || (!strings.Contains(err.Error(), "can write") && !strings.Contains(err.Error(), "have access")) {
		t.Errorf("Load with files that others can change or read: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "missing.toml")); err == nil {
		t.Error("Load took a config file that is not there")
	}
}

// TestRunReadsTheClientConfig: Run reads ~/.config/nodkey/client.toml
// with the checks of Load, and exits with 69 when it cannot.
func TestRunReadsTheClientConfig(t *testing.T) { // not parallel: it sets HOME
	home := t.TempDir()
	t.Setenv("HOME", home)
	path, err := ConfigPath()
	if err != nil || path != filepath.Join(home, ".config", "nodkey", "client.toml") {
		t.Fatalf("ConfigPath = %q, %v", path, err)
	}
	var stderr strings.Builder
	code := Run([]string{"--secret", "GH_TOKEN=github-token", "--", self(t)}, &stderr, "dev")
	if last := lastLine(stderr.String()); code != exitUnavailable || !strings.HasPrefix(last, "nodkey: config: ") ||
		!strings.HasSuffix(last, "(exit 69)") {
		t.Errorf("without a config: exit code %d, stderr %q", code, safe(stderr.String()))
	}
	t.Setenv("HOME", "")
	if _, err := ConfigPath(); err == nil {
		t.Error("ConfigPath without a home directory")
	}
}

// TestRunRelativePath: a command that PATH finds only through a relative
// directory, such as ".", does not run (exec.ErrDot): 126, without a
// request. A path given as ./tool runs.
func TestRunRelativePath(t *testing.T) { // not parallel: it changes PATH and the working directory
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // G306: the file must look like a program.
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".")
	fb := newFakeBroker(t, answer(http.StatusOK, secretsAnswer(t, "GH_TOKEN", madeUp("value"))))
	fx := &fakeExec{}
	code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token", "--", "tool")
	if code != exitCannotRun || !strings.Contains(stderr, "relative directory of PATH") || fb.requests.Load() != 0 {
		t.Errorf("exit code %d, stderr %q, %d requests; want 126 and no request", code, safe(stderr),
			fb.requests.Load())
	}
	code, stderr = runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token", "--", "./tool")
	// The real working directory, and the path as it was given.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if calls := fx.ran(); code != exitOK || len(calls) != 1 || calls[0].path != real+"/./tool" ||
		!slices.Equal(calls[0].argv, []string{"./tool"}) {
		t.Errorf("./tool: exit code %d, stderr %q; want it to run as %s", code, safe(stderr), real+"/./tool")
	}
}

// TestRunRelativePathGODEBUG: GODEBUG=execerrdot=0 turns off the check of
// exec.LookPath for a program that PATH finds only through a relative
// directory. nodkey run refuses it anyway (126), before any request.
// Otherwise the message would show "tool" while ./tool runs.
func TestRunRelativePathGODEBUG(t *testing.T) { // not parallel: PATH, GODEBUG and the working directory
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // G306: the file must look like a program.
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".:/usr/bin:/bin")
	t.Setenv("GODEBUG", "execerrdot=0")
	if path, err := exec.LookPath("tool"); err != nil || filepath.IsAbs(path) {
		t.Logf("exec.LookPath with GODEBUG=execerrdot=0 = %q, %v: Go checks it itself now", path, err)
	}
	fb := newFakeBroker(t, func(http.ResponseWriter, *http.Request) {
		t.Error("a request reached the broker")
	})
	fx := &fakeExec{}
	code, stderr := runIn(t.Context(), testRunner(fb.b, nil, fx), "--secret", "GH_TOKEN=github-token", "--", "tool")
	if code != exitCannotRun || !strings.Contains(lastLine(stderr), "relative directory of PATH") {
		t.Errorf("exit code %d, stderr %q; want 126", code, safe(stderr))
	}
	if fb.requests.Load() != 0 || len(fx.ran()) != 0 {
		t.Error("a request was sent or the command started")
	}
}
