package client

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/code6x/nodkey/internal/audit"
)

// TestRunMask: with --mask, nodkey run gives the command and the values
// to masked, and does not replace itself. It returns masked's code.
func TestRunMask(t *testing.T) {
	t.Parallel()
	tb := newTestBroker(t)
	tb.approver.Auto(audit.AnswerApproveOnce)
	fx := &fakeExec{}
	r := testRunner(tb.client(t), []string{"PATH=/usr/bin"}, fx)
	var gotValues [][]byte
	var gotArgv []string
	r.masked = func(path string, argv, envv []string, values [][]byte, stderr io.Writer) int {
		gotArgv = slices.Clone(argv)
		for _, v := range values {
			gotValues = append(gotValues, bytes.Clone(v))
		}
		return 7
	}
	cmd := self(t)
	code, stderr := runIn(t.Context(), r, "--secret", "GH_TOKEN=github-token", "--secret", "NPM_TOKEN=npm-token",
		"--mask", "--", cmd, "x")
	if code != 7 {
		t.Fatalf("exit code %d, want 7 (the command's); stderr %q", code, safe(stderr))
	}
	if len(fx.ran()) != 0 {
		t.Error("with --mask, nodkey replaced itself with the command")
	}
	if !slices.Equal(gotArgv, []string{cmd, "x"}) {
		t.Errorf("masked got the arguments %q", gotArgv)
	}
	if len(gotValues) != 2 || string(gotValues[0]) != tb.values["github-token"] ||
		string(gotValues[1]) != tb.values["npm-token"] {
		t.Errorf("masked got %d values, or not the fetched ones", len(gotValues))
	}
}

// masked runs maskedCommand with values and a shell script, and returns
// the exit code, the signal, stdout and stderr.
func masked(t *testing.T, values []string, script string, args ...string) (int, syscall.Signal, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	vs := make([][]byte, len(values))
	env := []string{"PATH=/usr/bin:/bin"}
	for i, v := range values {
		vs[i] = []byte(v)
		env = append(env, "V"+itoa(i)+"="+v)
	}
	argv := append([]string{"sh", "-c", script, "sh"}, args...)
	code, sig, err := maskedCommand("/bin/sh", argv, env, vs, &stdout, &stderr)
	if err != nil {
		t.Fatalf("maskedCommand: %v", err)
	}
	return code, sig, stdout.String(), stderr.String()
}

func TestMaskedCommand(t *testing.T) {
	t.Parallel()
	canary := madeUp("canary")
	other := madeUp("other")
	code, sig, out, errOut := masked(t, []string{canary, other},
		`printf 'value=%s\n' "$V0"; printf '%s%s' "$V1" "$V0" >&2; exit 3`)
	if code != 3 || sig != 0 {
		t.Errorf("exit %d, signal %d; want 3, 0", code, sig)
	}
	if out != "value=***\n" || errOut != "******" {
		t.Errorf("stdout %q, stderr %q; want %q and %q", safe(out), safe(errOut), "value=***\n", "******")
	}
	mustNotLeak(t, canary, out, errOut)
	mustNotLeak(t, other, out, errOut)
}

// TestMaskedCommandSplit: the command writes the value in two writes, with
// a pause between them, so nodkey reads it in two parts.
func TestMaskedCommandSplit(t *testing.T) {
	t.Parallel()
	canary := madeUp("canary")
	half := len(canary) / 2
	_, _, out, _ := masked(t, []string{canary}, `printf '<%s' "$1"; sleep 0.2; printf '%s>' "$2"`,
		canary[:half], canary[half:])
	if out != "<***>" {
		t.Errorf("stdout %q, want %q", safe(out), "<***>")
	}
	mustNotLeak(t, canary, out)
}

// TestMaskedCommandBinary: binary output, with bytes that are not text and
// a value with such bytes, comes out as it is, with the value masked.
func TestMaskedCommandBinary(t *testing.T) {
	t.Parallel()
	value := "\xff\xfe\x01secret\x80"
	code, _, out, _ := masked(t, []string{value}, `printf '\000\377\200'; printf '%s' "$V0"; printf '\000\n\377'`)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if want := "\x00\xff\x80***\x00\n\xff"; out != want {
		t.Errorf("stdout %q, want %q", out, want)
	}
}

// TestMaskedCommandSignal: a command that dies of a signal gives 128 and
// its number, and the signal, which nodkey then raises.
func TestMaskedCommandSignal(t *testing.T) {
	t.Parallel()
	code, sig, _, _ := masked(t, []string{"x"}, `kill -TERM $$`)
	if code != 128+int(syscall.SIGTERM) || sig != syscall.SIGTERM {
		t.Errorf("exit %d, signal %d; want %d, %d", code, sig, 128+int(syscall.SIGTERM), syscall.SIGTERM)
	}
}

// TestMaskedCommandCannotStart: a file that cannot be run gives an error
// with its path, and nodkey run exits with 126.
func TestMaskedCommandCannotStart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "not-a-program")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := runMasked(path, []string{path}, nil, [][]byte{[]byte("x")}, &stderr)
	if code != exitCannotRun || !strings.Contains(stderr.String(), "cannot run") ||
		!strings.Contains(stderr.String(), "(exit 126)") {
		t.Errorf("exit %d, stderr %q", code, stderr.String())
	}
}

// TestMaskedCommandOutputFails: a command that exits with 0 while its
// output cannot be written does not count as a success.
func TestMaskedCommandOutputFails(t *testing.T) {
	t.Parallel()
	code, _, err := maskedCommand("/bin/sh", []string{"sh", "-c", "echo hello"}, nil, [][]byte{[]byte("x")},
		failWriter{}, io.Discard)
	if err != nil || code == 0 {
		t.Errorf("exit %d, %v; want a code that is not 0", code, err)
	}
}
