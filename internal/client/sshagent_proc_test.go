package client

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/transport"
)

// fakeProc is a /proc tree of a test.
type fakeProc struct{ root string }

func newFakeProc(t *testing.T) fakeProc { return fakeProc{root: t.TempDir()} }

// fs returns the procFS that reads the tree.
func (f fakeProc) fs() *procFS { return &procFS{root: f.root} }

// write writes the file name of process pid.
func (f fakeProc) write(t *testing.T, pid int, name string, data []byte) {
	t.Helper()
	dir := filepath.Join(f.root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// add adds process pid with its parent, its command line (a NUL byte
// after each argument, as Linux writes it) and its environment.
func (f fakeProc) add(t *testing.T, pid, ppid int, argv, env []string) {
	t.Helper()
	f.write(t, pid, "cmdline", nulList(argv))
	f.write(t, pid, "stat", fmt.Appendf(nil, "%d (%s) S %d %d %d 0 -1 4194304", pid, filepath.Base(argv[0]), ppid,
		ppid, ppid))
	f.write(t, pid, "environ", nulList(env))
}

// commandLineOf reads the command line of process pid of the tree p.
func commandLineOf(p *procFS, pid int) ([]string, bool) {
	pr, err := p.openProcess(pid)
	if err != nil {
		return nil, false
	}
	defer pr.close()
	return pr.commandLine()
}

// reasonOf reads NODKEY_REASON of process pid of the tree p.
func reasonOf(p *procFS, pid int) string {
	pr, err := p.openProcess(pid)
	if err != nil {
		return ""
	}
	defer pr.close()
	return pr.reason()
}

// nulList returns the strings, each followed by a NUL byte.
func nulList(list []string) []byte {
	var b []byte
	for _, s := range list {
		b = append(append(b, s...), 0)
	}
	return b
}

// TestClaimedContextParents: the command lines of the process that
// connected and of at most 3 of its parents (DESIGN.md section 6), that
// process first, and NODKEY_REASON from the environment of that process
// only.
func TestClaimedContextParents(t *testing.T) {
	t.Parallel()
	p := newFakeProc(t)
	p.add(t, 100, 99, []string{"ssh", "deploy@web-1"}, []string{"A=1", "NODKEY_REASON=apply the nginx fix", "B=2"})
	p.add(t, 99, 98, []string{"ansible-playbook", "site.yml"}, []string{"NODKEY_REASON=from the parent"})
	p.add(t, 98, 97, []string{"/bin/bash", "-c", "make deploy"}, nil)
	p.add(t, 97, 96, []string{"node", "agent.js"}, nil)
	p.add(t, 96, 1, []string{"sshd: dev@pts/0"}, nil)
	p.add(t, 1, 0, []string{"/sbin/init"}, nil)
	commands, reason := p.fs().claimedContext(100)
	want := [][]string{{"ssh", "deploy@web-1"}, {"ansible-playbook", "site.yml"}, {"/bin/bash", "-c", "make deploy"},
		{"node", "agent.js"}}
	if !slices.EqualFunc(commands, want, slices.Equal) || reason != "apply the nginx fix" {
		t.Errorf("claimedContext = %q, %q; want %q, the reason of process 100", commands, reason, want)
	}
	if got, _ := p.fs().claimedContext(98); len(got) != 4 || got[3][0] != "/sbin/init" {
		t.Errorf("from process 98: %q; want 98, 97, 96 and 1", got)
	}
	if got, reason := p.fs().claimedContext(1); len(got) != 1 || reason != "" {
		t.Errorf("from process 1: %q, %q; it has no parent", got, reason)
	}
}

// TestClaimedContextStops: the chain of parents stops at a parent that
// cannot be read, has no command line (a kernel thread), or is there
// twice. Without the command line of the process that connected, there
// is no claimed context at all.
func TestClaimedContextStops(t *testing.T) {
	t.Parallel()
	p := newFakeProc(t)
	p.add(t, 10, 11, []string{"ssh", "web-1"}, []string{"NODKEY_REASON=r"}) // 11 is not there
	p.add(t, 20, 21, []string{"ssh", "web-1"}, nil)
	p.add(t, 21, 2, []string{"x"}, nil)
	p.write(t, 21, "cmdline", nil) // a kernel thread
	p.add(t, 30, 31, []string{"ssh"}, nil)
	p.add(t, 31, 30, []string{"loop"}, nil)
	p.add(t, 40, 41, []string{"ssh"}, nil)
	p.write(t, 40, "stat", []byte("40 (ssh) S"))
	p.add(t, 50, 51, []string{"ssh"}, nil)
	p.write(t, 50, "stat", []byte("50 (a) b (c) d) S 51 1 1"))
	p.add(t, 51, 0, []string{"parent of a strange name"}, nil)
	p.write(t, 60, "environ", nulList([]string{"NODKEY_REASON=only an environment"}))
	tests := []struct {
		pid    int32
		want   [][]string
		reason string
	}{
		{10, [][]string{{"ssh", "web-1"}}, "r"},
		{20, [][]string{{"ssh", "web-1"}}, ""},
		{30, [][]string{{"ssh"}, {"loop"}}, ""},
		{40, [][]string{{"ssh"}}, ""},
		{50, [][]string{{"ssh"}, {"parent of a strange name"}}, ""},
		{60, [][]string{}, ""},
		{70, [][]string{}, ""},
		{0, [][]string{}, ""},
		{-1, [][]string{}, ""},
	}
	for _, tt := range tests {
		commands, reason := p.fs().claimedContext(tt.pid)
		if !slices.EqualFunc(commands, tt.want, slices.Equal) || commands == nil || reason != tt.reason {
			t.Errorf("process %d: %q, %q; want %q, %q", tt.pid, commands, reason, tt.want, tt.reason)
		}
	}
}

// TestCommandLine: a command line is as nodkey run sends one: more than
// api.MaxArgs arguments, or more than api.MaxText bytes in all, become
// "[hidden: too long]".
func TestCommandLine(t *testing.T) {
	t.Parallel()
	p := newFakeProc(t)
	full := make([]string, api.MaxArgs)
	for i := range full {
		full[i] = strings.Repeat("a", api.MaxText/api.MaxArgs)
	}
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{"arguments", []byte("ssh\x00-p\x002222\x00web-1\x00"), []string{"ssh", "-p", "2222", "web-1"}},
		{"an empty argument", []byte("ssh\x00\x00"), []string{"ssh", ""}},
		{"no NUL at the end", []byte("ssh: web-1 [mux]"), []string{"ssh: web-1 [mux]"}},
		{"at the limits", nulList(full), full},
		{"too many arguments", nulList(append(slices.Clone(full[:2]), make([]string, api.MaxArgs)...)),
			[]string{tooLong}},
		{"too long", nulList(append(slices.Clone(full), "a")), []string{tooLong}},
		{"far too long", bytes.Repeat([]byte("a"), maxCmdline+1), []string{tooLong}},
	}
	for i, tt := range tests {
		p.write(t, 200+i, "cmdline", tt.data)
		got, ok := commandLineOf(p.fs(), 200+i)
		if !ok || !slices.Equal(got, tt.want) {
			t.Errorf("%s: %d arguments, %v; want %d", tt.name, len(got), ok, len(tt.want))
		}
	}
	if _, ok := commandLineOf(p.fs(), 300); ok {
		t.Error("a process that is not there has a command line")
	}
}

// TestEnvValue: the first NODKEY_REASON of an environment, exactly that
// name, also without a NUL byte at the end; a value over the limit is
// "too long".
func TestEnvValue(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("r", api.MaxText)
	tests := []struct {
		name  string
		env   string
		value string
		found bool
		long  bool
	}{
		{"one", "A=1\x00NODKEY_REASON=apply the fix\x00B=2\x00", "apply the fix", true, false},
		{"first", "NODKEY_REASON=first\x00NODKEY_REASON=second\x00", "first", true, false},
		{"empty", "NODKEY_REASON=\x00", "", true, false},
		{"no NUL at the end", "A=1\x00NODKEY_REASON=last", "last", true, false},
		{"a longer name", "NODKEY_REASONS=x\x00NODKEY_REASON_2=y\x00", "", false, false},
		{"a name that ends with it", "X_NODKEY_REASON=x\x00", "", false, false},
		{"the name in a value", "A=NODKEY_REASON=x\x00", "", false, false},
		{"without =", "NODKEY_REASON\x00NODKEY_REASON=after\x00", "after", true, false},
		{"a short entry first", "NODKEY\x00NODKEY_REASON=after\x00", "after", true, false},
		{"a line break in the value", "NODKEY_REASON=a\nb\x00", "a\nb", true, false},
		{"at the limit", "NODKEY_REASON=" + long + "\x00", long, true, false},
		{"too long", "NODKEY_REASON=" + long + "r\x00", "", true, true},
		{"not set", "A=1\x00B=2\x00", "", false, false},
		{"empty environment", "", "", false, false},
	}
	for _, tt := range tests {
		// One byte at a time, so that every place where a piece ends is
		// tried, and in pieces of 4 KiB.
		value, found, long := envValue(iotest.OneByteReader(strings.NewReader(tt.env)), reasonVar, api.MaxText)
		if found != tt.found || long != tt.long || (!long && value != tt.value) {
			t.Errorf("%s: %d bytes, %v, %v; want %d bytes, %v, %v", tt.name, len(value), found, long,
				len(tt.value), tt.found, tt.long)
		}
		value2, found2, long2 := envValue(strings.NewReader(tt.env), reasonVar, api.MaxText)
		if value2 != value || found2 != found || long2 != long {
			t.Errorf("%s: another result when read in larger pieces", tt.name)
		}
	}
	p := newFakeProc(t)
	p.write(t, 5, "environ", []byte("NODKEY_REASON="+long+"r\x00"))
	if got := reasonOf(p.fs(), 5); got != tooLong {
		t.Errorf("a reason over api.MaxText is %d bytes", len(got))
	}
	if got := reasonOf(p.fs(), 6); got != "" {
		t.Errorf("the reason of a process that is not there is %q", got)
	}
}

// TestAgentSendsClaimedContext: the sign request holds the command lines
// and the reason of the process that connected, from /proc, and nothing
// from the agent's own environment.
func TestAgentSendsClaimedContext(t *testing.T) { // not parallel: it sets NODKEY_REASON
	t.Setenv(reasonVar, "the reason of the agent itself")
	canary := madeUp("canary")
	p := newFakeProc(t)
	p.add(t, 4242, 4241, []string{"ssh", "-o", "Password=" + canary, "web-1"},
		[]string{"SECRET=" + canary, "NODKEY_REASON=apply the nginx fix", "TOKEN=" + canary})
	p.add(t, 4241, 4240, []string{"ansible-playbook", "site.yml"}, []string{"NODKEY_REASON=from ansible"})
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(chan []byte, 1)
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		bodies <- readBody(t, r)
		transport.WriteError(w, http.StatusForbidden)
	})
	au := startAgent(t, fb.b, agentOptions{proc: p.fs(), peer: func(*net.UnixConn) (peer, error) {
		return peer{uid: self, pid: 4242}, nil
	}})
	if signatureOf(t, rawCall(t, au.conn(t), signRequestMessage([]byte("key"), []byte("data"), 0))) != nil {
		t.Fatal("the agent gave ssh a signature")
	}
	body := <-bodies
	var req api.SignRequest
	if err := req.UnmarshalJSON(body); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"ssh", "-o", "Password=" + canary, "web-1"}, {"ansible-playbook", "site.yml"}}
	if !slices.EqualFunc(req.Commands, want, slices.Equal) || req.Reason != "apply the nginx fix" {
		t.Errorf("the request has %q and the reason %q", safe(fmt.Sprint(req.Commands)), req.Reason)
	}
	// The command line goes as it is: the broker masks it. Nothing else
	// of the environment goes.
	if n := strings.Count(string(body), canary); n != 1 {
		t.Errorf("the request holds the canary %d times; want once, in the command line", n)
	}
}

// readBody reads the body of a request to a fake broker.
func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := b.ReadFrom(r.Body); err != nil {
		t.Error(err)
	}
	return b.Bytes()
}
