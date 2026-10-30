package doctor

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/release"
	"github.com/code6x/nodkey/internal/version"
)

type fakeProber struct {
	keys     int
	warnings []string
	err      error
}

func (f fakeProber) Probe(context.Context, string) (int, []string, error) {
	return f.keys, f.warnings, f.err
}

type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return "agent.sock" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }

func rel(t *testing.T, s string) version.Release {
	t.Helper()
	r, ok := version.ParseRelease(s)
	if !ok {
		t.Fatal(s)
	}
	return r
}

// goodClient returns a ClientEnv in which every check passes.
func goodClient(t *testing.T) ClientEnv {
	return ClientEnv{
		Version: "0.3.0",
		Lookup: func(context.Context, version.Release) (release.Info, error) {
			return release.Info{Newest: rel(t, "0.3.0")}, nil
		},
		ConfigPath: "/home/agent/.config/nodkey/client.toml",
		Load:       func(string) (Prober, error) { return fakeProber{keys: 2}, nil },
		SSHVersion: func() (string, error) { return "OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13", nil },
		Getenv: func(k string) string {
			return map[string]string{"SSH_AUTH_SOCK": "/run/user/1000/nodkey/agent.sock", "XDG_RUNTIME_DIR": "/run/user/1000"}[k]
		},
		Lstat: func(string) (fs.FileInfo, error) { return fakeInfo{mode: fs.ModeSocket}, nil },
	}
}

// result returns the result of the check name.
func result(t *testing.T, r Report, name string) Result {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q", name)
	return Result{}
}

func TestClientAllPass(t *testing.T) {
	r := Run(ClientChecks(t.Context(), goodClient(t)))
	if !r.OK() {
		t.Fatalf("not OK: %+v", r.Checks)
	}
	if d := result(t, r, "ssh agent").Detail; d != "the socket of nodkey ssh-agent" {
		t.Errorf("ssh agent detail %q", d)
	}
}

func TestClientOffline(t *testing.T) {
	env := goodClient(t)
	env.Lookup = nil
	r := Run(ClientChecks(t.Context(), env))
	if d := result(t, r, "version").Detail; !strings.Contains(d, "no check for a newer release") {
		t.Errorf("version detail %q", d)
	}
}

func TestClientNewerRelease(t *testing.T) {
	env := goodClient(t)
	env.Lookup = func(context.Context, version.Release) (release.Info, error) {
		return release.Info{Newest: rel(t, "0.4.0")}, nil
	}
	res := result(t, Run(ClientChecks(t.Context(), env)), "version")
	if res.Status != OK || !strings.Contains(res.Detail, "nodkey 0.4.0") {
		t.Errorf("version %+v", res)
	}
}

// TestClientFails makes each check of the client fail, and checks that
// each FAIL is complete: what, why, the fix and the docs section.
func TestClientFails(t *testing.T) {
	tests := []struct {
		name   string
		check  string
		change func(*ClientEnv)
		what   string
		skips  []string
	}{
		{"lookup fails", "version", func(e *ClientEnv) {
			e.Lookup = func(context.Context, version.Release) (release.Info, error) {
				return release.Info{}, errors.New("no answer from GitHub")
			}
		}, "cannot check for a newer release", nil},
		{"security release", "version", func(e *ClientEnv) {
			e.Lookup = func(context.Context, version.Release) (release.Info, error) {
				return release.Info{Newest: rel(t, "0.3.1"), Security: []release.Security{{Version: rel(t, "0.3.1")}}}, nil
			}
		}, "0.3.1", nil},
		{"no home", "config", func(e *ClientEnv) { e.ConfigPath = "" }, "home directory",
			[]string{"broker", "broker version"}},
		{"no config", "config", func(e *ClientEnv) {
			e.Load = func(string) (Prober, error) { return nil, fs.ErrNotExist }
		}, "not exist", []string{"broker", "broker version"}},
		{"bad config", "config", func(e *ClientEnv) {
			e.Load = func(string) (Prober, error) { return nil, errors.New("config x: broker_pin: is missing") }
		}, "broker_pin", []string{"broker", "broker version"}},
		{"broker down", "broker", func(e *ClientEnv) {
			e.Load = func(string) (Prober, error) {
				return fakeProber{err: errors.New("cannot connect to the broker at 192.0.2.1:8443")}, nil
			}
		}, "cannot connect", []string{"broker version"}},
		{"versions differ", "broker version", func(e *ClientEnv) {
			e.Load = func(string) (Prober, error) {
				return fakeProber{warnings: []string{"warning: the broker runs nodkey 0.2.0, which is older"}}, nil
			}
		}, "the broker runs nodkey 0.2.0", nil},
		{"no ssh", "ssh", func(e *ClientEnv) {
			e.SSHVersion = func() (string, error) { return "", os.ErrNotExist }
		}, "cannot run ssh", nil},
		{"not openssh", "ssh", func(e *ClientEnv) {
			e.SSHVersion = func() (string, error) { return "Dropbear", nil }
		}, "not OpenSSH", nil},
		{"old openssh", "ssh", func(e *ClientEnv) {
			e.SSHVersion = func() (string, error) { return "OpenSSH_8.8p1", nil }
		}, "older than 8.9", nil},
		{"no SSH_AUTH_SOCK", "ssh agent", func(e *ClientEnv) {
			e.Getenv = func(string) string { return "" }
		}, "not set", nil},
		{"no socket", "ssh agent", func(e *ClientEnv) {
			e.Lstat = func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }
		}, "not a socket", nil},
		{"a file, not a socket", "ssh agent", func(e *ClientEnv) {
			e.Lstat = func(string) (fs.FileInfo, error) { return fakeInfo{}, nil }
		}, "not a socket", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := goodClient(t)
			tt.change(&env)
			r := Run(ClientChecks(t.Context(), env))
			res := result(t, r, tt.check)
			if res.Status != Fail || !strings.Contains(res.What, tt.what) {
				t.Fatalf("check %q: %+v, want FAIL with %q", tt.check, res, tt.what)
			}
			checkProblem(t, &Problem{What: res.What, Why: res.Why, Fix: res.Fix, Docs: res.Docs})
			for _, s := range tt.skips {
				if st := result(t, r, s).Status; st != Skip {
					t.Errorf("check %q: %s, want skip", s, st)
				}
			}
			for _, c := range r.Checks {
				if c.Status == Fail && c.Name != tt.check {
					t.Errorf("check %q failed too", c.Name)
				}
			}
			if r.OK() {
				t.Error("OK() with a FAIL")
			}
		})
	}
}

func TestClientOtherSocket(t *testing.T) {
	env := goodClient(t)
	env.Getenv = func(k string) string { return map[string]string{"SSH_AUTH_SOCK": "/tmp/agent.sock"}[k] }
	res := result(t, Run(ClientChecks(t.Context(), env)), "ssh agent")
	if res.Status != OK || !strings.Contains(res.Detail, "not the default socket") {
		t.Errorf("ssh agent %+v", res)
	}
}
