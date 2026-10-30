package doctor

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/release"
	"github.com/code6x/nodkey/internal/version"
)

// probeTimeout bounds the call to the broker, and lookupTimeout the call
// to GitHub.
const (
	probeTimeout  = 15 * time.Second
	lookupTimeout = 10 * time.Second
)

// Prober is the broker of a client config: *client.Broker.
type Prober interface {
	Probe(ctx context.Context, own string) (keys int, warnings []string, err error)
}

// ClientEnv is what the client checks use. Tests use fakes, so that no
// test needs the network, ssh or a home directory.
type ClientEnv struct {
	Version string // this nodkey's version
	// Lookup asks GitHub for the newest release. Nil means --offline.
	Lookup     func(ctx context.Context, own version.Release) (release.Info, error)
	ConfigPath string                            // the client config; "" when the home directory is not known
	Load       func(path string) (Prober, error) // client.Load
	SSHVersion func() (string, error)            // the output of ssh -V
	Getenv     func(string) string
	Lstat      func(string) (fs.FileInfo, error)
}

// ClientChecks returns the checks of nodkey doctor on a client.
func ClientChecks(ctx context.Context, env ClientEnv) []Check {
	var broker Prober
	var warnings []string
	return []Check{
		{Name: "version", Run: func() (string, *Problem) { return checkVersion(ctx, env) }},
		{Name: "config", Run: func() (string, *Problem) {
			var p *Problem
			broker, p = loadClient(env)
			if p != nil {
				return "", p
			}
			return env.ConfigPath, nil
		}},
		{Name: "broker", Needs: []string{"config"}, Run: func() (string, *Problem) {
			ctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			keys, w, err := broker.Probe(ctx, env.Version)
			warnings = w
			if err != nil {
				return "", &Problem{
					What: err.Error(),
					Why:  "nodkey run, ssh-agent, ssh-grant and preapprove need the broker",
					Fix: "check that the broker runs (systemctl status nodkey on the broker host), " +
						"broker and broker_pin in the client config, and that the pin of this client's " +
						"TLS key is in the broker config",
					Docs: "docs/setup.md section 14",
				}
			}
			return "the broker answers; SSH keys for this client: " + strconv.Itoa(keys), nil
		}},
		{Name: "broker version", Needs: []string{"broker"}, Run: func() (string, *Problem) {
			if len(warnings) > 0 {
				return "", &Problem{
					What: strings.TrimPrefix(strings.Join(warnings, "; "), "warning: "),
					Why:  "a client and a broker of different versions can disagree on what a request means",
					Fix:  "run nodkey update as root on the side with the older version",
					Docs: "docs/setup.md section 13",
				}
			}
			return "the same as this client", nil
		}},
		{Name: "ssh", Run: func() (string, *Problem) { return checkSSH(env) }},
		{Name: "ssh agent", Run: func() (string, *Problem) { return checkAgentSocket(env) }},
	}
}

// checkVersion is the check of this nodkey's version, as nodkey version.
func checkVersion(ctx context.Context, env ClientEnv) (string, *Problem) {
	detail := "nodkey " + env.Version
	own, isRelease := version.ParseRelease(env.Version)
	if env.Lookup == nil || !isRelease {
		return detail + "; no check for a newer release", nil
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	info, err := env.Lookup(ctx, own)
	if err != nil {
		return "", &Problem{
			What: "cannot check for a newer release: " + err.Error(),
			Why:  "a newer release can fix a security problem",
			Fix:  "check the connection to github.com, or run nodkey doctor --offline",
			Docs: "docs/setup.md section 13",
		}
	}
	if fixes, _ := info.SecurityNewer(own); len(fixes) > 0 {
		return "", &Problem{
			What: detail + "; " + release.SecurityFixes(fixes),
			Why:  "this nodkey has a known security problem",
			Fix:  "run nodkey update as root",
			Docs: "docs/setup.md section 13",
		}
	}
	if info.Newest.Compare(own) > 0 {
		return detail + "; a newer release is out: nodkey " + info.Newest.String() + "; run nodkey update as root", nil
	}
	return detail + "; the newest release", nil
}

// loadClient loads the client config and the client's TLS key.
func loadClient(env ClientEnv) (Prober, *Problem) {
	p := &Problem{
		Why:  "every nodkey command on this machine needs the client config and the TLS key",
		Docs: "docs/setup.md section 11",
	}
	if env.ConfigPath == "" {
		p.What = "the home directory is not known, so the client config cannot be found"
		p.Fix = "run nodkey doctor as the user of the agent, with HOME set"
		return nil, p
	}
	b, err := env.Load(env.ConfigPath)
	if err != nil {
		// The errors of client.Load never hold a value from the files.
		p.What = err.Error()
		p.Fix = "fix the client config or the key file as the error says"
		if errors.Is(err, fs.ErrNotExist) {
			p.Fix = "make the client config and the key with nodkey keygen"
		}
		return nil, p
	}
	return b, nil
}

// sshVersionPattern finds the version of OpenSSH in the output of ssh -V.
var sshVersionPattern = regexp.MustCompile(`OpenSSH_([0-9]+)\.([0-9]+)`)

// checkSSH checks that ssh is OpenSSH 8.9 or newer: it must send
// session-bind@openssh.com.
func checkSSH(env ClientEnv) (string, *Problem) {
	p := &Problem{
		Why:  "nodkey ssh-agent signs only for an ssh that sends session-bind@openssh.com, which OpenSSH 8.9 added",
		Fix:  "install OpenSSH 8.9 or newer",
		Docs: "docs/setup.md section 1",
	}
	out, err := env.SSHVersion()
	if err != nil {
		p.What = "cannot run ssh -V"
		return "", p
	}
	m := sshVersionPattern.FindStringSubmatch(out)
	if m == nil {
		p.What = "ssh is not OpenSSH"
		return "", p
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil || major < 8 || major == 8 && minor < 9 {
		p.What = "ssh is OpenSSH " + m[1] + "." + m[2] + ", older than 8.9"
		return "", p
	}
	return "OpenSSH " + m[1] + "." + m[2], nil
}

// checkAgentSocket checks that SSH_AUTH_SOCK names a socket, and says
// whether it is the default socket of nodkey ssh-agent.
func checkAgentSocket(env ClientEnv) (string, *Problem) {
	p := &Problem{
		Why: "ssh finds nodkey ssh-agent by SSH_AUTH_SOCK",
		Fix: `start nodkey ssh-agent, and export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/nodkey/agent.sock"; ` +
			"skip this when this machine uses no SSH keys of nodkey",
		Docs: "docs/setup.md section 11",
	}
	sock := env.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		p.What = "SSH_AUTH_SOCK is not set"
		return "", p
	}
	fi, err := env.Lstat(sock)
	if err != nil || fi.Mode().Type() != fs.ModeSocket {
		p.What = "SSH_AUTH_SOCK is not a socket: " + strconv.Quote(sock)
		return "", p
	}
	if dir := env.Getenv("XDG_RUNTIME_DIR"); dir != "" && sock == filepath.Join(dir, "nodkey", "agent.sock") {
		return "the socket of nodkey ssh-agent", nil
	}
	return "SSH_AUTH_SOCK is not the default socket of nodkey ssh-agent: " + strconv.Quote(sock), nil
}
