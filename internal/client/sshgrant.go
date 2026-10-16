package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/transport"
)

// grantUsage is the help of nodkey ssh-grant.
const grantUsage = `Usage: nodkey ssh-grant --key NAME --user USER --host NAME... --for DURATION [--reason TEXT]

Ask the broker once for SSH logins as USER with the key NAME to a list of
hosts, for DURATION, and wait until a person approves the request on the
phone. Until the grants end, ssh, git and Ansible through nodkey ssh-agent
log in to these hosts as USER without another tap. Other hosts, users and
keys still ask.

  --key NAME      a key of the broker; its rule must be "window"
  --user USER     the remote user; it must match
                  [A-Za-z0-9._][A-Za-z0-9._-]{0,31}
  --host NAME     a host by its name in the broker's known_hosts; 1 to 20
                  hosts, each with its own --host
  --for DURATION  how long the grants last, in whole minutes, such as 15m
                  or 1h; at most the window of the key
  --reason TEXT   why the logins are needed. Without it, the reason is the
                  environment variable NODKEY_REASON.

The client config is ~/.config/nodkey/client.toml. nodkey ssh-grant exits
with 0 when the person approved, or with 64 (wrong usage), 69 (the broker
cannot be reached) or 77 (denied). SIGINT or SIGTERM while it waits
cancel the request.
`

// grantNamePattern is the name rule of the broker config for keys and
// known hosts (DESIGN.md section 14). The client checks the names with it
// to give a quick error; the broker checks them again.
var grantNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// grantNameRule says what grantNamePattern allows, for errors.
const grantNameRule = `1 to 64 letters, digits, ".", "_" or "-", starting with a letter or digit`

// grantClock is the format of the end of the grants in the last line: the
// hour and the minute. The seconds are cut off, so the end that the line
// shows is never later than the end that it stands for.
const grantClock = "15:04"

// SSHGrant runs nodkey ssh-grant with args, the arguments after
// "ssh-grant", and writes its own messages to stderr (DESIGN.md sections
// 13 and 15). version is the version of nodkey, as for Run. It returns
// the exit code. Its last line on stderr is always
// "nodkey: <result> (exit <code>)". After an approval, the result names the
// remote user, the number of hosts, and when the grants end.
//
// As nodkey run, it catches SIGINT and SIGTERM while it waits. When one
// comes, it cancels the request: the connection closes, so the broker
// cancels the request too. Then it prints its last line and ends nodkey
// with the same signal, so that a shell sees it.
func SSHGrant(args []string, stderr io.Writer, version string) int {
	g := granter{load: Load, configPath: ConfigPath, environ: os.Environ, now: time.Now, version: version}
	return g.main(args, stderr)
}

// granter runs nodkey ssh-grant. Tests replace its parts.
type granter struct {
	// load reads the client config and the TLS key: Load.
	load func(path string) (*Broker, error)
	// configPath returns the path of the client config: ConfigPath.
	configPath func() (string, error)
	// environ returns the environment: os.Environ.
	environ func() []string
	// now returns the time of this machine's clock, for the end of the
	// grants in the last line: time.Now.
	now func() time.Time
	// version is the version of nodkey (warnVersions); "" sends none.
	version string
}

// main is SSHGrant with the parts of g.
func (g granter) main(args []string, stderr io.Writer) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	in := watchInterrupts(cancel)
	defer in.stop()
	code := g.run(ctx, args, stderr)
	var sig interrupted
	if errors.As(context.Cause(ctx), &sig) && code == sig.status() {
		// run printed "cancelled by SIG... (exit 128+N)". A shell stops a
		// loop or a script only when a command dies of SIGINT.
		in.stop()
		raise(sig.sig)
	}
	return code
}

// run runs nodkey ssh-grant, and returns the exit code. When ctx ends while
// the request waits, run cancels the request, and returns the code of
// cancelled.
func (g granter) run(ctx context.Context, args []string, w io.Writer) int {
	stderr := &lockedWriter{w: w}
	if len(args) == 1 && isHelp(args[0]) {
		_, _ = io.WriteString(stderr, grantUsage)
		return exitOK
	}
	o, err := parseGrantArgs(args)
	if err != nil {
		_, _ = io.WriteString(stderr, grantUsage)
		return fail(stderr, exitUsage, err.Error())
	}
	reason := o.reason
	if !o.reasonSet {
		reason = lookupEnv(g.environ(), reasonVar)
	}
	body, err := encodeGrantRequest(newGrantRequest(o, reason))
	if err != nil {
		return fail(stderr, exitUsage, err.Error())
	}
	configPath, err := g.configPath()
	if err != nil {
		return fail(stderr, exitUnavailable, err.Error())
	}
	b, err := g.load(configPath)
	if err != nil {
		return fail(stderr, exitUnavailable, err.Error())
	}
	b.warnVersions(g.version, func(text string) { warnLine(stderr, text) })
	// The broker fixes the end of the grants when the request comes: its
	// time plus the minutes. This time is taken before the request goes
	// out, so the end in the last line is not later than the real end,
	// when the two clocks agree. The broker's clocks decide.
	sent := g.now()
	ans, err := Post[api.GrantAnswer](ctx, b, api.PathSSHGrant, body, func(code string) {
		_, _ = fmt.Fprintf(stderr, "nodkey: waiting for approval (request %s)\n", code)
	})
	if err == nil && ctx.Err() != nil {
		// A signal came while the request waited, and Post still returned
		// the answer that came at that moment (see Post). As DESIGN.md
		// sections 13 and 15 say, the client says cancelled then, and dies
		// of the signal, so that a shell loop stops.
		err = context.Cause(ctx)
	}
	if err != nil {
		return requestFailed(ctx, stderr, err)
	}
	minutes := int(o.duration / time.Minute)
	if ans.Minutes < 1 || ans.Minutes > minutes {
		// The person approved, and the broker sent a wrong answer. The
		// error does not show the number from the answer.
		return fail(stderr, exitUnavailable,
			fmt.Sprintf("the answer of the broker is not valid: its time is not 1 to %d minutes", minutes))
	}
	// The grants end at a time that the broker fixed when the request
	// came, also after a late tap. So the line shows that end, not the
	// minutes. A signal that comes now does not change the result: the
	// grants are made.
	until := sent.Add(time.Duration(ans.Minutes) * time.Minute)
	_, _ = fmt.Fprintf(stderr, "nodkey: SSH logins as %s to %s allowed until %s (exit %d)\n",
		o.user, grantHostCount(len(o.hosts)), until.Format(grantClock), exitOK)
	return exitOK
}

// grantHostCount returns "1 host" or "N hosts".
func grantHostCount(n int) string {
	if n == 1 {
		return "1 host"
	}
	return strconv.Itoa(n) + " hosts"
}

// grantOptions are the arguments of nodkey ssh-grant.
type grantOptions struct {
	key       string
	user      string
	hosts     []string      // in the order of the arguments, each once
	duration  time.Duration // --for: whole minutes, from 1 minute to config.MaxWindow
	reason    string
	reasonSet bool
}

// parseGrantArgs reads the arguments of nodkey ssh-grant. They are only
// options: --key NAME, --user USER, --host NAME, which may repeat, --for
// DURATION and --reason TEXT, each also with one dash and with "=" before
// the value, as the flag package reads them.
//
// It checks what the broker checks too, to give a quick error: the key
// name and each host name follow the name rule of the config, the remote
// user matches sshauth.ValidUser, there are 1 to api.MaxGrantHosts hosts,
// each only once, and --for is a time in whole minutes, from 1 minute to
// config.MaxWindow. The broker checks all of it again, and more: the rule
// and the window of the key, and that each host is in its known_hosts and
// in the hosts of the key.
func parseGrantArgs(args []string) (*grantOptions, error) {
	o := &grantOptions{}
	given := make(map[string]bool) // the options that may come only once
	hosts := make(map[string]bool)
	for rest := args; len(rest) > 0; {
		arg := rest[0]
		rest = rest[1:]
		name, value, hasValue := splitOption(arg)
		switch name {
		case "key", "user", "host", "for", "reason":
		case "h", "help":
			// With other arguments, help would exit with 0 and ask
			// nothing, which looks like a request that was approved.
			return nil, errors.New("--help must be the only argument")
		default:
			if !strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unexpected argument %.64q; put each host after its own --host", arg)
			}
			return nil, fmt.Errorf("unknown option %.64q", arg)
		}
		if !hasValue {
			if len(rest) == 0 {
				return nil, fmt.Errorf("--%s needs a value", name)
			}
			value, rest = rest[0], rest[1:]
		}
		if name != "host" {
			if given[name] {
				return nil, fmt.Errorf("--%s is given twice", name)
			}
			given[name] = true
		}
		var err error
		switch name {
		case "key":
			if !grantNamePattern.MatchString(value) {
				err = fmt.Errorf("--key: the key name %.64q must be %s", value, grantNameRule)
			}
			o.key = value
		case "user":
			if !sshauth.ValidUser(value) {
				err = fmt.Errorf("--user: the remote user name %.64q must match [A-Za-z0-9._][A-Za-z0-9._-]{0,31}",
					value)
			}
			o.user = value
		case "host":
			err = addGrantHost(o, hosts, value)
		case "for":
			o.duration, err = parseGrantDuration(value)
		case "reason":
			o.reason, o.reasonSet = value, true
		}
		if err != nil {
			return nil, err
		}
	}
	switch {
	case !given["key"]:
		return nil, errors.New("give the key with --key NAME")
	case !given["user"]:
		return nil, errors.New("give the remote user with --user USER")
	case len(o.hosts) == 0:
		return nil, errors.New("give at least one host with --host NAME")
	case !given["for"]:
		return nil, errors.New("give the time of the grants with --for DURATION, such as --for 15m")
	}
	return o, nil
}

// addGrantHost adds the value of one --host to o. hosts holds the hosts
// that o has already.
func addGrantHost(o *grantOptions, hosts map[string]bool, host string) error {
	switch {
	case !grantNamePattern.MatchString(host):
		return fmt.Errorf("--host: %.64q is not a host name: a name in the broker's known_hosts is %s; "+
			"give each host with its own --host", host, grantNameRule)
	case hosts[host]:
		return fmt.Errorf("--host: the host %s is given twice", host)
	case len(o.hosts) == api.MaxGrantHosts:
		return fmt.Errorf("at most %d --host options", api.MaxGrantHosts)
	}
	hosts[host] = true
	o.hosts = append(o.hosts, host)
	return nil
}

// parseGrantDuration reads the value of --for: a time in the form of Go,
// such as 15m, 90m or 1h30m, in whole minutes, from 1 minute to
// config.MaxWindow, the longest window of a key.
func parseGrantDuration(value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	switch {
	case err != nil, d < time.Minute, d%time.Minute != 0:
		return 0, fmt.Errorf("--for %.64q: give a time in whole minutes, such as 15m or 1h", value)
	case d > config.MaxWindow:
		return 0, fmt.Errorf("--for %.64q: the grants can last at most %d hours, the longest window of a key",
			value, int(config.MaxWindow/time.Hour))
	}
	return d, nil
}

// newGrantRequest makes the request for SSH grants (DESIGN.md sections 10
// and 13): the key, the remote user, the hosts, --for in seconds, and the
// claimed reason. A reason over api.MaxText bytes becomes "[hidden: too
// long]", as for nodkey run.
func newGrantRequest(o *grantOptions, reason string) api.GrantRequest {
	return api.GrantRequest{
		Key:     o.key,
		User:    o.user,
		Hosts:   o.hosts,
		Seconds: int64(o.duration / time.Second),
		Reason:  claimedText(reason),
	}
}

// encodeGrantRequest returns req as JSON. It checks the caps of the
// request, and that the body is not larger than the broker reads
// (transport.MaxRequestBody). Every request of newGrantRequest with the
// options of parseGrantArgs passes: an error here is a bug.
func encodeGrantRequest(req api.GrantRequest) ([]byte, error) {
	if err := req.Check(); err != nil {
		return nil, errors.New("the request is over a cap of the broker")
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > transport.MaxRequestBody {
		return nil, errors.New("the request is larger than the broker reads")
	}
	return body, nil
}
