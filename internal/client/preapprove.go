package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/grantkey"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/transport"
)

// preapproveUsage is the help of nodkey preapprove.
const preapproveUsage = `Usage: nodkey preapprove (--secret NAME... | --key NAME --user USER --host NAME...)
                         --until TIME --uses N [--from TIME] [--reason TEXT]
       nodkey preapprove --secret NAME...
                         (--daily HH:MM-HH:MM | --weekly DAYS HH:MM-HH:MM)
                         --until TIME [--from TIME] [--uses N]
                         --grant-token FILE [--reason TEXT]
       nodkey preapprove --cancel ID

Ask the broker now for a grant that you use later, and wait until a person
approves it on the phone. The grant hands out nothing. From the time given
by --from, until the time given by --until, the same machine can get the
named secrets, or SSH logins to the named hosts, without another tap, N
times in all. Each use sends a silent notice to the phone. Then the grant
is gone. A job that runs at night can ask for its grant when it is planned.

  --secret NAME   a secret of the broker; give each with its own --secret.
                  One use is one run with some or all of them.
  --key NAME      a key of the broker, with --user and --host, as for
                  nodkey ssh-grant. One use is one SSH login: ssh opens one
                  connection for each login, unless it shares one.
  --from TIME     the first moment of the grant (default: now)
  --until TIME    the end of the grant; it is not part of the grant
                  Both times are RFC 3339 with a UTC offset, such as
                  2026-10-28T03:00:00+02:00, or without an offset, such as
                  2026-10-28T03:00, which is the broker's local time.
                  Give an offset near the change to summer time.
  --uses N        how many uses the grant has
  --daily W       a standing grant (secrets only): the window W, such as
                  03:00-05:00, every day, in the broker's local time
  --weekly D W    the same, on the days D, such as mon,thu (mon tue wed
                  thu fri sat sun). Give --daily or --weekly, not both.
                  With one of them, --until is a must, --from is optional
                  (default: now), --uses is the number in each window
                  (default 1), and the grant needs no tap after the first.
  --grant-token FILE
                  for a standing grant: the file where the token is
                  written. The token is never printed. It must be a new
                  file, or your own file with mode 0600.
  --reason TEXT   why the grant is needed. Without it, the reason is the
                  environment variable NODKEY_REASON.
  --cancel ID     end a grant of this machine now, without a tap; ID is
                  what nodkey preapprove printed on its standard output

After an approval, the ID of the grant is printed on standard output. For a
standing grant, nodkey run --grant-token FILE uses the token. The
client config is ~/.config/nodkey/client.toml. nodkey preapprove exits with
0 when the person approved or the grant is cancelled, or with 64 (wrong
usage), 69 (the broker cannot be reached) or 77 (denied, or not a grant of
this machine). SIGINT or SIGTERM while it waits cancel the request.
`

// maxPreapproveUses is the most uses that the client sends. The broker
// holds the real limit.
const maxPreapproveUses = 1 << 20

// Preapprove runs nodkey preapprove with args, the arguments after
// "preapprove" (DESIGN.md sections 8 and 15). It writes the ID of an
// approved grant to stdout, and its own messages to stderr. version is
// the version of nodkey, as for Run. It returns the exit code. Its last
// line on stderr is always "nodkey: <result> (exit <code>)".
//
// As nodkey ssh-grant, it catches SIGINT and SIGTERM while it waits, and
// cancels the request.
func Preapprove(args []string, stdout, stderr io.Writer, version string) int {
	g := granter{load: Load, configPath: ConfigPath, environ: os.Environ, now: time.Now, version: version}
	return g.mainPreapprove(args, stdout, stderr)
}

// mainPreapprove is Preapprove with the parts of g.
func (g granter) mainPreapprove(args []string, stdout, stderr io.Writer) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	in := watchInterrupts(cancel)
	defer in.stop()
	code := g.runPreapprove(ctx, args, stdout, stderr)
	var sig interrupted
	if errors.As(context.Cause(ctx), &sig) && code == sig.status() {
		in.stop()
		raise(sig.sig)
	}
	return code
}

// preapproveOptions are the arguments of nodkey preapprove.
type preapproveOptions struct {
	// grantOptions holds the key, the remote user, the hosts and the
	// reason, as for nodkey ssh-grant. Its duration is not used.
	grantOptions
	secrets     []string // in the order of the arguments, each once
	from, until string   // as typed
	uses        int
	cancel      string // --cancel: the ID; the other options are not given
	// windows is the standing grant: one window, from --daily or --weekly.
	// Nil for a scheduled grant.
	windows []api.Window
	// grantToken is the file of --grant-token, for a standing grant.
	grantToken string
}

// runPreapprove runs nodkey preapprove, and returns the exit code.
func (g granter) runPreapprove(ctx context.Context, args []string, stdout, w io.Writer) int {
	stderr := &lockedWriter{w: w}
	if len(args) == 1 && isHelp(args[0]) {
		_, _ = io.WriteString(stderr, preapproveUsage)
		return exitOK
	}
	o, err := parsePreapproveArgs(args)
	if err != nil {
		return UsageError(stderr, "preapprove", err.Error())
	}
	reason := o.reason
	if !o.reasonSet {
		reason = lookupEnv(g.environ(), reasonVar)
	}
	if o.windows != nil {
		// Fail before the tap, not after: the token would have no place.
		if err := CheckGrantTokenFile(o.grantToken); err != nil {
			return fail(stderr, exitUsage, err.Error())
		}
	}
	if o.from == "" {
		o.from = g.now().Format(time.RFC3339)
	}
	path, body, err := newPreapprove(o, reason)
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
	if o.cancel != "" {
		ans, err := Post[api.PreapproveCancelAnswer](ctx, b, path, body, nil)
		if err != nil {
			return requestFailed(ctx, stderr, err)
		}
		if ans.ID != o.cancel {
			return fail(stderr, exitUnavailable, "the answer of the broker is not valid: it names another grant")
		}
		return fail(stderr, exitOK, "grant "+o.cancel+" cancelled")
	}
	var shortCode atomic.Pointer[string]
	ans, err := Post[api.PreapproveAnswer](ctx, b, path, body, func(code string) {
		shortCode.Store(&code)
		_, _ = fmt.Fprintf(stderr, "nodkey: waiting for approval (request %s)\n", code)
	})
	// mayHaveStarted says so when the answer with the ID is lost after the
	// request was sent: the person may have tapped, and the ID is lost.
	mayHaveStarted := func() {
		if code := shortCode.Load(); code != nil {
			warnLine(stderr, "a grant may have started; its ID is in the audit log, in the grant_id of the entries of the request whose message shows "+
				*code+"; cancel it with: nodkey preapprove --cancel ID")
		}
	}
	if err != nil {
		var e *Error
		if !errors.As(err, &e) || e.Status == 0 || e.Status == http.StatusOK {
			// No final answer other than 200: a signal, a broken
			// connection, a timeout, or a 200 that cannot be read.
			mayHaveStarted()
		}
		return requestFailed(ctx, stderr, err)
	}
	valid := validGrantID(ans.ID) && validAnswerTime(ans.From) && validAnswerTime(ans.Until)
	if ctx.Err() != nil {
		// A signal came as the answer did: the broker made a grant, and
		// nobody else knows its ID. Cancel it, then say cancelled. A
		// signal wins over a bad answer, as in nodkey ssh-grant. A valid ID
		// is enough to cancel, even when a time is bad.
		if validGrantID(ans.ID) {
			cancelLeftover(ctx, b, ans.ID, stderr)
		} else {
			mayHaveStarted()
		}
		return cancelled(ctx, stderr)
	}
	if !valid {
		if o.windows != nil && validGrantID(ans.ID) {
			// A standing grant without a usable answer has no use. End it.
			cancelLeftover(ctx, b, ans.ID, stderr)
		} else {
			mayHaveStarted()
		}
		return fail(stderr, exitUnavailable, "the answer of the broker is not valid")
	}
	if err := saveAnswerToken(o, ans.GrantToken); err != nil {
		// A standing grant without its token is of no use. End it.
		cancelLeftover(ctx, b, ans.ID, stderr)
		return fail(stderr, exitUnavailable, err.Error()+"; the grant "+ans.ID+" is cancelled")
	}
	// The grant is made. The ID goes to stdout for a script that cancels.
	_, _ = fmt.Fprintln(stdout, ans.ID)
	_, _ = fmt.Fprintf(stderr, "nodkey: grant %s: %s from %s until %s (exit %d)\n",
		ans.ID, usesText(o.uses), ans.From, ans.Until, exitOK)
	return exitOK
}

// saveAnswerToken checks the token of the answer against the request and
// saves it. A scheduled grant must come with no token; a standing grant
// must come with a token that grantkey.Parse accepts. The errors never
// hold the token.
func saveAnswerToken(o *preapproveOptions, raw string) error {
	if o.windows == nil {
		if raw != "" {
			return errors.New("the answer of the broker is not valid: it has a token for a grant that is not a standing grant")
		}
		return nil
	}
	if raw == "" {
		return errors.New("the answer of the broker is not valid: it has no token")
	}
	tok, err := grantkey.Parse(raw)
	if err != nil {
		return errors.New("the answer of the broker is not valid: its token is not a token")
	}
	if err := SaveGrantToken(o.grantToken, tok); err != nil {
		return err
	}
	return nil
}

// cancelWait is the most time that cancelLeftover waits for the broker.
const cancelWait = 30 * time.Second

// cancelLeftover cancels the grant id that the broker made just as a signal
// came, with a new deadline, because ctx has ended. If that fails, it tells
// the person how to cancel the grant.
func cancelLeftover(ctx context.Context, b *Broker, id string, stderr io.Writer) {
	path, body, err := newPreapprove(&preapproveOptions{cancel: id}, "")
	if err == nil {
		// Not the whole RequestTimeout: the person waits for the exit.
		cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), cancelWait)
		defer stop()
		var ans *api.PreapproveCancelAnswer
		ans, err = Post[api.PreapproveCancelAnswer](cctx, b, path, body, nil)
		if err == nil && ans.ID == id {
			return
		}
	}
	warnLine(stderr, "grant "+id+" may be active; cancel it with: nodkey preapprove --cancel "+id)
}

// validGrantID reports whether id has the form of a grant ID.
func validGrantID(id string) bool {
	if len(id) != 22 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		letter := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		if !letter && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// validAnswerTime reports whether s is a time in RFC 3339 form with an
// offset, as the broker writes it.
func validAnswerTime(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return err == nil && len(s) <= api.MaxTime
}

// usesText returns "1 use" or "N uses".
func usesText(n int) string {
	if n == 1 {
		return "1 use"
	}
	return strconv.Itoa(n) + " uses"
}

// parsePreapproveArgs reads the arguments of nodkey preapprove. They are
// only options: --secret NAME and --host NAME, which may repeat, --key,
// --user, --from, --until, --uses and --reason, or --cancel ID alone. Each
// option may have one dash, and "=" before the value.
//
// It checks what the broker checks too, to give a quick error: the names
// follow the name rule of the config, the remote user matches
// sshauth.ValidUser, there are 1 to api.MaxSecrets secrets
// or 1 to api.MaxGrantHosts hosts, each only once, the times have a form
// that api.ParseTime reads, and the uses are a number from 1. The broker
// checks all of it again, and more: the rules, the limits and the span.
func parsePreapproveArgs(args []string) (*preapproveOptions, error) {
	o := &preapproveOptions{}
	given := make(map[string]bool) // the options that may come only once
	hosts := make(map[string]bool)
	seen := make(map[string]bool) // the secrets
	for rest := args; len(rest) > 0; {
		arg := rest[0]
		rest = rest[1:]
		name, value, hasValue := splitOption(arg)
		switch name {
		case "secret", "key", "user", "host", "from", "until", "uses", "reason", "cancel",
			"daily", "weekly", "grant-token":
		case "h", "help":
			return nil, errors.New("--help must be the only argument")
		default:
			if !strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("unexpected argument %.64q; put each name after its own option", arg)
			}
			return nil, fmt.Errorf("unknown option %.64q", arg)
		}
		if !hasValue {
			if len(rest) == 0 {
				return nil, fmt.Errorf("--%s needs a value", name)
			}
			value, rest = rest[0], rest[1:]
		}
		if name != "host" && name != "secret" {
			if given[name] {
				return nil, fmt.Errorf("--%s is given twice", name)
			}
			given[name] = true
		}
		var err error
		switch name {
		case "daily":
			err = addWindow(o, given, name, value, "")
		case "weekly":
			if len(rest) == 0 {
				return nil, errors.New("--weekly needs days and a window, such as --weekly mon,thu 03:00-05:00")
			}
			var span string
			span, rest = rest[0], rest[1:]
			err = addWindow(o, given, name, value, span)
		case "grant-token":
			if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) {
				err = errors.New("--grant-token: give the path of a file")
			}
			o.grantToken = value
		case "secret":
			err = addSecret(o, seen, value)
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
			err = addGrantHost(&o.grantOptions, hosts, value)
		case "from":
			o.from, err = checkTime(name, value)
		case "until":
			o.until, err = checkTime(name, value)
		case "uses":
			n, perr := strconv.Atoi(value)
			if perr != nil || n < 1 || n > maxPreapproveUses {
				err = fmt.Errorf("--uses %.64q: give a number from 1 to %d", value, maxPreapproveUses)
			}
			o.uses = n
		case "reason":
			o.reason, o.reasonSet = value, true
		case "cancel":
			if !validGrantID(value) {
				err = errors.New("--cancel: the ID is the one that nodkey preapprove printed, 22 characters")
			}
			o.cancel = value
		}
		if err != nil {
			return nil, err
		}
	}
	return o, checkPreapproveGiven(o, given)
}

// checkPreapproveGiven checks that the options that were given fit
// together: --cancel alone, or a request for secrets or for a key with its
// time and uses.
func checkPreapproveGiven(o *preapproveOptions, given map[string]bool) error {
	if given["cancel"] {
		if len(given) > 1 || len(o.secrets) > 0 || len(o.hosts) > 0 {
			return errors.New("--cancel must be the only option")
		}
		return nil
	}
	if o.windows != nil {
		return checkStandingGiven(o, given)
	}
	if given["grant-token"] {
		return errors.New("--grant-token is for a standing grant: give --daily or --weekly")
	}
	switch {
	case len(o.secrets) > 0 && (given["key"] || given["user"] || len(o.hosts) > 0):
		return errors.New("give secrets with --secret, or a key with --key, --user and --host, not both")
	case len(o.secrets) == 0 && !given["key"]:
		return errors.New("give the secrets with --secret NAME, or the key with --key NAME")
	case len(o.secrets) == 0 && !given["user"]:
		return errors.New("give the remote user with --user USER")
	case len(o.secrets) == 0 && len(o.hosts) == 0:
		return errors.New("give at least one host with --host NAME")
	case !given["until"]:
		return errors.New("give the end with --until TIME, such as --until 2026-10-28T04:00")
	case !given["uses"]:
		return errors.New("give the number of uses with --uses N")
	}
	return nil
}

// addSecret adds the value of one --secret to o. seen holds the secrets
// that o has already.
func addSecret(o *preapproveOptions, seen map[string]bool, name string) error {
	switch {
	case !grantNamePattern.MatchString(name):
		return fmt.Errorf("--secret: %.64q is not a secret name: it is %s", name, grantNameRule)
	case seen[name]:
		return fmt.Errorf("--secret: the secret %s is given twice", name)
	case len(o.secrets) == api.MaxSecrets:
		return fmt.Errorf("at most %d --secret options", api.MaxSecrets)
	}
	seen[name] = true
	o.secrets = append(o.secrets, name)
	return nil
}

// checkTime checks that value has a form of api.ParseTime. The zone does
// not matter here: the broker reads a time without an offset in its own
// zone, so only the broker can tell a time that the clock skips.
func checkTime(option, value string) (string, error) {
	if _, err := api.ParseTime(value, time.UTC); err != nil {
		return "", fmt.Errorf("--%s %.64q: give a time such as 2026-10-28T03:00 or 2026-10-28T03:00:00+02:00", option, value)
	}
	return value, nil
}

// newPreapprove returns the path and the JSON body of the request: a
// request for a scheduled grant, or for the cancel of one. A reason over
// api.MaxText bytes becomes "[hidden: too long]", as for nodkey run. Every
// request of the options of parsePreapproveArgs passes: an error here is a
// bug.
func newPreapprove(o *preapproveOptions, reason string) (string, []byte, error) {
	var path string
	var v any
	if o.cancel != "" {
		path, v = api.PathPreapproveCancel, api.PreapproveCancelRequest{ID: o.cancel}
	} else {
		req := api.PreapproveRequest{
			Secrets: o.secrets, Key: o.key, User: o.user, Hosts: o.hosts,
			From: o.from, Until: o.until, Uses: int64(o.uses), Reason: claimedText(reason),
			Windows: o.windows,
		}
		if err := req.Check(); err != nil {
			return "", nil, errors.New("the request is over a cap of the broker")
		}
		path, v = api.PathPreapprove, req
	}
	body, err := json.Marshal(v)
	if err != nil || len(body) > transport.MaxRequestBody {
		return "", nil, errors.New("the request is larger than the broker reads")
	}
	return path, body, nil
}

// checkStandingGiven checks the options of a standing grant: secrets,
// --until and --grant-token are a must; --from and --uses are optional.
func checkStandingGiven(o *preapproveOptions, given map[string]bool) error {
	switch {
	case given["key"] || given["user"] || len(o.hosts) > 0:
		return errors.New("a standing grant is for secrets only; give them with --secret")
	case len(o.secrets) == 0:
		return errors.New("give the secrets with --secret NAME")
	case !given["until"]:
		return errors.New("a standing grant needs its end: give --until TIME, such as --until 2026-12-28T00:00")
	case !given["grant-token"]:
		return errors.New("a standing grant needs --grant-token FILE, the file where the token is written")
	}
	if !given["uses"] {
		o.uses = 1
	}
	return nil
}

// addWindow adds the window of --daily (days "") or --weekly to o. Only one
// of the two may be given, and only once. For --weekly, days is the list
// of day names; span is the window "HH:MM-HH:MM".
func addWindow(o *preapproveOptions, given map[string]bool, option, value, span string) error {
	if given["daily"] && option == "weekly" || given["weekly"] && option == "daily" {
		return errors.New("give --daily or --weekly, not both")
	}
	w := api.Window{Kind: api.WindowDaily, Days: []string{}}
	if option == "weekly" {
		w.Kind = api.WindowWeekly
		days, err := parseDays(value)
		if err != nil {
			return fmt.Errorf("--weekly: %w", err)
		}
		w.Days = days
	} else {
		span = value
	}
	from, to, ok := strings.Cut(span, "-")
	if !ok {
		return fmt.Errorf("--%s %.64q: give a window such as 03:00-05:00", option, span)
	}
	w.From, w.To = from, to
	if err := w.Check(); err != nil {
		return fmt.Errorf("--%s %.64q: give a window of two times HH:MM on one day, such as 03:00-05:00, with the first before the second", option, span)
	}
	o.windows = []api.Window{w}
	return nil
}

// parseDays reads day names such as "mon,thu": lower case, each once. It
// returns them in the order of the week.
func parseDays(s string) ([]string, error) {
	var days []string
	for name := range strings.SplitSeq(s, ",") {
		if !slices.Contains(api.Weekdays[:], name) {
			return nil, fmt.Errorf("%.64q is not a day; use mon, tue, wed, thu, fri, sat or sun, with commas, such as mon,thu", name)
		}
		if slices.Contains(days, name) {
			return nil, fmt.Errorf("the day %s is given twice", name)
		}
		days = append(days, name)
	}
	slices.SortFunc(days, func(a, b string) int {
		return slices.Index(api.Weekdays[:], a) - slices.Index(api.Weekdays[:], b)
	})
	return days, nil
}
