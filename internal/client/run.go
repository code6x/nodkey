package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/grantkey"
	"github.com/code6x/nodkey/internal/transport"
)

// The exit codes of nodkey run when nodkey itself exits (DESIGN.md section
// 15). When the person approves, the command replaces nodkey, and the
// command's exit code is the exit code of nodkey run.
const (
	exitOK          = 0
	exitUsage       = 64  // EX_USAGE: wrong usage
	exitUnavailable = 69  // EX_UNAVAILABLE: the broker cannot be reached, or it answered with an error
	exitDenied      = 77  // EX_NOPERM: denied, expired or not allowed
	exitCannotRun   = 126 // the command was found but cannot be run
	exitNotFound    = 127 // the command was not found
)

// runUsage is the help of nodkey run.
const runUsage = `Usage: nodkey run [--secret VAR=NAME]... [--grant-token FILE] [--reason TEXT] -- COMMAND [ARGS...]

Ask the broker for secrets, and wait until a person approves the request
on the phone. Then run COMMAND, with the value of the secret NAME in the
environment variable VAR. nodkey never prints a value.

  --secret VAR=NAME  a secret for COMMAND; 1 to 32 of them. VAR must match
                     [A-Z_][A-Z0-9_]{0,63}, and must not be a name whose
                     value programs show or run, such as PATH, LD_PRELOAD
                     or GIT_SSH_COMMAND. NAME is a secret of the broker.
  --grant-token FILE the token file of a standing grant (nodkey preapprove).
                     With it, no tap is needed inside a window of the grant.
                     nodkey replaces the token in FILE with a new one before
                     it runs COMMAND, and never prints it. If FILE cannot be
                     saved, COMMAND does not run (exit 77).
  --reason TEXT      why COMMAND needs the secrets. Without it, the reason
                     is the environment variable NODKEY_REASON.

The client config is ~/.config/nodkey/client.toml. nodkey run exits with
the exit code of COMMAND, or with 64 (wrong usage), 69 (the broker cannot
be reached), 77 (denied), 126 (COMMAND cannot be run) or 127 (COMMAND was
not found). SIGINT or SIGTERM while it waits cancel the request.
`

// tooLong replaces a claimed field that is too long to send (DESIGN.md
// section 10). The broker shows it as any claimed text.
const tooLong = "[hidden: too long]"

// reasonVar holds the reason when --reason is not given.
const reasonVar = "NODKEY_REASON"

// Run runs nodkey run with args, the arguments after "run", and writes its
// own messages to stderr. version is the version of nodkey: it goes to the
// broker, and Run prints a warning when the broker runs another version.
// When the person approves, the command replaces nodkey (execve), with the
// values in its environment, and Run does not return. Otherwise Run
// returns the exit code of DESIGN.md section 15, and the last line on
// stderr is "nodkey: <reason> (exit <code>)".
//
// Run never ignores SIGPIPE: an ignored signal stays ignored after execve,
// so the command would run with it ignored. Run catches SIGINT and SIGTERM
// only until the command starts. When one comes, Run cancels the request:
// the connection closes, so the broker cancels the request too. Then it
// prints its last line and ends nodkey with the same signal, so that a
// shell sees it, as for a program that does not catch it. Right before the
// command starts, Run stops catching them, so they end nodkey as they end
// any Go program.
func Run(args []string, stderr io.Writer, version string) int {
	r := runner{load: Load, configPath: ConfigPath, environ: os.Environ, exec: syscall.Exec,
		notDumpable: notDumpable, version: version}
	return r.main(args, stderr)
}

// runner runs nodkey run. Tests replace its parts.
type runner struct {
	// load reads the client config and the TLS key: Load.
	load func(path string) (*Broker, error)
	// configPath returns the path of the client config: ConfigPath.
	configPath func() (string, error)
	// environ returns the environment: os.Environ.
	environ func() []string
	// exec replaces nodkey with the command: syscall.Exec, which returns
	// only when it fails. A test's exec may return nil; then the run ends
	// with 0.
	exec func(argv0 string, argv, envv []string) error
	// notDumpable marks nodkey as not dumpable before it asks for the
	// values: notDumpable. Tests in the test process replace it, so the
	// test process stays as it is.
	notDumpable func() error
	// version is the version of nodkey (warnVersions); "" sends none.
	version string
}

// main is Run with the parts of r.
func (r runner) main(args []string, stderr io.Writer) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	in := watchInterrupts(cancel)
	defer in.stop()
	code := r.run(ctx, args, stderr, in.stop)
	var sig interrupted
	if errors.As(context.Cause(ctx), &sig) && code == sig.status() {
		// run printed "cancelled by SIG... (exit 128+N)". A shell stops a
		// loop or a script only when a command dies of SIGINT; when the
		// command just exits, it goes on with the next request.
		in.stop()
		raise(sig.sig)
	}
	return code
}

// run runs nodkey run, and returns the exit code when nodkey itself exits.
// When ctx ends, run cancels the request, and returns the code of
// cancelled. beforeExec runs right before the command starts; after it,
// run looks at ctx once more.
func (r runner) run(ctx context.Context, args []string, w io.Writer, beforeExec func()) int {
	stderr := &lockedWriter{w: w}
	if len(args) == 1 && isHelp(args[0]) {
		_, _ = io.WriteString(stderr, runUsage)
		return exitOK
	}
	o, err := parseArgs(args)
	if err != nil {
		_, _ = io.WriteString(stderr, runUsage)
		return fail(stderr, exitUsage, err.Error())
	}
	// Look for the command before anyone is asked: a person must never
	// approve a command that cannot start. path is absolute.
	path, code, err := lookPath(o.command[0])
	if err != nil {
		return fail(stderr, code, err.Error())
	}
	env := r.environ()
	reason := o.reason
	if !o.reasonSet {
		reason = lookupEnv(env, reasonVar)
	}
	dir, err := os.Getwd()
	if err != nil {
		dir = "" // the message then has no "in:" line
	}
	// The message shows the file that runs: the program as the path that
	// PATH found, and the arguments as they are. execve gets argv as it is.
	shown := append([]string{path}, o.command[1:]...)
	body, err := encodeRequest(newRequest(o.secrets, shown, dir, reason))
	if err != nil {
		return fail(stderr, exitUsage, err.Error())
	}
	// Check the token file before any request, so a bad file asks no one.
	var hdr http.Header
	if o.grantToken != "" {
		tok, err := readGrantToken(o.grantToken)
		if err != nil {
			return fail(stderr, exitUsage, err.Error())
		}
		hdr = http.Header{api.GrantTokenHeader: {tok.Reveal()}}
	}
	configPath, err := r.configPath()
	if err != nil {
		return fail(stderr, exitUnavailable, err.Error())
	}
	b, err := r.load(configPath)
	if err != nil {
		return fail(stderr, exitUnavailable, err.Error())
	}
	b.warnVersions(r.version, func(text string) { warnLine(stderr, text) })
	// From here on, nodkey may hold values. So it writes no core dump, and
	// other processes of the user cannot read its memory. execve makes the
	// command dumpable again (DESIGN.md section 16).
	if err := r.notDumpable(); err != nil {
		return fail(stderr, exitUnavailable, "cannot mark nodkey as not dumpable: "+err.Error())
	}
	// A request with a token is never sent again (postWith sends once).
	ans, err := postWith[api.SecretsAnswer](ctx, b, api.PathSecrets, body, func(code string) {
		_, _ = fmt.Fprintf(stderr, "nodkey: waiting for approval (request %s)\n", code)
	}, hdr)
	if err != nil {
		return requestFailed(ctx, stderr, err)
	}
	// The new token is saved before the values are used (DESIGN.md section
	// 8). If it cannot be, the command does not run.
	if err := rotateToken(o.grantToken, ans.GrantToken); err != nil {
		ans.Clear()
		if errors.Is(err, ErrTokenFile) {
			return fail(stderr, exitDenied, err.Error()) // DESIGN.md section 15: exit 77
		}
		return fail(stderr, exitUnavailable, err.Error())
	}
	envv, err := commandEnv(env, o.secrets, ans)
	ans.Clear() // best effort: envv holds the values as Go strings
	if err != nil {
		// The person approved, and the broker sent a wrong answer: as for
		// an answer that is not valid.
		return fail(stderr, exitUnavailable, err.Error())
	}
	beforeExec()
	if ctx.Err() != nil {
		return cancelled(ctx, stderr)
	}
	if err := r.exec(path, o.command, envv); err != nil {
		return fail(stderr, exitCannotRun, fmt.Sprintf("cannot run %q: %v", path, err))
	}
	return exitOK
}

// cancelled reports a run whose context ended before the command started,
// and returns its exit code. For SIGINT and SIGTERM, that is the status
// that a shell shows for a command that the signal ended: 128 and the
// number of the signal, 130 or 143. main then ends nodkey with the signal.
func cancelled(ctx context.Context, stderr io.Writer) int {
	var sig interrupted
	if errors.As(context.Cause(ctx), &sig) {
		return fail(stderr, sig.status(), "cancelled by "+sig.name())
	}
	return fail(stderr, exitDenied, "cancelled")
}

// requestFailed reports a request for secrets that got no valid answer,
// and returns the exit code: 77 when the broker denied it (403 or 429),
// the one of cancelled when SIGINT or SIGTERM stopped it, and 69 otherwise
// (DESIGN.md section 15).
func requestFailed(ctx context.Context, stderr io.Writer, err error) int {
	var e *Error
	switch {
	case ctx.Err() != nil:
		return cancelled(ctx, stderr)
	case errors.As(err, &e) && e.Denied():
		return fail(stderr, exitDenied, e.Error())
	case errors.As(err, &e):
		return fail(stderr, exitUnavailable, e.Error())
	default:
		return fail(stderr, exitUnavailable, "the request to the broker failed")
	}
}

// fail writes the last line of nodkey run when nodkey itself exits
// (DESIGN.md section 15), "nodkey: <reason> (exit <code>)", and returns
// code.
func fail(w io.Writer, code int, reason string) int {
	_, _ = fmt.Fprintf(w, "nodkey: %s (exit %d)\n", oneLine(reason), code)
	return code
}

// warnLine writes "nodkey: " and text as one line, such as a warning about
// the version of the broker. It comes before the last line.
func warnLine(w io.Writer, text string) {
	_, _ = io.WriteString(w, "nodkey: "+oneLine(text)+"\n")
}

// oneLine replaces control characters and line breaks in s with spaces.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

// lockedWriter writes to w under a lock: the short code comes from a
// goroutine of net/http.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// isHelp reports whether arg asks for the help: -h or --help, also -help
// and --h, as the flag package reads them.
func isHelp(arg string) bool {
	name, _, hasValue := splitOption(arg)
	return !hasValue && (name == "h" || name == "help")
}

// runOptions are the arguments of nodkey run.
type runOptions struct {
	secrets   []api.SecretRef
	reason    string
	reasonSet bool
	// grantToken is the file of --grant-token ("" for none).
	grantToken string
	command    []string
}

// parseArgs reads the arguments of nodkey run: the options, "--", and the
// command. Options are --secret VAR=NAME, which may repeat, and --reason
// TEXT, each also with one dash and with "=" before the value, as the flag
// package reads them. The command must come after "--", so that its own
// options are never read as options of nodkey run.
//
// It checks what the broker checks too, to give a quick error: 1 to
// api.MaxSecrets variables, each name valid (api.ValidVar), not on the
// deny list (api.DeniedVar) and there only once, and each secret name 1
// to api.MaxName bytes. The broker checks all of it again.
func parseArgs(args []string) (*runOptions, error) {
	o := &runOptions{}
	vars := make(map[string]bool)
	for rest := args; len(rest) > 0; {
		arg := rest[0]
		rest = rest[1:]
		if arg == "--" {
			o.command = rest
			switch {
			case len(o.command) == 0:
				return nil, errors.New(`no command after "--"`)
			case len(o.secrets) == 0:
				return nil, errors.New("give at least one --secret VAR=NAME")
			}
			return o, nil
		}
		name, value, hasValue := splitOption(arg)
		switch name {
		case "secret", "reason", "grant-token":
		case "h", "help":
			// With other arguments, help would exit with 0 and run
			// nothing, which looks like a command that ran.
			return nil, errors.New("--help must be the only argument")
		default:
			if !strings.HasPrefix(arg, "-") {
				return nil, errors.New(`put "--" before the command, as in: ` +
					`nodkey run --secret GH_TOKEN=github-token -- gh release create v1.2.0`)
			}
			return nil, fmt.Errorf("unknown option %.64q", arg)
		}
		if !hasValue {
			if len(rest) == 0 {
				return nil, fmt.Errorf("--%s needs a value", name)
			}
			value, rest = rest[0], rest[1:]
		}
		if name == "grant-token" {
			if o.grantToken != "" {
				return nil, errors.New("--grant-token is given twice")
			}
			if value == "" {
				return nil, errors.New("--grant-token needs a file")
			}
			o.grantToken = value
			continue
		}
		if name == "reason" {
			if o.reasonSet {
				return nil, errors.New("--reason is given twice")
			}
			o.reason, o.reasonSet = value, true
			continue
		}
		ref, err := parseSecret(value)
		if err != nil {
			return nil, err
		}
		switch {
		case vars[ref.Var]:
			return nil, fmt.Errorf("--secret: the variable %s is given twice", ref.Var)
		case len(o.secrets) == api.MaxSecrets:
			return nil, fmt.Errorf("at most %d --secret options", api.MaxSecrets)
		}
		vars[ref.Var] = true
		o.secrets = append(o.secrets, ref)
	}
	return nil, errors.New(`put "--" before the command, as in: ` +
		`nodkey run --secret GH_TOKEN=github-token -- gh release create v1.2.0`)
}

// splitOption splits an option such as --secret=VALUE or -reason into its
// name and value. name is "" for an argument that is not an option.
func splitOption(arg string) (name, value string, hasValue bool) {
	if len(arg) < 2 || arg[0] != '-' {
		return "", "", false
	}
	s := arg[1:]
	if s[0] == '-' {
		s = s[1:]
	}
	return strings.Cut(s, "=")
}

// parseSecret reads the value of --secret: VAR=NAME.
func parseSecret(value string) (api.SecretRef, error) {
	v, name, ok := strings.Cut(value, "=")
	prefix, denied := api.DeniedVar(v)
	switch {
	case !ok:
		return api.SecretRef{}, errors.New("--secret needs VAR=NAME, such as GH_TOKEN=github-token")
	case !api.ValidVar(v):
		return api.SecretRef{}, fmt.Errorf("--secret: the variable name %.64q must match [A-Z_][A-Z0-9_]{0,63}", v)
	case denied && prefix != "":
		return api.SecretRef{}, fmt.Errorf("--secret %s=...: nodkey refuses variables that start with %s, "+
			"because programs show or run their values", v, prefix)
	case denied:
		return api.SecretRef{}, fmt.Errorf("--secret %s=...: nodkey refuses the variable %s, "+
			"because programs show or run its value", v, v)
	case name == "" || len(name) > api.MaxName:
		return api.SecretRef{}, fmt.Errorf("--secret %s=...: the secret name must have 1 to %d bytes",
			v, api.MaxName)
	}
	return api.SecretRef{Var: v, Name: name}, nil
}

// lookPath finds the command name as a shell does, with the PATH of
// nodkey (exec.LookPath). It returns the absolute path to run, or the exit
// code and the reason: 127 when the command is not found, and 126 when it
// is found but cannot be run, such as a directory, a file without execute
// permission, or a file that PATH finds only through a relative directory
// such as ".".
func lookPath(name string) (string, int, error) {
	path, err := exec.LookPath(name)
	// exec.LookPath refuses a relative result for a name without "/"
	// (exec.ErrDot), but GODEBUG=execerrdot=0 turns that off; the agent
	// sets GODEBUG. So check it here too.
	relative := err == nil && !strings.Contains(name, "/") && !filepath.IsAbs(path)
	var ee *exec.Error
	switch {
	case errors.Is(err, exec.ErrDot), relative:
		return "", exitCannotRun, fmt.Errorf("%.64q is found only in a relative directory of PATH, such as "+
			`"."; give its path instead`, name)
	case err == nil:
		abs, err := absolute(path)
		if err != nil {
			return "", exitCannotRun, fmt.Errorf("cannot find the absolute path of %.64q: %w", name, err)
		}
		return abs, exitOK, nil
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return "", exitNotFound, fmt.Errorf("command %.64q not found", name)
	case errors.As(err, &ee):
		return "", exitCannotRun, fmt.Errorf("cannot run %.64q: %w", name, ee.Err)
	default:
		return "", exitCannotRun, fmt.Errorf("cannot run %.64q", name)
	}
}

// absolute returns path as an absolute path of the same file, the file
// that exec.LookPath checked. A relative path starts from the real working
// directory (syscall.Getwd), not from $PWD, which can name the directory
// through a symbolic link. The path is not cleaned: in "a/link/../b", the
// kernel follows link before "..", so it is not "a/b".
func absolute(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	wd, err := syscall.Getwd()
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(wd, "/") {
		wd += "/"
	}
	return wd + path, nil
}

// lookupEnv returns the value of the variable name in env, or "". As in
// Go's os.Getenv, the first one counts.
func lookupEnv(env []string, name string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// newRequest makes the request for secrets: the variables, and the
// claimed command line, working directory and reason (DESIGN.md sections
// 5 and 10). A text over api.MaxText bytes, and a command line with more
// than api.MaxArgs arguments or more than api.MaxText bytes in all,
// become "[hidden: too long]": a command line becomes one argument with
// that text. The broker would not show them anyway, and so every request
// fits in the broker's cap on its size.
func newRequest(secrets []api.SecretRef, command []string, dir, reason string) api.SecretsRequest {
	return api.SecretsRequest{
		Secrets: secrets,
		Command: claimedCommand(command),
		Dir:     claimedText(dir),
		Reason:  claimedText(reason),
	}
}

// claimedText returns s, or "[hidden: too long]" when s is too long.
func claimedText(s string) string {
	if len(s) > api.MaxText {
		return tooLong
	}
	return s
}

// claimedCommand returns argv, or one argument "[hidden: too long]" when
// argv is too long. The bytes of all arguments count together, as for the
// broker (claim.Command).
func claimedCommand(argv []string) []string {
	if len(argv) > api.MaxArgs {
		return []string{tooLong}
	}
	size := 0
	for _, a := range argv {
		if size += len(a); size > api.MaxText {
			return []string{tooLong}
		}
	}
	return argv
}

// encodeRequest returns req as JSON. It checks the caps of the request,
// and that the body is not larger than the broker reads
// (transport.MaxRequestBody). Every request of newRequest passes: an error
// here is a bug.
func encodeRequest(req api.SecretsRequest) ([]byte, error) {
	if err := req.Check(); err != nil {
		return nil, errors.New("the request is over a cap of the broker")
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > transport.MaxRequestBody {
		return nil, errors.New("the request is larger than the broker reads")
	}
	return body, nil
}

// commandEnv checks the broker's answer against the request, and returns
// the environment for the command: env without the variables of secrets,
// and then each variable with its value, in the order of secrets. So a
// value replaces a variable of the same name.
//
// The answer must have exactly one value for each variable, in the same
// order and with the same names, each 1 byte to api.MaxValue bytes,
// without a NUL byte (the environment cannot hold one), and at most
// api.MaxValues bytes together. Otherwise the command must not run. An
// error never holds a value, or a name from the answer.
func commandEnv(env []string, secrets []api.SecretRef, ans *api.SecretsAnswer) ([]string, error) {
	if len(ans.Secrets) != len(secrets) {
		return nil, fmt.Errorf("the answer of the broker has %d values for %d variables",
			len(ans.Secrets), len(secrets))
	}
	total := 0
	for i, ref := range secrets {
		s, want := ans.Secrets[i], ref.Var
		total += len(s.Value)
		switch {
		case s.Var != want:
			return nil, fmt.Errorf("the answer of the broker has another variable where %s should be", want)
		case len(s.Value) == 0:
			return nil, fmt.Errorf("the answer of the broker has an empty value for %s", want)
		case len(s.Value) > api.MaxValue, total > api.MaxValues:
			return nil, fmt.Errorf("the answer of the broker has a value for %s that is too long", want)
		case bytes.IndexByte(s.Value, 0) >= 0:
			return nil, fmt.Errorf("the answer of the broker has a value with a NUL byte for %s", want)
		}
	}
	drop := make(map[string]bool, len(secrets))
	for _, s := range secrets {
		drop[s.Var] = true
	}
	out := make([]string, 0, len(env)+len(secrets))
	for _, kv := range env {
		if name, _, _ := strings.Cut(kv, "="); !drop[name] {
			out = append(out, kv)
		}
	}
	for _, s := range ans.Secrets {
		out = append(out, s.Var+"="+string(s.Value))
	}
	return out, nil
}

// interrupted is the cause of the end of a run's context when nodkey got
// SIGINT or SIGTERM.
type interrupted struct{ sig syscall.Signal }

func (e interrupted) Error() string { return "client: " + e.name() }

// name returns the name of the signal, such as "SIGINT".
func (e interrupted) name() string {
	switch e.sig {
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGTERM:
		return "SIGTERM"
	}
	return "signal " + strconv.Itoa(int(e.sig))
}

// status returns the status that a shell shows for a command that the
// signal ended: 128 and the number of the signal.
func (e interrupted) status() int { return 128 + int(e.sig) }

// interrupts ends a run's context on SIGINT or SIGTERM, until stop.
type interrupts struct {
	ch     chan os.Signal
	quit   chan struct{}
	done   chan struct{}
	cancel context.CancelCauseFunc
	once   sync.Once
}

// watchInterrupts starts to watch for SIGINT and SIGTERM. A signal that
// nodkey ignores, as a shell makes a job in the background ignore SIGINT,
// stays ignored. SIGPIPE is never touched.
func watchInterrupts(cancel context.CancelCauseFunc) *interrupts {
	in := &interrupts{ch: make(chan os.Signal, 1), quit: make(chan struct{}), done: make(chan struct{}),
		cancel: cancel}
	var sigs []os.Signal
	for _, s := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		if !signal.Ignored(s) {
			sigs = append(sigs, s)
		}
	}
	if len(sigs) > 0 {
		signal.Notify(in.ch, sigs...)
	}
	go func() {
		defer close(in.done)
		select {
		case s := <-in.ch:
			cancel(interruptedBy(s))
		case <-in.quit:
		}
	}()
	return in
}

// interruptedBy returns the cause of the end of a run's context for the
// signal s.
func interruptedBy(s os.Signal) interrupted {
	sig, ok := s.(syscall.Signal)
	if !ok {
		sig = syscall.SIGINT
	}
	return interrupted{sig: sig}
}

// stop stops the watch. From then on, SIGINT and SIGTERM end nodkey, as
// they end any Go program; after execve, the command has the usual
// handling of them. A signal that came before stop ends the context. stop
// may be called more than once.
func (in *interrupts) stop() {
	in.once.Do(func() {
		close(in.quit)
		<-in.done
		signal.Stop(in.ch)
		select {
		case s := <-in.ch:
			in.cancel(interruptedBy(s))
		default:
		}
	})
}

// readGrantToken checks the token file and reads the token from it. The
// errors never hold the token.
func readGrantToken(path string) (grantkey.Token, error) {
	if err := CheckGrantTokenFile(path); err != nil {
		return grantkey.Token{}, err
	}
	data, err := os.ReadFile(path) //nolint:gosec,forbidigo // G304: the path is the person's; CheckGrantTokenFile checked owner and mode above.
	if err != nil {
		return grantkey.Token{}, fmt.Errorf("%w: cannot read %q: %s", ErrTokenFile, path, errText(err))
	}
	tok, err := grantkey.Parse(strings.TrimSuffix(string(data), "\n"))
	if err != nil {
		return grantkey.Token{}, fmt.Errorf("%w: %q does not hold a token", ErrTokenFile, path)
	}
	return tok, nil
}

// rotateToken saves the new token raw of the answer to the file path. With
// a file, the answer must have a valid new token. Without one, the answer
// must have none. The errors never hold the token.
func rotateToken(path, raw string) error {
	if path == "" {
		if raw != "" {
			return errors.New("the answer of the broker is not valid: it has a token for a request without one")
		}
		return nil
	}
	if raw == "" {
		return errors.New("the answer of the broker is not valid: it has no new token; the command does not run")
	}
	tok, err := grantkey.Parse(raw)
	if err != nil {
		return errors.New("the answer of the broker is not valid: its new token is not a token; the command does not run")
	}
	if err := SaveGrantToken(path, tok); err != nil {
		return fmt.Errorf("%w; the command does not run", err)
	}
	return nil
}
