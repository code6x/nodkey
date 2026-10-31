package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/client"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/telegram"
	"github.com/code6x/nodkey/internal/transport"
)

// tryDirName is the directory of the trial, in $XDG_RUNTIME_DIR or else
// in the user's cache directory. Its path is fixed, so that nodkey try run
// finds the trial without a flag or a variable.
const tryDirName = "nodkey-try"

// The files in the directory of the trial.
const (
	tryLockFile   = "lock"
	tryBrokerKey  = "broker.key"
	tryClientKey  = "client.key"
	tryClientConf = "client.toml"
	tryAuditLog   = "audit.log"
	tryBrokerLog  = "broker.log"
)

// tryClientName is the name of the one client of the trial.
const tryClientName = "try-client"

// tryStoreName is the name of the one store of the trial.
const tryStoreName = "try"

// tryTimeout is how long a request of the trial waits for an answer, and
// tryWindow is the N of "Approve N min". They are variables only so that
// a test can make them short.
var (
	tryTimeout = 120 * time.Second
	tryWindow  = 5 * time.Minute
)

const tryUsage = `Usage: nodkey try [--telegram]
       nodkey try run [--secret VAR=NAME]... [--reason TEXT] -- COMMAND [ARGS...]

Try nodkey on this machine, with fake secrets, in a few minutes. It needs
no root, no config file and no store account.

nodkey try starts a trial broker on 127.0.0.1, with a test store of three
fake secrets: demo-token, demo-password and demo-api-key. Their values are
random and start with TRY-. It asks for each request in its own terminal:
Approve once, Approve N min, or Deny. A request with no answer expires and
is denied. Its files are in a new directory, $XDG_RUNTIME_DIR/nodkey-try
(or the cache directory of the user), and Ctrl-C removes them.

nodkey try run is nodkey run with the client config of the trial. Run it
in a second terminal while nodkey try runs. It never reads
~/.config/nodkey/client.toml.

With --telegram, the requests show up in Telegram on your phone instead.
Make a new bot with @BotFather for this, never the bot of a real broker.
nodkey try asks for its token (hidden, kept only in memory), prints a link
that you open on the phone, and takes your user ID from that message.

Try mode is not a setup: it shows the flow, never a real secret. See
docs/setup.md for a real one.
`

// runTry runs nodkey try with args (after "try") and returns the exit
// code.
func runTry(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "run" {
		return runTryRun(args[1:], stderr)
	}
	fs := flag.NewFlagSet("nodkey try", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	useTelegram := fs.Bool("telegram", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stderr, tryUsage)
		}
		return parseErrorCode(stderr, "try", err)
	}
	if fs.NArg() > 0 {
		return usageFail(stderr, "try", fmt.Sprintf("unexpected argument %.64q; it takes none, or run", fs.Arg(0)))
	}
	dir, err := tryDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey try: TRY MODE: %s (exit 1)\n", err)
		return exitFailure
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer stop()
	var tg *tryTelegram
	if *useTelegram {
		tg, err = setupTryTelegram(ctx, bufio.NewReaderSize(stdin, maxTryLine), stdin, stdout)
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "nodkey try: TRY MODE: %s (exit 1)\n", err)
			return exitFailure
		}
	}
	return serveTry(ctx, dir, stdin, stdout, tg)
}

// runTryRun runs nodkey try run: nodkey run with the client config of the
// trial. Each line that nodkey itself writes says TRY MODE.
func runTryRun(args []string, stderr io.Writer) int {
	out := &tryLines{w: stderr, start: true}
	dir, err := tryDir()
	if err != nil {
		_, _ = fmt.Fprintf(out, "nodkey: %s (exit 69)\n", err)
		return 69
	}
	conf := filepath.Join(dir, tryClientConf)
	if _, err := os.Lstat(conf); err != nil {
		_, _ = fmt.Fprintf(out, "nodkey: no trial runs: start nodkey try in another terminal first (exit 69)\n")
		return 69
	}
	return client.RunWithConfig(args, out, version, conf)
}

// tryLines writes to w and starts each line with "TRY MODE ".
type tryLines struct {
	mu    sync.Mutex
	w     io.Writer
	start bool // the next byte starts a line
}

func (t *tryLines) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var b []byte
	for _, c := range p {
		if t.start {
			b = append(b, "TRY MODE "...)
			t.start = false
		}
		b = append(b, c)
		if c == '\n' {
			t.start = true
		}
	}
	if _, err := t.w.Write(b); err != nil {
		return 0, err
	}
	return len(p), nil
}

// tryDir returns the path of the directory of the trial. Its parent must
// exist: nodkey try makes nothing outside of it.
func tryDir() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return "", errors.New("neither XDG_RUNTIME_DIR nor the cache directory of the user is known")
		}
		base = d
	}
	if !filepath.IsAbs(base) {
		return "", errors.New("the directory for the trial is not an absolute path")
	}
	return filepath.Join(base, tryDirName), nil
}

// trial is a running trial.
type trial struct {
	dir   string
	lock  *os.File
	made  bool // this run made the directory
	logF  *os.File
	log   *slog.Logger
	audit *audit.Logger
	store *tryStore
	svc   *broker.Service
	srv   *transport.Server

	stopRun   context.CancelFunc
	runDone   chan struct{}
	runErr    error // the error of the approver's Run; read after runDone
	serveDone chan struct{}
}

// serveTry runs the trial in dir until ctx ends or a part stops, then
// stops it and removes dir.
// With tg, the approver is the Telegram bot of tg, and ap only prints.
func serveTry(ctx context.Context, dir string, stdin io.Reader, stdout io.Writer, tg *tryTelegram) int {
	tr := &trial{dir: dir}
	ap := newTryApprover(stdin, stdout)
	addr, err := tr.start(ap, tg)
	code := exitOK
	if err != nil {
		ap.say(fmt.Sprintf("nodkey try: TRY MODE: cannot start: %s\n", err))
		code = exitFailure
	} else {
		ap.say(tryIntro(addr, tg != nil))
		select {
		case <-ctx.Done():
		case <-tr.runDone:
			if tg != nil {
				ap.say("nodkey try: TRY MODE: Telegram stopped: " + tryTelegramErr(tr.runErr) + "\n")
			} else {
				ap.say("nodkey try: TRY MODE: the terminal approver stopped: no answer can come any more\n")
			}
			code = exitFailure
		case <-tr.serveDone:
			ap.say("nodkey try: TRY MODE: the trial broker stopped\n")
			code = exitFailure
		}
	}
	if !tr.stop() {
		ap.say(fmt.Sprintf("nodkey try: TRY MODE: cannot remove %s; remove it yourself\n", dir))
		code = exitFailure
	}
	ap.say(tryOutro)
	return code
}

// start makes the directory and the parts of the trial: the keys, the
// config, the audit log, the store, the service, the approval core with
// the terminal approver, and the server on 127.0.0.1 with a random port.
func (tr *trial) start(ap *tryApprover, tg *tryTelegram) (string, error) {
	// As nodkey broker: no core dumps, and other processes of the user
	// cannot read its memory. It needs no root.
	if err := hardenProcess(); err != nil {
		return "", fmt.Errorf("cannot turn off core dumps: %w", err)
	}
	if err := tr.makeDir(); err != nil {
		return "", err
	}
	logF, err := os.OpenFile(filepath.Join(tr.dir, tryBrokerLog), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	tr.logF = logF
	tr.log = broker.NewLogger(logF)
	brokerKey := filepath.Join(tr.dir, tryBrokerKey)
	brokerPin, err := transport.GenerateKeyFile(brokerKey)
	if err != nil {
		return "", err
	}
	clientKey := filepath.Join(tr.dir, tryClientKey)
	clientPin, err := transport.GenerateKeyFile(clientKey)
	if err != nil {
		return "", err
	}
	tlsKey, err := transport.LoadKeyFile(brokerKey)
	if err != nil {
		return "", err
	}
	userID := int64(tryUserID)
	if tg != nil {
		userID = tg.userID
	}
	cfg := tryConfig(tr.dir, clientPin, userID)
	tr.audit, err = audit.Open(cfg.AuditLog, audit.Options{Journal: logF, Alert: func(audit.Recovery) {}})
	if err != nil {
		return "", err
	}
	tr.store = newTryStore()
	tr.svc, err = broker.New(broker.Parts{Config: cfg, Audit: tr.audit,
		Stores: map[string]store.Store{tryStoreName: tr.store}, Logger: tr.log, Version: version})
	if err != nil {
		return "", err
	}
	var approver approval.Approver = ap
	if tg != nil {
		tga, err := telegram.NewWithToken(cfg.Telegram, tg.token,
			telegram.Options{Logger: tr.log, ForeignTap: tr.svc.ForeignTap, Prefix: tryPrefix})
		clear(tg.token)
		if err != nil {
			return "", err
		}
		approver = tga
	}
	core, err := approval.New(cfg, approver, approval.Options{Logger: tr.log})
	if err != nil {
		return "", err
	}
	tr.srv, err = transport.NewServer(tlsKey, cfg.Clients, tr.svc, tr.log)
	if err != nil {
		return "", err
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	if err := writeTryClientConfig(filepath.Join(tr.dir, tryClientConf), addr, brokerPin, clientKey); err != nil {
		_ = ln.Close()
		return "", err
	}
	if _, err := tr.audit.Append(audit.BrokerStarted{Version: version}); err != nil {
		_ = ln.Close()
		return "", err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	tr.stopRun = cancel
	tr.runDone = make(chan struct{})
	say := func(_ context.Context, msg string) error {
		ap.say("nodkey try: TRY MODE: " + tryClean(msg) + "\n")
		return nil
	}
	go func() {
		defer close(tr.runDone)
		tr.runErr = tr.svc.Run(runCtx, core, say, say)
	}()
	tr.serveDone = make(chan struct{})
	go func() {
		defer close(tr.serveDone)
		_ = tr.srv.Serve(ln)
	}()
	return addr, nil
}

// makeDir makes the directory of the trial, mode 0700, and locks it. A
// directory of an earlier trial that did not end cleanly, such as after
// SIGKILL, is removed first, but only when no trial holds its lock.
func (tr *trial) makeDirOnce() error {
	err := os.Mkdir(tr.dir, 0o700)
	if errors.Is(err, fs.ErrExist) {
		if err := removeStaleTryDir(tr.dir); err != nil {
			return err
		}
		err = os.Mkdir(tr.dir, 0o700)
	}
	if err != nil {
		return err
	}
	tr.made = true
	// The umask may have removed bits of the owner; it never adds any.
	if err := os.Chmod(tr.dir, 0o700); err != nil { //nolint:gosec // G302: a directory, private to its owner.
		return err
	}
	// The lock file gets its name only after it is locked. So another
	// start never finds it unlocked while this trial runs.
	lock := filepath.Join(tr.dir, tryLockFile)
	f, err := os.OpenFile(lock+".new", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the trial's own directory.
	if err != nil {
		return err
	}
	tr.lock = f
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	return os.Rename(lock+".new", lock)
}

// makeDir makes the directory of the trial. When it fails after the
// directory exists, the directory is removed again.
func (tr *trial) makeDir() error {
	if err := tr.makeDirOnce(); err != nil {
		tr.removeMade()
		return err
	}
	return nil
}

// removeMade removes the directory, which this run made, and closes the lock.
func (tr *trial) removeMade() {
	if tr.made {
		_ = os.RemoveAll(tr.dir)
	}
	if tr.lock != nil {
		_ = tr.lock.Close()
		tr.lock = nil
	}
}

// removeStaleTryDir removes dir, the directory of an earlier trial, when
// it holds a lock file that no trial holds.
func removeStaleTryDir(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, tryLockFile), os.O_RDWR|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the lock file of the trial's own directory.
	if err != nil {
		return fmt.Errorf("%s exists and is not the directory of a trial; remove it, then start nodkey try again", dir)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("a trial runs already, in another terminal; stop it with Ctrl-C first")
	}
	return os.RemoveAll(dir)
}

// stop ends the parts of the trial in the order of nodkey broker, and
// removes its directory. It reports whether the directory is gone.
func (tr *trial) stop() bool {
	if tr.stopRun != nil {
		tr.stopRun()
		<-tr.runDone
	}
	if tr.svc != nil {
		tr.svc.Close()
	}
	if tr.srv != nil {
		_ = tr.srv.Close()
		if tr.serveDone != nil {
			<-tr.serveDone
		}
	}
	if tr.store != nil {
		tr.store.Close()
	}
	if tr.audit != nil {
		_, _ = tr.audit.Append(audit.BrokerStopped{})
		_ = tr.audit.Close()
	}
	if tr.logF != nil {
		_ = tr.logF.Close()
	}
	if !tr.made {
		return true // the directory is not ours, or it was not made
	}
	err := os.RemoveAll(tr.dir)
	if tr.lock != nil {
		_ = tr.lock.Close()
	}
	return err == nil
}

// tryConfig is the broker config of the trial. It is made here, not read
// from a file: the trial reads no config file. Its one store is the trial
// store, a name that no config file can give a store type to.
func tryConfig(dir string, clientPin config.Pin, userID int64) *config.Broker {
	// The rule is one that LoadBroker would make from ask = "window".
	rule := config.Rule{Ask: config.AskWindow, Window: tryWindow}
	cfg := &config.Broker{
		Listen:   netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0),
		TLSKey:   filepath.Join(dir, tryBrokerKey),
		AuditLog: filepath.Join(dir, tryAuditLog),
		Telegram: config.Telegram{UserID: userID, NoticeChatID: userID, Timeout: tryTimeout, SSHTimeout: tryTimeout},
		// Preapprove and Standing stay zero: the trial allows no scheduled
		// and no standing grant.
		Clients: map[string]config.Client{tryClientName: {Name: tryClientName, Pin: clientPin}},
		Stores:  map[string]config.Store{tryStoreName: {Name: tryStoreName}},
		Secrets: make(map[string]config.Secret, len(trySecretNames)),
	}
	for _, name := range trySecretNames {
		cfg.Secrets[name] = config.Secret{Name: name, Store: tryStoreName, ID: name, Clients: []string{tryClientName},
			Rule: rule}
	}
	return cfg
}

// writeTryClientConfig writes the client config of the trial.
func writeTryClientConfig(path, addr string, brokerPin config.Pin, key string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a new file in the trial's own directory.
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "# The client config of nodkey try. It is removed when the trial ends.\n"+
		"broker = %q\nbroker_pin = %q\ntls_key = %q\n", addr, brokerPin.String(), key)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// tryIntro is what nodkey try prints when the trial is ready.
func tryIntro(addr string, inTelegram bool) string {
	answer := "The request shows up here. Type 1, 2 or 3 and Enter to answer it, or\nwait"
	if inTelegram {
		answer = "The request shows up in Telegram. Tap a button to answer it, or\nwait"
	}
	return fmt.Sprintf(`nodkey try: TRY MODE: a trial broker listens on %s, with fake secrets only:
  demo-token, demo-password and demo-api-key. Their values start with TRY-.

In a second terminal, run:

  nodkey try run --secret DEMO_TOKEN=demo-token -- sh -c 'echo "got ${#DEMO_TOKEN} characters"'

%s %s: then it expires and is denied. Press Ctrl-C to end the trial.

`, addr, answer, tryTimeout)
}

// tryOutro is what nodkey try prints when the trial ends.
const tryOutro = `nodkey try: TRY MODE: the trial has ended, and its files are removed.

A real setup adds what the trial leaves out:
  - a separate broker host, so the agent cannot reach the keys or the
    approval (docs/setup.md, "Where you do the setup");
  - a secret store, such as Bitwarden, in place of the fake values;
  - Telegram on your phone, in place of this terminal: on the agent
    machine, the agent could type the answer;
  - the rules of each secret and SSH key.
See docs/setup.md.
`
