package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/release"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/telegram"
	"github.com/code6x/nodkey/internal/transport"
	nodkeyversion "github.com/code6x/nodkey/internal/version"
)

// defaultBrokerConfig is the broker config of DESIGN.md section 14.
const defaultBrokerConfig = "/etc/nodkey/broker.toml"

// exitPollConflict is the exit code of nodkey broker after Telegram
// reported a polling conflict: another program polls with the bot token,
// or a webhook is set, so the token may be stolen. The example systemd
// unit lists it in RestartPreventExitStatus=, so systemd does not start
// the broker again into the same conflict, with a new alert each time. It
// is EX_PROTOCOL from sysexits.h: Telegram answered what cannot happen
// while the broker is the only program that polls with the token.
const exitPollConflict = 76

// exitTokenRefused is the exit code of nodkey broker after Telegram
// answered getUpdates with 401 or 404: it does not accept the bot token,
// such as after the token was revoked or the bot deleted. Only a new
// token helps, so the example unit lists it in RestartPreventExitStatus=
// too: starting again would call Telegram with the same token, and write
// broker_started and broker_stopped, every few seconds. It is EX_NOPERM
// from sysexits.h.
const exitTokenRefused = 77

// storesDirName is the store directory: the directory next to the audit
// log that holds the home directory of each store (DESIGN.md section 16).
const storesDirName = "stores"

// Time limits of the start and the stop.
const (
	// storeStartTimeout bounds the start of the stores. A bw store runs
	// bw unlock, and after a failure bw status: two runs of at most
	// store.DefaultTimeout each.
	storeStartTimeout = 2*store.DefaultTimeout + 10*time.Second
	// stopTimeout bounds the whole stop. The service waits for the
	// requests in progress, which may write an answer for up to 30
	// seconds, and for its alert messages, up to 30 seconds more. The
	// tries of the alert messages of the start that are in progress run at
	// the same time, for at most alertTimeout (sendAlerts). The example
	// unit sets TimeoutStopSec=90s, so the broker ends on its own first and
	// logs why. The stop of the approver also takes up to 5 seconds for the
	// updates of the messages of scheduled grants, and up to 5 seconds for
	// the stop notice about them: 10 seconds more.
	stopTimeout = 80 * time.Second
)

// The tries of an alert message of the start (sendAlerts). After a power
// cut, the broker host can be up before the router or the link to the
// internet, so Telegram cannot be reached for a while. Each try takes at
// most alertTimeout, as telegram.Approver.Alert does. After a failed try,
// the next one comes after alertFirstWait, then after twice as long each
// time, at most alertMaxWait, until the alert is out or the stop begins.
// They are variables only so that a test can make them short.
var (
	alertTimeout   = 30 * time.Second
	alertFirstWait = 5 * time.Second
	alertMaxWait   = 5 * time.Minute
)

// releaseFirstWait is the wait from the start of the broker to its first
// check for a newer release (release.FirstWait). It is a variable only so
// that a test can make it short.
var releaseFirstWait = release.FirstWait

// newStore makes the store of one [store.*] section. It is a variable
// only so that a test can run nodkey broker in a child process with a
// store whose start fails; nodkey never changes it.
var newStore = store.New

// errPanicked is the error of a part of the broker that panicked. The
// panic value is never logged: it could hold text from a request.
var errPanicked = errors.New("it panicked; the panic value is not logged")

const brokerUsage = `Usage: nodkey broker [--config FILE]

Run the broker: the daemon that holds the SSH keys and the access to the
secret stores. It asks the approver on Telegram before it hands out a
secret or signs an SSH login. Run it as its own user, from a systemd
unit such as contrib/systemd/nodkey.service.

  --config FILE  the broker config (default /etc/nodkey/broker.toml)

It logs to stderr, which systemd keeps in the journal, with the anchors
of the audit log. SIGTERM or SIGINT stops it.

Exit codes: 0 stopped by SIGTERM or SIGINT, 1 any other error, 64 wrong
usage, 76 Telegram reports a polling conflict: the bot token may be
stolen, 77 Telegram does not accept the bot token. After 64, 76 and 77,
systemd must not start the broker again: only a person can fix them.
`

// runBroker runs nodkey broker with args (after "broker") and returns the
// exit code.
func runBroker(args []string, stderr io.Writer) int {
	// One logger for every part: the command, the service, the server,
	// the approval core and Telegram. Its lines start with "time=" and
	// escape line breaks, so no line can look like an audit anchor
	// (DESIGN.md section 9).
	log := broker.NewLogger(stderr)
	fs := flag.NewFlagSet("nodkey broker", flag.ContinueOnError)
	// The flag package would print a wrong argument as it is, so its
	// errors go through the logger.
	fs.SetOutput(io.Discard)
	path := fs.String("config", defaultBrokerConfig, "the broker config")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printBrokerUsage(stderr)
			return exitOK
		}
		log.Error("nodkey broker: wrong usage", slog.String("error", err.Error()))
		printBrokerUsage(stderr)
		return exitUsage
	}
	if fs.NArg() > 0 {
		log.Error("nodkey broker: wrong usage: it takes no arguments, only --config FILE")
		printBrokerUsage(stderr)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return serveBroker(ctx, *path, stderr, log)
}

// printBrokerUsage writes the usage of nodkey broker to w. A failed write
// to stderr cannot be reported anywhere, so the error is ignored.
func printBrokerUsage(w io.Writer) {
	_, _ = io.WriteString(w, brokerUsage)
}

// serveBroker starts the broker with the config at path, serves until ctx
// ends (a signal) or a part stops, then stops the broker and returns the
// exit code (DESIGN.md section 15).
func serveBroker(ctx context.Context, path string, stderr io.Writer, log *slog.Logger) (code int) {
	defer func() {
		// The runtime would print the panic value, and no line of the
		// broker may hold text it did not choose.
		if recover() != nil {
			log.Error("nodkey broker: a panic stopped the broker; the panic value is not logged")
			code = exitFailure
		}
	}()
	b := &brokerParts{log: log, stderr: stderr}
	bySignal := false
	switch err := b.start(ctx, path); {
	case err != nil && errors.Is(err, context.Canceled) && ctx.Err() != nil:
		log.Info("nodkey broker: a signal asked to stop during the start")
		bySignal = true
	case err != nil:
		log.Error("nodkey broker: cannot start", slog.String("error", err.Error()))
	default:
		bySignal = b.wait(ctx)
	}
	runErr, clean := b.stop(time.Now().Add(stopTimeout))
	code = brokerExitCode(bySignal, runErr, clean)
	switch code {
	case exitOK:
		log.Info("nodkey broker: stopped", slog.Int("exit_code", code))
	case exitPollConflict:
		log.Error("nodkey broker: stopped after a polling conflict; the bot token may be stolen, so systemd "+
			"does not start the broker again", slog.Int("exit_code", code))
	case exitTokenRefused:
		log.Error("nodkey broker: stopped, because Telegram does not accept the bot token; put a new token "+
			"into the token file, then start the broker", slog.Int("exit_code", code))
	default:
		log.Error("nodkey broker: stopped", slog.Int("exit_code", code))
	}
	return code
}

// brokerExitCode returns the exit code of nodkey broker: exitPollConflict
// after a polling conflict, exitTokenRefused when Telegram does not accept
// the bot token, 0 after a clean stop that a signal asked for, and 1 for
// every other end, such as a failed start, an approver that stopped for
// another reason, or a stop that was not clean.
func brokerExitCode(bySignal bool, runErr error, clean bool) int {
	switch {
	case errors.Is(runErr, telegram.ErrPollConflict):
		return exitPollConflict
	case errors.Is(runErr, telegram.ErrTokenRefused):
		return exitTokenRefused
	case bySignal && clean:
		return exitOK
	default:
		return exitFailure
	}
}

// brokerParts are the parts of a running broker. start makes them in the
// order of DESIGN.md section 15; stop ends those that start made, in the
// order of that section. Only the goroutine of serveBroker uses the
// fields, except where a comment says otherwise.
type brokerParts struct {
	log    *slog.Logger
	stderr io.Writer

	cfg    *config.Broker
	audit  *audit.Logger
	stores map[string]store.Store
	svc    *broker.Service
	tg     *telegram.Approver

	// alerts are the alert messages that wait until the approver can send
	// them: a torn line in the audit log, and stores that did not start.
	alerts []string
	// alertsDone is closed when each alert went out, or its sender gave
	// up because the stop began. stop closes alertsStop when it begins;
	// the senders of the alerts read it.
	alertsDone chan struct{}
	alertsStop chan struct{}

	// started is true once the broker_started entry is on disk.
	started bool

	// stopCheck ends the check for a newer release; checkDone is closed
	// when the check returned. Both are nil when the check is off.
	stopCheck context.CancelFunc
	checkDone chan struct{}

	// stopRun ends the service's Run; runDone is closed when Run returned,
	// and runErr is its error, set before runDone is closed.
	stopRun context.CancelFunc
	runDone chan struct{}
	runErr  error

	// ln is the listen address. Until serve, nothing reads from it.
	ln net.Listener

	// srv serves the clients; serveDone is closed when Serve returned, and
	// serveErr is its error, set before serveDone is closed.
	srv       *transport.Server
	serveDone chan struct{}
	serveErr  error
}

// start makes the parts of the broker, in this order (DESIGN.md section
// 15): the config and the checks of the files it names, no core dumps,
// the broker's TLS key, the SSH keys, the audit log, the stores, the
// service, the Telegram approver and the approval core, the server and
// its listen address, the broker_started entry, the approver's Run, the
// check for a newer release, and only then Serve. On an error it returns
// at once; stop then ends what start made. It returns context.Canceled
// when ctx ended during the start.
func (b *brokerParts) start(ctx context.Context, path string) error {
	b.log.Info("nodkey broker: starting", slog.String("version", version), slog.String("config", path))
	cfg, err := config.LoadBroker(path) // it runs CheckFiles
	if err != nil {
		return err
	}
	b.cfg = cfg
	b.log.Info("nodkey broker: the config and the files it names passed their checks")
	if err := hardenProcess(); err != nil {
		return fmt.Errorf("cannot turn off core dumps: %w", err)
	}
	b.log.Info("nodkey broker: core dumps are off: the soft and the hard limit of core dumps are 1, " +
		"and the process is not dumpable")
	tlsKey, err := transport.LoadKeyFile(cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("tls_key: %w", err)
	}
	b.log.Info("nodkey broker: the TLS key is loaded", slog.String("pin", transport.PinOf(tlsKey.Leaf).String()))
	keys, err := loadSSHKeys(cfg, config.ReadPrivateFile)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(keys)) {
		b.log.Info("nodkey broker: an SSH key is loaded and can sign", slog.String("key", name),
			slog.String("fingerprint", ssh.FingerprintSHA256(keys[name].PublicKey())))
	}
	b.log.Info("nodkey broker: the SSH keys are loaded", slog.Int("keys", len(keys)))
	if err := ctx.Err(); err != nil {
		return err
	}

	// The audit log is opened once, before anything can ask. Its Alert
	// only queues the message: the approver does not exist yet.
	l, err := audit.Open(cfg.AuditLog, audit.Options{Journal: b.stderr, Alert: b.logRecovered})
	if err != nil {
		return err
	}
	b.audit = l
	b.log.Info("nodkey broker: the audit log is open", slog.String("path", cfg.AuditLog))
	if r, ok := l.LastRecovery(); ok {
		// An earlier start recorded a torn line and stopped before its
		// broker_started entry, such as when its listen address was not
		// there yet. Its alert may never have gone out.
		b.log.Warn("nodkey broker: ALERT: the last entry of the audit log records a torn line, and the start "+
			"that recorded it stopped before it could send the alert; this start sends it",
			slog.Uint64("seq", r.Seq), slog.Int("torn_length", r.TornLength),
			slog.String("torn_sha256", hex.EncodeToString(r.TornSHA256[:])))
		b.alerts = append(b.alerts, tornLineAlert(r))
	}
	if err := b.startStores(ctx); err != nil {
		return err
	}

	svc, err := broker.New(broker.Parts{Config: cfg, Audit: l, Stores: b.stores, Keys: keys, Logger: b.log,
		Version: version})
	if err != nil {
		return err
	}
	b.svc = svc
	// The approval core takes the approver, so Telegram comes first.
	tg, err := telegram.New(cfg.Telegram, telegram.Options{Logger: b.log, ForeignTap: svc.ForeignTap})
	if err != nil {
		return err
	}
	b.tg = tg
	core, err := approval.New(cfg, tg, approval.Options{Logger: b.log})
	if err != nil {
		return err
	}
	// The server checks the client pins here.
	srv, err := transport.NewServer(tlsKey, cfg.Clients, svc, b.log)
	if err != nil {
		return err
	}
	// The listen address is opened now, so that a missing address, such
	// as at boot before the private network is up, stops the start before
	// any entry and any call to Telegram; systemd starts the broker again
	// later. Nothing reads from it until serve below: a client that
	// connects waits.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen.String())
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("cannot listen on %s: %w", cfg.Listen, err)
	}
	b.ln = ln
	b.log.Info("nodkey broker: the listen address is open; nothing reads from it yet",
		slog.String("address", ln.Addr().String()))
	if err := ctx.Err(); err != nil {
		return err
	}

	// The broker_started entry is the last step of the start that can
	// fail.
	if _, err := l.Append(audit.BrokerStarted{Version: version}); err != nil {
		return fmt.Errorf("cannot write the broker_started entry: %w", err)
	}
	b.started = true
	b.startRun(core)
	b.sendAlerts(tg.Alert)
	b.startCheck(tg.Inform)
	b.serve(srv, ln)
	b.log.Info("nodkey broker: listening; the broker is ready", slog.String("address", ln.Addr().String()))
	return nil
}

// logRecovered is the Alert of the audit log: Open found a torn last line
// and recorded it with a log_recovered entry. It logs that, and queues an
// alert message for the approver.
func (b *brokerParts) logRecovered(r audit.Recovery) {
	b.log.Warn("nodkey broker: ALERT: the audit log ended in a torn line, as after a power cut; "+
		"a log_recovered entry records its length and hash", slog.Uint64("seq", r.Seq),
		slog.Int("torn_length", r.TornLength), slog.String("torn_sha256", hex.EncodeToString(r.TornSHA256[:])))
	b.alerts = append(b.alerts, tornLineAlert(r))
}

// tornLineAlert returns the alert message about the torn line that r
// records.
func tornLineAlert(r audit.Recovery) string {
	return fmt.Sprintf("The audit log ended in a torn line, as after a power cut. Entry %d (log_recovered) "+
		"records it. Check the log with nodkey audit verify and the anchors in the journal.", r.Seq)
}

// startStores makes the store of each [store.*] section, in the store
// directory, and starts them all at once. A store that does not start
// does not stop the broker: the broker denies its requests until it works
// (each request tries again), and the approver gets one alert for all
// such stores.
func (b *brokerParts) startStores(ctx context.Context) error {
	if len(b.cfg.Stores) == 0 {
		return nil
	}
	dir := filepath.Join(filepath.Dir(b.cfg.AuditLog), storesDirName)
	if err := store.PrepareDir(dir); err != nil {
		return err
	}
	names := slices.Sorted(maps.Keys(b.cfg.Stores))
	b.stores = make(map[string]store.Store, len(names))
	for _, name := range names {
		s, err := newStore(b.cfg.Stores[name], dir)
		if err != nil {
			return err // it names the store and a file, never a token
		}
		b.stores[name] = s
	}
	startCtx, cancel := context.WithTimeout(ctx, storeStartTimeout)
	defer cancel()
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		s := b.stores[name]
		wg.Go(func() { errs[i] = s.Start(startCtx) })
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	var failed []string
	for i, name := range names {
		if errs[i] != nil {
			failed = append(failed, strconv.Quote(name))
			// Store errors have fixed texts: never a token or the program's output.
			b.log.Error("nodkey broker: a store could not start; the broker denies requests for its secrets "+
				"until it works, and each request tries again", slog.String("store", name),
				slog.String("error", errs[i].Error()))
			continue
		}
		b.log.Info("nodkey broker: a store started", slog.String("store", name))
	}
	if len(failed) > 0 {
		b.alerts = append(b.alerts, "These stores could not start: "+strings.Join(failed, ", ")+
			". The broker denies requests for their secrets until they work; each request tries again. "+
			"The journal of the broker says why.")
	}
	return nil
}

// startRun runs the service with the approval core and the approver's
// alert, until stop ends it or the approver stops.
func (b *brokerParts) startRun(core *approval.Core) {
	ctx, cancel := context.WithCancel(context.Background())
	b.stopRun = cancel
	b.runDone = make(chan struct{})
	go func() {
		defer close(b.runDone)
		b.runErr = errPanicked
		defer func() {
			if recover() != nil {
				b.log.Error("nodkey broker: the approver panicked; the panic value is not logged; " +
					"every request is denied, and the broker stops")
			}
		}()
		b.runErr = b.svc.Run(ctx, core, b.tg.Alert, b.tg.Inform)
	}()
	b.log.Info("nodkey broker: the approver runs: it polls Telegram for the answers")
}

// startCheck starts the check for a newer release (DESIGN.md section 15):
// it asks GitHub 10 minutes after the start, and then every 24 hours, and
// sends a notice with notice when a newer release is out. A broker that
// ends sooner, such as one that systemd starts again and again, never
// asks. The check runs on its own, so it never delays the start, the stop
// or a request. It is off when [updates] says check = false, and in a
// build from the source, which has no release to compare. A panic in the
// check ends only the check.
func (b *brokerParts) startCheck(notice broker.NoticeFunc) {
	own, isRelease := nodkeyversion.ParseRelease(version)
	switch {
	case !b.cfg.Updates.Check:
		b.log.Info("nodkey broker: the check for a newer release is off, as [updates] check = false says")
		return
	case !isRelease:
		b.log.Info("nodkey broker: the check for a newer release is off: this is a build from the source")
		return
	}
	check := release.NewCheck(own, releaseFirstWait, release.New(own).Lookup, notice, b.log)
	ctx, cancel := context.WithCancel(context.Background())
	b.stopCheck = cancel
	b.checkDone = make(chan struct{})
	go func() {
		defer close(b.checkDone)
		defer func() {
			if recover() != nil {
				b.log.Error("nodkey broker: the check for a newer release panicked; the panic value is not logged; " +
					"the broker goes on without it")
			}
		}()
		check.Run(ctx)
	}()
	b.log.Info("nodkey broker: the check for a newer release runs: it asks GitHub 10 minutes after the start, " +
		"and then every 24 hours")
}

// sendAlerts sends the alert messages that waited for the approver with
// send, each in a goroutine of its own. So their tries run at the same
// time: a slow try of one alert does not delay the others, and the stop
// waits for them at most as long as one try takes, however many alerts
// wait. Each alert gets a first try, also when the stop has begun; the
// stop waits for it. After a failed try, sendAlert tries again (see
// alertFirstWait) until the alert is out or the stop begins. Each failed
// try gets one log line, with the number of the alert: its place in the
// queue, from 1. The growing wait limits the lines of each alert to one
// in 5 seconds at first and one in 5 minutes later. An alert that did not
// go out before the stop is lost, and the journal says so.
func (b *brokerParts) sendAlerts(send broker.AlertFunc) {
	msgs := b.alerts
	b.alerts = nil
	done := make(chan struct{})
	b.alertsDone = done
	b.alertsStop = make(chan struct{})
	sent := make([]bool, len(msgs))
	var wg sync.WaitGroup
	for i, msg := range msgs {
		wg.Go(func() {
			defer func() {
				if recover() != nil {
					b.log.Error("nodkey broker: sending an alert message panicked; the panic value is not logged",
						slog.Int("alert", i+1))
				}
			}()
			sent[i] = b.sendAlert(send, i+1, msg)
		})
	}
	go func() {
		defer close(done)
		wg.Wait()
		lost := 0
		for _, ok := range sent {
			if !ok {
				lost++
			}
		}
		if lost > 0 {
			b.log.Error("nodkey broker: alert messages of the start did not go out before the stop; they are lost",
				slog.Int("lost", lost))
		}
	}()
}

// sendAlert tries to send msg, the alert with the number n, until it is
// out, and reports true. After the stop began, it makes no new try, and
// reports false.
func (b *brokerParts) sendAlert(send broker.AlertFunc, n int, msg string) bool {
	wait := alertFirstWait
	for try := 1; ; try++ {
		ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
		err := send(ctx, msg)
		cancel()
		if err == nil {
			return true
		}
		select {
		case <-b.alertsStop:
			// Telegram's errors never hold the token or Go's error text.
			b.log.Warn("nodkey broker: an alert message did not go out", slog.Int("alert", n),
				slog.String("error", err.Error()), slog.Int("try", try))
			return false
		default:
		}
		b.log.Warn("nodkey broker: an alert message did not go out; the broker tries again", slog.Int("alert", n),
			slog.String("error", err.Error()), slog.Int("try", try), slog.Duration("next_try_in", wait))
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-b.alertsStop:
			t.Stop()
			return false
		}
		wait = min(2*wait, alertMaxWait)
	}
}

// serve serves the clients on ln.
func (b *brokerParts) serve(srv *transport.Server, ln net.Listener) {
	b.srv = srv
	b.serveDone = make(chan struct{})
	go func() {
		defer close(b.serveDone)
		b.serveErr = errPanicked
		defer func() {
			if recover() != nil {
				b.log.Error("nodkey broker: the server panicked; the panic value is not logged")
			}
		}()
		b.serveErr = srv.Serve(ln)
	}()
}

// wait waits until ctx ends, the approver stops, or the server stops. It
// reports whether a signal asked to stop.
func (b *brokerParts) wait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		b.log.Info("nodkey broker: stopping, as a signal asked")
		return true
	case <-b.runDone:
		// The service has logged why.
		b.log.Error("nodkey broker: stopping, because the approver stopped: no answer can come any more")
		return false
	case <-b.serveDone:
		b.log.Error("nodkey broker: stopping, because the server stopped", slog.String("error", errText(b.serveErr)))
		return false
	}
}

// errText returns the text of err, or "" for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// stop ends the parts that start made, in this order (DESIGN.md section
// 15): the check for a newer release; the approver's Run, so the polling
// stops and its connection is closed; the service, which ends the
// requests in progress and waits for them; the server; the alert messages
// of the start; the stores; and last the broker_stopped entry and the
// audit log. It waits at most until deadline: when a part takes longer,
// it gives up on the rest, and the process ends. It returns the error of
// Run, and whether the stop was clean: every part ended in time without
// an error or a panic, and the audit log took its last entry.
func (b *brokerParts) stop(deadline time.Time) (runErr error, clean bool) {
	b.log.Info("nodkey broker: stopping: the check for a newer release, the approver, the service, the server, " +
		"the stores, then the audit log")
	clean = true
	if b.alertsStop != nil {
		close(b.alertsStop) // no more tries again of an alert of the start
	}
	if b.stopCheck != nil {
		b.stopCheck() // the wait, a lookup or a notice that runs now is cancelled
		if !waitUntil(b.checkDone, deadline) {
			return nil, b.late("the check for a newer release")
		}
		b.log.Info("nodkey broker: the check for a newer release stopped")
	}
	if b.stopRun != nil {
		b.stopRun()
		if !waitUntil(b.runDone, deadline) {
			return nil, b.late("the approver")
		}
		runErr = b.runErr
		b.log.Info("nodkey broker: the approver stopped; no answer counts any more")
	}
	if b.svc != nil {
		done, ok := b.step("the service", b.svc.Close, deadline)
		if !done {
			return runErr, false
		}
		clean = clean && ok
		b.log.Info("nodkey broker: the service stopped; every request has ended")
	}
	switch {
	case b.srv != nil:
		// It closes the listen address too.
		if err := b.srv.Close(); err != nil {
			b.log.Error("nodkey broker: cannot close the server", slog.String("error", err.Error()))
			clean = false
		}
		if !waitUntil(b.serveDone, deadline) {
			return runErr, b.late("the server")
		}
		b.log.Info("nodkey broker: the server is closed")
	case b.ln != nil:
		if err := b.ln.Close(); err != nil {
			b.log.Error("nodkey broker: cannot close the listen address", slog.String("error", err.Error()))
			clean = false
		}
	}
	if b.alertsDone != nil && !waitUntil(b.alertsDone, deadline) {
		return runErr, b.late("an alert message")
	}
	if b.stores != nil {
		done, ok := b.step("the stores", b.closeStores, deadline)
		if !done {
			return runErr, false
		}
		clean = clean && ok
		b.log.Info("nodkey broker: the stores are closed; their tokens and session keys are cleared")
	}
	if b.audit != nil {
		closed := false
		done, ok := b.step("the audit log", func() { closed = b.closeAudit() }, deadline)
		if !done {
			return runErr, false
		}
		clean = clean && ok && closed
	}
	return runErr, clean
}

// step runs f, a step of the stop, in a goroutine of its own, and waits
// for it at most until deadline. done is false when f did not return in
// time: then f goes on, and the process ends without it. ok is false when
// f panicked. step logs both.
func (b *brokerParts) step(part string, f func(), deadline time.Time) (done, ok bool) {
	finished := make(chan struct{})
	panicked := false
	go func() {
		defer close(finished)
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		f()
	}()
	if !waitUntil(finished, deadline) {
		return b.late(part), false
	}
	if panicked {
		b.log.Error("nodkey broker: a step of the stop panicked; the panic value is not logged",
			slog.String("step", part))
		return true, false
	}
	return true, true
}

// late logs that the stop took too long while it waited for part, and
// returns false: the stop is not clean.
func (b *brokerParts) late(part string) bool {
	b.log.Error("nodkey broker: the stop takes too long; the broker ends without waiting for the rest",
		slog.String("waiting_for", part), slog.Duration("limit", stopTimeout))
	return false
}

// closeStores closes every store: each clears its token or session key.
func (b *brokerParts) closeStores() {
	for _, name := range slices.Sorted(maps.Keys(b.stores)) {
		b.stores[name].Close()
	}
}

// closeAudit writes the broker_stopped entry, if broker_started is on
// disk, and closes the audit log. It reports whether both worked.
func (b *brokerParts) closeAudit() bool {
	ok := true
	if b.started {
		if _, err := b.audit.Append(audit.BrokerStopped{}); err != nil {
			b.log.Error("nodkey broker: cannot write the broker_stopped entry", slog.String("error", err.Error()))
			ok = false
		}
	}
	if err := b.audit.Close(); err != nil {
		b.log.Error("nodkey broker: cannot close the audit log", slog.String("error", err.Error()))
		return false
	}
	b.log.Info("nodkey broker: the audit log is closed")
	return ok
}

// waitUntil waits until done is closed, at most until deadline. It
// reports whether done was closed in time.
func waitUntil(done <-chan struct{}, deadline time.Time) bool {
	select {
	case <-done:
		return true
	default:
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}
