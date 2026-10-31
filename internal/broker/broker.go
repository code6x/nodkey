// Package broker is the broker's service: it answers the requests of the
// clients over the API of package api (DESIGN.md sections 5, 6, 10 and
// 13). It puts the other parts together: the pinned TLS connection
// (transport), the checks of claimed text (claim) and of SSH logins
// (sshauth), the approval core (approval), the audit log (audit) and the
// stores (store).
//
// A Service is an http.Handler for transport.NewServer. For each request
// it does, in this order:
//
//  1. It takes the client name only from transport.ClientName, and
//     refuses a request without one. Then it compares the version that
//     the client claims with its own (version.go). The claim changes
//     nothing about the request.
//  2. It routes by the exact method and path: anything else gets 404 or
//     405, also "OPTIONS *" and "PRI *".
//  3. It refuses every request while the approver is not running, after
//     the approver stopped, after a failed write to the audit log, and
//     when the client has MaxRequestsPerClient requests in progress.
//  4. It reads the body strictly (transport.ReadJSON into the types of
//     package api), with their caps, while it holds one of the few places
//     for reading bodies (maxBodiesPerClient, maxBodies).
//  5. It checks every input itself: variable names, also against the deny
//     list (api.DeniedVar), the names of secrets and keys against the
//     config and the client's lists, the remote user name, and for an SSH
//     login the data to sign and the session-bind (sshauth.Key.Check),
//     before any message or place in a queue.
//  6. It makes the claimed text safe (claim.Mask and claim.Line, or
//     claim.Command), and builds an approval.Request from checked data
//     only.
//  7. It calls approval.Core.Decide with a context that ends when the
//     client hangs up. While the request waits for the person, the client
//     gets a 102 Processing answer with the short code.
//  8. It writes every entry of the result to the audit log, in order. Any
//     failed write denies the request. Only when all are on disk does it
//     start the grants of the answer, and only then does it fetch values
//     or sign: those steps need a receipt that only the audit writes give.
//  9. It writes secret_sent or signed, and only then the answer. Every
//     error denies; every fetched value is cleared on every path. The
//     answer with values is written by hand into one buffer, which is
//     cleared too (api.SecretsAnswer.Encode).
//
// Every answer, with every status, has the broker's version in the header
// api.VersionHeader.
//
// A panic in a request denies it: the connection drops, and the audit log
// records the request, also before the core gave it an ID. Requests that a
// limit denies, or that come after the approver stopped, cost the client
// nothing, so their entries are limited per minute and client.
//
// The Service never starts the process: nodkey broker loads the config
// and the keys, opens the audit log, makes the stores and the approver,
// and then makes a Service with New and calls Run.
package broker

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/telegram"
	"github.com/code6x/nodkey/internal/version"
)

// MaxRequestsPerClient is the most requests of one client that the broker
// works on at a time. A request over it is denied at once, with 429. The
// approval core lets at most 15 requests of a client wait for the person
// (5 messages and 10 in the queue), and grants let more pass quickly, such
// as the parallel logins of Ansible. The cap keeps the memory of one
// client small: reading a body can take 20 MiB for a moment
// (THREAT-MODEL.md T28).
const MaxRequestsPerClient = 32

// Request bodies that the broker reads and decodes at the same time. A
// body of 2 MiB can take 20 MiB while it is read and cleaned, so these
// bound that memory: one client cannot take more than 4 places, and all
// clients together not more than 16. A request waits for a place at most
// bodyWait; then it is denied for a limit (429).
const (
	maxBodiesPerClient = 4
	maxBodies          = 16
)

// bodyWait is how long a request waits for a place to read its body. It
// is a variable only so that a test can make it short.
var bodyWait = 10 * time.Second

// Lines and entries about refused requests: at most this many in a
// minute. A client can send refused requests fast; the others are only
// counted, and the count goes to the log at the end of the minute.
const (
	// refusedEntriesPerMinute is the most refused requests of one client
	// whose audit entries the broker writes in a minute: requests denied
	// for a limit, and requests refused after the approver stopped.
	refusedEntriesPerMinute = 20
	// refusedLinesPerMinute is the most log lines in a minute about
	// requests that a check refused, for all clients together: SSH logins,
	// and requests for secrets with a variable on the deny list.
	refusedLinesPerMinute = 20
)

const (
	// fetchTimeout bounds the fetch of one value. A bw fetch can run bw
	// 4 times (status, unlock, sync, get), each for at most
	// store.DefaultTimeout.
	fetchTimeout = 4*store.DefaultTimeout + 10*time.Second
	// alertTimeout bounds an alert message.
	alertTimeout = 30 * time.Second
	// tapQueue is the most foreign_tap entries that wait to be written.
	// The Telegram approver reports at most 20 refused taps a minute.
	tapQueue = 64
)

// The alerts that the broker sends. They are its own text.
const (
	brokenAlert = "The audit log of the broker cannot be written. The broker denies every request until it " +
		"starts again. Check the disk, then restart the broker."
)

// AuditLog is the part of *audit.Logger that the broker uses. Append
// writes one entry and syncs it to disk; an error means that the entry is
// not on disk. An error that holds audit.ErrBroken means that every later
// entry fails too.
type AuditLog interface {
	Append(ev audit.Event) (audit.Anchor, error)
}

// AlertFunc sends an alert message to the approver, such as
// telegram.Approver.Alert. msg is the broker's own text. ctx has a
// deadline.
type AlertFunc func(ctx context.Context, msg string) error

// NoticeFunc sends a silent notice of the broker itself to the notice
// chat, such as telegram.Approver.Inform. It must not take from the
// limits of the notices of "never ask" uses. It makes one try; the
// Service tries again later after an error (version.go). msg is the
// broker's own text. ctx has a deadline.
type NoticeFunc func(ctx context.Context, msg string) error

// Parts are the parts that a Service uses. nodkey broker makes them at
// start: it checks the config files, loads each SSH key with
// sshauth.NewKey and the hosts of its [key.*] section, opens the audit
// log once, and makes each store with store.New.
type Parts struct {
	// Config is the broker config, from config.LoadBroker. Nothing may
	// change it later.
	Config *config.Broker
	// Audit is the audit log, such as an *audit.Logger.
	Audit AuditLog
	// Stores holds a store for each [store.*] section, by its name.
	Stores map[string]store.Store
	// Keys holds a key for each [key.*] section, by its name.
	Keys map[string]sshauth.Key
	// Logger gets the broker's log lines, such as from NewLogger. It may
	// be nil; then nothing is logged.
	Logger *slog.Logger
	// Version is the version of this broker, as nodkey version prints it,
	// such as "1.2.0" or "dev". The broker sends it in the header
	// api.VersionHeader of every answer, and compares it with the version
	// that each client sends (version.go). Without a valid version, it
	// sends none and compares nothing.
	Version string
}

// Service answers the requests of the clients. Make it with New, pass it
// to transport.NewServer as the handler, call Run, and Close it when the
// broker stops. Its methods are safe for use by many goroutines.
type Service struct {
	cfg    *config.Broker
	audit  AuditLog
	stores map[string]store.Store
	keys   map[string]sshauth.Key
	keysOf map[string]api.KeysAnswer // the answer of PathKeys, by client
	log    *slog.Logger
	random io.Reader // crypto/rand.Reader, for request IDs
	// version is the broker's own version (Parts.Version), or "" when it
	// is not valid.
	version string
	// now is time.Now, for the tries of the notices about versions; tests
	// change it. Read it with mu held.
	now func() time.Time

	// startHook, if set, runs in a request for a scheduled grant right
	// before ("before") and after ("after") the core starts the grant.
	// Only tests set it.
	startHook func(point string)

	// maxPerClient is MaxRequestsPerClient; tests change it.
	maxPerClient int

	// bodies holds a place for each body that is read and decoded now;
	// clientBodies holds the places of each client, by name.
	bodies       chan struct{}
	clientBodies map[string]chan struct{}

	// refusedEntries limits the audit entries of refused requests, by
	// client; refusedLines limits the log lines about requests that a
	// check refused: SSH logins, and variables on the deny list.
	refusedEntries map[string]*rateLimit
	refusedLines   *rateLimit

	// stopCtx ends when Close is called: every request then ends too.
	stopCtx context.Context
	stop    context.CancelFunc

	mu       sync.Mutex
	core     *approval.Core // set by Run
	alert    AlertFunc      // set by Run
	notice   NoticeFunc     // set by Run
	closed   bool
	inflight map[string]int // requests in progress, by client
	// versionNotes holds where the broker is with the notice about the
	// version of each client of the config, in this start (version.go).
	versionNotes map[string]*versionNote
	// securityGen counts the rounds of notices about a security release;
	// securityNewest and securityAt are the release and the start of the
	// last round. securityNotes holds where the broker is with that
	// notice, for each client of the config (security.go).
	securityGen    uint64
	securityNewest version.Release
	securityAt     time.Time
	securityNotes  map[string]*securityNote
	// rateAlerts holds when the broker last sent the alert about the
	// rate limit of each store (rateLimited).
	rateAlerts map[string]time.Time
	// security is the newest security release that the check found, or
	// nil for none (SetSecurity). The handler reads it without mu.
	security atomic.Pointer[securityInfo]

	coreStopped atomic.Bool // the approval core's Run returned
	broken      atomic.Bool // an audit write failed

	requests  sync.WaitGroup // the requests that the Service took
	bg        sync.WaitGroup // the goroutines of the Service: taps and alerts
	closeOnce sync.Once

	taps        chan audit.ForeignTap
	tapsStop    chan struct{}
	droppedTaps atomic.Int64
}

// errClosed is the error of Run after Close.
var errClosed = errors.New("broker: the service is closed")

// New returns a Service made of p. It checks that the parts fit the
// config: a store for each [store.*] section, and a key for each [key.*]
// section, with the name of its section. Two [key.*] sections must not
// hold the same public key: the config check finds one key file named
// twice, not a copy of a key in a second file. Errors name sections of
// the config, never a key.
func New(p Parts) (*Service, error) {
	if p.Config == nil || p.Audit == nil {
		return nil, errors.New("broker: the config and the audit log are required")
	}
	cfg := p.Config
	if err := checkStores(cfg, p.Stores); err != nil {
		return nil, err
	}
	keysOf, err := checkKeys(cfg, p.Keys)
	if err != nil {
		return nil, err
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	stopCtx, stop := context.WithCancel(context.Background())
	s := &Service{
		cfg:            cfg,
		audit:          p.Audit,
		stores:         maps.Clone(p.Stores),
		keys:           maps.Clone(p.Keys),
		keysOf:         keysOf,
		log:            logger,
		random:         rand.Reader,
		maxPerClient:   MaxRequestsPerClient,
		bodies:         make(chan struct{}, maxBodies),
		clientBodies:   make(map[string]chan struct{}, len(cfg.Clients)),
		refusedEntries: make(map[string]*rateLimit, len(cfg.Clients)),
		stopCtx:        stopCtx,
		stop:           stop,
		inflight:       make(map[string]int),
		versionNotes:   make(map[string]*versionNote, len(cfg.Clients)),
		securityNotes:  make(map[string]*securityNote, len(cfg.Clients)),
		now:            time.Now,
		taps:           make(chan audit.ForeignTap, tapQueue),
		tapsStop:       make(chan struct{}),
	}
	if version.Valid(p.Version) {
		s.version = p.Version
	}
	for name := range cfg.Clients {
		s.versionNotes[name] = &versionNote{}
		s.securityNotes[name] = &securityNote{}
		s.clientBodies[name] = make(chan struct{}, maxBodiesPerClient)
		s.refusedEntries[name] = newRateLimit(refusedEntriesPerMinute, func(n int) {
			s.log.Warn("broker: did not write the audit entries of refused requests, to keep the log small",
				slog.String("client", name), slog.Int("requests", n), slog.Int("limit_per_minute", refusedEntriesPerMinute))
		})
	}
	s.refusedLines = newRateLimit(refusedLinesPerMinute, func(n int) {
		s.log.Info("broker: did not log refused requests, to keep the log small", slog.Int("dropped", n),
			slog.Int("limit_per_minute", refusedLinesPerMinute))
	})
	s.bg.Add(1)
	go s.writeTaps()
	return s, nil
}

// checkStores checks that stores has a store for each [store.*] section,
// and no other, and that each secret's store is there.
func checkStores(cfg *config.Broker, stores map[string]store.Store) error {
	for _, name := range slices.Sorted(maps.Keys(cfg.Stores)) {
		if stores[name] == nil {
			return fmt.Errorf("broker: [store.%s] has no store", name)
		}
	}
	for name := range stores {
		if _, ok := cfg.Stores[name]; !ok {
			return errors.New("broker: a store has no [store.*] section")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Secrets)) {
		if stores[cfg.Secrets[name].Store] == nil {
			return fmt.Errorf("broker: [secret.%s]: its store has no store", name)
		}
	}
	return nil
}

// checkKeys checks that keys has a key for each [key.*] section, made with
// the name of its section, and no other, and that no two sections hold the
// same public key. It returns the answer of PathKeys for each client: its
// keys, sorted by name.
func checkKeys(cfg *config.Broker, keys map[string]sshauth.Key) (map[string]api.KeysAnswer, error) {
	for name := range keys {
		if _, ok := cfg.Keys[name]; !ok {
			return nil, errors.New("broker: a key has no [key.*] section")
		}
	}
	byBlob := make(map[string]string)
	for _, name := range slices.Sorted(maps.Keys(cfg.Keys)) {
		k, ok := keys[name]
		if !ok || k.PublicKey() == nil || k.Name() != name {
			return nil, fmt.Errorf("broker: [key.%s] has no key, or a key made for another section", name)
		}
		blob := string(k.PublicKey().Marshal())
		if other, dup := byBlob[blob]; dup {
			return nil, fmt.Errorf("broker: [key.%s] and [key.%s] hold the same public key; "+
				"each key may have one section", other, name)
		}
		byBlob[blob] = name
	}
	keysOf := make(map[string]api.KeysAnswer, len(cfg.Clients))
	for client := range cfg.Clients {
		ans := api.KeysAnswer{Keys: []api.Key{}}
		for _, name := range slices.Sorted(maps.Keys(cfg.Keys)) {
			if slices.Contains(cfg.Keys[name].Clients, client) {
				ans.Keys = append(ans.Keys, api.Key{Name: name, PublicKey: keys[name].PublicKey().Marshal()})
			}
		}
		if len(ans.Keys) > api.MaxKeys {
			return nil, fmt.Errorf("broker: [client.%s] may use more than %d keys", client, api.MaxKeys)
		}
		keysOf[client] = ans
	}
	return keysOf, nil
}

// Run serves the requests with the approval core: it runs core.Run, which
// passes the person's answers to the core, until ctx ends or the approver
// stops. Requests that come before Run, and after Run returned, are
// denied. alert sends an alert message, such as when the audit log
// breaks; it may be nil. notice sends a notice about a client that runs
// another version of nodkey (version.go); it may be nil.
//
// When the core's Run returns, every request is denied, also one that a
// grant or a "never ask" rule would allow, and the broker must stop. Run
// returns why the core stopped. If it was telegram.ErrPollConflict,
// another program polls with the bot token, so Run first writes an error
// entry with code poll_conflict.
func (s *Service) Run(ctx context.Context, core *approval.Core, alert AlertFunc, notice NoticeFunc) error {
	if core == nil {
		return errors.New("broker: Run needs the approval core")
	}
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return errClosed
	case s.core != nil:
		s.mu.Unlock()
		return errors.New("broker: Run can run only once")
	}
	s.core, s.alert, s.notice = core, alert, notice
	s.mu.Unlock()

	// Deny every request once the core stops, also when the approver's
	// Run panics and the caller recovers the panic.
	defer s.coreStopped.Store(true)
	// A scheduled grant that ends by itself has no request to carry its
	// entry (DESIGN.md section 8).
	var dropped droppedGrants
	core.OnGrantEnded(func(ev audit.GrantEnded) {
		if _, err := s.append(ev); err != nil {
			s.log.Warn("broker: cannot write the grant_ended entry of a scheduled grant")
		}
		dropped.note(ev)
	})
	core.OnGrantAlarm(func(ev audit.GrantAlarm) {
		if _, err := s.append(ev); err != nil {
			s.log.Warn("broker: cannot write the grant_alarm entry of a missed window")
		}
	})
	// A Renew counts only when its decision entry is on disk.
	core.OnRenewed(func(ev audit.Decision) error {
		if _, err := s.append(ev); err != nil {
			s.log.Warn("broker: cannot write the decision entry of a Renew; the Renew does not count")
			return err
		}
		return nil
	})
	err := core.Run(ctx)
	s.coreStopped.Store(true) // first: deny every request from now on
	// The grants are dropped by now. Their messages are updated, and one
	// notice lists them, each with a short time limit. This comes after the
	// line above, so a slow Telegram never leaves the broker open to
	// requests that a grant would allow.
	core.FlushMessages()
	s.sendStopNotice(ctx, notice, dropped.list())
	switch {
	case errors.Is(err, telegram.ErrPollConflict):
		s.log.Error("broker: another program polls with the bot token, or a webhook is set, so the token may be " +
			"stolen; every request is denied, and the broker stops")
		if _, aerr := s.append(audit.Failure{Code: audit.CodePollConflict}); aerr != nil {
			s.log.Error("broker: cannot write the poll_conflict entry to the audit log")
		}
	case ctx.Err() != nil:
		s.log.Info("broker: the approver stopped, as asked; every request is denied")
	default:
		s.log.Error("broker: the approver stopped; every request is denied, and the broker stops",
			slog.String("error", errorText(err)))
	}
	return err
}

// Close stops the Service: it denies new requests, ends the requests in
// progress (their contexts end, so they are denied), waits for them, and
// then writes the foreign_tap entries that still wait. nodkey broker calls
// it before it closes the stores and the audit log. Close may be called
// more than once.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.stop()
		s.requests.Wait()
		close(s.tapsStop)
		s.bg.Wait()
		for _, l := range s.refusedEntries {
			l.stop()
		}
		s.refusedLines.stop()
	})
}

// stopping reports whether Close has begun: requests in progress end, and
// their clients get 503, not a deny.
func (s *Service) stopping() bool { return s.stopCtx.Err() != nil }

// ForeignTap queues a foreign_tap entry for a button press that did not
// count (DESIGN.md section 7). Pass it to the Telegram approver as
// telegram.Options.ForeignTap; Run of the approver calls it from its
// polling goroutine. So ForeignTap only queues the entry: it never blocks
// and never panics. When the queue is full, it drops the entry, and the
// broker logs how many it dropped.
func (s *Service) ForeignTap(t audit.ForeignTap) {
	defer func() { _ = recover() }() // a panic here would stop the polling
	select {
	case s.taps <- t:
	default:
		s.droppedTaps.Add(1)
	}
}

// writeTaps writes the queued foreign_tap entries until Close.
func (s *Service) writeTaps() {
	defer s.bg.Done()
	for {
		select {
		case t := <-s.taps:
			s.writeTap(t)
		case <-s.tapsStop:
			for {
				select {
				case t := <-s.taps:
					s.writeTap(t)
				default:
					s.logDroppedTaps()
					return
				}
			}
		}
	}
}

// writeTap writes one foreign_tap entry.
func (s *Service) writeTap(t audit.ForeignTap) {
	defer s.recoverGoroutine("writing a foreign_tap entry")
	s.logDroppedTaps()
	if _, err := s.append(t); err != nil {
		s.log.Warn("broker: cannot write a foreign_tap entry")
	}
}

// logDroppedTaps logs how many foreign_tap entries were dropped since the
// last time.
func (s *Service) logDroppedTaps() {
	if n := s.droppedTaps.Swap(0); n > 0 {
		s.log.Warn("broker: dropped foreign_tap entries, because too many waited to be written",
			slog.Int64("dropped", n))
	}
}

// append writes ev to the audit log. On an error it logs, and after a
// failed write it denies every later request and sends one alert.
func (s *Service) append(ev audit.Event) (audit.Anchor, error) {
	a, err := s.audit.Append(ev)
	if err == nil {
		return a, nil
	}
	if errors.Is(err, audit.ErrBroken) {
		if s.broken.CompareAndSwap(false, true) {
			s.log.Error("broker: ALERT: the audit log cannot be written; every request is denied until the broker "+
				"starts again", slog.String("error", errorText(err)))
			s.sendAlert(brokenAlert)
		}
		return audit.Anchor{}, err
	}
	// Audit errors never hold the value of a field.
	s.log.Error("broker: the audit log refused an entry; the request is denied", slog.String("error", errorText(err)))
	return audit.Anchor{}, err
}

// sendAlert sends msg with the alert function of Run, in a goroutine of
// its own, with a deadline. Before Run and after Close it sends nothing.
func (s *Service) sendAlert(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alert == nil || s.closed {
		return
	}
	alert := s.alert
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		defer s.recoverGoroutine("sending an alert")
		ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
		defer cancel()
		if err := alert(ctx, msg); err != nil {
			s.log.Error("broker: cannot send an alert message", slog.String("error", errorText(err)))
		}
	}()
}

// rateAlertEvery is the shortest time between two alerts about the rate
// limit of one store. 1Password counts the reads of a token by the hour;
// Infisical counts by the minute, but one alert an hour is enough.
const rateAlertEvery = time.Hour

// rateLimited sends one alert when the store reached its rate limit, and
// no more for that store for rateAlertEvery. The request is denied anyway.
func (s *Service) rateLimited(name string) {
	s.mu.Lock()
	now := s.now()
	last, seen := s.rateAlerts[name]
	send := !seen || now.Sub(last) >= rateAlertEvery || now.Before(last)
	if send {
		if s.rateAlerts == nil {
			s.rateAlerts = make(map[string]time.Time)
		}
		s.rateAlerts[name] = now
	}
	s.mu.Unlock()
	if send {
		service := "1Password"
		if s.cfg.Stores[name].Type == config.StoreInfisical {
			service = "Infisical"
		}
		s.sendAlert(fmt.Sprintf("The store %q reached the rate limit of %s. The broker denies its secrets "+
			"until %s allows more requests. This alert comes at most once an hour.", name, service, service))
	}
}

// recoverGoroutine recovers a panic in a goroutine of the Service, and
// logs where it happened, but not the panic value, which can hold
// anything. It must be called by defer.
func (s *Service) recoverGoroutine(task string) {
	if v := recover(); v != nil {
		s.log.Error("broker: a goroutine panicked; the panic value is not logged",
			slog.String("task", task), slog.String("where", panicPlace()))
	}
}
