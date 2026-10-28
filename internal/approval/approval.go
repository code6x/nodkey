// Package approval is the approval core of the broker (DESIGN.md sections
// 7 and 8). For each request, it decides whether to ask the person, and it
// turns the person's answer, or no answer, into approve or deny.
//
// The broker checks a request first: the client's TLS key, the names, and
// for SSH the session-bind and the host key. Then it calls Core.Decide.
// The core:
//
//   - checks the request again against the broker config, and denies it on
//     any problem, such as a rule that is not "always", "window" or
//     "never", or a "never" rule for a key without hosts;
//   - allows it without a tap when grants and "never ask" rules cover
//     every secret or key in it;
//   - else shows it to the person through an Approver, such as Telegram,
//     within the limits per client, and takes the first valid answer, until
//     the request expires or the client hangs up.
//
// Grants (also scheduled ones), the pauses after a Deny and the uses of
// "never ask" rules live only in memory, so a restart ends them. Time limits use the monotonic
// clock; requests and grants also end on the wall clock, so a host that
// slept does not make them longer (see Clock).
//
// The core fails closed: an error, a timeout, a cancel, a rule it does not
// know, or any other unclear case is a deny.
//
// The core does not write the audit log. Result.Events returns the entries
// of a request, and the broker writes them. The broker calls
// Result.StartGrants only after the decision entry is on disk, so a grant
// never exists without its record.
package approval

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// Limits per client, so a broken or hostile agent cannot flood the phone
// (DESIGN.md section 8). Requests that grants and "never ask" rules allow
// do not count, and are not limited, except for the notices of "never ask"
// uses.
const (
	// MaxOpenMessages is the most messages that wait for an answer.
	MaxOpenMessages = 5
	// MaxNewMessagesPerMinute is the most new messages in any 60 seconds.
	MaxNewMessagesPerMinute = 6
	// MaxQueued is the most requests that wait for a place, without a
	// message.
	MaxQueued = 10
	// MinTimeLeft is the least time a request must have left to leave the
	// queue and get a message.
	MinTimeLeft = 30 * time.Second
	// DenyPause is how long new requests for a secret or key are denied
	// without a message after the person pressed Deny for it.
	DenyPause = 60 * time.Second
	// MaxNoticesPerMinute is the most notices of "never ask" uses in any
	// 60 seconds. A use that would need one more is denied.
	MaxNoticesPerMinute = 6
)

// MaxPreapproveSecrets is the most secrets in one scheduled grant (the most
// variables of one run, DESIGN.md section 5).
const MaxPreapproveSecrets = 32

// MaxGrantHosts is the most hosts in one SSH grant (nodkey ssh-grant,
// DESIGN.md section 13).
const MaxGrantHosts = 20

// endTimeout bounds End. The request is decided already, and Decide
// returns after End, so an approved SSH login must not wait long: sshd
// drops a login after LoginGraceTime.
const endTimeout = 5 * time.Second

// Options are the optional parts of a Core.
type Options struct {
	// Clock is the time source. The default is the real clock.
	Clock Clock
	// Logger gets problems that do not change a decision, such as a
	// message that could not be updated. The default drops them.
	Logger *slog.Logger
}

// Core decides requests. Make it with New, and call Run. It is safe for
// use by many goroutines.
type Core struct {
	cfg      *config.Broker
	approver Approver
	clock    Clock
	logger   *slog.Logger
	random   io.Reader // crypto/rand.Reader; tests of IDs replace it

	// stopCtx ends when Run returns: then no answer can come any more.
	// The calls to the approver about a request end with it.
	stopCtx  context.Context
	stopRuns context.CancelFunc

	mu      sync.Mutex
	ids     map[string]*pending     // the requests in Decide, by ID
	codes   map[string]bool         // the short codes of the requests in Decide
	waiting map[string]*pending     // the requests whose message waits for an answer, by ID
	clients map[string]*clientState // by client name
	grants  []*grant                // the grants that have not ended
	uses    map[useKey]dayUses      // uses of "never ask" rules
	// endedQueue holds the entries of scheduled grants that ended, until
	// watchGrants hands them to onEnded.
	endedQueue []audit.GrantEnded
	onEnded    func(audit.GrantEnded)
	grantWake  chan struct{} // wakes watchGrants; it has room for one
	decisions  uint64        // counts the answers that counted
	running    bool          // Run has started
	stopped    bool          // Run has returned: no answer can come any more
}

// New returns a core that decides requests by the rules of cfg and asks
// the person through a. cfg must come from config.LoadBroker, and nothing
// may change it later. The approver's user ID, cfg.Telegram.UserID, is the
// only one whose answers count.
func New(cfg *config.Broker, a Approver, opts Options) (*Core, error) {
	switch {
	case cfg == nil:
		return nil, errors.New("approval: the broker config is missing")
	case a == nil:
		return nil, errors.New("approval: the approver is missing")
	case cfg.Telegram.UserID <= 0:
		return nil, errors.New("approval: the broker config has no approver user ID")
	case cfg.Telegram.Timeout <= 0 || cfg.Telegram.SSHTimeout <= 0:
		return nil, errors.New("approval: the broker config has no request timeouts")
	}
	stopCtx, stopRuns := context.WithCancel(context.Background())
	c := &Core{
		cfg:       cfg,
		approver:  a,
		clock:     opts.Clock,
		logger:    opts.Logger,
		random:    rand.Reader,
		stopCtx:   stopCtx,
		stopRuns:  stopRuns,
		ids:       make(map[string]*pending),
		codes:     make(map[string]bool),
		waiting:   make(map[string]*pending),
		clients:   make(map[string]*clientState),
		grantWake: make(chan struct{}, 1),
		uses:      make(map[useKey]dayUses),
	}
	if c.clock == nil {
		c.clock = realClock{}
	}
	if c.logger == nil {
		c.logger = slog.New(slog.DiscardHandler)
	}
	return c, nil
}

// Run passes the person's answers from the approver to the core, until ctx
// ends or the approver stops. Then no answer can come any more: the core
// denies every request that waits for the person (audit cause error, code
// approver_failed), and every new request that needs a message. The
// context of each call to Ask and Notify ends too, so a "never ask" use
// that needs a notice is denied as well. Grants still allow requests, and
// so do "never ask" rules with notify = false; the broker should stop.
//
// Run returns why it stopped. It can run only once. If the approver's Run
// panics, the core stops too, and the panic goes on.
func (c *Core) Run(ctx context.Context) error {
	if !c.start() {
		return errors.New("approval: Run can run only once")
	}
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		c.watchGrants(ctx)
	}()
	defer func() {
		c.stopAll()
		<-watched
		c.dropScheduled()
	}()
	if err := c.approver.Run(ctx, c.Answer); err != nil {
		return err
	}
	return ErrStopped
}

// start marks that Run has started. It reports false if Run ran before.
func (c *Core) start() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return false
	}
	c.running = true
	return true
}

// stopAll marks that no answer can come any more, and wakes every request
// that waits for one.
func (c *Core) stopAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopped = true // first, so a request that wakes sees it
	c.stopRuns()
}

// callContext returns the context of a call to the approver about a
// request: it ends after d, when ctx ends, or when Run returns.
func (c *Core) callContext(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	cctx, cancel := context.WithTimeout(ctx, d)
	unhook := context.AfterFunc(c.stopCtx, cancel)
	if c.stopCtx.Err() != nil {
		// Run has returned. AfterFunc cancels in a goroutine of its own,
		// maybe after the call has begun; end the context now.
		cancel()
	}
	return cctx, func() {
		unhook()
		cancel()
	}
}

// timeout returns how long a request of kind k waits for an answer. SSH
// logins have their own, shorter time, below sshd's LoginGraceTime
// (DESIGN.md section 6). An SSH grant is not a login, so it has the time
// of secrets.
func (c *Core) timeout(k audit.Kind) time.Duration {
	if k == audit.KindSSHLogin {
		return c.cfg.Telegram.SSHTimeout
	}
	return c.cfg.Telegram.Timeout
}
