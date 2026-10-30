package release

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/version"
)

// FirstWait is the wait of nodkey broker from its start to its first
// check. A broker that ends sooner, such as one that systemd starts again
// and again, never asks GitHub, and sends no notice in each start
// (DESIGN.md section 15).
const FirstWait = 10 * time.Minute

// The other times of the broker's check (Check.Run).
const (
	// every is the time from a check that worked to the next one.
	every = 24 * time.Hour
	// retry is the time from a check that failed, in its lookup or in its
	// notice, to the next one.
	retry = time.Hour
	// noticeTimeout bounds one try of the notice.
	noticeTimeout = 30 * time.Second
)

// Check is the broker's check for a newer release (DESIGN.md section 15).
// It waits first (FirstWait in nodkey broker), then asks GitHub, and then
// every 24 hours; after a failed lookup or a failed notice, it asks again
// after 1 hour instead. When the newest
// release is newer than the broker's own version, it sends one notice
// (DESIGN.md section 7). Each newer release gets one notice that went out
// in a start of the broker: a notice counts as sent only when the notice
// function reports no error. A release that is not newer than the broker,
// or than a release that got its notice, gets none: the notice never
// suggests a downgrade. Make a Check with NewCheck, and call Run once.
type Check struct {
	own    version.Release
	first  time.Duration // the wait before the first check
	lookup func(ctx context.Context) (Info, error)
	notice func(ctx context.Context, msg string) error
	// loud sends the notice about a security release, with a sound.
	loud func(ctx context.Context, msg string) error
	log  *slog.Logger
	// wait waits for d, or until ctx ends. It is a field only so that a
	// test can use a fake.
	wait func(ctx context.Context, d time.Duration) error
}

// NewCheck returns the check of a broker whose version is own. Its first
// check comes after first, such as FirstWait. lookup finds the newest
// release, such as Client.Lookup. notice sends the notice to the
// approver, such as telegram.Approver.Inform: it makes one try, and its
// ctx has a deadline. log gets a line for each newer release, each
// notice, each failed lookup and each failed notice, with fixed texts and
// release versions only; it may be nil.
func NewCheck(own version.Release, first time.Duration, lookup func(ctx context.Context) (Info, error),
	notice, loud func(ctx context.Context, msg string) error, log *slog.Logger,
) *Check {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Check{own: own, first: first, lookup: lookup, notice: notice, loud: loud, log: log, wait: sleep}
}

// Run checks for a newer release until ctx ends. It never stops on its
// own. The wait, a lookup or a notice that runs when ctx ends is
// cancelled, and no request and no notice goes out after Run returned.
// So a ctx that ends during the first wait ends Run without any call.
func (c *Check) Run(ctx context.Context) {
	// noticed is the newest release that a notice went out for, or the
	// broker's own version; logged is the same for the log line.
	noticed, logged := c.own, c.own
	for next := c.first; c.wait(ctx, next) == nil; {
		next = c.once(ctx, &noticed, &logged)
	}
}

// once makes one check, and returns the time until the next one.
func (c *Check) once(ctx context.Context, noticed, logged *version.Release) time.Duration {
	info, err := c.lookup(ctx)
	if ctx.Err() != nil {
		return 0 // the broker stops
	}
	if err != nil {
		c.log.Warn("release: cannot check for a newer release of nodkey; the next check is in 1 hour",
			slog.String("error", err.Error()))
		return retry
	}
	if fixes, ids := info.SecurityNewer(c.own); len(fixes) > 0 {
		return c.security(ctx, fixes, ids)
	}
	newest := info.Newest
	if newest.Compare(*noticed) <= 0 {
		return every // no newer release, or its notice went out
	}
	if newest.Compare(*logged) > 0 {
		*logged = newest
		c.log.Warn("release: a newer release of nodkey is out; update the broker host and the agent machines",
			slog.String("newest", newest.String()), slog.String("broker_version", c.own.String()))
	}
	nctx, cancel := context.WithTimeout(ctx, noticeTimeout)
	err = c.notice(nctx, noticeText(newest, c.own))
	cancel()
	if ctx.Err() != nil {
		return 0
	}
	if err != nil {
		// The errors of the Telegram approver have fixed texts.
		c.log.Warn("release: the notice about a newer release of nodkey did not go out; the next check is in 1 hour",
			slog.String("newest", newest.String()), slog.String("error", err.Error()))
		return retry
	}
	*noticed = newest
	c.log.Info("release: the notice about a newer release of nodkey went out", slog.String("newest", newest.String()))
	return every
}

// security sends the loud notice about the security releases fixes, which
// are newer than the broker. It goes out at each check until the broker
// runs one of them or a newer release: a security release does not get
// only one notice, as a normal release does (DESIGN.md section 15).
func (c *Check) security(ctx context.Context, fixes []version.Release, ids []string) time.Duration {
	newest := fixes[len(fixes)-1]
	c.log.Warn("release: GitHub lists a security release of nodkey; update the broker host and the agent machines",
		slog.String("newest_security", newest.String()), slog.String("broker_version", c.own.String()))
	nctx, cancel := context.WithTimeout(ctx, noticeTimeout)
	err := c.loud(nctx, securityText(fixes, ids, c.own))
	cancel()
	if ctx.Err() != nil {
		return 0
	}
	if err != nil {
		c.log.Warn("release: the notice about a security release of nodkey did not go out; the next check is in 1 hour",
			slog.String("newest_security", newest.String()), slog.String("error", err.Error()))
		return retry
	}
	c.log.Info("release: the notice about a security release of nodkey went out", slog.String("newest_security", newest.String()))
	return every
}

// securityText returns the text of the notice about the security releases
// fixes, for a broker that runs own. It holds fixed text, release
// versions, GHSA IDs in their strict form (at most 3), and the link made
// from the newest of fixes. The text ends with the link.
func securityText(fixes []version.Release, ids []string, own version.Release) string {
	newest := fixes[len(fixes)-1]
	adv := ""
	if len(ids) > 0 {
		adv = " Advisories: " + strings.Join(ids, ", ") + "."
	}
	return "SECURITY UPDATE: " + SecurityFixes(fixes) + ". The broker runs nodkey " + own.String() + "." + adv +
		" This flag comes from GitHub's answer and is not checked: read the checked notes with " +
		"nodkey update --notes. To update the broker, run as root on the broker host: nodkey update. " +
		"Then restart it: systemctl restart nodkey. The restart ends all grants. Update the agent machines " +
		"too: run nodkey update as root. This notice comes again each day until the broker runs nodkey " +
		newest.String() + " or newer. Release notes: " + PageURL(newest)
}

// noticeText returns the text of the notice about the release newest, for
// a broker that runs own. Both are release versions, which hold only
// digits and dots, and the link is made from newest. The text ends with
// the link, so that no dot follows it.
func noticeText(newest, own version.Release) string {
	return "A newer release is out: nodkey " + newest.String() + ". The broker runs nodkey " + own.String() +
		". To update the broker, run as root on the broker host: nodkey update. Then restart it: " +
		"systemctl restart nodkey. The restart ends all grants. Update the agent machines too: " +
		"run nodkey update as root. What is new: nodkey update --notes. Release notes: " + PageURL(newest)
}

// sleep waits for d, or until ctx ends. A ctx that has ended returns at
// once, also for d 0.
func sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
