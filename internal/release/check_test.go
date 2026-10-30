package release

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/version"
)

// lookup is what one lookup of a checkRun returns.
type lookup struct {
	newest   version.Release
	err      error
	security []Security
}

// checkRun is a Check that runs in its own goroutine, with fakes. Its
// wait is a fake clock: the check tells the test each wait it asks for,
// and the wait ends only when the test lets the time pass (tick). The test
// gives the result of each lookup, and decides how each try of the notice
// ends.
type checkRun struct {
	t       *testing.T
	lookups chan lookup
	waits   chan time.Duration
	ticks   chan struct{}
	cancel  context.CancelFunc
	done    chan struct{}
	logs    *syncBuffer

	mu        sync.Mutex
	looked    int           // the lookups that began
	tries     []string      // the text of each try of the notice
	sent      []string      // the notices that went out
	noticeErr error         // the result of the next tries
	gate      chan struct{} // if set, each try waits until it is closed, or its context ends
	deadlines []time.Duration

	nextSecurity []Security // the security releases of each next lookup; only the test goroutine uses it
}

// syncBuffer is a log that many goroutines can write.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startCheck runs the check of a broker of version own, with the first
// wait of nodkey broker, and returns when the check waits for its first
// check. That wait must be FirstWait, and no lookup may come before it.
func startCheck(t *testing.T, own version.Release) *checkRun {
	t.Helper()
	r := &checkRun{t: t, lookups: make(chan lookup), waits: make(chan time.Duration), ticks: make(chan struct{}),
		done: make(chan struct{}), logs: &syncBuffer{}}
	c := NewCheck(own, FirstWait, r.latest, r.notice, r.loud, slog.New(slog.NewTextHandler(r.logs, nil)))
	c.wait = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case r.waits <- d:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-r.ticks:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		defer close(r.done)
		c.Run(ctx)
	}()
	t.Cleanup(r.stop)
	if got := r.nextWait(); got != 10*time.Minute {
		t.Fatalf("the first check in %s, want 10 minutes", got)
	}
	if n := r.lookupsBegun(); n != 0 {
		t.Fatalf("%d lookups before the first wait ended", n)
	}
	return r
}

// nextWait returns the next wait that the check asks for.
func (r *checkRun) nextWait() time.Duration {
	r.t.Helper()
	select {
	case d := <-r.waits:
		return d
	case <-time.After(10 * time.Second):
		r.t.Fatal("the check does not wait")
		return 0
	}
}

// tick ends the wait of the check, as the time of the wait passed.
func (r *checkRun) tick() {
	r.t.Helper()
	select {
	case r.ticks <- struct{}{}:
	case <-time.After(10 * time.Second):
		r.t.Fatal("the check does not wait")
	}
}

// lookupsBegun returns the number of lookups that began.
func (r *checkRun) lookupsBegun() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.looked
}

func (r *checkRun) latest(ctx context.Context) (Info, error) {
	r.mu.Lock()
	r.looked++
	r.mu.Unlock()
	select {
	case l := <-r.lookups:
		return Info{Newest: l.newest, Security: l.security}, l.err
	case <-ctx.Done():
		return Info{}, ctx.Err()
	}
}

// loud is the notice with a sound. Its texts start with "LOUD " in tries
// and sent.
func (r *checkRun) loud(ctx context.Context, msg string) error { return r.notice(ctx, "LOUD "+msg) }

func (r *checkRun) notice(ctx context.Context, msg string) error {
	r.mu.Lock()
	r.tries = append(r.tries, msg)
	if dl, ok := ctx.Deadline(); ok {
		r.deadlines = append(r.deadlines, time.Until(dl))
	}
	err, gate := r.noticeErr, r.gate
	r.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.sent = append(r.sent, msg)
	r.mu.Unlock()
	return nil
}

// round lets the wait before the next check pass, gives the lookup of
// that check its result, and returns the wait that the check asks for
// after it.
func (r *checkRun) round(newest version.Release, err error) time.Duration {
	r.t.Helper()
	r.tick()
	r.lookup(newest, err)
	return r.nextWait()
}

// lookup gives the lookup that waits its result.
func (r *checkRun) lookup(newest version.Release, err error) {
	r.t.Helper()
	select {
	case r.lookups <- lookup{newest: newest, err: err, security: r.nextSecurity}:
	case <-time.After(10 * time.Second):
		r.t.Fatal("the check made no lookup")
	}
}

// mustRound fails unless the round asks for the wait want.
func (r *checkRun) mustRound(newest version.Release, err error, want time.Duration) {
	r.t.Helper()
	if got := r.round(newest, err); got != want {
		r.t.Fatalf("after %v, %v: the next check in %s, want %s", newest, err, got, want)
	}
}

// setNotice sets the result of the next tries of the notice.
func (r *checkRun) setNotice(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.noticeErr = err
}

// notices returns the tries of the notice, and the notices that went
// out.
func (r *checkRun) notices() (tries, sent []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.tries...), append([]string(nil), r.sent...)
}

// stop ends the check, and waits until Run returned.
func (r *checkRun) stop() {
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
		r.t.Error("Run did not return after its context ended")
	}
}

// rel returns the release major.minor.patch.
func rel(major, minor, patch int) version.Release {
	return version.Release{Major: major, Minor: minor, Patch: patch}
}

// TestCheckNotices: a newer release gets one notice, with the versions,
// the steps and the link made from its version. The same release later
// gets none, and neither does the broker's own release, an older one, or
// one older than a release that got its notice: the notice never
// suggests a downgrade. A second newer release gets a second notice. Each
// check that worked waits 24 hours.
func TestCheckNotices(t *testing.T) {
	r := startCheck(t, rel(0, 2, 0))
	r.mustRound(rel(0, 2, 0), nil, 24*time.Hour)
	r.mustRound(rel(0, 1, 9), nil, 24*time.Hour)
	if tries, _ := r.notices(); len(tries) != 0 {
		t.Fatalf("notices %q for releases that are not newer", tries)
	}
	r.mustRound(rel(0, 3, 0), nil, 24*time.Hour)
	r.mustRound(rel(0, 3, 0), nil, 24*time.Hour)
	r.mustRound(rel(0, 10, 0), nil, 24*time.Hour) // 0.10.0 is newer than 0.3.0
	r.mustRound(rel(0, 4, 0), nil, 24*time.Hour)  // newer than the broker, older than 0.10.0
	r.mustRound(rel(0, 1, 0), nil, 24*time.Hour)
	r.stop()
	tries, sent := r.notices()
	want := []string{noticeText(rel(0, 3, 0), rel(0, 2, 0)), noticeText(rel(0, 10, 0), rel(0, 2, 0))}
	if strings.Join(tries, "\n") != strings.Join(want, "\n") || len(sent) != 2 {
		t.Errorf("tries:\n%s\nwant:\n%s", strings.Join(tries, "\n"), strings.Join(want, "\n"))
	}
	if want := "A newer release is out: nodkey 0.3.0. The broker runs nodkey 0.2.0. To update the broker, run as " +
		"root on the broker host: nodkey update. Then restart it: systemctl restart nodkey. The restart ends all " +
		"grants. Update the agent machines too: run nodkey update as root. What is new: nodkey update --notes. " +
		"Release notes: " +
		"https://github.com/code6x/nodkey/releases/tag/v0.3.0"; tries[0] != want {
		t.Errorf("the notice:\n%s\nwant:\n%s", tries[0], want)
	}
	logs := r.logs.String()
	for _, v := range []string{"0.3.0", "0.10.0"} {
		line := `msg="release: a newer release of nodkey is out; update the broker host and the agent machines" ` +
			"newest=" + v + " broker_version=0.2.0"
		if strings.Count(logs, line) != 1 {
			t.Errorf("want one line %q; the log:\n%s", line, logs)
		}
	}
	if strings.Contains(logs, "level=WARN msg=\"release: cannot") || strings.Contains(logs, "did not go out") {
		t.Errorf("the log has an error:\n%s", logs)
	}
}

// TestCheckRetries: a failed lookup gives one log line with its error, no
// notice, and the next check after 1 hour. So does a notice that did not
// go out, also one that the limit of the notices stopped; the next check
// tries it again. Once it went out, no more tries come for that release.
// The log line about the newer release comes once.
func TestCheckRetries(t *testing.T) {
	r := startCheck(t, rel(0, 2, 0))
	errs := []error{
		fmt.Errorf("%w (HTTP 403); try again later", ErrRateLimit),
		errors.New("cannot reach GitHub: the lookup timed out"),
		errors.New("the tag of the newest release on GitHub is not vX.Y.Z"),
	}
	for _, err := range errs {
		r.mustRound(version.Release{}, err, time.Hour)
	}
	if tries, _ := r.notices(); len(tries) != 0 {
		t.Fatalf("notices %q after failed lookups", tries)
	}
	r.setNotice(errors.New("telegram: sendMessage: Telegram has a server error (500)"))
	r.mustRound(rel(0, 3, 0), nil, time.Hour)
	r.setNotice(errors.New("telegram: too many notices of the broker in the last minute"))
	r.mustRound(rel(0, 3, 0), nil, time.Hour)
	r.setNotice(nil)
	r.mustRound(rel(0, 3, 0), nil, 24*time.Hour)
	r.mustRound(rel(0, 3, 0), nil, 24*time.Hour)
	r.mustRound(rel(0, 3, 0), errors.New("cannot reach GitHub: the connection failed"), time.Hour)
	r.mustRound(rel(0, 3, 0), nil, 24*time.Hour)
	r.stop()
	tries, sent := r.notices()
	if len(tries) != 3 || len(sent) != 1 {
		t.Errorf("%d tries and %d notices, want 3 and 1", len(tries), len(sent))
	}
	logs := r.logs.String()
	for _, err := range append(errs, errors.New("cannot reach GitHub: the connection failed")) {
		line := `msg="release: cannot check for a newer release of nodkey; the next check is in 1 hour" error="` +
			err.Error() + `"`
		if !strings.Contains(logs, line) {
			t.Errorf("no line %q; the log:\n%s", line, logs)
		}
	}
	for _, line := range []string{
		`msg="release: the notice about a newer release of nodkey did not go out; the next check is in 1 hour" ` +
			`newest=0.3.0 error="telegram: sendMessage: Telegram has a server error (500)"`,
		`msg="release: the notice about a newer release of nodkey did not go out; the next check is in 1 hour" ` +
			`newest=0.3.0 error="telegram: too many notices of the broker in the last minute"`,
		`msg="release: the notice about a newer release of nodkey went out" newest=0.3.0`,
	} {
		if strings.Count(logs, line) != 1 {
			t.Errorf("want one line %q; the log:\n%s", line, logs)
		}
	}
	if n := strings.Count(logs, "a newer release of nodkey is out"); n != 1 {
		t.Errorf("%d lines about the newer release, want 1:\n%s", n, logs)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.deadlines {
		if d <= 0 || d > noticeTimeout {
			t.Errorf("a try of the notice had %s left, want at most %s", d, noticeTimeout)
		}
	}
	if len(r.deadlines) != 3 {
		t.Errorf("%d tries had a deadline, want 3", len(r.deadlines))
	}
}

// TestCheckWaitsFirst: the first check comes 10 minutes after the start
// (startCheck checks the wait), with no lookup before. A stop during that
// wait ends Run at once, without a lookup, a notice or a log line. So a
// broker that systemd starts again and again, and that ends within 10
// minutes, never asks GitHub, and sends no notice in each start.
func TestCheckWaitsFirst(t *testing.T) {
	r := startCheck(t, rel(0, 2, 0))
	r.stop()
	tries, _ := r.notices()
	if n := r.lookupsBegun(); n != 0 || len(tries) != 0 || r.logs.String() != "" {
		t.Errorf("a stop during the first wait: %d lookups, %d notices, the log %q; want none", n, len(tries),
			r.logs.String())
	}
}

// TestCheckStops: when the context ends, Run returns, whether it waits
// for a lookup, for a notice or for the next check. A lookup or a notice
// that it ends logs no failure, and nothing goes out after Run returned.
// (TestCheckRealWait: the real wait ends with the context too.)
func TestCheckStops(t *testing.T) {
	// During the first lookup, during the wait after a check, and during a
	// later lookup.
	r := startCheck(t, rel(0, 2, 0))
	r.tick()
	r.stop()
	r = startCheck(t, rel(0, 2, 0))
	r.mustRound(rel(0, 2, 0), nil, 24*time.Hour)
	r.stop()
	r = startCheck(t, rel(0, 2, 0))
	r.mustRound(rel(0, 2, 0), nil, 24*time.Hour)
	r.tick()
	r.stop()
	if n := r.lookupsBegun(); n != 2 {
		t.Errorf("%d lookups, want 2", n)
	}

	// During a notice.
	r = startCheck(t, rel(0, 2, 0))
	gate := make(chan struct{})
	r.mu.Lock()
	r.gate = gate
	r.mu.Unlock()
	r.tick()
	r.lookup(rel(0, 3, 0), nil)
	deadline := time.Now().Add(10 * time.Second)
	for tries, _ := r.notices(); len(tries) == 0; tries, _ = r.notices() {
		if time.Now().After(deadline) {
			t.Fatal("no try of the notice")
		}
		time.Sleep(time.Millisecond)
	}
	r.stop()
	close(gate)
	tries, sent := r.notices()
	if len(tries) != 1 || len(sent) != 0 {
		t.Errorf("%d tries and %d notices after the stop, want 1 and 0", len(tries), len(sent))
	}
	if logs := r.logs.String(); strings.Contains(logs, "did not go out") || strings.Contains(logs, "cannot check") {
		t.Errorf("the stop logged a failure:\n%s", logs)
	}
}

// TestCheckRealWait: the wait of a Check is a timer that ends with its
// context, also a wait of 0 after the context ended.
func TestCheckRealWait(t *testing.T) {
	if err := sleep(t.Context(), time.Millisecond); err != nil {
		t.Errorf("sleep: %v", err)
	}
	if err := sleep(t.Context(), 0); err != nil {
		t.Errorf("sleep for 0: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if err := sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleep while the context ends: %v", err)
	}
	for range 100 {
		if err := sleep(ctx, 0); !errors.Is(err, context.Canceled) {
			t.Fatalf("sleep for 0 with a context that ended: %v", err)
		}
	}
}

// TestCheckSecurity: a security release newer than the broker, also one
// older than the newest release, gets the loud notice at each daily check,
// until the broker runs it. A failed loud notice is tried again after 1
// hour. A security release that is not newer gets no loud notice.
func TestCheckSecurity(t *testing.T) {
	id := "GHSA-" + strings.Repeat("c", 4) + "-" + strings.Repeat("f", 4) + "-" + strings.Repeat("g", 4)
	r := startCheck(t, rel(0, 3, 0))
	r.nextSecurity = []Security{{Version: rel(0, 2, 9)}}
	r.mustRound(rel(0, 3, 0), nil, 24*time.Hour)
	r.nextSecurity = []Security{{Version: rel(0, 3, 1), IDs: []string{id}}}
	r.mustRound(rel(0, 3, 2), nil, 24*time.Hour) // a skipped security release
	r.mustRound(rel(0, 3, 2), nil, 24*time.Hour) // again the next day
	r.setNotice(errors.New("telegram: no answer"))
	r.mustRound(rel(0, 3, 2), nil, time.Hour)
	r.stop()
	tries, sent := r.notices()
	want := "LOUD " + securityText([]version.Release{rel(0, 3, 1)}, []string{id}, rel(0, 3, 0))
	if len(tries) != 3 || len(sent) != 2 || tries[0] != want || tries[1] != want || tries[2] != want {
		t.Fatalf("tries %q, %d sent; want 3 tries of %q, 2 sent", tries, len(sent), want)
	}
	if want := "LOUD SECURITY UPDATE: nodkey 0.3.1 fixes a security problem. The broker runs nodkey 0.3.0. " +
		"Advisories: " + id + ". This flag comes from GitHub's answer and is not checked: read the checked " +
		"notes with nodkey update --notes. To update the broker, run as root on the broker host: nodkey update. " +
		"Then restart it: systemctl restart nodkey. The restart ends all grants. Update the agent machines too: " +
		"run nodkey update as root. This notice comes again each day until the broker runs nodkey 0.3.1 or " +
		"newer. Release notes: https://github.com/code6x/nodkey/releases/tag/v0.3.1"; tries[0] != want {
		t.Errorf("the notice:\n%s\nwant:\n%s", tries[0], want)
	}
}
