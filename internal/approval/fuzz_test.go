package approval_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// FuzzCore runs random steps against the core: requests of each kind from
// three clients, taps (also ones that must not count), cancels, clock
// steps, StartGrants, and an approver that fails, refuses notices because
// of its own limit, or stops. After each step it checks what the core
// promises:
//
//   - a request is allowed only by one counted tap on Approve, or, without
//     a tap, by grants and "never ask" rules that a model of them allows;
//   - no second answer to one request counts;
//   - per client: at most 5 open messages, at most 10 queued requests, at
//     most 6 new messages in any 60 seconds;
//   - every message has at least 30 seconds left;
//   - no message for a secret or key within 60 seconds after a Deny for
//     it, and no grant for it from a tap before that Deny;
//   - per client, at most 6 notices of "never ask" uses in any 60 seconds;
//   - a use whose notice a limit of the approver refused is denied with
//     cause limit, and it does not count for max_per_day; a use whose
//     notice failed in another way counts: the core counts the same uses
//     as the model;
//   - an SSH grant is approved only before its grants end;
//   - every message is updated exactly once, and every request ends.
//
// One step moves only the wall clock forward, as a host that slept.
func FuzzCore(f *testing.F) {
	f.Add([]byte{0, 0x15, 0, 0x15, 5, 0x00, 7, 30, 9, 0, 0, 0x15})
	f.Add([]byte{0, 0x08, 0, 0x08, 0, 0x08, 0, 0x08, 0, 0x08, 0, 0x08, 0, 0x08, 5, 0x02, 7, 61, 5, 0x01, 7, 200})
	f.Add([]byte{3, 0x00, 0x00, 5, 0x01, 9, 0, 3, 0x00, 0x00, 3, 0x04, 0x00, 7, 255, 3, 0x00, 0x00})
	f.Add([]byte{4, 0x00, 0x0f, 0x03, 5, 0x01, 9, 0, 3, 0x00, 0x00, 3, 0x08, 0x00, 7, 255, 7, 255, 7, 255, 7, 255})
	f.Add([]byte{0, 0x03, 0, 0x03, 0, 0x03, 0, 0x03, 0, 0x03, 0, 0x03, 0, 0x0b, 3, 0x83, 0x02, 3, 0x83, 0x02, 7, 100, 3, 0x83, 0x02})
	f.Add([]byte{0, 0x08, 8, 0, 6, 0, 10, 0, 0, 0x08, 10, 0, 11, 0, 0, 0x0b, 12, 0, 0, 0x08})
	// backup-token by ci, max_per_day = 2: a notice fails, and that use
	// counts; the approver's limit refuses two notices, and those uses do
	// not count. So one more use goes without a tap, and the next asks.
	f.Add([]byte{11, 0, 0x20, 11, 0, 0x20, 0, 0x20, 11, 7, 61, 0, 0x20, 0, 0x20, 0, 0x20})
	f.Fuzz(runFuzzInput)
}

// runFuzzInput runs the steps in ops (at most 400 bytes of them).
func runFuzzInput(t *testing.T, ops []byte) {
	if len(ops) > 400 {
		ops = ops[:400]
	}
	cfg, h := fuzzConfig()
	synctest.Test(t, func(t *testing.T) {
		m := newModel(t, cfg, h)
		defer m.stop()
		for i := 0; i < len(ops); {
			i = m.step(ops, i)
			synctest.Wait()
			m.collect()
			m.check()
		}
		// Every request ends.
		m.clock.Advance(30 * time.Minute)
		synctest.Wait()
		m.collect()
		m.check()
		for i, r := range m.reqs {
			if r.res == nil {
				t.Fatalf("request %d did not end", i)
			}
		}
		for _, x := range m.fake.Asked() {
			if n := m.ended(x.Message); n != 1 {
				t.Fatalf("message %s was updated %d times, want 1", x.Message, n)
			}
		}
		for _, c := range []string{"laptop", "build", "ci"} {
			if open, queued := m.core.Counts(c); open != 0 || queued != 0 {
				t.Fatalf("%s: %d open, %d queued after all ended", c, open, queued)
			}
		}
	})
}

var (
	fuzzOnce  sync.Once
	fuzzCfg   *config.Broker
	fuzzHosts hosts
)

// fuzzConfig returns the test config with limits on the "never ask"
// rules: backup-token may be used twice a day, and the backup key only
// from 12:00 to 12:05. Nothing changes it, so all runs share it.
func fuzzConfig() (*config.Broker, hosts) {
	fuzzOnce.Do(func() {
		var t fakeTB
		fuzzCfg, fuzzHosts = testConfig(&t)
		setSecretRule(fuzzCfg, "backup-token", config.Rule{Ask: config.AskNever, Notify: true, MaxPerDay: 2})
		hours := parseHours(&t, "12:00-12:05")
		setKeyRule(fuzzCfg, "backup", config.Rule{Ask: config.AskNever, Notify: true, Hours: &hours})
	})
	return fuzzCfg, fuzzHosts
}

// fakeTB lets testConfig run outside a test; it panics on a failure.
type fakeTB struct{ testing.TB }

func (fakeTB) Helper()                      {}
func (fakeTB) Fatal(args ...any)            { panic(args) }
func (fakeTB) Fatalf(f string, args ...any) { panic(f) }

var (
	errAskFails    = errors.New("fuzz: Ask fails")
	errNotifyFails = errors.New("fuzz: Notify fails")
	// errNotifyLimit is a limit of the approver itself: Notify sends
	// nothing.
	errNotifyLimit = fmt.Errorf("fuzz: Notify is over its limit: %w", approval.ErrLimit)
)

type fuzzReq struct {
	req       *approval.Request
	ch        <-chan *approval.Result
	cancel    context.CancelFunc
	start     time.Time // when it was made, on the monotonic clock
	startWall time.Time // and on the wall clock
	seq       int       // the step that made it
	res       *approval.Result
	started   bool // StartGrants was called
}

type fuzzAsk struct {
	seq    int
	at     time.Time
	prompt approval.Prompt
}

type fuzzTap struct {
	action audit.Answer
	at     time.Time // on the monotonic clock
	atWall time.Time
	seq    int
	client string
	items  []string
}

// fuzzEnd is the end of a grant on both clocks.
type fuzzEnd struct{ mono, wall time.Time }

type fuzzNotice struct {
	client string
	at     time.Time // on the monotonic clock
}

type scope struct {
	client, item, hostKey, user string
}

type model struct {
	t     *testing.T
	cfg   *config.Broker
	h     hosts
	clock *approvaltest.Clock
	fake  *approvaltest.Approver
	core  *approval.Core
	quit  context.CancelFunc
	run   chan error

	mu      sync.Mutex // guards seq, asks, notices and refused, which the core's goroutines touch
	seq     int
	asks    []fuzzAsk
	notices []fuzzNotice
	refused map[string]bool // the requests whose notice the approver's limit refused, by ID

	reqs       []*fuzzReq
	taps       map[string]fuzzTap // the counted taps, by request ID
	denies     []fuzzTap
	grants     map[scope]fuzzEnd
	uses       map[string]int // never item and day → uses
	failAsk    bool
	notifyMode int // Notify 0: works; 1: fails; 2: refuses because of its own limit
	stopped    bool
}

// recorder records when each message is sent.
type recorder struct {
	*approvaltest.Approver
	m *model
}

func (r recorder) Ask(ctx context.Context, p approval.Prompt) (approval.Shown, error) {
	shown, err := r.Approver.Ask(ctx, p)
	if err == nil {
		r.m.mu.Lock()
		r.m.asks = append(r.m.asks, fuzzAsk{seq: r.m.seq, at: r.m.clock.Now(), prompt: p})
		r.m.mu.Unlock()
	}
	return shown, err
}

func (r recorder) Notify(ctx context.Context, p approval.Prompt) error {
	err := r.Approver.Notify(ctx, p)
	r.m.mu.Lock()
	defer r.m.mu.Unlock()
	switch {
	case err == nil:
		r.m.notices = append(r.m.notices, fuzzNotice{client: p.Client, at: r.m.clock.Now()})
	case errors.Is(err, approval.ErrLimit):
		r.m.refused[p.RequestID] = true
	}
	return err
}

func newModel(t *testing.T, cfg *config.Broker, h hosts) *model {
	m := &model{
		t: t, cfg: cfg, h: h, clock: approvaltest.NewClock(noon), fake: approvaltest.NewApprover(approverID),
		refused: map[string]bool{}, taps: map[string]fuzzTap{}, grants: map[scope]fuzzEnd{}, uses: map[string]int{},
		run: make(chan error, 1),
	}
	core, err := approval.New(cfg, recorder{m.fake, m}, approval.Options{Clock: m.clock})
	if err != nil {
		t.Fatal(err)
	}
	m.core = core
	ctx, quit := context.WithCancel(context.Background())
	m.quit = quit
	go func() { m.run <- core.Run(ctx) }()
	synctest.Wait()
	return m
}

func (m *model) stop() {
	m.quit()
	<-m.run
	synctest.Wait()
}

// step runs the step at ops[i] and returns the index of the next one.
func (m *model) step(ops []byte, i int) int {
	arg := func(k int) int {
		if i+k < len(ops) {
			return int(ops[i+k])
		}
		return 0
	}
	m.mu.Lock()
	m.seq++
	m.mu.Unlock()
	clients := []string{"laptop", "build", "ci"}
	switch ops[i] % 14 {
	case 0, 1, 2: // secrets
		var names []string
		for b, name := range []string{"github-token", "npm-token", "db-password", "backup-token"} {
			if arg(1)>>(2+b)&1 == 1 {
				names = append(names, name)
			}
		}
		if len(names) == 0 {
			names = []string{"github-token"}
		}
		m.add(secretsReq(clients[arg(1)%3], names...))
		return i + 2
	case 3: // an SSH login
		keys := []string{"deploy", "web", "admin", "backup"}
		hostKeys := []ssh.PublicKey{m.h.web1, m.h.web1ecdsa, m.h.web2, m.h.db1}
		users := []string{"deploy", "root", "backup", "deploy"}
		a, b := arg(1), arg(2)
		m.add(loginReq(clients[a%3], keys[a>>2%4], hostKeys[a>>4%4], users[b%4]))
		return i + 3
	case 4: // an SSH grant
		keys := []string{"deploy", "web", "admin", "deploy"}
		var names []string
		for b, name := range []string{"web-1", "web-2", "web-3", "db-1", "more-1"} {
			if arg(2)>>b&1 == 1 {
				names = append(names, name)
			}
		}
		a := arg(1)
		m.add(grantReq(clients[a%2], keys[a>>1%4], []string{"deploy", "root"}[a>>3%2], time.Duration(arg(3)%20)*time.Minute, names...))
		return i + 4
	case 5: // a tap as the person
		asked := m.fake.Asked()
		if len(asked) > 0 {
			x := asked[arg(1)%len(asked)]
			action := []audit.Answer{audit.AnswerApproveOnce, audit.AnswerApproveWindow, audit.AnswerDeny, audit.AnswerDeny}[arg(1)>>6]
			m.tap(approval.Answer{RequestID: x.Prompt.RequestID, Action: action, Message: x.Message, UserID: approverID}, x.Prompt)
		}
		return i + 2
	case 6: // a tap that must not count
		asked := m.fake.Asked()
		if len(asked) > 1 {
			x, y := asked[arg(1)%len(asked)], asked[(arg(1)+1)%len(asked)]
			bad := []approval.Answer{
				{RequestID: x.Prompt.RequestID, Action: audit.AnswerApproveOnce, Message: x.Message, UserID: approverID + 1},
				{RequestID: x.Prompt.RequestID, Action: audit.AnswerApproveOnce, Message: y.Message, UserID: approverID},
				{RequestID: x.Prompt.ShortCode, Action: audit.AnswerApproveOnce, Message: x.Message, UserID: approverID},
				{RequestID: x.Prompt.RequestID, Action: "approve", Message: x.Message, UserID: approverID},
			}[arg(1)>>6]
			if x.Prompt.RequestID != y.Prompt.RequestID || bad.Message == x.Message {
				if err := m.fake.Answer(bad); err == nil {
					m.t.Fatalf("a bad answer %+v counted", bad)
				}
			}
		}
		return i + 2
	case 7: // time passes
		m.clock.Advance(time.Duration(arg(1)) * time.Second)
		return i + 2
	case 8: // a client hangs up
		if len(m.reqs) > 0 {
			m.reqs[arg(1)%len(m.reqs)].cancel()
		}
		return i + 2
	case 9: // the broker has written the decision
		if len(m.reqs) > 0 {
			m.startGrants(m.reqs[arg(1)%len(m.reqs)])
		}
		return i + 2
	case 10:
		m.failAsk = !m.failAsk
		m.fake.FailAsk(map[bool]error{true: errAskFails}[m.failAsk])
		return i + 1
	case 11: // Notify works, fails, or refuses because of its own limit, in turn
		m.notifyMode = (m.notifyMode + 1) % 3
		m.fake.FailNotify([]error{nil, errNotifyFails, errNotifyLimit}[m.notifyMode])
		return i + 1
	case 12: // the approver stops, rarely
		if arg(1) == 0x5a && !m.stopped {
			m.stopped = true
			m.fake.Stop(errors.New("fuzz: the approver stops"))
		}
		return i + 2
	default: // 13: the host slept: only the wall clock moves on
		m.clock.JumpWall(time.Duration(arg(1)) * 10 * time.Second)
		return i + 2
	}
}

func (m *model) add(req *approval.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *approval.Result, 1)
	m.reqs = append(m.reqs, &fuzzReq{req: req, ch: ch, cancel: cancel, start: m.clock.Now(), startWall: m.clock.Wall(), seq: m.seq})
	go func() { ch <- m.core.Decide(ctx, req) }()
}

func (m *model) tap(a approval.Answer, p approval.Prompt) {
	err := m.fake.Answer(a)
	if err != nil {
		return
	}
	if prev, ok := m.taps[a.RequestID]; ok {
		m.t.Fatalf("two taps counted for one request: %s and %s", prev.action, a.Action)
	}
	tap := fuzzTap{action: a.Action, at: m.clock.Now(), atWall: m.clock.Wall(), seq: m.seq, client: p.Client, items: items(p)}
	m.taps[a.RequestID] = tap
	if p.Kind == audit.KindSSHGrant && !tap.atWall.Before(p.GrantEnds) {
		m.t.Fatalf("an SSH grant was approved at %v, after its grants ended at %v", tap.atWall, p.GrantEnds)
	}
	if a.Action == audit.AnswerDeny {
		m.denies = append(m.denies, tap)
		// A Deny ends the client's grants for these secrets or the key.
		for s := range m.grants {
			if s.client == tap.client && slices.Contains(tap.items, s.item) {
				delete(m.grants, s)
			}
		}
	}
}

// items names the secrets or the key of a prompt.
func items(p approval.Prompt) []string {
	if p.Key != "" {
		return []string{"key:" + p.Key}
	}
	var names []string
	for _, s := range p.Secrets {
		names = append(names, "secret:"+s)
	}
	return names
}

func (m *model) startGrants(r *fuzzReq) {
	if r.res == nil {
		return
	}
	r.res.StartGrants()
	if r.started || !r.res.Allowed || r.res.Answer != audit.AnswerApproveWindow {
		r.started = true
		return
	}
	r.started = true
	tap := m.taps[r.res.RequestID]
	d := time.Duration(r.res.WindowMinutes) * time.Minute
	end := fuzzEnd{mono: tap.at.Add(d), wall: tap.atWall.Add(d)}
	if r.req.Kind == audit.KindSSHGrant {
		// The grants end at the end shown in the message: the start of the
		// request plus --for, in whole minutes, on both clocks.
		d = time.Duration(int(r.req.For/time.Minute)) * time.Minute
		end = fuzzEnd{mono: r.start.Add(d), wall: r.startWall.Add(d)}
	}
	if !m.clock.Now().Before(end.mono) || !m.clock.Wall().Before(end.wall) {
		return
	}
	add := func(s scope) {
		for _, deny := range m.denies {
			if deny.client == s.client && deny.seq > tap.seq && slices.Contains(deny.items, s.item) {
				return // a Deny after the tap
			}
		}
		if old, ok := m.grants[s]; !ok || old.mono.Before(end.mono) {
			m.grants[s] = end
		}
	}
	switch r.req.Kind {
	case audit.KindSecrets:
		for _, name := range r.res.Subject.Secrets {
			add(scope{client: r.req.Client, item: "secret:" + name})
		}
	case audit.KindSSHLogin:
		add(scope{client: r.req.Client, item: "key:" + r.req.Key, hostKey: string(r.req.HostKey.Marshal()), user: r.req.RemoteUser})
	case audit.KindSSHGrant:
		for _, host := range r.res.Subject.Hosts {
			for _, hk := range m.cfg.KnownHosts.KeysFor(host) {
				add(scope{client: r.req.Client, item: "key:" + r.req.Key, hostKey: string(hk.Marshal()), user: r.req.RemoteUser})
			}
		}
	}
}

func (m *model) snapshotAsks() []fuzzAsk {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.asks)
}

func (m *model) ended(msg approval.MessageID) int {
	n := 0
	for _, e := range m.fake.Ended() {
		if e.Message == msg {
			n++
		}
	}
	return n
}

// collect takes the results that have come, and checks each.
func (m *model) collect() {
	for _, r := range m.reqs {
		if r.res != nil {
			continue
		}
		select {
		case res := <-r.ch:
			r.res = res
			m.checkResult(r)
		default:
		}
	}
}

func (m *model) checkResult(r *fuzzReq) {
	t, res := m.t, r.res
	if res.Message != "" {
		found := false
		for _, x := range m.fake.Asked() {
			if x.Prompt.RequestID == res.RequestID {
				found = true
				if m.ended(x.Message) != 1 {
					t.Fatalf("request %s ended, its message was updated %d times", res.RequestID, m.ended(x.Message))
				}
			}
		}
		if !found {
			t.Fatalf("request %s has a message text, but no message was sent", res.RequestID)
		}
	}
	m.mu.Lock()
	refused := m.refused[res.RequestID]
	m.mu.Unlock()
	if refused && (res.Allowed || res.Cause != audit.CauseLimit || res.ErrorCode != "" || res.Err != nil) {
		t.Fatalf("the approver's limit refused the notice of request %s: allowed %v, cause %q, code %q, err %v; want cause limit",
			res.RequestID, res.Allowed, res.Cause, res.ErrorCode, res.Err)
	}
	switch {
	case res.Answer != "":
		tap, ok := m.taps[res.RequestID]
		if !ok || tap.action != res.Answer || res.Allowed != (res.Answer != audit.AnswerDeny) {
			t.Fatalf("result %q (allowed %v) without the counted tap; the tap was %+v", res.Answer, res.Allowed, tap)
		}
	case res.Allowed:
		if r.seq != m.seq {
			t.Fatalf("a request was allowed without a tap after it waited")
		}
		m.checkCovered(r)
	case errors.Is(res.Err, errNotifyFails), res.Cause == audit.CauseError && errors.Is(res.Err, context.Canceled):
		// The notice failed, or could not go out because Run had returned.
		// The core counted the uses before, and keeps them: the notice may
		// have gone out. A notice that the approver's limit refused ends
		// with cause limit (checked above), and its uses do not count.
		m.checkCovered(r)
	default:
		switch res.Cause {
		case audit.CauseExpired, audit.CauseCancelled, audit.CauseNotAllowed, audit.CauseLimit, audit.CauseError:
		default:
			t.Fatalf("denied with cause %q", res.Cause)
		}
	}
}

// checkCovered checks that the model of grants and "never ask" rules
// allows every item of r at its start, and counts the uses of the rules.
func (m *model) checkCovered(r *fuzzReq) {
	t := m.t
	at, atWall := r.start, r.startWall
	var never []string
	check := func(item string, rule config.Rule, s scope) {
		switch rule.Ask {
		case config.AskWindow:
			if end, ok := m.grants[s]; !ok || !at.Before(end.mono) || !atWall.Before(end.wall) {
				t.Fatalf("%s was allowed without a tap, but the model has no grant for %+v", item, s)
			}
		case config.AskNever:
			if rule.Hours != nil && !rule.Hours.Contains(atWall) {
				t.Fatalf("%s was allowed without a tap outside its hours", item)
			}
			day := item + atWall.Format(time.DateOnly)
			if rule.MaxPerDay > 0 && m.uses[day] >= rule.MaxPerDay {
				t.Fatalf("%s was allowed without a tap over its max_per_day", item)
			}
			never = append(never, day)
		default:
			t.Fatalf("%s was allowed without a tap with the rule %q", item, rule.Ask)
		}
	}
	switch r.req.Kind {
	case audit.KindSecrets:
		for _, name := range r.res.Subject.Secrets {
			check("secret:"+name, m.cfg.Secrets[name].Rule, scope{client: r.req.Client, item: "secret:" + name})
		}
	case audit.KindSSHLogin:
		check("key:"+r.req.Key, m.cfg.Keys[r.req.Key].Rule,
			scope{client: r.req.Client, item: "key:" + r.req.Key, hostKey: string(r.req.HostKey.Marshal()), user: r.req.RemoteUser})
	default:
		t.Fatalf("a %s request was allowed without a tap", r.req.Kind)
	}
	for _, day := range never {
		m.uses[day]++
	}
}

// check checks the limits, the time left and the pauses.
func (m *model) check() {
	t := m.t
	for _, c := range []string{"laptop", "build", "ci"} {
		if open, queued := m.core.Counts(c); open > approval.MaxOpenMessages || queued > approval.MaxQueued || open < 0 {
			t.Fatalf("%s: %d open messages, %d queued", c, open, queued)
		}
	}
	asks := m.snapshotAsks()
	for i, a := range asks {
		if a.prompt.TimeLeft < approval.MinTimeLeft {
			t.Fatalf("a message with %v left", a.prompt.TimeLeft)
		}
		n := 0
		for _, b := range asks[:i+1] {
			if b.prompt.Client == a.prompt.Client && a.at.Sub(b.at) < time.Minute {
				n++
			}
		}
		if n > approval.MaxNewMessagesPerMinute {
			t.Fatalf("%s got %d messages in a minute", a.prompt.Client, n)
		}
		for _, d := range m.denies {
			if d.client == a.prompt.Client && d.seq <= a.seq && a.at.Sub(d.at) < approval.DenyPause &&
				slices.ContainsFunc(items(a.prompt), func(s string) bool { return slices.Contains(d.items, s) }) {
				t.Fatalf("a message for %v %v after a Deny for it", items(a.prompt), a.at.Sub(d.at))
			}
		}
	}
	for _, x := range m.fake.Asked() {
		if m.ended(x.Message) > 1 {
			t.Fatalf("message %s was updated %d times", x.Message, m.ended(x.Message))
		}
	}
	m.mu.Lock()
	notices := slices.Clone(m.notices)
	m.mu.Unlock()
	for i, a := range notices {
		n := 0
		for _, b := range notices[:i+1] {
			if b.client == a.client && a.at.Sub(b.at) < time.Minute {
				n++
			}
		}
		if n > approval.MaxNoticesPerMinute {
			t.Fatalf("%s sent %d notices in a minute", a.client, n)
		}
	}
	// The core counts the same uses of the "never ask" rules as the model:
	// also those whose notice failed, but not those whose notice the
	// approver's limit refused.
	now := m.clock.Wall()
	for _, it := range []struct {
		key  bool
		name string
	}{{false, "backup-token"}, {true, "backup"}} {
		item := "secret:" + it.name
		if it.key {
			item = "key:" + it.name
		}
		if got, want := m.core.Uses("ci", it.key, it.name, now), m.uses[item+now.Format(time.DateOnly)]; got != want {
			t.Fatalf("the core counts %d uses of %s today, the model %d", got, item, want)
		}
	}
}
