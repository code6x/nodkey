package approval_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// The tests run in synctest bubbles: synctest.Wait returns when every
// goroutine of the test waits, so a test knows when the core has sent its
// messages or put a request in the queue. The core's time is the fake
// clock of package approvaltest; it moves only with Advance.

// approverID is the Telegram user ID of the approver.
const approverID int64 = 123456789

// noon is the start of the fake clock.
var noon = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// Timeouts of the test config: the defaults of the broker config.
const (
	secretsTimeout = 120 * time.Second
	sshTimeout     = 90 * time.Second
)

// hosts are the host keys in the known_hosts of the test config.
type hosts struct {
	web1, web1ecdsa, web2, web3, db1 ssh.PublicKey
	// more are hosts more-1 to more-21, for the limit of 20 hosts.
	more []ssh.PublicKey
}

func newEd25519Key(t testing.TB) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newECDSAKey(t testing.TB) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// testConfig returns a broker config as LoadBroker would make it:
//
//   - clients laptop, build and ci;
//   - secrets github-token (window 15m, laptop and build), npm-token
//     (window 5m, laptop), db-password (always, laptop) and backup-token
//     (never, ci);
//   - keys deploy (window 15m, laptop and build, any host), web (window
//     15m, laptop, web-1 and web-2), admin (always, laptop, web-1) and
//     backup (never, ci, db-1);
//   - hosts web-1 (an ed25519 and an ECDSA key), web-2, web-3, db-1 and
//     more-1 to more-21.
func testConfig(t testing.TB) (*config.Broker, hosts) {
	t.Helper()
	h := hosts{
		web1: newEd25519Key(t), web1ecdsa: newECDSAKey(t), web2: newEd25519Key(t),
		web3: newEd25519Key(t), db1: newEd25519Key(t),
	}
	var b strings.Builder
	line := func(name string, key ssh.PublicKey) {
		fmt.Fprintf(&b, "%s %s %s\n", name, key.Type(), base64.StdEncoding.EncodeToString(key.Marshal()))
	}
	line("web-1", h.web1)
	line("web-1", h.web1ecdsa)
	line("web-2", h.web2)
	line("web-3", h.web3)
	line("db-1", h.db1)
	for i := 1; i <= approval.MaxGrantHosts+1; i++ {
		key := newEd25519Key(t)
		h.more = append(h.more, key)
		line(fmt.Sprintf("more-%d", i), key)
	}
	kh, err := config.ParseKnownHosts([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	window := func(d time.Duration) config.Rule { return config.Rule{Ask: config.AskWindow, Window: d} }
	never := config.Rule{Ask: config.AskNever, Notify: true}
	always := config.Rule{Ask: config.AskAlways}
	cfg := &config.Broker{
		Telegram: config.Telegram{
			UserID: approverID, NoticeChatID: approverID, Timeout: secretsTimeout, SSHTimeout: sshTimeout,
		},
		Clients: map[string]config.Client{
			"laptop": {Name: "laptop"}, "build": {Name: "build"}, "ci": {Name: "ci"},
		},
		Secrets: map[string]config.Secret{
			"github-token": {Name: "github-token", Clients: []string{"laptop", "build"}, Rule: window(15 * time.Minute)},
			"npm-token":    {Name: "npm-token", Clients: []string{"laptop"}, Rule: window(5 * time.Minute)},
			"db-password":  {Name: "db-password", Clients: []string{"laptop"}, Rule: always},
			"backup-token": {Name: "backup-token", Clients: []string{"ci"}, Rule: never},
		},
		Keys: map[string]config.Key{
			"deploy": {Name: "deploy", Clients: []string{"laptop", "build"}, Rule: window(15 * time.Minute)},
			"web":    {Name: "web", Clients: []string{"laptop"}, Rule: window(15 * time.Minute), Hosts: []string{"web-1", "web-2"}},
			"admin":  {Name: "admin", Clients: []string{"laptop"}, Rule: always, Hosts: []string{"web-1"}},
			"backup": {Name: "backup", Clients: []string{"ci"}, Rule: never, Hosts: []string{"db-1"}},
		},
		KnownHosts: kh,
	}
	return cfg, h
}

// setSecretRule and setKeyRule change a rule in the config.
func setSecretRule(cfg *config.Broker, name string, r config.Rule) {
	s := cfg.Secrets[name]
	s.Rule = r
	cfg.Secrets[name] = s
}

func setKeyRule(cfg *config.Broker, name string, r config.Rule) {
	k := cfg.Keys[name]
	k.Rule = r
	cfg.Keys[name] = k
}

// env is a running core with the test config, a fake clock and a fake
// approver.
type env struct {
	t      *testing.T
	cfg    *config.Broker
	hosts  hosts
	clock  *approvaltest.Clock
	fake   *approvaltest.Approver
	core   *approval.Core
	cancel context.CancelFunc
	runErr chan error
	ran    bool  // Run has returned, and err is its error
	err    error // the error of Run
}

// newEnv starts a core. edit, if set, changes the config first. Call it
// inside synctest.Test, and defer stop.
func newEnv(t *testing.T, edit func(*config.Broker)) *env {
	t.Helper()
	cfg, h := testConfig(t)
	if edit != nil {
		edit(cfg)
	}
	return newEnvWith(t, cfg, h, approvaltest.NewClock(noon))
}

func newEnvWith(t *testing.T, cfg *config.Broker, h hosts, clock *approvaltest.Clock) *env {
	t.Helper()
	fake := approvaltest.NewApprover(approverID)
	core, err := approval.New(cfg, fake, approval.Options{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &env{t: t, cfg: cfg, hosts: h, clock: clock, fake: fake, core: core, cancel: cancel, runErr: make(chan error, 1)}
	go func() { e.runErr <- core.Run(ctx) }()
	synctest.Wait()
	return e
}

// stop stops the core and waits until every request has ended.
func (e *env) stop() {
	e.cancel()
	_ = e.runResult() // a test that cares about the error reads it itself
	synctest.Wait()
}

// runResult waits until Run returns, and returns its error.
func (e *env) runResult() error {
	if !e.ran {
		e.err = <-e.runErr
		e.ran = true
	}
	return e.err
}

// decide runs Decide in a new goroutine. Its result comes on the channel.
func (e *env) decide(r *approval.Request) <-chan *approval.Result {
	return e.decideCtx(context.Background(), r)
}

func (e *env) decideCtx(ctx context.Context, r *approval.Request) <-chan *approval.Result {
	ch := make(chan *approval.Result, 1)
	go func() { ch <- e.core.Decide(ctx, r) }()
	return ch
}

// now runs Decide and returns its result. Use it for requests that are
// decided without waiting for the person.
func (e *env) now(r *approval.Request) *approval.Result {
	e.t.Helper()
	return mustResult(e.t, e.decide(r))
}

// mustResult returns the result on ch, once every goroutine waits. It
// fails the test if the request is not decided yet.
func mustResult(t *testing.T, ch <-chan *approval.Result) *approval.Result {
	t.Helper()
	synctest.Wait()
	select {
	case r := <-ch:
		return r
	default:
		t.Fatal("the request is not decided yet")
		return nil
	}
}

// mustWait checks that the request on ch is not decided yet.
func mustWait(t *testing.T, ch <-chan *approval.Result) {
	t.Helper()
	synctest.Wait()
	select {
	case r := <-ch:
		t.Fatalf("the request was decided: allowed %v, cause %q; want it to wait", r.Allowed, r.Cause)
	default:
	}
}

// asked returns the messages the core asked for, and checks how many.
func (e *env) asked(n int) []approvaltest.Asked {
	e.t.Helper()
	synctest.Wait()
	asked := e.fake.Asked()
	if len(asked) != n {
		e.t.Fatalf("the core asked for %d messages, want %d", len(asked), n)
	}
	return asked
}

// tap presses a button on the message n (counted from 1) as the person,
// and checks that the tap counted.
func (e *env) tap(n int, action audit.Answer) {
	e.t.Helper()
	asked := e.fake.Asked()
	if n < 1 || n > len(asked) {
		e.t.Fatalf("no message %d; the core asked for %d", n, len(asked))
	}
	if err := e.fake.Tap(asked[n-1].Prompt.RequestID, action); err != nil {
		e.t.Fatalf("tap %s on message %d: %v", action, n, err)
	}
}

// answer passes an answer for message n with the given changes, and
// returns what the core said.
func (e *env) answer(n int, change func(*approval.Answer)) error {
	e.t.Helper()
	asked := e.fake.Asked()
	if n < 1 || n > len(asked) {
		e.t.Fatalf("no message %d; the core asked for %d", n, len(asked))
	}
	a := approval.Answer{
		RequestID: asked[n-1].Prompt.RequestID, Action: audit.AnswerApproveOnce,
		Message: asked[n-1].Message, UserID: approverID,
	}
	if change != nil {
		change(&a)
	}
	return e.fake.Answer(a)
}

// The requests of the tests. Their claimed text is clean.

func secretsReq(client string, names ...string) *approval.Request {
	return &approval.Request{
		Client: client, Kind: audit.KindSecrets, Secrets: names,
		Claim: approval.Claim{
			Vars: "GH_TOKEN", Command: "gh release create v1.2.0", Dir: "/home/dev/src/app",
			Reason: "publish the release the user asked for",
		},
	}
}

func loginReq(client, key string, hostKey ssh.PublicKey, user string) *approval.Request {
	return &approval.Request{
		Client: client, Kind: audit.KindSSHLogin, Key: key, HostKey: hostKey, RemoteUser: user,
		Claim: approval.Claim{Command: "ssh deploy@web-1 ← ansible-playbook site.yml", Reason: "apply the nginx fix"},
	}
}

func grantReq(client, key, user string, d time.Duration, hostNames ...string) *approval.Request {
	return &approval.Request{
		Client: client, Kind: audit.KindSSHGrant, Key: key, RemoteUser: user, Hosts: hostNames, For: d,
		Claim: approval.Claim{Reason: "apply the nginx fix"},
	}
}

// eventNames returns the "event" names of the entries of r.
func eventNames(r *approval.Result) []string {
	var names []string
	for _, ev := range r.Events() {
		switch ev := ev.(type) {
		case audit.Request:
			names = append(names, "request")
		case audit.Decision:
			names = append(names, "decision:"+string(ev.Answer))
		case audit.GrantUsed:
			names = append(names, "grant_used:"+string(ev.Via))
		case audit.Denied:
			names = append(names, "denied:"+string(ev.Cause))
		case audit.Failure:
			names = append(names, "error:"+string(ev.Code))
		default:
			names = append(names, fmt.Sprintf("%T", ev))
		}
	}
	return names
}

// checkEvents checks the entries of r by their names.
func checkEvents(t *testing.T, r *approval.Result, want ...string) {
	t.Helper()
	got := eventNames(r)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("events %v, want %v", got, want)
	}
}

// checkAllowed checks that r allows the request.
func checkAllowed(t *testing.T, r *approval.Result) {
	t.Helper()
	if !r.Allowed || r.Cause != "" {
		t.Fatalf("allowed %v, cause %q, err %v; want allowed", r.Allowed, r.Cause, r.Err)
	}
}

// checkDenied checks that r denies the request for cause.
func checkDenied(t *testing.T, r *approval.Result, cause audit.Cause) {
	t.Helper()
	if r.Allowed || r.Cause != cause {
		t.Fatalf("allowed %v, cause %q, err %v; want denied with cause %q", r.Allowed, r.Cause, r.Err, cause)
	}
}

// parseHours returns the hours "HH:MM-HH:MM", as the config has them.
func parseHours(t testing.TB, s string) config.Hours {
	t.Helper()
	var h1, m1, h2, m2 int
	if _, err := fmt.Sscanf(s, "%d:%d-%d:%d", &h1, &m1, &h2, &m2); err != nil {
		t.Fatalf("hours %q: %v", s, err)
	}
	clock := func(h, m int) time.Duration { return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute }
	return config.Hours{From: clock(h1, m1), To: clock(h2, m2)}
}
