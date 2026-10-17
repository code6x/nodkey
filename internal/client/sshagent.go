package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/transport"
)

// nodkey ssh-agent (DESIGN.md sections 6 and 15) serves the SSH agent
// protocol on a Unix socket, so that plain ssh, git and Ansible work. It
// holds no SSH key. For each list request it asks the broker for the keys
// of this client (api.PathKeys), and for each sign request it asks the
// broker for the signature (api.PathSign), with the session-bind messages
// of that agent connection and the claimed context from /proc. The broker
// checks the real target host and asks the person. The agent refuses to
// add, remove, lock or unlock keys, and every other extension.
//
// The requests to the broker follow the rules of nodkey run: one POST on
// a connection of its own, with a deadline, and never again (Post). Only a
// final 200 whose body passes api.ReadAnswer counts, and the short code
// comes only from the 102 Processing answer. Before the agent hands a
// signature to ssh, it checks that its format fits the key and the sign
// flags, and that it is a valid signature of the data with that key. Any
// other result is SSH_AGENT_FAILURE, which says nothing about why.
//
// The agent writes its lines to its stderr: where it listens, the short
// code of each request that waits for the person, and why a request was
// refused or failed. Each line is fixed text, with at most numbers, the
// short code, the broker's address from the client config, the socket
// path and errors of the operating system. No line holds text that ssh or
// another process sent. The lines with a short code, and the lines about
// refused and failed requests, each have a limit per minute
// (agentLogLines).

// exitAgentFailed is the exit code of nodkey ssh-agent when it cannot make
// its socket, or the socket stops working.
const exitAgentFailed = 1

// signTimeout is the deadline of a request for a signature. The broker
// waits for the person at most its ssh_timeout, which is at most
// config.MaxSSHTimeout (110 s). sshd drops a login that does not finish
// within its LoginGraceTime, 120 seconds by default. The deadline lies
// between them: a late tap still counts, and the agent gives up before
// sshd does.
const signTimeout = config.MaxSSHTimeout + 5*time.Second

// keysTimeout is the deadline of a request for the list of keys. The
// broker answers it at once, without asking anyone.
const keysTimeout = 30 * time.Second

// agentLogLines is the most lines of one kind in a minute: lines with the
// short code of a request that waits for the person, and lines about
// refused and failed requests. Any process of the user can cause both
// kinds at will: the broker sends a short code for every request that
// starts to wait, in the queue too, and a request that hangs up frees its
// place. Any other user can cause the lines about refused connections.
// Honest use has at most 15 requests that wait at the same time (5
// messages and 10 in the queue, DESIGN.md section 8). The lines over the
// limit are counted. The count goes out with the next line of the same
// kind in a later minute, or when the agent stops.
const (
	agentLogLines  = 60
	agentLogWindow = time.Minute
)

// maxAgentConns is the most connections that the agent serves at the same
// time. ssh uses one for each login, and Ansible makes 5 logins at the
// same time by default. A connection over it is closed at once.
const maxAgentConns = 128

// procTimeout is the longest wait for the claimed context from /proc. A
// read there can block, such as on a mapping of a stuck FUSE or NFS file
// system. Then the request goes without the command lines and the
// reason.
const procTimeout = 2 * time.Second

// maxProcReads is the most reads of /proc at the same time. A read that
// blocks keeps its goroutine. When this many block, the agent starts no
// other read, and requests go without the claimed context.
const maxProcReads = 4

// stopWait is the longest wait for the connections when the agent stops.
// Every wait of a connection has its own limit, so this is only a last
// resort.
const stopWait = 5 * time.Second

// agentUsage is the help of nodkey ssh-agent.
const agentUsage = `Usage: nodkey ssh-agent [--socket PATH]

Serve an SSH agent on a Unix socket, for ssh, git and Ansible. The SSH keys
stay on the broker. For each login, the agent asks the broker for a
signature, and the broker asks a person on the phone. Point ssh to the
socket:

  export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/nodkey/agent.sock

  --socket PATH  the socket. The default is $XDG_RUNTIME_DIR/nodkey/agent.sock.
                 Its directory must have mode 0700; nodkey makes it if it is
                 missing.

The message shows NODKEY_REASON from the environment of ssh as the reason.
The agent cannot add, remove or lock keys. The client config is
~/.config/nodkey/client.toml. nodkey ssh-agent runs until SIGINT or
SIGTERM, and then removes the socket. It exits with 64 (wrong usage), 69
(the client config or the TLS key cannot be read) or 1 (the socket cannot
be made).
`

// SSHAgent runs nodkey ssh-agent with args, the arguments after
// "ssh-agent", and writes its lines to stderr. version is the version of
// nodkey, as for Run; the agent prints one warning for each version of
// the broker that differs from it. It serves the agent until
// SIGINT or SIGTERM. Then it removes the socket, writes its last line,
// such as "nodkey: stopped by SIGTERM (exit 143)", and ends nodkey with
// the same signal, as nodkey run does. Otherwise it returns the exit code
// of DESIGN.md section 15, and its last line is "nodkey: <reason> (exit
// <code>)".
func SSHAgent(args []string, stderr io.Writer, version string) int {
	r := agentRunner{
		load:       Load,
		configPath: ConfigPath,
		getenv:     os.Getenv,
		checkDirs:  config.CheckParentDirs,
		proc:       procFS{root: procDir},
		peer:       peerCredentials,
		version:    version,
	}
	return r.main(args, stderr)
}

// agentRunner runs nodkey ssh-agent. Tests replace its parts.
type agentRunner struct {
	// load reads the client config and the TLS key: Load.
	load func(path string) (*Broker, error)
	// configPath returns the path of the client config: ConfigPath.
	configPath func() (string, error)
	// getenv reads the agent's own environment, for XDG_RUNTIME_DIR.
	getenv func(string) string
	// checkDirs checks the directories on the way to the socket:
	// config.CheckParentDirs.
	checkDirs func(path string) error
	// proc reads the claimed context of a sign request.
	proc procFS
	// peer returns who connected to the socket: peerCredentials.
	peer func(*net.UnixConn) (peer, error)
	// ready, if set, gets the socket path once the agent serves it.
	ready func(path string)
	// tune, if set, changes the agent before it serves, such as its
	// limits. Tests use it.
	tune func(*sshAgent)
	// version is the version of nodkey (warnVersions); "" sends none.
	version string
}

// main is SSHAgent with the parts of r.
func (r agentRunner) main(args []string, stderr io.Writer) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	in := watchInterrupts(cancel)
	defer in.stop()
	// After the first SIGINT or SIGTERM, nodkey no longer catches them: a
	// second one ends it at once, even when it still waits for its
	// connections.
	stopCatching := context.AfterFunc(ctx, in.stop)
	defer stopCatching()
	code := r.run(ctx, args, stderr)
	var sig interrupted
	if errors.As(context.Cause(ctx), &sig) && code == sig.status() {
		// As for nodkey run: a shell sees the signal, and systemd counts
		// SIGTERM as a clean stop.
		in.stop()
		raise(sig.sig)
	}
	return code
}

// run runs nodkey ssh-agent until ctx ends, and returns its exit code.
func (r agentRunner) run(ctx context.Context, args []string, w io.Writer) int {
	log := newAgentLog(w)
	if len(args) == 1 && isHelp(args[0]) {
		_, _ = io.WriteString(log, agentUsage)
		return exitOK
	}
	path, err := parseAgentArgs(args)
	if err == nil && path == "" {
		path, err = defaultSocket(r.getenv)
	}
	if err == nil {
		err = checkSocketPath(path)
	}
	if err != nil {
		_, _ = io.WriteString(log, agentUsage)
		return fail(log, exitUsage, err.Error())
	}
	configPath, err := r.configPath()
	if err != nil {
		return fail(log, exitUnavailable, err.Error())
	}
	b, err := r.load(configPath)
	if err != nil {
		return fail(log, exitUnavailable, err.Error())
	}
	// At most one line for each version of the broker, so no budget.
	b.warnVersions(r.version, func(text string) { log.say("%s", text) })
	self, err := currentUID()
	if err != nil {
		return fail(log, exitAgentFailed, err.Error())
	}
	sock, err := listenAgent(ctx, path, self, r.checkDirs)
	if err != nil {
		if code, ok := stoppedBySignal(ctx, log); ok {
			return code // the signal came while the agent started
		}
		return fail(log, exitAgentFailed, err.Error())
	}
	a := newSSHAgent(b, log, r.proc, r.peer, self)
	if r.tune != nil {
		r.tune(a)
	}
	log.say("the SSH agent listens on %s; set SSH_AUTH_SOCK to this path for ssh", path)
	if r.ready != nil {
		r.ready(path)
	}
	a.serve(ctx, sock.ln)
	sock.close()
	log.flush()
	if code, ok := stoppedBySignal(ctx, log); ok {
		return code
	}
	if ctx.Err() != nil {
		return fail(log, exitOK, "stopped")
	}
	return fail(log, exitAgentFailed, "the socket stopped working")
}

// stoppedBySignal writes the last line when SIGINT or SIGTERM ended ctx,
// and returns the status that a shell shows for the signal.
func stoppedBySignal(ctx context.Context, log io.Writer) (int, bool) {
	var sig interrupted
	if !errors.As(context.Cause(ctx), &sig) {
		return 0, false
	}
	return fail(log, sig.status(), "stopped by "+sig.name()), true
}

// parseAgentArgs reads the arguments of nodkey ssh-agent: at most one
// --socket PATH, also with one dash and with "=" before the value, as the
// flag package reads them. It returns "" when --socket is not given.
func parseAgentArgs(args []string) (string, error) {
	socket, set := "", false
	for rest := args; len(rest) > 0; {
		arg := rest[0]
		rest = rest[1:]
		name, value, hasValue := splitOption(arg)
		switch name {
		case "socket":
		case "h", "help":
			return "", errors.New("--help must be the only argument")
		default:
			if !strings.HasPrefix(arg, "-") {
				return "", fmt.Errorf("unexpected argument %.64q", arg)
			}
			return "", fmt.Errorf("unknown option %.64q", arg)
		}
		if !hasValue {
			if len(rest) == 0 {
				return "", errors.New("--socket needs a value")
			}
			value, rest = rest[0], rest[1:]
		}
		if set {
			return "", errors.New("--socket is given twice")
		}
		if value == "" {
			return "", errors.New("--socket needs a path")
		}
		socket, set = value, true
	}
	return socket, nil
}

// currentUID returns the user ID that runs nodkey.
func currentUID() (uint32, error) {
	euid := os.Geteuid()
	if euid < 0 || uint64(euid) > math.MaxUint32 {
		return 0, errors.New("cannot get the user ID on this system")
	}
	return uint32(euid), nil
}

// peer is the process at the other end of an agent connection, as the
// kernel recorded it at connect(2).
type peer struct {
	uid uint32
	pid int32 // 0 when it is not known
}

// checkPeer allows only the user that runs nodkey ssh-agent (DESIGN.md
// section 15). Every other user is refused, also root: root can read the
// client's TLS key anyway, and ask the broker with it.
func checkPeer(p peer, self uint32) error {
	if p.uid != self {
		return fmt.Errorf("refused a connection of user ID %d: only user ID %d may use this agent", p.uid, self)
	}
	return nil
}

// sshAgent serves the agent protocol to ssh, and asks the broker. Make it
// with newSSHAgent; tests change its limits.
type sshAgent struct {
	broker *Broker
	log    *agentLog
	proc   procFS
	peer   func(*net.UnixConn) (peer, error)
	self   uint32
	// keysTimeout and signTimeout are the deadlines of the requests to the
	// broker.
	keysTimeout, signTimeout time.Duration
	// maxConns is the most open connections: maxAgentConns.
	maxConns int
	// procTimeout is the longest wait for the claimed context:
	// procTimeout.
	procTimeout time.Duration
	// stopWait is the longest wait for the connections at the end:
	// stopWait.
	stopWait time.Duration

	procReads atomic.Int32 // reads of /proc that run now

	mu     sync.Mutex
	closed bool                       // the agent stops: no new connection
	conns  map[*net.UnixConn]struct{} // the open connections
	wg     sync.WaitGroup             // one for each connection
}

// newSSHAgent returns an agent that asks the broker b, writes its lines to
// log, reads the claimed context with proc, checks each connection with
// peer, and serves only the user self.
func newSSHAgent(b *Broker, log *agentLog, proc procFS, peer func(*net.UnixConn) (peer, error),
	self uint32) *sshAgent {
	return &sshAgent{broker: b, log: log, proc: proc, peer: peer, self: self,
		keysTimeout: keysTimeout, signTimeout: signTimeout, maxConns: maxAgentConns, procTimeout: procTimeout,
		stopWait: stopWait}
}

// serve serves the connections to ln until ctx ends or ln fails. Then it
// closes ln and every connection, and waits until each has ended. A
// request to the broker that still runs then ends too: the connection to
// the broker closes, so the broker cancels the request.
func (a *sshAgent) serve(ctx context.Context, ln *net.UnixListener) {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var backoff time.Duration
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			// Such as too many open files: wait a little, and try again.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			a.log.note("cannot take a connection: %s", systemError(err))
			sleep(ctx, backoff)
			continue
		}
		backoff = 0
		switch a.track(c) {
		case trackStopping:
			_ = c.Close()
			continue
		case trackFull:
			a.log.note("refused a connection: %d connections are open, the most that the agent serves", a.maxConns)
			_ = c.Close()
			continue
		}
		a.wg.Go(func() {
			defer a.untrack(c)
			a.serveConn(ctx, c)
		})
	}
	a.closeAll()
	a.waitConns()
}

// waitConns waits until every connection has ended, but at most
// a.stopWait: each wait of a connection has its own limit, so this is
// only a last resort.
func (a *sshAgent) waitConns() {
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	t := time.NewTimer(a.stopWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		a.mu.Lock()
		n := len(a.conns)
		a.mu.Unlock()
		a.log.note("stopped without waiting longer for its connections (%d still open)", n)
	}
}

// sleep waits for d, or until ctx ends.
func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// The results of track.
const (
	trackOK       = iota // c is open and tracked
	trackStopping        // the agent stops
	trackFull            // a.maxConns connections are open
)

// track adds c to the open connections, unless the agent stops or
// a.maxConns connections are open.
func (a *sshAgent) track(c *net.UnixConn) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.closed:
		return trackStopping
	case len(a.conns) >= a.maxConns:
		return trackFull
	}
	if a.conns == nil {
		a.conns = make(map[*net.UnixConn]struct{})
	}
	a.conns[c] = struct{}{}
	return trackOK
}

// untrack removes c from the open connections.
func (a *sshAgent) untrack(c *net.UnixConn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.conns, c)
}

// closeAll closes every open connection, and takes no new one.
func (a *sshAgent) closeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for c := range a.conns {
		_ = c.Close()
	}
}

// serveConn serves one connection: first it checks the user that
// connected (SO_PEERCRED), then it answers one request after the other,
// until the connection closes. A message that is empty or longer than
// maxAgentMessage closes the connection.
func (a *sshAgent) serveConn(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	defer func() {
		// A request must never stop the agent. The panic value is not
		// written: it can hold anything from the request.
		if recover() != nil {
			a.log.note("a request made the agent fail; its connection is closed")
		}
	}()
	p, err := a.peer(c)
	if err != nil {
		a.log.note("refused a connection: its user cannot be checked")
		return
	}
	if err := checkPeer(p, a.self); err != nil {
		a.log.note("%s", err.Error())
		return
	}
	conn := &agentConn{a: a, conn: c, pid: p.pid}
	for {
		msg, err := readAgentMessage(c)
		if err != nil {
			if errors.Is(err, errMessageSize) {
				a.log.note("closed a connection that sent a message that is empty or longer than %d bytes",
					maxAgentMessage)
			}
			return
		}
		answer := conn.handle(ctx, msg)
		// An add request holds a private key, and a lock request a
		// passphrase. Best effort: the operating system keeps copies.
		clear(msg)
		if err := writeAgentMessage(c, answer); err != nil {
			return
		}
	}
}

// agentConn is one connection to the agent. Its methods run in the one
// goroutine of the connection.
type agentConn struct {
	a    *sshAgent
	conn *net.UnixConn
	pid  int32 // the process that connected, from SO_PEERCRED
	// binds are the contents of the session-bind@openssh.com messages of
	// this connection, in order: at most api.MaxBinds.
	binds [][]byte
	// refusedBind is set when the agent refused a session-bind. Then this
	// connection gets no signature: the agent could not send all of its
	// session-binds.
	refusedBind bool
}

// handle answers one request.
func (c *agentConn) handle(ctx context.Context, msg []byte) []byte {
	body := msg[1:]
	switch msg[0] {
	case agentListRequest:
		if len(body) != 0 {
			c.a.log.note("refused a key list request that is not valid")
			return failureMessage
		}
		return c.a.list(ctx)
	case agentSignRequest:
		key, data, flags, ok := parseSignRequest(body)
		if !ok {
			c.a.log.note("refused a sign request that is not valid")
			return failureMessage
		}
		return c.sign(ctx, key, data, flags)
	case agentExtension:
		name, contents, ok := parseExtension(body)
		switch {
		case !ok:
			c.a.log.note("refused an extension request that is not valid")
			return failureMessage
		case name != sessionBindRequest:
			c.a.log.note("refused an extension request: the agent knows only " + sessionBindRequest)
			return failureMessage
		}
		return c.bind(contents)
	case agentAddIdentity, agentAddConstrained, agentAddSmartcardKey, agentAddSmartcardConstrained,
		agentRemoveIdentity, agentRemoveAll, agentRemoveSmartcardKey, agentLock, agentUnlock,
		agentAddRSA, agentRemoveRSA, agentRemoveAllRSA, agentAddRSAConstrained:
		c.a.log.note("refused a request to add, remove, lock or unlock keys: the keys stay on the broker")
		return failureMessage
	}
	c.a.log.note("refused an agent request of the unknown type %d", msg[0])
	return failureMessage
}

// bind keeps the contents of a session-bind@openssh.com message for this
// connection, and answers success, as OpenSSH's own agent does. The
// broker checks it. The agent keeps at most api.MaxBinds of them, each at
// most api.MaxBind bytes: the most that the broker reads. It refuses
// more, and then this connection gets no signature.
func (c *agentConn) bind(contents []byte) []byte {
	switch {
	case c.refusedBind:
		c.a.log.note("refused a session-bind: the agent refused one before on this connection")
	case len(contents) > api.MaxBind:
		c.a.log.note("refused a session-bind longer than %d bytes; this connection gets no signature", api.MaxBind)
	case len(c.binds) >= api.MaxBinds:
		c.a.log.note("refused a session-bind after %d of them; this connection gets no signature", api.MaxBinds)
	default:
		c.binds = append(c.binds, bytes.Clone(contents))
		return []byte{agentSuccess}
	}
	c.refusedBind = true
	return failureMessage
}

// sign asks the broker for a signature of data with key (DESIGN.md
// section 6, step 5). It sends the exact bytes of the key, the data and
// the flags that ssh sent, every session-bind of this connection, and the
// claimed context of the process that connected. It checks the answer
// with checkSignAnswer before it gives the signature to ssh. When ssh
// closes the connection while the request waits, it ends the request.
// After a hang-up, the deadline or a stop of the agent, ssh gets no
// signature, whatever the broker answers then.
func (c *agentConn) sign(ctx context.Context, key, data []byte, flags uint32) []byte {
	a := c.a
	switch {
	case c.refusedBind:
		a.log.note("no signature: the agent refused a session-bind on this connection")
		return failureMessage
	case len(key) > api.MaxKey, len(data) > api.MaxData:
		a.log.note("no signature: the key or the data to sign is longer than the broker reads")
		return failureMessage
	}
	commands, reason := a.claimed(ctx, c.pid)
	body, err := encodeSignRequest(newSignRequest(key, data, flags, c.binds, commands, reason))
	if err != nil {
		a.log.note("no signature: %s", err.Error())
		return failureMessage
	}
	code := &shortCode{}
	reqCtx, cancel := context.WithTimeoutCause(ctx, a.signTimeout, deadline{a.signTimeout})
	defer cancel()
	// When ssh ends while the request waits, such as after Ctrl-C, the
	// connection to the broker closes, so the broker cancels the request
	// (DESIGN.md section 7).
	waitCtx, hangUp := context.WithCancelCause(reqCtx)
	defer hangUp(nil)
	stop := watchHangUp(c.conn, hangUp)
	ans, err := Post[api.SignAnswer](waitCtx, a.broker, api.PathSign, body, func(s string) {
		code.set(s)
		a.log.waitingFor(s)
	})
	stop()
	if cause := context.Cause(waitCtx); cause != nil {
		// The request was cancelled: ssh hung up, the deadline passed, or the
		// agent stops. Go's HTTP client can still return an answer that came
		// while it closed the connection to the broker: the 403 that the
		// broker sends when it sees the request cancelled, or a signature
		// after a tap at that moment. A cancel means deny: the cause is the
		// result, and ssh gets no signature after it.
		err = cause
	}
	if err != nil {
		a.log.note("no signature%s: %s", code.label(), failureText(err))
		return failureMessage
	}
	sig, err := checkSignAnswer(key, data, flags, ans)
	if err != nil {
		a.log.note("no signature%s: %s", code.label(), err.Error())
		return failureMessage
	}
	return signAnswerMessage(sig)
}

// claimed returns the claimed context of a sign request from process pid
// (procFS.claimedContext). It waits for the reads of /proc at most
// a.procTimeout, and at most maxProcReads such reads run at the same
// time: a read can block, such as on a stuck FUSE or NFS file system.
// Otherwise the request goes without the command lines and the reason,
// and a line says why.
func (a *sshAgent) claimed(ctx context.Context, pid int32) ([][]string, string) {
	if a.procReads.Add(1) > maxProcReads {
		a.procReads.Add(-1)
		a.log.note("sent a sign request without the command lines and the reason: %d reads of /proc are stuck",
			maxProcReads)
		return [][]string{}, ""
	}
	type found struct {
		commands [][]string
		reason   string
	}
	got := make(chan found, 1)
	go func() {
		defer a.procReads.Add(-1)
		commands, reason := a.proc.claimedContext(pid)
		got <- found{commands, reason}
	}()
	t := time.NewTimer(a.procTimeout)
	defer t.Stop()
	select {
	case c := <-got:
		return c.commands, c.reason
	case <-t.C:
		a.log.note("sent a sign request without the command lines and the reason: /proc did not answer within %s",
			a.procTimeout)
	case <-ctx.Done():
	}
	return [][]string{}, ""
}

// list asks the broker for the keys that this client may use, and
// answers ssh with them. The comment of each key is its name in the
// broker config.
func (a *sshAgent) list(ctx context.Context) []byte {
	reqCtx, cancel := context.WithTimeoutCause(ctx, a.keysTimeout, deadline{a.keysTimeout})
	defer cancel()
	ans, err := Post[api.KeysAnswer](reqCtx, a.broker, api.PathKeys, []byte("{}"), nil)
	if err != nil {
		a.log.note("no key list: %s", failureText(err))
		return failureMessage
	}
	if err := checkKeys(ans.Keys); err != nil {
		a.log.note("no key list: %s", err.Error())
		return failureMessage
	}
	return listAnswerMessage(ans.Keys)
}

// newSignRequest makes the request for a signature (DESIGN.md sections 6
// and 10). It keeps at most api.MaxCommands command lines, and makes each
// claimed field as nodkey run does: a command line or a reason that is too
// long becomes "[hidden: too long]". So every request fits in the broker's
// cap on its size (transport.MaxRequestBody).
func newSignRequest(key, data []byte, flags uint32, binds [][]byte, commands [][]string, reason string) api.SignRequest {
	shown := make([][]string, 0, min(len(commands), api.MaxCommands))
	for _, argv := range commands[:min(len(commands), api.MaxCommands)] {
		shown = append(shown, claimedCommand(argv))
	}
	return api.SignRequest{
		PublicKey: key, Data: data, Flags: flags, Binds: binds, Commands: shown, Reason: claimedText(reason),
	}
}

// encodeSignRequest returns req as JSON. It checks the caps of the request,
// and that the body is not larger than the broker reads
// (transport.MaxRequestBody). Every request of newSignRequest within the
// caps of the key, the data and the session-binds passes.
func encodeSignRequest(req api.SignRequest) ([]byte, error) {
	if err := req.Check(); err != nil {
		return nil, errors.New("the request is over a cap of the broker")
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > transport.MaxRequestBody {
		return nil, errors.New("the request is larger than the broker reads")
	}
	return body, nil
}

// The errors of checkSignAnswer and checkKeys. They hold nothing from the
// answer or the request.
var (
	errSignatureKey    = errors.New("the key of the request is not a valid SSH public key")
	errSignatureFormat = errors.New("the signature of the broker does not fit the key and the sign flags")
	errSignatureValid  = errors.New("the signature of the broker is not a valid signature of the data")
	errKeyList         = errors.New("the answer of the broker has a key that is not valid")
)

// checkSignAnswer checks the broker's signature before the agent gives it
// to ssh: its format must be the one that the key and the flags ask for
// (signatureFormat), and it must be a valid signature of data with key.
// It returns the signature for the sign answer.
func checkSignAnswer(key, data []byte, flags uint32, ans *api.SignAnswer) (*ssh.Signature, error) {
	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return nil, errSignatureKey
	}
	if want, ok := signatureFormat(pub.Type(), flags); !ok || ans.Format != want {
		return nil, errSignatureFormat
	}
	sig := &ssh.Signature{Format: ans.Format, Blob: ans.Blob}
	if err := pub.Verify(data, sig); err != nil {
		return nil, errSignatureValid
	}
	return sig, nil
}

// signatureFormat returns the format of a signature with a key of type
// keyType and these sign flags: the formats that the broker signs with
// (DESIGN.md section 6). Ed25519 and ECDSA keys take no flags. An RSA key
// needs the flag of SHA-256 or of SHA-512. ok is false for any other key
// type or flags.
func signatureFormat(keyType string, flags uint32) (string, bool) {
	switch keyType {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return keyType, flags == 0
	case ssh.KeyAlgoRSA:
		switch agent.SignatureFlags(flags) {
		case agent.SignatureFlagRsaSha256:
			return ssh.KeyAlgoRSASHA256, true
		case agent.SignatureFlagRsaSha512:
			return ssh.KeyAlgoRSASHA512, true
		}
	}
	return "", false
}

// keyNamePattern is the name rule of the broker config (DESIGN.md section
// 14).
var keyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// checkKeys checks the keys of the broker's answer: each has a name that
// follows the name rule of the config, and a plain Ed25519, ECDSA or RSA
// public key in its usual SSH wire form, as the broker signs only with
// such keys.
func checkKeys(keys []api.Key) error {
	for _, k := range keys {
		if !keyNamePattern.MatchString(k.Name) {
			return errKeyList
		}
		pub, err := ssh.ParsePublicKey(k.PublicKey)
		if err != nil || !bytes.Equal(pub.Marshal(), k.PublicKey) {
			return errKeyList
		}
		switch pub.Type() {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		default:
			return errKeyList
		}
	}
	return nil
}

// watchHangUp cancels a request with errHungUp when the process at the
// other end of c, ssh, closes the connection while the request waits for
// the broker. stop ends the watch; call it before the next read of c.
func watchHangUp(c *net.UnixConn, cancel context.CancelCauseFunc) (stop func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if waitHangUp(c) {
			cancel(errHungUp)
		}
	}()
	return func() {
		_ = c.SetReadDeadline(time.Now()) // ends waitHangUp
		<-done
		_ = c.SetReadDeadline(time.Time{})
	}
}

// errHungUp is the cause of the end of a request's context when ssh closed
// its connection to the agent while the request waited.
var errHungUp = errors.New("client: ssh closed its connection to the agent")

// deadline is the cause of the end of a request's context when its
// deadline passed.
type deadline struct{ d time.Duration }

func (e deadline) Error() string { return "no answer from the broker within " + e.d.String() }

// failureText describes a request to the broker that got no valid answer,
// for a line of the agent: the text of an *Error, which says "denied" for
// 403, or the deadline. It holds nothing from the answer.
func failureText(err error) string {
	var e *Error
	var d deadline
	var sig interrupted
	switch {
	case errors.As(err, &e):
		return e.Error()
	case errors.As(err, &d):
		return d.Error()
	case errors.As(err, &sig):
		return "the agent stops"
	case errors.Is(err, errHungUp):
		return "ssh closed its connection while the request waited"
	}
	return "the request to the broker failed"
}

// shortCode is the short code of one request, once the broker sent it.
// Post calls onCode in a goroutine of net/http.
type shortCode struct {
	mu   sync.Mutex
	code string
}

func (s *shortCode) set(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.code = code
}

// label returns " (request CODE)", or "" when no code came.
func (s *shortCode) label() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.code == "" {
		return ""
	}
	return " (request " + s.code + ")"
}

// agentLog writes the lines of nodkey ssh-agent. Each line starts with
// "nodkey: ", is one line (oneLine), and goes out in one write, under a
// lock: lines come from many connections.
type agentLog struct {
	mu      sync.Mutex
	w       io.Writer
	now     func() time.Time
	waiting lineBudget // the lines with the short code of a request that waits
	refused lineBudget // the lines about refused and failed requests
}

// lineBudget counts the lines of one kind in the current minute.
type lineBudget struct {
	about   string    // what the lines are about, for the count of those left out
	start   time.Time // the start of the current minute
	lines   int       // the lines written in that minute
	dropped int       // the lines left out in that minute
}

func newAgentLog(w io.Writer) *agentLog {
	return &agentLog{w: w, now: time.Now,
		waiting: lineBudget{about: "requests that wait for approval"},
		refused: lineBudget{about: "refused or failed requests"},
	}
}

// Write writes p as it is: the usage and the last line.
func (l *agentLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// say writes a line without a limit: lines that come once, such as where
// the agent listens.
func (l *agentLog) say(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line(fmt.Sprintf(format, args...))
}

// waitingFor writes the line with the short code of a request that waits
// for the person: at most agentLogLines in a minute.
func (l *agentLog) waitingFor(code string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limited(&l.waiting, "waiting for approval (request "+code+")")
}

// note writes a line about a refused or failed request: at most
// agentLogLines in a minute.
func (l *agentLog) note(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limited(&l.refused, fmt.Sprintf(format, args...))
}

// limited writes text, unless b already let agentLogLines lines through in
// the current minute. Then it counts the line. The first line of a later
// minute says first how many lines were left out. l.mu must be held.
func (l *agentLog) limited(b *lineBudget, text string) {
	// time.Now has a monotonic clock reading, so a change of the wall
	// clock does not move the minute.
	if now := l.now(); b.start.IsZero() || now.Sub(b.start) >= agentLogWindow {
		l.flushLocked(b)
		b.start, b.lines = now, 0
	}
	if b.lines >= agentLogLines {
		b.dropped++
		return
	}
	b.lines++
	l.line(text)
}

// flush writes how many lines were left out, if any. The agent calls it
// when it stops.
func (l *agentLog) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushLocked(&l.waiting)
	l.flushLocked(&l.refused)
}

func (l *agentLog) flushLocked(b *lineBudget) {
	if b.dropped > 0 {
		l.line(fmt.Sprintf("left out %d lines about %s, to keep the log short", b.dropped, b.about))
		b.dropped = 0
	}
}

// line writes "nodkey: " and text as one line. l.mu must be held.
func (l *agentLog) line(text string) {
	_, _ = io.WriteString(l.w, "nodkey: "+oneLine(text)+"\n")
}
