package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/transport"
)

// The tests of nodkey broker run the real command in a child process: the
// test binary again, with TestBrokerChild only, as the keygen test does.
// The child gets a config whose files pass every check of nodkey (in a
// private directory, see privateTestDir), fake store programs (small
// shell scripts), and a fake Telegram server.
//
// The child reaches the fake through a fake HTTPS proxy (HTTPS_PROXY). The
// proxy takes only a CONNECT to api.telegram.org, and answers the TLS
// handshake itself, with a certificate from a test CA that the child
// trusts through SSL_CERT_FILE (and an empty SSL_CERT_DIR). So the child
// runs the same code as in production, and nothing goes to the real Bot
// API. Go reads the proxy setting and the system's CAs once per process,
// which is one more reason for a child process.
//
// Each start of the broker gets a new made-up user name in HTTPS_PROXY.
// Go's HTTP client sends it to the proxy with each CONNECT, so the fake
// knows which start made each call. This matters when a test starts the
// broker again: Go's HTTP client goes on with a dial after the request
// that started it was canceled, so a broker that stops can send a CONNECT
// just before it ends, and the proxy, in its own goroutines, can take it
// only after the test saw that broker end (issue #69).

// Variables of the child process.
const (
	// brokerChildConfig is the config of the child's broker. Without it,
	// TestBrokerChild skips.
	brokerChildConfig = "NODKEY_TEST_BROKER_CONFIG"
	// brokerChildSeams lists test changes in the child, with commas: see
	// TestBrokerChild.
	brokerChildSeams = "NODKEY_TEST_BROKER_SEAMS"
	// brokerChildProxy is the address of the fake proxy. The child checks
	// that every call to Telegram goes there.
	brokerChildProxy = "NODKEY_TEST_BROKER_PROXY"
)

// The test changes in the child (brokerChildSeams).
const (
	// seamStoreStartFails makes the start of the store brokenStore fail.
	seamStoreStartFails = "store-start-fails"
	// seamNoCoreDumps sets the hard limit of core dumps to 0 before the
	// broker starts, so the broker cannot set its soft limit to 1.
	seamNoCoreDumps = "core-hard-limit-0"
	// seamStoreStartWaits makes the start of every store wait until the
	// start of the broker ends, such as by a signal.
	seamStoreStartWaits = "store-start-waits"
	// seamFastAlertTries makes the tries of the alert messages of the
	// start short: 1.5 seconds each, and 0.1 to 0.4 seconds between them.
	seamFastAlertTries = "fast-alert-tries"
	// seamReleaseVersion makes the child the release 0.2.0, as a release
	// build is with -ldflags "-X main.version=0.2.0".
	seamReleaseVersion = "release-version"
	// seamFastReleaseCheck makes the check for a newer release ask at once,
	// not 10 minutes after the start.
	seamFastReleaseCheck = "fast-release-check"
)

// telegramHost is the host of the Bot API, and githubHost the host of
// GitHub's API, where the broker's check for a newer release asks.
const (
	telegramHost = "api.telegram.org"
	githubHost   = "api.github.com"
)

// approverID is the made-up Telegram user ID of the approver.
const approverID int64 = 7000001

// brokerWait bounds every wait of the tests of nodkey broker.
const brokerWait = 20 * time.Second

// brokenStore is the store whose start fails with seamStoreStartFails. Its
// program fails too.
const brokenStore = "vault"

// The item IDs of the test secrets.
const (
	idGitHub = "00000000-0000-0000-0000-000000000001"
	idDB     = "00000000-0000-0000-0000-000000000002"
)

// TestBrokerChild runs only as the child of the tests of nodkey broker:
// it runs nodkey broker with the config in brokerChildConfig, and exits
// with its exit code.
func TestBrokerChild(t *testing.T) {
	path := os.Getenv(brokerChildConfig)
	if path == "" {
		t.Skip("runs only as the child of the tests of nodkey broker")
	}
	for seam := range strings.SplitSeq(os.Getenv(brokerChildSeams), ",") {
		switch seam {
		case "":
		case seamStoreStartFails:
			real := newStore
			newStore = func(cfg config.Store, dir string) (store.Store, error) {
				s, err := real(cfg, dir)
				if err != nil || cfg.Name != brokenStore {
					return s, err
				}
				return startFails{s}, nil
			}
		case seamStoreStartWaits:
			real := newStore
			newStore = func(cfg config.Store, dir string) (store.Store, error) {
				s, err := real(cfg, dir)
				if err != nil {
					return s, err
				}
				return startWaits{s}, nil
			}
		case seamFastAlertTries:
			alertTimeout, alertFirstWait, alertMaxWait = 1500*time.Millisecond, 100*time.Millisecond, 400*time.Millisecond
		case seamReleaseVersion:
			version = "0.2.0"
		case seamFastReleaseCheck:
			releaseFirstWait = 0
		case seamNoCoreDumps:
			if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
				fmt.Fprintln(os.Stderr, "child: cannot set the hard limit of core dumps to 0")
				os.Exit(3)
			}
		default:
			fmt.Fprintln(os.Stderr, "child: unknown test change")
			os.Exit(3)
		}
	}
	// Every call to Telegram, and to GitHub for the check for a newer
	// release, must go to the fake, through the proxy of the test: never
	// to the real Bot API or the real GitHub. Both clients use
	// http.ProxyFromEnvironment, and Go reads it once per process.
	for _, host := range []string{telegramHost, githubHost} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+host+"/", nil)
		if err != nil {
			os.Exit(3)
		}
		proxy, err := http.ProxyFromEnvironment(req)
		if err != nil || proxy == nil || proxy.Host != os.Getenv(brokerChildProxy) {
			fmt.Fprintln(os.Stderr, "child: calls to "+host+" would not go to the fake proxy; the broker does not start")
			os.Exit(3)
		}
	}
	os.Exit(run([]string{"broker", "--config", path}, os.Stdin, os.Stdout, os.Stderr))
}

// startFails is a store whose start fails. Fetch is the real store's.
type startFails struct{ store.Store }

func (startFails) Start(context.Context) error {
	return fmt.Errorf("store %q: made-up: the store cannot start", brokenStore)
}

// startWaits is a store whose start waits until its context ends. Fetch is
// the real store's.
type startWaits struct{ store.Store }

func (startWaits) Start(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// privateTestDir returns a new directory for the files of one test. Every
// directory on the way to it passes the checks of nodkey (DESIGN.md
// section 14): owned by root or by this user, and not writable by group or
// others. The system temporary directory fails them, so it is made in
// $XDG_RUNTIME_DIR or in the user's cache directory. It must also be on a
// local file system that nodkey knows, and allow running programs. The
// test is skipped if there is no such place, or fails when CI is set.
func privateTestDir(t *testing.T) string {
	t.Helper()
	var bases []string
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		bases = append(bases, d)
	}
	if d, err := os.UserCacheDir(); err == nil {
		bases = append(bases, d)
	}
	for _, base := range bases {
		dir, err := os.MkdirTemp(base, "nodkey-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G703: the test's own new directory.
		if usableTestDir(t, dir) {
			return dir
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("no directory passes the file checks of nodkey: tried %q", bases)
	}
	t.Skipf("no directory passes the file checks of nodkey: tried %q", bases)
	return ""
}

// usableTestDir reports whether dir passes the checks of a key file, and
// whether a program there can run.
func usableTestDir(t *testing.T, dir string) bool {
	t.Helper()
	if os.Chmod(dir, 0o700) != nil { //nolint:gosec // G302: a directory, private to its owner.
		return false
	}
	probe := filepath.Join(dir, "probe")
	if writeUninherited(probe, []byte("#!/bin/sh\nexit 0\n")) != nil || config.CheckPrivateFile(probe) != nil {
		return false
	}
	if os.Chmod(probe, 0o700) != nil { //nolint:gosec // G302: a program of the test.
		return false
	}
	ok := exec.CommandContext(t.Context(), probe).Run() == nil //nolint:gosec // G204: a program that the test wrote.
	_ = os.Remove(probe)                                       //nolint:gosec // G703: a file in the test's own new directory.
	return ok
}

// writeTestFile writes data to path with exactly mode.
func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := writeUninherited(path, data); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// writeUninherited writes data to path with mode 0600, so that no child
// process gets a copy of the file descriptor that writes it. The tests run
// in parallel, and many start child processes. A child gets a copy of each
// open descriptor of the test process and keeps it until it runs its own
// program. While a child keeps a copy of the descriptor that writes a
// program, the start of that program fails with ETXTBSY, "text file busy"
// (go.dev/issue/22315): then the probe of privateTestDir failed, and the
// test failed or was skipped. Each start of a child holds syscall.ForkLock
// for writing until the child runs its program, so no child starts while
// this holds it for reading.
func writeUninherited(path string, data []byte) error {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	return os.WriteFile(path, data, 0o600) //nolint:gosec // G703: a file in the test's own directory.
}

// madeUp returns a made-up value with what at its start, made at run time,
// so the source holds nothing that looks like a token.
func madeUp(what string) string {
	return "made-up-" + what + "-" + rand.Text()
}

// canarySecret returns a made-up secret, made at run time, as in the tests of
// package broker: 32 upper-case letters and digits that change often. It
// is a valid variable name, and package claim masks it in every form, as
// a random-looking word.
func canarySecret() string {
	const letters = "QWERTYUPASDFGHJKLZXCVBNM"
	const digits = "7391542860"
	var b strings.Builder
	for i := range 16 {
		b.WriteByte(letters[(i*7+3)%len(letters)])
		b.WriteByte(digits[(i*3+1)%len(digits)])
	}
	return b.String()
}

// newBotToken returns a made-up bot token: digits, ":", and 35 random
// characters.
func newBotToken() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
	if err != nil {
		panic(err)
	}
	secret := strings.Map(func(r rune) rune {
		if r >= '2' && r <= '7' {
			return r
		}
		return r | 0x20 // some lower case letters
	}, rand.Text()+rand.Text())
	return strconv.FormatInt(1_000_000_000+n.Int64(), 10) + ":" + secret[:35]
}

// brokerOptions change the broker of a test.
type brokerOptions struct {
	// refusePolls, if set, is the status of Telegram's error answer to
	// every getUpdates call, such as 409 for a polling conflict.
	refusePolls int
	// unknownToken puts a bot token into the token file that the fake
	// Telegram does not know: it answers every call with 401, as Telegram
	// does for a revoked token.
	unknownToken bool
	// holdAlerts makes alert messages (messages without buttons) wait at
	// the fake Telegram until the test releases them.
	holdAlerts bool
	// sameKeyTwice adds [key.copy], whose file is a copy of the key file
	// of [key.deploy].
	sameKeyTwice bool
	// listen is the listen address of the broker; the default is a free
	// port (freeAddress).
	listen string
	// newestRelease is the tag of the newest release at the fake GitHub;
	// the default is v0.2.0, the version of seamReleaseVersion.
	newestRelease string
	// securityRelease gives the newest release at the fake GitHub the
	// line "### Security" in its notes.
	securityRelease bool
	// updatesOff adds [updates] check = false to the config.
	updatesOff bool
	// standing adds [standing] and standing = true for github-token.
	standing bool
	// ntfy, if set, gives the broker [ntfy] with this fake server instead
	// of [telegram].
	ntfy *fakeNtfy
}

// brokerEnv is nodkey broker in a child process, with its files and the
// fake Telegram server.
type brokerEnv struct {
	t         *testing.T
	dir       string // the private directory of the test
	cfgPath   string
	auditPath string
	addr      string // the listen address
	brokerPin config.Pin
	client    tls.Certificate // the TLS key of the client laptop
	tg        *fakeTelegram
	values    map[string]string // the secret values, by secret name
	userKey   ssh.Signer        // the key of [key.deploy]
	hostKeys  map[string]ssh.Signer

	cmd     *exec.Cmd
	stderr  *lineLog // the child's stderr: the broker's journal
	exited  chan struct{}
	waitErr error // set before exited is closed
	// proxyUser is the user name in HTTPS_PROXY of the last start: a new
	// one for each start (see fakeTelegram.proxiedBy).
	proxyUser string
	// caFile, if set, is the file of CA certificates the child trusts
	// instead of those of the fake Telegram.
	caFile string
}

// newBrokerEnv makes the files of a broker in a new private directory,
// and a fake Telegram server. It does not start the broker; see start.
func newBrokerEnv(t *testing.T, opts brokerOptions) *brokerEnv {
	t.Helper()
	dir := privateTestDir(t)
	e := &brokerEnv{
		t:         t,
		dir:       dir,
		cfgPath:   filepath.Join(dir, "etc", "broker.toml"),
		auditPath: filepath.Join(dir, "state", "audit.jsonl"),
		values:    map[string]string{"github-token": madeUp("github"), "db-password": madeUp("db")},
		hostKeys:  make(map[string]ssh.Signer),
		stderr:    newLineLog(),
	}
	for _, sub := range []string{"etc", "creds", "bin", "state"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	creds := filepath.Join(dir, "creds")

	// The TLS keys, as nodkey keygen makes them.
	pin, err := transport.GenerateKeyFile(filepath.Join(creds, "broker-tls-key"))
	if err != nil {
		t.Fatal(err)
	}
	e.brokerPin = pin
	clientPin, err := transport.GenerateKeyFile(filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	if e.client, err = transport.LoadKeyFile(filepath.Join(dir, "client.key")); err != nil {
		t.Fatal(err)
	}

	// The tokens, and the fake store programs. The store "main" hands out
	// github-token; the program of the store "vault" always fails.
	e.tg = newFakeTelegram(t, opts)
	token := e.tg.token
	if opts.unknownToken {
		token = newBotToken()
	}
	writeTestFile(t, filepath.Join(creds, "telegram-token"), []byte(token+"\n"), 0o600)
	writeTestFile(t, filepath.Join(creds, "bws-token"), []byte(madeUp("bws-token")+"\n"), 0o600)
	writeTestFile(t, filepath.Join(creds, "bws-token-vault"), []byte(madeUp("bws-token")+"\n"), 0o600)
	bws := fmt.Sprintf("#!/bin/sh\n# A fake bws: it prints the secret with the ID $3.\n"+
		"case \"$3\" in\n%s) printf '%%s' '{\"id\":\"%s\",\"value\":\"%s\"}' ;;\n*) exit 1 ;;\nesac\n",
		idGitHub, idGitHub, e.values["github-token"])
	writeTestFile(t, filepath.Join(dir, "bin", "bws"), []byte(bws), 0o700)
	writeTestFile(t, filepath.Join(dir, "bin", "bws-vault"), []byte("#!/bin/sh\nexit 1\n"), 0o700)

	// The SSH key of [key.deploy], and the hosts.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if e.userKey, err = ssh.NewSignerFromSigner(priv); err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(creds, "ssh-deploy"), pem.EncodeToMemory(block), 0o600)
	var knownHosts strings.Builder
	for _, host := range []string{"web-1", "db-1"} {
		_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if e.hostKeys[host], err = ssh.NewSignerFromSigner(hostPriv); err != nil {
			t.Fatal(err)
		}
		knownHosts.WriteString(host + " " + string(ssh.MarshalAuthorizedKey(e.hostKeys[host].PublicKey())))
	}
	writeTestFile(t, filepath.Join(dir, "etc", "known_hosts"), []byte(knownHosts.String()), 0o600)

	e.addr = opts.listen
	if e.addr == "" {
		e.addr = freeAddress(t)
	}
	cfg := fmt.Sprintf(`listen = %q
tls_key = "${CREDENTIALS_DIRECTORY}/broker-tls-key"
audit_log = %q
known_hosts = %q

[telegram]
token_file = "${CREDENTIALS_DIRECTORY}/telegram-token"
user_id = %d

[client.laptop]
pin = %q

[store.main]
type = "bws"
program = %q
token_file = "${CREDENTIALS_DIRECTORY}/bws-token"

[store.vault]
type = "bws"
program = %q
token_file = "${CREDENTIALS_DIRECTORY}/bws-token-vault"

[secret.github-token]
store = "main"
id = %q
clients = ["laptop"]
ask = "always"

[secret.db-password]
store = "vault"
id = %q
clients = ["laptop"]
ask = "never"
notify = false

[key.deploy]
file = "${CREDENTIALS_DIRECTORY}/ssh-deploy"
clients = ["laptop"]
ask = "always"
hosts = ["web-1"]
`, e.addr, e.auditPath, filepath.Join(dir, "etc", "known_hosts"), approverID, clientPin.String(),
		filepath.Join(dir, "bin", "bws"), filepath.Join(dir, "bin", "bws-vault"), idGitHub, idDB)
	if opts.sameKeyTwice {
		copied, err := os.ReadFile(filepath.Join(creds, "ssh-deploy")) //nolint:gosec // G304: the test's own key file.
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(creds, "ssh-copy"), copied, 0o600)
		cfg += `
[key.copy]
file = "${CREDENTIALS_DIRECTORY}/ssh-copy"
clients = ["laptop"]
ask = "always"
hosts = ["db-1"]
`
	}
	if opts.standing {
		cfg = strings.Replace(cfg, "[secret.github-token]\n", "[secret.github-token]\nstanding = true\n", 1) + "\n[standing]\n"
	}
	if opts.updatesOff {
		cfg += "\n[updates]\ncheck = false\n"
	}
	if opts.ntfy != nil {
		cfg = opts.ntfy.useIn(e, cfg)
	}
	writeTestFile(t, e.cfgPath, []byte(cfg), 0o600)
	return e
}

// The ports that freeAddress handed out in this process.
var (
	portsMu    sync.Mutex
	portsTaken = make(map[int64]bool)
)

// freeAddress returns an address on the loopback interface with a port
// that is free now, for the broker of one test. The broker listens on it
// a moment later, and again when the test starts it again. So the port is
// outside the range of ports that the kernel gives out by itself, to
// sockets that ask for any port or connect (net.ipv4.ip_local_port_range):
// no other socket of the tests takes it in between. No two tests of this
// process get the same port, and no two tests of two processes that run
// at the same time (reservePort), such as the tests of two checkouts. When
// the kernel's range leaves no room, the kernel chooses the port, and
// startListening tries again if another socket takes it first.
func freeAddress(t *testing.T) string {
	t.Helper()
	low, high := int64(0), int64(0)
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if f := strings.Fields(string(data)); len(f) == 2 {
			lo, err1 := strconv.ParseInt(f[0], 10, 64)
			hi, err2 := strconv.ParseInt(f[1], 10, 64)
			if err1 == nil && err2 == nil {
				low, high = portsOutside(lo, hi)
			}
		}
	}
	for range 200 {
		if high <= low {
			break
		}
		n, err := rand.Int(rand.Reader, big.NewInt(high-low))
		if err != nil {
			t.Fatal(err)
		}
		port := low + n.Int64()
		portsMu.Lock()
		taken := portsTaken[port]
		portsTaken[port] = true
		portsMu.Unlock()
		if taken || !reservePort(t, port) {
			continue
		}
		addr := "127.0.0.1:" + strconv.FormatInt(port, 10)
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", addr)
		if err != nil {
			continue // in use
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		return addr
	}
	for range 200 {
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().(*net.TCPAddr)
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		portsMu.Lock()
		taken := portsTaken[int64(addr.Port)]
		portsTaken[int64(addr.Port)] = true
		portsMu.Unlock()
		if !taken && reservePort(t, int64(addr.Port)) {
			return addr.String()
		}
	}
	t.Fatal("found no free port for the broker")
	return ""
}

// reservePort reserves port for the test t against other processes of
// these tests, such as a second go test run at the same time. Until t
// ends, it holds the abstract Unix socket "@nodkey-test-port-PORT", and
// only one socket can hold such a name. It reports false when another
// process holds the name. Without it, such a process could take the port
// while the broker of t was stopped, and the next start of that broker
// failed; or it could listen there, and TestBrokerNoListenBeforeTheAuditLog
// saw a broker listen. The kernel frees the name when the socket closes,
// also when the process ends without cleanup. A port that turns out to be
// in use stays reserved until t ends; that does no harm.
func reservePort(t *testing.T, port int64) bool {
	t.Helper()
	c, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "unixgram",
		"@nodkey-test-port-"+strconv.FormatInt(port, 10))
	if err != nil {
		return false
	}
	t.Cleanup(func() { _ = c.Close() })
	return true
}

// portsOutside returns the ports [low, high) for the brokers of the tests,
// outside the kernel's own range of ports from lo to hi: the larger of the
// ports from 10000 to below lo, and the ports above hi. high is not more
// than low when neither has 1000 ports.
func portsOutside(lo, hi int64) (low, high int64) {
	const first, last, enough = 10000, 65535, 1000
	below, above := lo-first, last-hi
	switch {
	case below >= enough && below >= above:
		return first, lo
	case above >= enough:
		return hi + 1, last + 1
	}
	return 0, 0
}

// startBroker makes the files of a broker and starts it.
func startBroker(t *testing.T, opts brokerOptions, seams ...string) *brokerEnv {
	t.Helper()
	e := newBrokerEnv(t, opts)
	e.start(seams...)
	return e
}

// startListening makes the files of a broker, starts it, and waits until
// it has opened its listen address. The port was free a moment before the
// broker opens it, but another program on the machine can take it in
// between; then the broker stops, and the test starts it again with
// another port.
func startListening(t *testing.T, opts brokerOptions, seams ...string) *brokerEnv {
	t.Helper()
	e := newBrokerEnv(t, opts)
	for try := 1; ; try++ {
		e.start(seams...)
		if e.stderr.waitOrEnd(t, lineListenOpen) {
			return e
		}
		if try == 3 || !e.stderr.has("address already in use") {
			t.Fatalf("the broker did not open its listen address; its log:\n%s", e.stderr.text())
		}
		e.waitExit()
		old := e.addr
		e.addr = freeAddress(t)
		cfg, err := os.ReadFile(e.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, e.cfgPath, bytes.Replace(cfg, []byte(strconv.Quote(old)), []byte(strconv.Quote(e.addr)), 1), 0o600)
	}
}

// start starts the broker in a child process, with the test changes
// seams. The child's environment holds only what the broker needs, so
// nothing from the environment of the test, such as NO_PROXY, changes
// where the calls to Telegram go. The start gets a new proxy user name,
// e.proxyUser.
func (e *brokerEnv) start(seams ...string) {
	t := e.t
	t.Helper()
	e.stderr = newLineLog()
	// Upper-case letters and digits: nothing to escape in the URL.
	e.proxyUser = rand.Text()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestBrokerChild$") //nolint:gosec // G204: the test runs its own binary again.
	caFile := e.tg.caFile
	if e.caFile != "" {
		caFile = e.caFile
	}
	cmd.Env = []string{
		brokerChildConfig + "=" + e.cfgPath,
		brokerChildSeams + "=" + strings.Join(seams, ","),
		brokerChildProxy + "=" + e.tg.proxyAddr,
		"CREDENTIALS_DIRECTORY=" + filepath.Join(e.dir, "creds"),
		"HTTPS_PROXY=http://" + e.proxyUser + "@" + e.tg.proxyAddr,
		"SSL_CERT_FILE=" + caFile,
		"SSL_CERT_DIR=" + e.tg.caDir,
	}
	for _, name := range []string{"GORACE", "GOCOVERDIR", "TMPDIR"} {
		if v, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+v)
		}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	e.cmd = cmd
	exited, log := make(chan struct{}), e.stderr
	e.exited = exited
	go func() {
		log.readFrom(stderr)
		e.waitErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = cmd.Process.Kill()
			<-exited
		}
		if strings.Contains(log.text(), "DATA RACE") {
			t.Error("the race detector found a data race in the broker")
		}
	})
}

// running reports whether the broker still runs.
func (e *brokerEnv) running() bool {
	select {
	case <-e.exited:
		return false
	default:
		return true
	}
}

// signal sends sig to the broker.
func (e *brokerEnv) signal(sig os.Signal) {
	e.t.Helper()
	if err := e.cmd.Process.Signal(sig); err != nil {
		e.t.Fatal(err)
	}
}

// waitExit waits until the broker ends, and returns its exit code.
func (e *brokerEnv) waitExit() int {
	e.t.Helper()
	select {
	case <-e.exited:
	case <-time.After(brokerWait + stopTimeout):
		e.t.Fatalf("the broker did not end; its log:\n%s", e.stderr.text())
	}
	var exit *exec.ExitError
	switch {
	case e.waitErr == nil:
		return 0
	case errors.As(e.waitErr, &exit) && exit.ExitCode() >= 0:
		return exit.ExitCode()
	}
	e.t.Fatalf("the broker: %v; its log:\n%s", e.waitErr, e.stderr.text())
	return -1
}

// mustExit waits until the broker ends, and fails unless it exited with
// code.
func (e *brokerEnv) mustExit(code int) {
	e.t.Helper()
	if got := e.waitExit(); got != code {
		e.t.Fatalf("the broker exited with %d, want %d; its log:\n%s", got, code, e.stderr.text())
	}
}

// httpClient returns an HTTP client of the client laptop.
func (e *brokerEnv) httpClient() *http.Client {
	e.t.Helper()
	c, err := transport.NewClient(e.addr, e.client, e.brokerPin)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(c.CloseIdleConnections)
	return c
}

// brokerAnswer is what a client got.
type brokerAnswer struct {
	status int
	header http.Header
	body   []byte
	err    error
}

// post sends body to path as JSON, and returns the answer. It does not
// fail the test, so it may run in its own goroutine.
func (e *brokerEnv) post(c *http.Client, path string, body any) brokerAnswer {
	return e.postWithToken(c, path, body, "")
}

// postWithToken is post with the header of a standing grant token, if
// token is not empty.
func (e *brokerEnv) postWithToken(c *http.Client, path string, body any, token string) brokerAnswer {
	return e.postWithHeader(c, path, body, api.GrantTokenHeader, token)
}

// postClaiming is post with claimed in the header api.VersionHeader.
func (e *brokerEnv) postClaiming(c *http.Client, path string, body any, claimed string) brokerAnswer {
	return e.postWithHeader(c, path, body, api.VersionHeader, claimed)
}

// postWithHeader is post with the header name set to value, if value is
// not empty.
func (e *brokerEnv) postWithHeader(c *http.Client, path string, body any, name, value string) brokerAnswer {
	data, err := json.Marshal(body)
	if err != nil {
		return brokerAnswer{err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*brokerWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+e.addr+path, bytes.NewReader(data))
	if err != nil {
		return brokerAnswer{err: err}
	}
	req.Header.Set("Content-Type", api.ContentType)
	if value != "" {
		req.Header.Set(name, value)
	}
	resp, err := c.Do(req)
	if err != nil {
		return brokerAnswer{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, api.MaxAnswer+1))
	return brokerAnswer{status: resp.StatusCode, header: resp.Header, body: b, err: err}
}

// approve sends a request that needs a tap, taps "Approve once" on its
// message at the fake Telegram, and returns the answer.
func (e *brokerEnv) approve(c *http.Client, path string, body any) brokerAnswer {
	e.t.Helper()
	n := e.tg.asked()
	res := make(chan brokerAnswer, 1)
	go func() { res <- e.post(c, path, body) }()
	msgID, requestID := e.tg.waitAsk(n + 1)
	// A tap can come before the broker knows that its message was sent.
	// Then the phone shows "Not ready yet. Tap again in a moment.", and
	// the person taps again.
	for try := 1; ; try++ {
		answer := e.tg.waitTapAnswer(e.tg.tap(msgID, "o:"+requestID))
		if !strings.Contains(answer, "Not ready yet") {
			break
		}
		if try == 100 {
			e.t.Fatalf("every tap came too early; the log of the broker:\n%s", e.stderr.text())
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case a := <-res:
		return a
	case <-time.After(2 * brokerWait):
		e.t.Fatalf("no answer; the log of the broker:\n%s", e.stderr.text())
		return brokerAnswer{}
	}
}

// mustStatus fails unless a has the status.
func mustStatus(t *testing.T, a brokerAnswer, status int) {
	t.Helper()
	if a.err != nil || a.status != status {
		t.Fatalf("the answer: %d %s, %v; want status %d", a.status, a.body, a.err, status)
	}
}

// signRequest returns a request to sign an SSH login as user to host with
// the key of [key.deploy] (see makeLogin), and the data to sign.
func (e *brokerEnv) signRequest(host, user string) (api.SignRequest, []byte) {
	e.t.Helper()
	pub := e.userKey.PublicKey()
	bind, data := makeLogin(e.t, pub, e.hostKeys[host], user)
	return api.SignRequest{
		PublicKey: pub.Marshal(),
		Data:      data,
		Binds:     [][]byte{bind},
		Commands:  [][]string{{"ssh", user + "@" + host}},
	}, data
}

// auditEntries reads the audit log of the broker: one map for each line.
// A line that is not JSON, such as a torn line before its log_recovered
// entry, has the event "(torn line)".
func (e *brokerEnv) auditEntries() []map[string]any {
	e.t.Helper()
	data, err := os.ReadFile(e.auditPath)
	if err != nil {
		e.t.Fatal(err)
	}
	var entries []map[string]any
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			m = map[string]any{"event": "(torn line)"}
		}
		entries = append(entries, m)
	}
	return entries
}

// eventNames returns the events of entries, with the code or cause, such
// as "error:poll_conflict" or "denied:error".
func eventNames(entries []map[string]any) []string {
	var names []string
	for _, m := range entries {
		name, _ := m["event"].(string)
		for _, k := range []string{"code", "cause", "answer", "via"} {
			if v, ok := m[k].(string); ok {
				name += ":" + v
			}
		}
		names = append(names, name)
	}
	return names
}

// lineLog holds the lines of the broker's stderr as they come.
type lineLog struct {
	mu      sync.Mutex
	lines   []string
	done    bool          // stderr is closed
	changed chan struct{} // closed and made new on each change
}

func newLineLog() *lineLog { return &lineLog{changed: make(chan struct{})} }

// readFrom reads lines from r until it ends.
func (l *lineLog) readFrom(r io.Reader) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		l.mu.Lock()
		l.lines = append(l.lines, s.Text())
		l.notifyLocked()
		l.mu.Unlock()
	}
	_, _ = io.Copy(io.Discard, r) // after a line that is too long
	l.mu.Lock()
	l.done = true
	l.notifyLocked()
	l.mu.Unlock()
}

func (l *lineLog) notifyLocked() {
	close(l.changed)
	l.changed = make(chan struct{})
}

// all returns the lines so far.
func (l *lineLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.lines)
}

// text returns the lines so far, each with a newline.
func (l *lineLog) text() string {
	var b strings.Builder
	for _, line := range l.all() {
		b.WriteString(line + "\n")
	}
	return b.String()
}

// has reports whether a line holds s.
func (l *lineLog) has(s string) bool {
	return slices.ContainsFunc(l.all(), func(line string) bool { return strings.Contains(line, s) })
}

// count returns the number of lines that hold s.
func (l *lineLog) count(s string) int {
	n := 0
	for _, line := range l.all() {
		if strings.Contains(line, s) {
			n++
		}
	}
	return n
}

// waitCount waits until n lines hold s.
func (l *lineLog) waitCount(t *testing.T, s string, n int) {
	t.Helper()
	deadline := time.NewTimer(brokerWait)
	defer deadline.Stop()
	for {
		l.mu.Lock()
		done, changed := l.done, l.changed
		l.mu.Unlock()
		switch {
		case l.count(s) >= n:
			return
		case done:
			t.Fatalf("the broker ended with fewer than %d lines that hold %q; its log:\n%s", n, s, l.text())
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("fewer than %d lines of the broker's log hold %q; its log:\n%s", n, s, l.text())
		}
	}
}

// wait waits until a line holds s.
func (l *lineLog) wait(t *testing.T, s string) {
	t.Helper()
	if !l.waitOrEnd(t, s) {
		t.Fatalf("the broker ended, and no line of its log holds %q; its log:\n%s", s, l.text())
	}
}

// waitOrEnd waits until a line holds s, and reports true, or until the
// log ends without such a line, and reports false.
func (l *lineLog) waitOrEnd(t *testing.T, s string) bool {
	t.Helper()
	deadline := time.NewTimer(brokerWait)
	defer deadline.Stop()
	for {
		l.mu.Lock()
		found := slices.ContainsFunc(l.lines, func(line string) bool { return strings.Contains(line, s) })
		done, changed := l.done, l.changed
		l.mu.Unlock()
		switch {
		case found:
			return true
		case done:
			return false
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("no line of the broker's log holds %q; its log:\n%s", s, l.text())
		}
	}
}

// inOrder fails unless lines hold each of parts, in this order.
func (l *lineLog) inOrder(t *testing.T, parts ...string) {
	t.Helper()
	lines := l.all()
	i := 0
	for _, p := range parts {
		for i < len(lines) && !strings.Contains(lines[i], p) {
			i++
		}
		if i == len(lines) {
			t.Errorf("no line holds %q after the lines of %q; the log:\n%s", p, parts, strings.Join(lines, "\n"))
			return
		}
		i++
	}
}
