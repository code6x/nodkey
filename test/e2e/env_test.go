//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The setup of the end-to-end test (DESIGN.md section 17):
//
//   - the nodkey binary, built from this repository;
//   - a private directory for the files of the broker and the clients,
//     which pass every file check of nodkey;
//   - the SSH targets: one container with an sshd for each of web-1,
//     web-2, db-1 and web-3, each with its own throwaway host key. The
//     broker's known_hosts has web-1, web-2 and db-1, not web-3. The users
//     deploy and ops have the public half of the broker's key deploy in
//     their authorized_keys; only the broker holds its private half;
//   - the fake Telegram server, behind its fake HTTPS proxy;
//   - nodkey broker, with a fake store program (a bws) that holds the
//     first canary as the value of the secret canary-token;
//   - two clients on this machine: laptop, which logs in with ssh and git
//     through its nodkey ssh-agent, and ci, which runs nodkey run. Each
//     has its own TLS key, made with nodkey keygen, and its own home
//     directory with its client config.
//
// The broker limits each client to 6 new messages in any 60 seconds
// (DESIGN.md section 8). The cases of laptop send exactly 6 messages, and
// those of ci 2: a new case that sends a message needs a client of its own,
// or it waits in the broker's queue.

// The names of the test, from the example names of AGENTS.md.
const (
	keyName    = "deploy"       // the broker's SSH key
	secretName = "canary-token" // the broker's secret, whose value is the first canary
	secretVar  = "E2E_TOKEN"    // the variable of nodkey run for it
)

// knownTargets are the targets in the broker's known_hosts, and
// unknownTarget is a target whose host key is not there. ssh on this
// machine knows all four (allTargets).
var (
	knownTargets  = []string{"web-1", "web-2", "db-1"}
	unknownTarget = "web-3"
)

// allTargets returns every target: the lines of the file "targets" of the
// container, in this order.
func allTargets() []string {
	return append(append([]string(nil), knownTargets...), unknownTarget)
}

// hostKeyTypes are the types of the host keys of the targets, so that the
// broker checks a session-bind of each type that it takes.
var hostKeyTypes = map[string]string{"web-1": "ed25519", "web-2": "ecdsa", "db-1": "rsa", "web-3": "ed25519"}

// clientPath is the PATH of the clients that look up programs: nodkey run
// finds sh there.
const clientPath = "/usr/local/bin:/usr/bin:/bin"

// env is the setup of the end-to-end test. Its methods take the test or
// subtest that uses them.
type env struct {
	procs procs

	bin     string // the nodkey binary
	self    string // the test binary, for the wrapper of ssh and git
	sshPath string
	gitPath string
	dir     string // the private directory

	canary1  string   // the value of the secret in the store
	canary2  string   // a word in the command line of a parent of ssh
	bwsToken string   // the made-up token of the store
	reasons  []string // every claimed reason of the cases (reason)

	tg       *fakeTelegram
	targets  *targets
	hostKeys map[string]ssh.PublicKey // the host key of each target

	brokerAddr string
	brokerPin  string
	secretID   string // the ID of the secret in the store
	auditPath  string
	broker     *proc
	audit      *auditLog

	laptop, ci *client
	agent      *proc  // nodkey ssh-agent of laptop
	socket     string // its socket
	sshConfig  string // the ssh config of laptop
}

// client is a client machine of the broker: its name, and its home
// directory with ~/.config/nodkey/client.toml and its TLS key.
type client struct {
	name string
	home string
	pin  string // the pin of its TLS key, from nodkey keygen
}

// newEnv makes the setup and starts it: the targets, the broker and the
// SSH agent of laptop. Everything ends when the test ends.
func newEnv(t *testing.T) *env {
	t.Helper()
	img := sshdImage(t)
	e := &env{canary1: newCanary1(t), canary2: newCanary2(t), hostKeys: make(map[string]ssh.PublicKey)}
	hide(e.canary1, e.canary2)
	e.sshPath, e.gitPath = requireOpenSSH(t), requireProgram(t, "git")
	var err error
	if e.self, err = os.Executable(); err != nil {
		t.Fatal(err)
	}
	_, e.bin = runDirectory(t)
	e.dir = subdirectory(t, "e2e-")
	for _, sub := range []string{"creds", "etc", "bin", "state", "ssh", "container", "ca"} {
		mkdirs(t, filepath.Join(e.dir, sub))
	}
	e.auditPath = filepath.Join(e.dir, "state", "audit.jsonl")
	e.audit = &auditLog{path: e.auditPath}

	// The keys: the broker's SSH key, and a host key for each target.
	deployKey, deployPub := newSSHKey(t, "ed25519")
	writeFile(t, filepath.Join(e.dir, "creds", "ssh-"+keyName), deployKey)
	files := filepath.Join(e.dir, "container") // the files of entrypoint.sh
	writeFile(t, filepath.Join(files, "authorized_keys"), ssh.MarshalAuthorizedKey(deployPub))
	var lines strings.Builder
	for i, name := range allTargets() {
		priv, pub := newSSHKey(t, hostKeyTypes[name])
		e.hostKeys[name] = pub
		writeFile(t, filepath.Join(files, name+".key"), priv)
		fmt.Fprintf(&lines, "%s %d\n", name, 2201+i)
	}
	writeFile(t, filepath.Join(files, "targets"), []byte(lines.String()))
	e.targets = startTargets(t, img, files, allTargets())

	e.tg = newFakeTelegram(t, filepath.Join(e.dir, "ca"))
	e.bwsToken = "made-up-bws-token-" + rand.Text()
	_, botSecret, _ := strings.Cut(e.tg.token, ":")
	hide(e.tg.token, botSecret, e.bwsToken)
	e.writeBrokerFiles(t)
	e.laptop = e.newClient(t, "laptop")
	e.ci = e.newClient(t, "ci")
	e.startBroker(t)
	e.audit.next(t, map[string]string{"version": "dev"}, "broker_started")
	e.startAgent(t)
	e.writeSSHConfig(t)
	return e
}

// newCanary1 returns the first canary: the secret value in the store. It
// is random, made at run time, so the source holds no value.
func newCanary1(t *testing.T) string {
	t.Helper()
	return canary1Prefix + rand.Text()
}

// newCanary2 returns the second canary: 32 random upper-case letters and
// digits, one after the other, so that it looks random as a whole (DESIGN.md
// section 7, "long random-looking words").
func newCanary2(t *testing.T) string {
	t.Helper()
	const letters, digits = "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789"
	var b strings.Builder
	for i := range 32 {
		set := letters
		if i%2 == 1 {
			set = digits
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			t.Fatal(err)
		}
		b.WriteByte(set[n.Int64()])
	}
	return b.String()
}

// requireOpenSSH returns the path of the OpenSSH client, and fails the
// test when it is missing or older than 8.9, which sends no session-bind.
func requireOpenSSH(t *testing.T) string {
	t.Helper()
	path := requireProgram(t, "ssh")
	out, err := exec.CommandContext(t.Context(), path, "-V").CombinedOutput() //nolint:gosec // G204: ssh from PATH.
	if err != nil {
		t.Fatalf("ssh -V: %v", err)
	}
	m := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("ssh is not OpenSSH: %q", out)
	}
	major, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	if major < 8 || major == 8 && minor < 9 {
		t.Fatalf("OpenSSH %d.%d sends no session-bind; the test needs 8.9 or newer", major, minor)
	}
	return path
}

// requireProgram returns the path of name in PATH, and fails the test when
// it is missing.
func requireProgram(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("the end-to-end test needs %s: %v", name, err)
	}
	return path
}

// mkdirs makes dir and its missing parents with mode 0700.
func mkdirs(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// writeFile writes data to path with mode 0600.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeProgram writes a program to path with mode 0700.
func writeProgram(t *testing.T, path, text string) {
	t.Helper()
	writeFile(t, path, []byte(text))
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // G302: a program of the test, private to its owner.
		t.Fatal(err)
	}
}

// newSSHKey returns a new SSH private key of kind (ed25519, ecdsa or
// rsa), in the OpenSSH format that sshd and the broker read, and its
// public key.
func newSSHKey(t *testing.T, kind string) ([]byte, ssh.PublicKey) {
	t.Helper()
	var priv any
	var err error
	switch kind {
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		t.Fatalf("no key type %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}

// nodkey runs nodkey with args, and returns its stdout. It fails the test
// unless nodkey exits with 0.
func (e *env) nodkey(t *testing.T, args ...string) string {
	t.Helper()
	p := e.procs.start(t, "nodkey "+args[0], "", append([]string{"PATH=" + clientPath}, quickExit()...), nil,
		append([]string{e.bin}, args...)...)
	p.mustExit(t, 0)
	return strings.TrimSpace(p.stdout.text())
}

// writeBrokerFiles writes the files of the broker, except its config,
// which needs the listen address (writeBrokerConfig).
func (e *env) writeBrokerFiles(t *testing.T) {
	t.Helper()
	creds := filepath.Join(e.dir, "creds")
	e.brokerPin = e.nodkey(t, "keygen", "--out", filepath.Join(creds, "broker-tls-key"))
	writeFile(t, filepath.Join(creds, "telegram-token"), []byte(e.tg.token+"\n"))
	writeFile(t, filepath.Join(creds, "bws-token"), []byte(e.bwsToken+"\n"))

	// A fake bws: it prints the secret with the ID $3, as
	// "bws secret get ID --output json --color no" does, and fails for
	// any other ID.
	id := newUUID(t)
	writeProgram(t, filepath.Join(e.dir, "bin", "bws"), fmt.Sprintf("#!/bin/sh\n"+
		"# A fake bws of the end-to-end test of nodkey.\n"+
		"case \"$1 $2 $3\" in\n"+
		"'secret get %s') printf '%%s' '{\"id\":\"%s\",\"value\":\"%s\"}' ;;\n"+
		"*) exit 1 ;;\n"+
		"esac\n", id, id, e.canary1))
	e.secretID = id

	var known strings.Builder
	for _, name := range knownTargets {
		known.WriteString(name + " " + string(ssh.MarshalAuthorizedKey(e.hostKeys[name])))
	}
	writeFile(t, filepath.Join(e.dir, "etc", "known_hosts"), []byte(known.String()))
}

// newUUID returns a random UUID (version 4).
func newUUID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// writeBrokerConfig writes the config of the broker, with its listen
// address.
func (e *env) writeBrokerConfig(t *testing.T) {
	t.Helper()
	cfg := fmt.Sprintf(`# The broker of the end-to-end test of nodkey.
listen = %q
tls_key = "${CREDENTIALS_DIRECTORY}/broker-tls-key"
audit_log = %q
known_hosts = %q

[telegram]
token_file = "${CREDENTIALS_DIRECTORY}/telegram-token"
user_id = %d
timeout = "60s"
ssh_timeout = "60s"

[client.laptop]
pin = %q

[client.ci]
pin = %q

[store.main]
type = "bws"
program = %q
token_file = "${CREDENTIALS_DIRECTORY}/bws-token"

[secret.%s]
store = "main"
id = %q
clients = ["ci"]
ask = "always"

[key.%s]
file = "${CREDENTIALS_DIRECTORY}/ssh-%s"
clients = ["laptop"]
ask = "window"
window = "15m"
`, e.brokerAddr, e.auditPath, filepath.Join(e.dir, "etc", "known_hosts"), approverID, e.laptop.pin, e.ci.pin,
		filepath.Join(e.dir, "bin", "bws"), secretName, e.secretID, keyName, keyName)
	writeFile(t, filepath.Join(e.dir, "etc", "broker.toml"), []byte(cfg))
}

// newClient makes the home directory of a client, with its TLS key from
// nodkey keygen. Its config needs the broker's address
// (writeClientConfig).
func (e *env) newClient(t *testing.T, name string) *client {
	t.Helper()
	c := &client{name: name, home: filepath.Join(e.dir, name)}
	for _, sub := range []string{".config/nodkey", "run", "work"} {
		mkdirs(t, filepath.Join(c.home, sub))
	}
	c.pin = e.nodkey(t, "keygen", "--out", filepath.Join(c.home, ".config", "nodkey", "client.key"))
	return c
}

// writeClientConfig writes ~/.config/nodkey/client.toml of c.
func (e *env) writeClientConfig(t *testing.T, c *client) {
	t.Helper()
	cfg := fmt.Sprintf("broker = %q\nbroker_pin = %q\ntls_key = \"~/.config/nodkey/client.key\"\n", e.brokerAddr, e.brokerPin)
	writeFile(t, filepath.Join(c.home, ".config", "nodkey", "client.toml"), []byte(cfg))
}

// env returns the environment of a nodkey client of c: its home, and
// clientPath. Nothing comes from the environment of the test, such as
// SSH_AUTH_SOCK.
func (c *client) env(more ...string) []string {
	return append(append([]string{"HOME=" + c.home, "PATH=" + clientPath}, quickExit()...), more...)
}

// quickExit returns the environment that makes a program built with the
// race detector exit at once: by default it waits a second at its exit
// (GORACE option atexit_sleep_ms), and the test starts many such
// programs, nodkey and the wrapper. A GORACE of the test's environment
// comes first, so its other options stay.
func quickExit() []string {
	if !raceEnabled {
		return goraceEnv()
	}
	return []string{"GORACE=" + strings.TrimSpace(os.Getenv("GORACE")+" atexit_sleep_ms=0")}
}

// goraceEnv returns GORACE of the test's environment, if it is set, for
// nodkey broker and nodkey ssh-agent.
func goraceEnv() []string {
	if v, ok := os.LookupEnv("GORACE"); ok {
		return []string{"GORACE=" + v}
	}
	return nil
}

// The lines of nodkey broker that the test looks for.
const (
	lineListening = "nodkey broker: listening; the broker is ready"
	lineProxy     = "telegram: calls to Telegram go through a proxy from the environment"
	lineStopped   = "nodkey broker: stopped"
)

// startBroker starts nodkey broker, and waits until it is ready. The port
// of its listen address was free a moment before, but another program can
// take it in between; then the broker stops, and the test starts it again
// with another port.
func (e *env) startBroker(t *testing.T) {
	t.Helper()
	brokerEnv := append([]string{
		"CREDENTIALS_DIRECTORY=" + filepath.Join(e.dir, "creds"),
		"HTTPS_PROXY=http://" + e.tg.proxyAddr,
		"SSL_CERT_FILE=" + e.tg.caFile,
		"SSL_CERT_DIR=" + e.tg.caDir,
	}, goraceEnv()...)
	for try := 1; ; try++ {
		e.brokerAddr = freeAddress(t)
		e.writeBrokerConfig(t)
		e.writeClientConfig(t, e.laptop)
		e.writeClientConfig(t, e.ci)
		p := e.procs.start(t, "nodkey broker", "", brokerEnv, nil,
			e.bin, "broker", "--config", filepath.Join(e.dir, "etc", "broker.toml"))
		if p.stderr.waitOrEnd(t, "nodkey broker", lineListening) {
			e.broker = p
			break
		}
		p.wait(t)
		if try == 3 || !p.stderr.has("address already in use") {
			t.Fatalf("nodkey broker did not start; its log:\n%s", redact(p.stderr.text()))
		}
	}
	if !e.broker.stderr.has(lineProxy) || !e.broker.stderr.has("proxy_host="+e.tg.proxyAddr) {
		t.Errorf("the broker does not log that it calls Telegram through the fake proxy; its log:\n%s",
			redact(e.broker.stderr.text()))
	}
}

// freeAddress returns an address on the loopback interface with a port
// that is free now, outside the range of ports that the kernel and Docker
// give out by themselves (net.ipv4.ip_local_port_range), as in the tests
// of nodkey broker.
func freeAddress(t *testing.T) string {
	t.Helper()
	low, high := int64(10000), int64(32768)
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if f := strings.Fields(string(data)); len(f) == 2 {
			lo, err1 := strconv.ParseInt(f[0], 10, 64)
			hi, err2 := strconv.ParseInt(f[1], 10, 64)
			switch {
			case err1 != nil || err2 != nil:
			case lo-10000 >= 1000:
				low, high = 10000, lo
			case 65535-hi >= 1000:
				low, high = hi+1, 65536
			default:
				low, high = 0, 0
			}
		}
	}
	for range 200 {
		addr := "127.0.0.1:0"
		if high > low {
			n, err := rand.Int(rand.Reader, big.NewInt(high-low))
			if err != nil {
				t.Fatal(err)
			}
			addr = "127.0.0.1:" + strconv.FormatInt(low+n.Int64(), 10)
		}
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", addr)
		if err != nil {
			continue // in use
		}
		addr = ln.Addr().String()
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		return addr
	}
	t.Fatal("found no free port for the broker")
	return ""
}

// startAgent starts nodkey ssh-agent of laptop on its default socket,
// $XDG_RUNTIME_DIR/nodkey/agent.sock, and waits until it listens.
func (e *env) startAgent(t *testing.T) {
	t.Helper()
	run := filepath.Join(e.laptop.home, "run")
	e.socket = filepath.Join(run, "nodkey", "agent.sock")
	agentEnv := append([]string{"HOME=" + e.laptop.home, "XDG_RUNTIME_DIR=" + run}, goraceEnv()...)
	e.agent = e.procs.start(t, "nodkey ssh-agent", "", agentEnv, nil, e.bin, "ssh-agent")
	e.agent.stderr.wait(t, "nodkey ssh-agent", "nodkey: the SSH agent listens on "+e.socket)
}

// writeSSHConfig writes the ssh config of laptop, and its known_hosts: ssh
// knows each target by its name (HostKeyAlias), also web-3, which the
// broker does not know. ssh uses no key file, only the agent. The config
// keeps ssh away from the files of the user who runs the test: -F skips
// ~/.ssh/config, and the known_hosts files and the key files are named.
func (e *env) writeSSHConfig(t *testing.T) {
	t.Helper()
	dir := filepath.Join(e.dir, "ssh")
	var known, cfg strings.Builder
	for _, name := range allTargets() {
		known.WriteString(name + " " + string(ssh.MarshalAuthorizedKey(e.hostKeys[name])))
		fmt.Fprintf(&cfg, "Host %s\n\tHostName 127.0.0.1\n\tPort %d\n\tHostKeyAlias %s\n", name, e.targets.ports[name], name)
	}
	writeFile(t, filepath.Join(dir, "known_hosts"), []byte(known.String()))
	fmt.Fprintf(&cfg, "Host *\n"+
		"\tIdentityFile %s\n"+ // no such file: no key file, only the agent
		"\tUserKnownHostsFile %s\n"+
		"\tGlobalKnownHostsFile /dev/null\n"+
		"\tStrictHostKeyChecking yes\n"+
		"\tCheckHostIP no\n"+
		"\tUpdateHostKeys no\n"+
		"\tBatchMode yes\n"+
		"\tPreferredAuthentications publickey\n"+
		"\tControlMaster no\n"+
		"\tControlPath none\n"+
		"\tForwardAgent no\n"+
		"\tConnectTimeout 20\n"+
		"\tLogLevel ERROR\n",
		filepath.Join(dir, "no-such-key"), filepath.Join(dir, "known_hosts"))
	e.sshConfig = filepath.Join(dir, "config")
	writeFile(t, e.sshConfig, []byte(cfg.String()))
}

// reason returns s, a claimed reason of a case, and keeps it: claimed text
// may be shown only in a message and the audit log (searchClaimed).
func (e *env) reason(s string) string {
	e.reasons = append(e.reasons, s)
	return s
}

// sshEnv returns the environment of ssh and git on laptop: SSH_AUTH_SOCK
// is the socket of its nodkey ssh-agent, and NODKEY_REASON the reason.
func (e *env) sshEnv(reason string, more ...string) []string {
	return e.laptop.env(append([]string{"SSH_AUTH_SOCK=" + e.socket, "NODKEY_REASON=" + reason}, more...)...)
}

// wrapped returns argv run by the wrapper, whose own arguments hold the
// second canary twice: as the value of an option with a secret name, and
// as a word of its own. nodkey ssh-agent sends the command line of the
// wrapper to the broker as claimed text, when the wrapper is one of the
// first 3 parents of ssh.
func (e *env) wrapped(argv ...string) []string {
	return append([]string{e.self, wrapperArg, "--api-token=" + e.canary2, e.canary2, "--"}, argv...)
}

// ssh starts ssh as user to host, through the wrapper, with the command
// "echo e2e-ok".
func (e *env) ssh(t *testing.T, user, host, reason string) *proc {
	t.Helper()
	return e.procs.start(t, "ssh "+user+"@"+host, filepath.Join(e.laptop.home, "work"), e.sshEnv(reason), nil,
		e.wrapped(e.sshPath, "-F", e.sshConfig, user+"@"+host, "echo", "e2e-ok")...)
}

// git starts git with args in dir, through the wrapper. git runs ssh with
// the config of laptop.
func (e *env) git(t *testing.T, dir, reason string, args ...string) *proc {
	t.Helper()
	gitEnv := e.sshEnv(reason,
		"GIT_SSH_COMMAND="+shellQuote(e.sshPath)+" -F "+shellQuote(e.sshConfig),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=dev", "GIT_AUTHOR_EMAIL=dev@example.com",
		"GIT_COMMITTER_NAME=dev", "GIT_COMMITTER_EMAIL=dev@example.com",
		"LC_ALL=C",
	)
	return e.procs.start(t, "git "+args[0], dir, gitEnv, nil, e.wrapped(append([]string{e.gitPath}, args...)...)...)
}

// shellQuote quotes s for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// readFile reads the file at path.
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: a file of the test.
	if err != nil {
		t.Fatal(err)
	}
	return data
}
