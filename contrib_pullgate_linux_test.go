package nodkey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

// The tests of the pullgate recipe in contrib/pullgate run the four
// scripts with /bin/sh, as pullgate runs them, against a fake broker:
//
//   - the real nodkey, built from this module, for nodkey broker check and
//     nodkey broker config-diff;
//   - a fake nodkey broker reload, which takes the config or refuses it,
//     and writes the broker's status file, reload-status.json;
//   - a fake systemctl, whose restart starts a new "process" (a new PID in
//     the status file) or fails.
//
// The scripts get the paths of the test in NKP_ETC, NKP_UNIT and
// NKP_CREDENTIALS. They run as the user of the test, not as root.

var (
	pgBuild    sync.Once
	pgBinary   string
	pgBuildErr error
)

// pgNodkey builds nodkey once for all the tests.
func pgNodkey(t *testing.T) string {
	t.Helper()
	pgBuild.Do(func() {
		dir, err := os.MkdirTemp("", "nodkey-pullgate-test-")
		if err != nil {
			pgBuildErr = err
			return
		}
		pgBinary = filepath.Join(dir, "nodkey")
		out, err := exec.CommandContext(context.Background(), "go", "build", "-o", pgBinary, "./cmd/nodkey").CombinedOutput() //nolint:gosec // G204: the test's own build.
		if err != nil {
			pgBuildErr = &buildError{out: string(out), err: err}
		}
	})
	if pgBuildErr != nil {
		t.Fatalf("build nodkey: %v", pgBuildErr)
	}
	return pgBinary
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + ": " + e.out }

// pgEnv is one broker host of a test.
type pgEnv struct {
	dir   string // the root of the test
	etc   string // NKP_ETC
	audit string // the directory of the audit log and the status file
	fake  string // the state of the fakes
	bin   string // the fakes, first in PATH
	// rollback sets PULLGATE_ROLLBACK=1.
	rollback bool
}

const pgSecretID = "00000000-0000-4000-8000-00003f9a1c2e"

// pgConfig is a valid broker config of the env, with edits.
func (e *pgEnv) pgConfig(t *testing.T, edits ...[2]string) string {
	t.Helper()
	cfg := `listen = "192.0.2.10:7743"
tls_key = "${CREDENTIALS_DIRECTORY}/broker-tls-key"
audit_log = "` + e.audit + `/audit.jsonl"
known_hosts = "` + e.etc + `/known_hosts"

[telegram]
token_file = "${CREDENTIALS_DIRECTORY}/telegram-token"
user_id = 123456789

[client.laptop]
pin = "` + config.Pin{1}.String() + `"

[store.main]
type = "bws"
program = "/usr/local/bin/bws"
token_file = "${CREDENTIALS_DIRECTORY}/bws-token"

[secret.github-token]
store = "main"
id = "` + pgSecretID + `"
clients = ["laptop"]
ask = "always"
`
	for _, ed := range edits {
		if !strings.Contains(cfg, ed[0]) {
			t.Fatalf("the config has no %q", ed[0])
		}
		cfg = strings.Replace(cfg, ed[0], ed[1], 1)
	}
	return cfg
}

// pgTree writes a tree of a commit with the config cfg, and returns it.
func (e *pgEnv) pgTree(t *testing.T, name, cfg string) string {
	t.Helper()
	tree := filepath.Join(e.dir, "trees", name)
	pgWrite(t, filepath.Join(tree, "broker.toml"), cfg)
	pgWrite(t, filepath.Join(tree, "known_hosts"), "")
	return tree
}

func pgWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil { //nolint:gosec // G306: a config file, not secret.
		t.Fatal(err)
	}
}

// pgFakeStatus is a shell function that writes the status file as the
// broker does: one line of JSON, in the order of the fields of
// reloadStatus in cmd/nodkey/brokerreload.go.
const pgFakeStatus = `status() {
	sha=$(sha256sum < "$NKP_ETC/broker.toml"); sha=${sha%% *}
	printf '{"pid":%s,"start":7,"reloads":1,"result":"%s","config_sha256":"%s","grants_ended":0,"at":"2026-11-17T00:00:00Z"}\n' \
		"$(cat "$FAKE/pid")" "$1" "$sha" > "$AUDIT/reload-status.json"
}
# fails NAME: true, and one less, while the count in $FAKE/NAME is above 0.
fails() {
	n=$(cat "$FAKE/$1" 2>/dev/null || echo 0)
	[ "$n" -gt 0 ] || return 1
	echo $((n - 1)) > "$FAKE/$1"
}
`

func newPGEnv(t *testing.T) *pgEnv {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("runs as root; the fakes in PATH are for a user that is not root")
	}
	real := pgNodkey(t)
	dir := pgTestDir(t)
	e := &pgEnv{dir: dir, etc: filepath.Join(dir, "etc"), audit: filepath.Join(dir, "var"),
		fake: filepath.Join(dir, "fake"), bin: filepath.Join(dir, "bin")}
	for _, d := range []string{e.etc, e.audit, e.fake, e.bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	vars := "FAKE='" + e.fake + "'\nAUDIT='" + e.audit + "'\n"
	pgScript(t, filepath.Join(e.bin, "nodkey"), vars+pgFakeStatus+`if [ "$1 $2" = "broker reload" ]; then
	echo reload >> "$FAKE/calls"
	[ -f "$FAKE/active" ] || { echo "nodkey broker reload: no broker runs" >&2; exit 1; }
	if fails reload-fails; then
		echo "nodkey broker reload: the broker refused the new config" >&2
		exit 1
	fi
	status loaded
	exit 0
fi
exec '`+real+`' "$@"
`)
	pgScript(t, filepath.Join(e.bin, "systemctl"), vars+pgFakeStatus+`case $1 in
is-active) [ -f "$FAKE/active" ] ;;
show) cat "$FAKE/pid" ;;
restart)
	echo restart >> "$FAKE/calls"
	if fails restart-fails; then
		rm -f "$FAKE/active"
		exit 1
	fi
	echo $(($(cat "$FAKE/pid") + 1)) > "$FAKE/pid"
	touch "$FAKE/active"
	status started
	;;
*) echo "fake systemctl: $*" >&2; exit 2 ;;
esac
`)
	// The broker runs the live config.
	pgWrite(t, filepath.Join(e.etc, "broker.toml"), e.pgConfig(t))
	pgWrite(t, filepath.Join(e.etc, "known_hosts"), "")
	pgWrite(t, filepath.Join(e.fake, "pid"), "100\n")
	pgWrite(t, filepath.Join(e.fake, "active"), "")
	e.runFake(t, "status", "started")
	return e
}

// pgTestDir returns a new directory for one test, on a path that passes
// the file checks of nodkey: the system temporary directory fails them
// (see privateTestDir in cmd/nodkey). It is made in $XDG_RUNTIME_DIR or
// in the user's cache directory. The test is skipped if there is no such
// place, or fails when CI is set.
func pgTestDir(t *testing.T) string {
	t.Helper()
	var bases []string
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		bases = append(bases, d)
	}
	if d, err := os.UserCacheDir(); err == nil {
		bases = append(bases, d)
	}
	for _, base := range bases {
		dir, err := os.MkdirTemp(base, "nodkey-pullgate-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G703: the test's own new directory.
		probe := filepath.Join(dir, "probe")
		ok := os.Chmod(dir, 0o700) == nil //nolint:gosec // G302: a directory, private to its owner.
		if ok && os.WriteFile(probe, nil, 0o600) == nil && config.CheckPrivateFile(probe) == nil {
			return dir
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatalf("no directory passes the file checks of nodkey: tried %q", bases)
	}
	t.Skipf("no directory passes the file checks of nodkey: tried %q", bases)
	return ""
}

func pgScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil { //nolint:gosec // G306: a fake program of the test.
		t.Fatal(err)
	}
}

// runFake runs a shell function of the fakes.
func (e *pgEnv) runFake(t *testing.T, args ...string) {
	t.Helper()
	script := "FAKE='" + e.fake + "'\nAUDIT='" + e.audit + "'\nNKP_ETC='" + e.etc + "'\n" + pgFakeStatus + `"$@"`
	cmd := exec.CommandContext(t.Context(), "/bin/sh", append([]string{"-c", script, "sh"}, args...)...) //nolint:gosec // G204: the test's own fake.
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fake %q: %v: %s", args, err, out)
	}
}

// run runs a script of contrib/pullgate with the environment that pullgate
// gives it, and returns its exit code and output.
func (e *pgEnv) run(t *testing.T, script, tree, oldTree string) (int, string) {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("contrib", "pullgate", script))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), path) //nolint:gosec // G204: a script of contrib/pullgate.
	cmd.Dir = tree
	cmd.Env = []string{
		"PATH=" + e.bin + ":/usr/local/bin:/usr/bin:/bin",
		"PULLGATE_INSTANCE=nodkey-broker",
		"PULLGATE_SHA=1111111111111111111111111111111111111111",
		"PULLGATE_TREE=" + tree,
		"PULLGATE_OLD_TREE=" + oldTree,
		"NKP_ETC=" + e.etc,
		"NKP_UNIT=nodkey.service",
		"NKP_CREDENTIALS=" + filepath.Join(e.dir, "no-credentials"),
		"NKP_HEALTH_TIMEOUT=2",
	}
	if e.rollback {
		cmd.Env = append(cmd.Env, "PULLGATE_ROLLBACK=1")
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("%s: %v", script, err)
		}
		code = ee.ExitCode()
	}
	return code, string(out)
}

func (e *pgEnv) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.fake, "calls"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\n", " "))
}

func (e *pgEnv) liveSum(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.etc, "broker.toml"))
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// The changes of the tests.
var (
	// A new secret: a reload takes it.
	pgReloadSafe = [2]string{"[secret.github-token]", "[secret.mail-password]\nstore = \"main\"\n" +
		"id = \"00000000-0000-4000-8000-000011112222\"\nclients = [\"laptop\"]\nask = \"always\"\n\n[secret.github-token]"}
	// [updates] check turned off: a reload refuses it, and a commit may
	// make it.
	pgRestartType = [2]string{"[client.laptop]", "[updates]\ncheck = false\n\n[client.laptop]"}
)

// pgTelegram is another timeout of [telegram]: a part of the gate.
var pgTelegram = [2]string{"user_id = 123456789", "user_id = 123456789\ntimeout = \"300s\""}

// TestPullgateCheck: check.sh passes a good commit, and refuses a missing
// file, a symlink, a config that is not valid, and a change of the path of
// known_hosts or audit_log.
func TestPullgateCheck(t *testing.T) {
	e := newPGEnv(t)
	if code, out := e.run(t, "check.sh", e.pgTree(t, "good", e.pgConfig(t, pgReloadSafe)), ""); code != 0 {
		t.Fatalf("a good commit: exit %d:\n%s", code, out)
	}
	for _, c := range []struct {
		name string
		tree func() string
		want string
	}{
		{"no known_hosts", func() string {
			tree := e.pgTree(t, "no-kh", e.pgConfig(t))
			if err := os.Remove(filepath.Join(tree, "known_hosts")); err != nil {
				t.Fatal(err)
			}
			return tree
		}, "known_hosts is missing, or is not a plain file"},
		{"a symlink", func() string {
			tree := e.pgTree(t, "link", e.pgConfig(t))
			p := filepath.Join(tree, "broker.toml")
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("broker.toml.real", p); err != nil {
				t.Fatal(err)
			}
			return tree
		}, "a symlink is refused"},
		{"not valid", func() string {
			return e.pgTree(t, "bad", e.pgConfig(t, [2]string{config.Pin{1}.String(), "not-a-pin"}))
		}, "Fix the config in the repo"},
		{"audit_log moved", func() string {
			return e.pgTree(t, "audit", e.pgConfig(t, [2]string{"/audit.jsonl", "/other.jsonl"}))
		}, "Refused: a commit may not change listen"},
		{"another approver", func() string {
			return e.pgTree(t, "approver", e.pgConfig(t, [2]string{"user_id = 123456789", "user_id = 987654321"}))
		}, "Refused"},
		{"another telegram timeout", func() string {
			return e.pgTree(t, "tgtimeout", e.pgConfig(t, pgTelegram))
		}, "Refused"},
		{"another store program", func() string {
			return e.pgTree(t, "program", e.pgConfig(t, [2]string{"/usr/local/bin/bws", "/tmp/bws"}))
		}, "Refused"},
		{"tls_key", func() string {
			return e.pgTree(t, "tls", e.pgConfig(t, [2]string{"/broker-tls-key", "/bws-token"}))
		}, "Refused"},
		{"known_hosts moved", func() string {
			tree := e.pgTree(t, "kh", e.pgConfig(t, [2]string{"/known_hosts\"", "/known_hosts2\""}))
			pgWrite(t, filepath.Join(tree, "known_hosts2"), "")
			return tree
		}, "Refused"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := e.run(t, "check.sh", c.tree(), "")
			if code == 0 || !strings.Contains(out, c.want) {
				t.Fatalf("exit %d, want a failure with %q:\n%s", code, c.want, out)
			}
		})
	}
}

// TestPullgateSummary: the change list, with "⚠ needs a broker restart"
// first only when a reload cannot take the change.
func TestPullgateSummary(t *testing.T) {
	e := newPGEnv(t)
	old := e.pgTree(t, "old", e.pgConfig(t))
	const restart = "⚠ needs a broker restart: all grants end"

	code, out := e.run(t, "summary.sh", e.pgTree(t, "safe", e.pgConfig(t, pgReloadSafe)), old)
	if code != 0 || strings.Contains(out, restart) ||
		!strings.Contains(out, `⚠ secret "mail-password": new secret in store "main", item …11112222`) {
		t.Fatalf("a reload-safe change: exit %d:\n%s", code, out)
	}

	code, out = e.run(t, "summary.sh", e.pgTree(t, "restart", e.pgConfig(t, pgRestartType)), old)
	if code != 0 || !strings.HasPrefix(out, restart+"\n") || !strings.Contains(out, "[updates] check") {
		t.Fatalf("a restart-type change: exit %d:\n%s", code, out)
	}

	// A new SSH key needs a restart: systemd loads its credential only at
	// the start.
	key := [2]string{"[secret.github-token]", "[key.deploy]\nfile = \"${CREDENTIALS_DIRECTORY}/ssh-deploy\"\n" +
		"clients = [\"laptop\"]\nask = \"always\"\n\n[secret.github-token]"}
	code, out = e.run(t, "summary.sh", e.pgTree(t, "key", e.pgConfig(t, key)), old)
	if code != 0 || !strings.HasPrefix(out, restart+"\n") {
		t.Fatalf("a new SSH key: exit %d:\n%s", code, out)
	}

	// Only a new host key in known_hosts: a reload takes it.
	kh := e.pgTree(t, "kh", e.pgConfig(t))
	pgWrite(t, filepath.Join(kh, "known_hosts"), "web-9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n")
	code, out = e.run(t, "summary.sh", kh, old)
	if code != 0 || strings.Contains(out, restart) || !strings.Contains(out, `known_hosts: new host "web-9"`) {
		t.Fatalf("a new host key: exit %d:\n%s", code, out)
	}

	// The first apply compares with the live config.
	code, out = e.run(t, "summary.sh", e.pgTree(t, "first", e.pgConfig(t, pgReloadSafe)), "")
	if code != 0 || !strings.Contains(out, "First apply") || !strings.Contains(out, `secret "mail-password"`) {
		t.Fatalf("the first apply: exit %d:\n%s", code, out)
	}

	// The live config is not the applied commit.
	code, out = e.run(t, "summary.sh", e.pgTree(t, "safe2", e.pgConfig(t, pgReloadSafe)),
		e.pgTree(t, "old2", e.pgConfig(t, [2]string{"ask = \"always\"", "ask = \"window\"\nwindow = \"5m\""})))
	if code != 0 || !strings.Contains(out, "⚠ the live config") {
		t.Fatalf("a hand edit: exit %d:\n%s", code, out)
	}
}

// TestPullgateApply: apply.sh reloads for a reload-safe change and
// restarts for another, and health.sh then sees the new config. When the
// reload or the restart fails, the old files go back, the broker reloads
// or restarts again, and apply.sh fails.
func TestPullgateApply(t *testing.T) {
	for _, c := range []struct {
		name      string
		change    [2]string
		fails     string // a file of the fakes with a count of failures
		inactive  bool   // the broker does not run
		rollback  bool   // PULLGATE_ROLLBACK=1
		wantCode  int
		wantCalls string
	}{
		{name: "reload-safe", change: pgReloadSafe, wantCalls: "reload"},
		{name: "restart-type", change: pgRestartType, wantCalls: "restart"},
		{name: "refused reload", change: pgReloadSafe, fails: "reload-fails", wantCode: 1, wantCalls: "reload reload"},
		{name: "failed restart", change: pgRestartType, fails: "restart-fails", wantCode: 1, wantCalls: "restart restart"},
		{name: "a broker that does not run", change: pgReloadSafe, inactive: true, wantCalls: "restart"},
		// A rollback whose reload fails: the failed files are not put back;
		// a restart runs the last good config.
		{name: "rollback", change: pgReloadSafe, fails: "reload-fails", rollback: true, wantCalls: "reload restart"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newPGEnv(t)
			before := e.liveSum(t)
			if c.fails != "" {
				pgWrite(t, filepath.Join(e.fake, c.fails), "1\n")
			}
			if c.inactive {
				if err := os.Remove(filepath.Join(e.fake, "active")); err != nil {
					t.Fatal(err)
				}
			}
			newCfg := e.pgConfig(t, c.change)
			e.rollback = c.rollback
			code, out := e.run(t, "apply.sh", e.pgTree(t, "new", newCfg), e.pgTree(t, "old", e.pgConfig(t)))
			if code != c.wantCode || e.calls(t) != c.wantCalls {
				t.Fatalf("exit %d, calls %q; want exit %d, calls %q:\n%s", code, e.calls(t), c.wantCode, c.wantCalls, out)
			}
			after := e.liveSum(t)
			if c.wantCode == 0 {
				want := sha256.Sum256([]byte(newCfg))
				if after != hex.EncodeToString(want[:]) {
					t.Errorf("the live config is not the new one:\n%s", out)
				}
			} else if after != before {
				t.Errorf("the old config is not back:\n%s", out)
			}
			for _, d := range []string{"pullgate-new", "pullgate-old"} {
				if _, err := os.Stat(filepath.Join(e.etc, d)); !os.IsNotExist(err) {
					t.Errorf("%s is left: %v", d, err)
				}
			}
			// The broker runs the config that is in place now.
			if code, out := e.run(t, "health.sh", e.dir, ""); code != 0 || !strings.Contains(out, "runs") {
				t.Errorf("health.sh: exit %d:\n%s", code, out)
			}
		})
	}
}

// TestPullgateApplyRefusesBadFiles: apply.sh installs nothing when a file
// of the commit is a symlink, or nodkey broker check refuses the config.
func TestPullgateApplyRefusesBadFiles(t *testing.T) {
	e := newPGEnv(t)
	before := e.liveSum(t)
	bad := e.pgTree(t, "bad", e.pgConfig(t, [2]string{config.Pin{1}.String(), "not-a-pin"}))
	if code, out := e.run(t, "apply.sh", bad, ""); code == 0 || !strings.Contains(out, "refused the new config") {
		t.Fatalf("a config that is not valid: exit %d:\n%s", code, out)
	}
	link := e.pgTree(t, "link", e.pgConfig(t))
	if err := os.Remove(filepath.Join(link, "known_hosts")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.etc, "known_hosts"), filepath.Join(link, "known_hosts")); err != nil {
		t.Fatal(err)
	}
	if code, out := e.run(t, "apply.sh", link, ""); code == 0 || !strings.Contains(out, "a symlink is refused") {
		t.Fatalf("a symlink: exit %d:\n%s", code, out)
	}
	// A part of the gate, also in a rollback, which runs no check.sh.
	gate := e.pgTree(t, "gate", e.pgConfig(t, pgTelegram))
	if code, out := e.run(t, "apply.sh", gate, ""); code == 0 || !strings.Contains(out, "refused: the commit changes a part") {
		t.Fatalf("a part of the gate: exit %d:\n%s", code, out)
	}
	// A copy of the old files that an earlier apply left: never removed.
	keep := filepath.Join(e.etc, "pullgate-old")
	if err := os.Mkdir(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, out := e.run(t, "apply.sh", e.pgTree(t, "safe", e.pgConfig(t, pgReloadSafe)), ""); code == 0 ||
		!strings.Contains(out, "is left from an earlier apply") {
		t.Fatalf("a left copy: exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("the left copy is gone: %v", err)
	}
	if e.liveSum(t) != before || e.calls(t) != "" {
		t.Errorf("the live config changed, or the broker was reloaded: calls %q", e.calls(t))
	}
}

// TestPullgateHealth: health.sh fails, after its timeout, when the status
// file is of another process or another config, or the broker does not
// run.
func TestPullgateHealth(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(e *pgEnv)
		want  string
	}{
		{"another process", func(e *pgEnv) { pgWrite(t, filepath.Join(e.fake, "pid"), "101\n") }, "but nodkey.service runs process 101"},
		{"another config", func(e *pgEnv) { pgWrite(t, filepath.Join(e.etc, "broker.toml"), e.pgConfig(t, pgReloadSafe)) },
			"the broker runs another config"},
		{"not running", func(e *pgEnv) {
			if err := os.Remove(filepath.Join(e.fake, "active")); err != nil {
				t.Fatal(err)
			}
		}, "nodkey.service does not run"},
		{"a refused reload", func(e *pgEnv) { e.runFake(t, "status", "refused") }, "says no good start or reload"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newPGEnv(t)
			if code, out := e.run(t, "health.sh", e.dir, ""); code != 0 {
				t.Fatalf("before: exit %d:\n%s", code, out)
			}
			c.setup(e)
			code, out := e.run(t, "health.sh", e.dir, "")
			if code == 0 || !strings.Contains(out, c.want) || !strings.Contains(out, "no good answer in 2s") {
				t.Fatalf("exit %d, want a failure with %q:\n%s", code, c.want, out)
			}
		})
	}
}
