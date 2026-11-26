package nodkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

// The tests of the host instance of the pullgate recipe (contrib/pullgate,
// host-*.sh and setup.sh) run the scripts with /bin/sh, with the
// environment that pullgate gives them, against fakes: a nodkey that
// prints its version, ansible-playbook and pullgate that log their calls,
// and the Ansible recipe of two versions, built from contrib/ansible.
// The scripts get the paths of the test in the NKH_ values, and
// NKH_ROOT_UID makes the user of the test count as root. The end-to-end
// test with systemd, real users and the released pullgate is
// contrib/pullgate/test/ci.sh.

// hostEnv is one broker host of a test of the host instance.
type hostEnv struct {
	dir, bin, fake, opt, pgetc string
	recipes                    map[string]string // version -> folder
}

const (
	hostReleases = "https://127.0.0.1:1/code6x/nodkey/releases/download"
	hostOld      = "1.2.3"
	hostNew      = "1.2.4"
)

func newHostEnv(t *testing.T) *hostEnv {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("runs as root; NKH_ROOT_UID is for a user that is not root")
	}
	if err := exec.CommandContext(t.Context(), "python3", "-I", "-c", "import yaml, tomllib").Run(); err != nil {
		skipOrFail(t, "python3 with PyYAML and tomllib is missing: %v", err)
	}
	dir := pgTestDir(t)
	e := &hostEnv{dir: dir, bin: filepath.Join(dir, "bin"), fake: filepath.Join(dir, "fake"),
		opt: filepath.Join(dir, "opt"), pgetc: filepath.Join(dir, "pgetc"), recipes: map[string]string{}}
	for _, d := range []string{e.bin, e.fake, e.opt, e.pgetc} {
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // G301: folders of the test host, as on a host
			t.Fatal(err)
		}
	}
	fake := "FAKE='" + e.fake + "'\n"
	pgScript(t, filepath.Join(e.bin, "nodkey"), fake+`[ "$1 $2" = "version --offline" ] || exit 2
echo "nodkey $(cat "$FAKE/version")"
`)
	pgScript(t, filepath.Join(e.bin, "ansible-playbook"), fake+`echo "ansible-playbook $*" >> "$FAKE/calls"
[ ! -e "$FAKE/playbook-fails" ] || { echo "fatal: the fake playbook fails"; exit 2; }
echo "localhost : ok=9 changed=0 unreachable=0 failed=0"
`)
	pgScript(t, filepath.Join(e.bin, "pullgate"), fake+`echo "pullgate $*" >> "$FAKE/calls"
[ ! -e "$FAKE/pullgate-fails" ] || exit 1
`)
	pgScript(t, filepath.Join(e.bin, "gh"), "exit 9\n")
	pgWrite(t, filepath.Join(e.fake, "version"), hostOld+"\n")
	for _, v := range []string{hostOld, hostNew} {
		e.recipe(t, v)
	}
	unit := readFile(t, filepath.Join(e.recipes[hostOld], "roles", "nodkey", "files", "nodkey.service"))
	pgWrite(t, filepath.Join(dir, "nodkey.service"), string(unit))
	for _, name := range []string{"nodkey-broker", "nodkey-host"} {
		e.record(t, name, hostOld)
	}
	// A record of another recipe: never moved.
	pgWrite(t, filepath.Join(e.pgetc, "other.recipe"), "repo = \"example/other\"\nfile = \"other_1.0.0_recipe.tar.gz\"\nversion = \"1.0.0\"\n")
	return e
}

// recipe builds the Ansible recipe of version v into NKH_OPT, as
// host-get-recipe.sh leaves it: nobody but its owner can write it.
func (e *hostEnv) recipe(t *testing.T, v string) {
	t.Helper()
	d := filepath.Join(e.opt, "nodkey-ansible-"+v)
	out, err := exec.CommandContext(t.Context(), "sh", "contrib/ansible/build.sh", v, ".", d).CombinedOutput() //nolint:gosec // G204: the test's own build.
	if err != nil {
		t.Fatalf("build the Ansible recipe %s: %v: %s", v, err, out)
	}
	if out, err := exec.CommandContext(t.Context(), "chmod", "-R", "go-w", d).CombinedOutput(); err != nil { //nolint:gosec // G204: the test's own folder.
		t.Fatalf("chmod: %v: %s", err, out)
	}
	e.recipes[v] = d
}

// record writes the record of pullgate for an instance on the recipe of
// nodkey version v.
func (e *hostEnv) record(t *testing.T, name, v string) {
	t.Helper()
	pgWrite(t, filepath.Join(e.pgetc, name+".recipe"), "url = \"https://github.com/code6x/nodkey/releases/download/v"+v+
		"/nodkey_"+v+"_pullgate.tar.gz\"\nrepo = \"code6x/nodkey\"\nversion = \""+v+"\"\nfile = \"nodkey_"+v+"_pullgate.tar.gz\"\n")
}

// tree writes the tree of a commit: host.yml with these lines, and the
// other files. It returns the folder.
func (e *hostEnv) tree(t *testing.T, hostYML string, files ...string) string {
	t.Helper()
	d, err := os.MkdirTemp(e.dir, "tree-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o755); err != nil { //nolint:gosec // G302: a tree of a commit, as pullgate exports it.
		t.Fatal(err)
	}
	pgWrite(t, filepath.Join(d, "host.yml"), hostYML)
	for _, f := range files {
		pgWrite(t, filepath.Join(d, f), "")
	}
	return d
}

func hostYML(version string, more ...string) string {
	return "nodkey_version: \"" + version + "\"\nnodkey_broker_config: /etc/nodkey/broker.toml\n" + strings.Join(more, "")
}

// changed writes the list of changed paths as pullgate does: each path
// ended by a NUL byte. With no names it lists every file of the tree.
func (e *hostEnv) changed(t *testing.T, tree string, names ...string) string {
	t.Helper()
	if names == nil {
		err := filepath.WalkDir(tree, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(tree, p)
			names = append(names, rel)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.CreateTemp(e.dir, "changed-")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if _, err := f.WriteString(n + "\x00"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// hostRun is one run of a script.
type hostRun struct {
	tree, old, changed, failed string
	args                       []string
	env                        []string
}

func (e *hostEnv) run(t *testing.T, script string, r hostRun) (int, string) {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("contrib", "pullgate", script))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), path, r.args...) //nolint:gosec // G204: a script of contrib/pullgate.
	cmd.Dir = e.dir
	if r.tree != "" {
		cmd.Dir = r.tree
	}
	cmd.Env = append([]string{
		"PATH=" + e.bin + ":/usr/local/bin:/usr/bin:/bin",
		"PULLGATE_INSTANCE=nodkey-host",
		"PULLGATE_TREE=" + r.tree,
		"PULLGATE_OLD_TREE=" + r.old,
		"PULLGATE_CHANGED_FILES=" + r.changed,
		"PULLGATE_FAILED_SHA=" + r.failed,
		"NKH_ROOT_UID=" + strconv.Itoa(os.Getuid()),
		"NKH_NODKEY=" + filepath.Join(e.bin, "nodkey"),
		"NKH_PULLGATE=" + filepath.Join(e.bin, "pullgate"),
		"NKH_ANSIBLE_PLAYBOOK=" + filepath.Join(e.bin, "ansible-playbook"),
		"NKH_GH=" + filepath.Join(e.bin, "gh"),
		"NKH_OPT=" + e.opt,
		"NKH_PGETC=" + e.pgetc,
		"NKH_WORK=" + filepath.Join(e.dir, "work"),
		"NKH_UNIT_FILE=" + filepath.Join(e.dir, "nodkey.service"),
		// No test reaches the network: a download fails at once.
		"NKH_RELEASES=" + hostReleases,
	}, r.env...)
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

func (e *hostEnv) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.fake, "calls"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

// check runs host-check.sh; changed nil means every file of the tree.
func (e *hostEnv) check(t *testing.T, tree, old string, changed ...string) (int, string) {
	t.Helper()
	return e.run(t, "host-check.sh", hostRun{tree: tree, old: old, changed: e.changed(t, tree, changed...)})
}

// TestPullgateHostCheck: host-check.sh passes a good commit, and refuses
// a file outside the layout, a submodule, another broker config, and a
// new version with another key.
func TestPullgateHostCheck(t *testing.T) {
	e := newHostEnv(t)
	good := e.tree(t, hostYML(hostOld), "README.md", "schema/host.schema.json", ".github/workflows/check.yml", ".github/pull_request_template.md")
	if code, out := e.check(t, good, ""); code != 0 || !strings.Contains(out, "host.yml passed check-data of nodkey "+hostOld) {
		t.Fatalf("a good commit: exit %d, output:\n%s", code, out)
	}
	for _, c := range []struct {
		name    string
		tree    string
		old     string
		changed []string
		want    string
	}{
		{"an unknown file", e.tree(t, hostYML(hostOld), "notes-with-a-long-name.txt"), "", nil,
			"notes-with-a-long-name.txt is not an allowed file of the data repo"},
		{"a file deeper in an allowed folder", e.tree(t, hostYML(hostOld), "schema/more/x.json"), "", nil,
			"schema/more/x.json is not an allowed file of the data repo"},
		{"a submodule in the changed files", good, "", []string{"host.yml", "&&&&-a-long-submodule-name"},
			"&&&&-a-long-submodule-name is not an allowed file of the data repo (a submodule counts too)"},
		{"a name with a newline", good, "", []string{"host.yml\nREADME.md"},
			"host.yml?README.md is not an allowed file of the data repo"},
		{"an empty list on the first apply", good, "", []string{},
			"the list of changed files is empty on the first apply"},
		{"another nodkey_broker_config", e.tree(t, "nodkey_version: \""+hostOld+"\"\nnodkey_broker_config: /etc/nodkey/other.toml\n"), "", nil,
			"nodkey_broker_config must be /etc/nodkey/broker.toml"},
		{"an empty nodkey_broker_config", e.tree(t, "nodkey_version: \""+hostOld+"\"\nnodkey_broker_config: \"\"\n"), "", nil,
			"nodkey_broker_config must be /etc/nodkey/broker.toml"},
		{"no nodkey_broker_config", e.tree(t, "nodkey_version: \""+hostOld+"\"\n"), "", nil,
			"nodkey_broker_config must be /etc/nodkey/broker.toml"},
		{"a new version with another key", e.tree(t, hostYML(hostNew, "nodkey_restart: false\n")), e.tree(t, hostYML(hostOld)), nil,
			"nodkey_version changes, and so does nodkey_restart"},
		{"an unknown key", e.tree(t, hostYML(hostOld, "nodkey_firewall: allow\n")), "", nil,
			"Fix host.yml in the data repo. Only the keys of nodkey " + hostOld},
		{"an older version", e.tree(t, hostYML("1.2.2")), "", nil,
			"never to an older version than " + hostOld},
		{"host.yml as a link", e.linkTree(t), "", []string{"host.yml"},
			"is missing, or is not a plain file (a link is refused)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := e.check(t, c.tree, c.old, c.changed...)
			if code != 1 || !strings.Contains(out, c.want) {
				t.Errorf("exit %d, output:\n%s\nwant exit 1 and %q", code, out, c.want)
			}
		})
	}
	t.Run("a missing list of changed files", func(t *testing.T) {
		code, out := e.run(t, "host-check.sh", hostRun{tree: good, changed: filepath.Join(e.dir, "no-such-list")})
		if code != 1 || !strings.Contains(out, "cannot read the list of changed files") {
			t.Errorf("exit %d, output:\n%s", code, out)
		}
	})
	t.Run("a nodkey that others can change", func(t *testing.T) {
		if err := os.Chmod(filepath.Join(e.bin, "nodkey"), 0o722); err != nil { //nolint:gosec // G302: the test makes it unsafe on purpose.
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(filepath.Join(e.bin, "nodkey"), 0o700) }() //nolint:gosec // G302: back to the mode of pgScript.
		code, out := e.check(t, good, "")
		if code != 1 || !strings.Contains(out, "can be written by a group or others") {
			t.Errorf("exit %d, output:\n%s", code, out)
		}
	})
	// The same key change without a new version passes; and after a
	// failed update (the new version installed, the applied file still
	// names the one before) a fix may change other keys.
	same := e.tree(t, hostYML(hostOld, "nodkey_restart: false\n"))
	if code, out := e.check(t, same, e.tree(t, hostYML(hostOld))); code != 0 {
		t.Errorf("a key change without a new version: exit %d, output:\n%s", code, out)
	}
	if code, out := e.check(t, same, e.tree(t, hostYML("1.2.2"))); code != 0 {
		t.Errorf("a fix after a failed update: exit %d, output:\n%s", code, out)
	}
	// A deleted allowed file is in the list, not in the tree: it passes.
	if code, out := e.check(t, good, good, "README.md"); code != 0 {
		t.Errorf("a deleted allowed file: exit %d, output:\n%s", code, out)
	}
}

func (e *hostEnv) linkTree(t *testing.T) string {
	t.Helper()
	d := e.tree(t, hostYML(hostOld))
	p := filepath.Join(d, "host.yml")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e.dir, "nodkey.service"), p); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestPullgateHostSummary: the ⚠ lines come first: a held commit, then a
// restart; then the changed keys.
func TestPullgateHostSummary(t *testing.T) {
	e := newHostEnv(t)
	old := e.tree(t, hostYML(hostOld))
	failed := strings.Repeat("0123456789abcdef", 2) + "01234567"
	for _, c := range []struct {
		name, tree, old, failed string
		first                   []string // the first lines
		has                     string
	}{
		{"a key change", e.tree(t, hostYML(hostOld, "nodkey_restart: false\n")), old, "",
			[]string{"  nodkey_restart: (not set) → false"}, ""},
		{"a held commit", e.tree(t, hostYML(hostOld, "nodkey_restart: false\n")), old, failed,
			[]string{"⚠ the last apply failed part way: a broker restart may be due"}, "  nodkey_restart: (not set) → false"},
		{"a new version", e.tree(t, hostYML(hostNew)), old, "",
			[]string{"⚠ broker restart: all grants end"}, "  nodkey_version: " + hostOld + " → " + hostNew},
		{"a new version while a commit is held", e.tree(t, hostYML(hostNew)), old, failed,
			[]string{"⚠ the last apply failed part way: a broker restart may be due", "⚠ broker restart: all grants end"},
			"nodkey update --version " + hostNew},
		{"the first apply", e.tree(t, hostYML(hostOld)), "", "",
			[]string{"First apply: the values in host.yml."}, "  nodkey_version: " + hostOld},
		{"a new SSH key", e.tree(t, hostYML(hostOld, "nodkey_ssh_keys:\n  - name: deploy\n")), old, "",
			[]string{"⚠ broker restart: all grants end", "⚠ new SSH keys made on the broker: deploy"}, "  nodkey_ssh_keys: (not set) → "},
		{"an SSH key on the first apply", e.tree(t, hostYML(hostOld, "nodkey_ssh_keys:\n  - name: deploy\n")), "", "",
			[]string{"⚠ broker restart: all grants end", "⚠ new SSH keys made on the broker: deploy"}, "First apply"},
		{"an SSH key change without a restart", e.tree(t, hostYML(hostOld, "nodkey_restart: false\nnodkey_ssh_keys:\n  - name: deploy\n")), e.tree(t, hostYML(hostOld, "nodkey_restart: false\n")), "",
			[]string{"⚠ a broker restart is due, but nodkey_restart is false: the broker runs as before until you restart it by hand (all grants end then)"}, "deploy"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := e.run(t, "host-summary.sh", hostRun{tree: c.tree, old: c.old, failed: c.failed})
			lines := strings.Split(out, "\n")
			if code != 0 || len(lines) < len(c.first) {
				t.Fatalf("exit %d, output:\n%s", code, out)
			}
			for i, want := range c.first {
				if lines[i] != want {
					t.Errorf("line %d is %q, want %q; output:\n%s", i+1, lines[i], want, out)
				}
			}
			if c.failed == "" && !strings.Contains(c.name, "version") && !strings.Contains(c.name, "SSH") && strings.Contains(out, "⚠") {
				t.Errorf("a ⚠ line without a reason:\n%s", out)
			}
			if !strings.Contains(out, c.has) {
				t.Errorf("no %q in:\n%s", c.has, out)
			}
		})
	}
}

// TestPullgateHostApply: the playbook runs with --connection local; a new
// version gets the recipes first and moves both instances only after the
// playbook passed; a failed playbook leaves the old scripts in place; a
// refused file never reaches the playbook.
func TestPullgateHostApply(t *testing.T) {
	playbook := regexp.MustCompile(`(?m)^ansible-playbook -i localhost, --connection local --diff \S+/nodkey-ansible-(\S+)/playbooks/broker-host\.yml -e nodkey_data_file=\S+/host\.yml$`)
	t.Run("the same version", func(t *testing.T) {
		e := newHostEnv(t)
		code, out := e.run(t, "host-apply.sh", hostRun{tree: e.tree(t, hostYML(hostOld, "nodkey_restart: false\n"))})
		calls := e.calls(t)
		if code != 0 || !strings.Contains(out, "nodkey host apply: done, nodkey "+hostOld) {
			t.Fatalf("exit %d, output:\n%s", code, out)
		}
		if m := playbook.FindStringSubmatch(calls); m == nil || m[1] != hostOld || strings.Contains(calls, "pullgate ") {
			t.Errorf("calls:\n%s", calls)
		}
	})
	t.Run("a new version", func(t *testing.T) {
		e := newHostEnv(t)
		code, out := e.run(t, "host-apply.sh", hostRun{tree: e.tree(t, hostYML(hostNew)), old: e.tree(t, hostYML(hostOld))})
		if code != 0 {
			t.Fatalf("exit %d, output:\n%s", code, out)
		}
		lines := strings.Split(strings.TrimSpace(e.calls(t)), "\n")
		want := []string{
			"pullgate recipe fetch " + hostReleases + "/v" + hostNew + "/nodkey_" + hostNew + "_pullgate.tar.gz --gh " + filepath.Join(e.bin, "gh"),
			"", // the playbook
			"pullgate recipe use nodkey-broker " + hostNew,
			"pullgate recipe use nodkey-host " + hostNew,
		}
		if len(lines) != len(want) {
			t.Fatalf("calls:\n%s", strings.Join(lines, "\n"))
		}
		for i, w := range want {
			if w == "" {
				if m := playbook.FindStringSubmatch(lines[i]); m == nil || m[1] != hostNew {
					t.Errorf("call %d is %q, want the playbook of %s", i+1, lines[i], hostNew)
				}
			} else if lines[i] != w {
				t.Errorf("call %d is %q, want %q", i+1, lines[i], w)
			}
		}
	})
	t.Run("a failed playbook leaves the old scripts in place", func(t *testing.T) {
		e := newHostEnv(t)
		pgWrite(t, filepath.Join(e.fake, "playbook-fails"), "")
		code, out := e.run(t, "host-apply.sh", hostRun{tree: e.tree(t, hostYML(hostNew)), old: e.tree(t, hostYML(hostOld))})
		calls := e.calls(t)
		if code != 1 || !strings.Contains(out, "the playbook failed; the instance pauses at this commit, and the pullgate instances stay on the recipe they had") {
			t.Errorf("exit %d, output:\n%s", code, out)
		}
		if strings.Contains(calls, "recipe use") || !strings.Contains(calls, "ansible-playbook") {
			t.Errorf("calls:\n%s", calls)
		}
	})
	t.Run("a later apply moves the instances that stayed behind", func(t *testing.T) {
		// nodkey update ran, then the playbook failed: the next commit has
		// the installed version, and the instances still run the old recipe.
		e := newHostEnv(t)
		pgWrite(t, filepath.Join(e.fake, "version"), hostNew+"\n")
		code, out := e.run(t, "host-apply.sh", hostRun{tree: e.tree(t, hostYML(hostNew, "nodkey_restart: true\n")), old: e.tree(t, hostYML(hostNew))})
		calls := e.calls(t)
		if code != 0 || !strings.Contains(calls, "pullgate recipe fetch") ||
			!strings.HasSuffix(calls, "pullgate recipe use nodkey-broker "+hostNew+"\npullgate recipe use nodkey-host "+hostNew+"\n") {
			t.Errorf("exit %d, output:\n%s\ncalls:\n%s", code, out, calls)
		}
	})
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, e *hostEnv)
		yml   string
		want  string
	}{
		{"another broker config", nil, "nodkey_version: \"" + hostOld + "\"\nnodkey_broker_config: /etc/nodkey/other.toml\n",
			"nodkey_broker_config must be /etc/nodkey/broker.toml"},
		{"an older version", nil, hostYML("1.2.2"), "host.yml did not pass check-data of nodkey " + hostOld},
		{"no record of this instance", func(t *testing.T, e *hostEnv) {
			if err := os.Remove(filepath.Join(e.pgetc, "nodkey-host.recipe")); err != nil {
				t.Fatal(err)
			}
		}, hostYML(hostNew), "the pullgate instance nodkey-host does not run the recipe of nodkey"},
		{"a record that cannot be read", func(t *testing.T, e *hostEnv) {
			pgWrite(t, filepath.Join(e.pgetc, "nodkey-broker.recipe"), "repo = \n")
		}, hostYML(hostNew), "cannot read the pullgate record"},
		{"the fetch fails", func(t *testing.T, e *hostEnv) {
			pgWrite(t, filepath.Join(e.fake, "pullgate-fails"), "")
		}, hostYML(hostNew), "the recipes of nodkey " + hostNew + " did not pass their checks; nothing was changed"},
		{"the Ansible recipe of the new version is not safe", func(t *testing.T, e *hostEnv) {
			if err := os.Chmod(filepath.Join(e.recipes[hostNew], "check-data"), 0o777); err != nil { //nolint:gosec // G302: unsafe on purpose.
				t.Fatal(err)
			}
		}, hostYML(hostNew), "is there but not safe, or not the recipe of " + hostNew},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newHostEnv(t)
			if c.setup != nil {
				c.setup(t, e)
			}
			code, out := e.run(t, "host-apply.sh", hostRun{tree: e.tree(t, c.yml), old: e.tree(t, hostYML(hostOld))})
			calls := e.calls(t)
			if code != 1 || !strings.Contains(out, c.want) {
				t.Errorf("exit %d, output:\n%s\nwant exit 1 and %q", code, out, c.want)
			}
			if strings.Contains(calls, "ansible-playbook") || strings.Contains(calls, "recipe use") {
				t.Errorf("a refused apply changed the host; calls:\n%s", calls)
			}
		})
	}
}

// TestPullgateHostGetRecipe: the usage, the recipe that is there already,
// and the gh of install.sh.
func TestPullgateHostGetRecipe(t *testing.T) {
	e := newHostEnv(t)
	for _, args := range [][]string{nil, {"v1.2.3"}, {"1.2"}, {hostOld, "--other"}} {
		code, out := e.run(t, "host-get-recipe.sh", hostRun{args: args})
		if code != 64 || !strings.Contains(out, "(exit 64)") {
			t.Errorf("%q: exit %d, output:\n%s", args, code, out)
		}
	}
	code, out := e.run(t, "host-get-recipe.sh", hostRun{args: []string{hostNew, "--with-pullgate"}})
	if code != 0 || !strings.Contains(out, "the Ansible recipe of nodkey "+hostNew+" is there already") ||
		!strings.Contains(e.calls(t), "pullgate recipe fetch "+hostReleases+"/v"+hostNew+"/nodkey_"+hostNew+"_pullgate.tar.gz") {
		t.Errorf("exit %d, output:\n%s\ncalls:\n%s", code, out, e.calls(t))
	}
	// No recipe: the download fails, and nothing is made.
	code, out = e.run(t, "host-get-recipe.sh", hostRun{args: []string{"1.9.8"}})
	if code != 1 || !strings.Contains(out, "cannot download nodkey_1.9.8_ansible.tar.gz") {
		t.Errorf("no release: exit %d, output:\n%s", code, out)
	}
	if _, err := os.Lstat(filepath.Join(e.opt, "nodkey-ansible-1.9.8")); !os.IsNotExist(err) {
		t.Errorf("a failed download left a folder: %v", err)
	}
	// A recipe of another version in the folder of this one is refused.
	if err := os.Rename(e.recipes[hostOld], filepath.Join(e.opt, "nodkey-ansible-1.9.9")); err != nil {
		t.Fatal(err)
	}
	code, out = e.run(t, "host-get-recipe.sh", hostRun{args: []string{"1.9.9"}})
	if code != 1 || !strings.Contains(out, "is there but not safe, or not the recipe of 1.9.9") {
		t.Errorf("a recipe of another version: exit %d, output:\n%s", code, out)
	}
	// The gh pins are those of install.sh.
	install := string(readFile(t, "install.sh"))
	get := string(readFile(t, filepath.Join("contrib", "pullgate", "host-get-recipe.sh")))
	for _, re := range []string{`(?m)^gh_version=\S+$`, `(?m)^gh_sha256_amd64=\S+$`, `(?m)^gh_sha256_arm64=\S+$`} {
		r := regexp.MustCompile(re)
		if a, b := r.FindString(install), r.FindString(get); a == "" || a != b {
			t.Errorf("install.sh has %q, host-get-recipe.sh %q", a, b)
		}
	}
}

// TestPullgateHostGetRecipeChecks: host-get-recipe.sh downloads the
// Ansible recipe from a local HTTPS server, checks it, and unpacks it
// only when every check passed.
func TestPullgateHostGetRecipeChecks(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		skipOrFail(t, "curl is missing: %v", err)
	}
	const v = "1.3.0"
	name := "nodkey_" + v + "_ansible.tar.gz"
	// tarOf packs the Ansible recipe of version rv as the release does.
	tarOf := func(t *testing.T, rv string) []byte {
		t.Helper()
		d := filepath.Join(t.TempDir(), "recipe")
		if out, err := exec.CommandContext(t.Context(), "sh", "contrib/ansible/build.sh", rv, ".", d).CombinedOutput(); err != nil { //nolint:gosec // G204: the test's own build.
			t.Fatalf("build: %v: %s", err, out)
		}
		out, err := exec.CommandContext(t.Context(), "tar", "-C", d, "-czf", "-", ".").Output() //nolint:gosec // G204: the test's own folder.
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	good := tarOf(t, v)
	other := tarOf(t, "1.2.9")
	sumOf := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	for _, c := range []struct {
		name    string
		tarball []byte
		sums    func(sum string) string
		gh      string // the output of the fake gh; "fail" makes it fail
		want    string
	}{
		{"good", good, nil, "", "the Ansible recipe of nodkey " + v + " is checked and in"},
		{"a wrong SHA-256", good, func(string) string { return strings.Repeat("0", 64) + "  " + name + "\n" }, "",
			"the SHA-256 of " + name + " is not the one in SHA256SUMS"},
		{"no line in SHA256SUMS", good, func(string) string { return strings.Repeat("0", 64) + "  other.tar.gz\n" }, "",
			"SHA256SUMS has no single line for " + name},
		{"two lines in SHA256SUMS", good, func(sum string) string { return sum + "  " + name + "\n" + sum + "  " + name + "\n" }, "",
			"SHA256SUMS has no single line for " + name},
		{"the attestation fails", good, nil, "fail", "gh attestation verify failed for " + name},
		{"the statement names another file", good, nil, `[{"verificationResult":{"statement":{"subject":[{"name":"nodkey_1.2.9_ansible.tar.gz","digest":{"sha256":"SUM"}}]}}}]`,
			"the signed statement does not name " + name + " with its SHA-256"},
		{"the statement names another SHA-256", good, nil, `[{"verificationResult":{"statement":{"subject":[{"name":"` + name + `","digest":{"sha256":"` + strings.Repeat("1", 64) + `"}}]}}}]`,
			"the signed statement does not name " + name + " with its SHA-256"},
		{"the role of another version", other, nil, "", "the role in " + name + " is not the one of " + v},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newHostEnv(t)
			sum := sumOf(c.tarball)
			sums := sum + "  " + name + "\n"
			if c.sums != nil {
				sums = c.sums(sum)
			}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/code6x/nodkey/releases/download/v" + v + "/" + name:
					_, _ = w.Write(c.tarball)
				case "/code6x/nodkey/releases/download/v" + v + "/SHA256SUMS":
					_, _ = w.Write([]byte(sums))
				case "/code6x/nodkey/releases/download/v" + v + "/nodkey_" + v + ".sigstore.json":
					_, _ = w.Write([]byte("{}"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			ca := filepath.Join(e.dir, "ca.pem")
			pgWrite(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
			out := c.gh
			if out == "" {
				out = `[{"verificationResult":{"statement":{"subject":[{"name":"` + name + `","digest":{"sha256":"SUM"}}]}}}]`
			}
			gh := filepath.Join(e.bin, "gh")
			if out == "fail" {
				pgScript(t, gh, "exit 1\n")
			} else {
				// The fake gh checks the flags of the real check, and
				// prints the statement with the SHA-256 of the file.
				pgScript(t, gh, `[ "$1 $2 $3" = "attestation verify `+name+`" ] || exit 9
case " $* " in *" --repo code6x/nodkey "*) ;; *) exit 8 ;; esac
case " $* " in *" --cert-identity https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main "*) ;; *) exit 8 ;; esac
case " $* " in *" --deny-self-hosted-runners "*) ;; *) exit 8 ;; esac
sum=$(sha256sum "$3"); sum=${sum%% *}
printf '%s' '`+out+`' | sed "s/SUM/$sum/"
`)
			}
			code, got := e.run(t, "host-get-recipe.sh", hostRun{args: []string{v}, env: []string{
				"NKH_RELEASES=" + srv.URL + "/code6x/nodkey/releases/download",
				"CURL_CA_BUNDLE=" + ca,
			}})
			d := filepath.Join(e.opt, "nodkey-ansible-"+v)
			if c.name == "good" {
				if code != 0 || !strings.Contains(got, c.want) {
					t.Fatalf("exit %d, output:\n%s", code, got)
				}
				if code, out := e.run(t, "host-get-recipe.sh", hostRun{args: []string{v}}); code != 0 || !strings.Contains(out, "there already") {
					t.Errorf("a second run: exit %d, output:\n%s", code, out)
				}
				return
			}
			if code != 1 || !strings.Contains(got, c.want) {
				t.Errorf("exit %d, output:\n%s\nwant exit 1 and %q", code, got, c.want)
			}
			for _, p := range []string{d, d + ".new"} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("a refused download left %s: %v", p, err)
				}
			}
		})
	}
}

// TestPullgateSharedLock: the apply commands of both templates take the
// same lock, so the two applies never run at the same time.
func TestPullgateSharedLock(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		skipOrFail(t, "flock is missing: %v", err)
	}
	apply := func(tmpl string) []string {
		var c struct {
			Commands struct {
				Apply []string `toml:"apply"`
			} `toml:"commands"`
		}
		data := strings.ReplaceAll(string(readFile(t, filepath.Join("contrib", "pullgate", tmpl))), "@", "x")
		if _, err := toml.Decode(data, &c); err != nil {
			t.Fatalf("%s: %v", tmpl, err)
		}
		return c.Commands.Apply
	}
	host, broker := apply("nodkey-host.toml.in"), apply("nodkey-broker.toml.in")
	for _, argv := range [][]string{host, broker} {
		if len(argv) != 5 || argv[0] != "/usr/bin/flock" || argv[1] != "-w" || argv[3] != "/run/nodkey-broker-apply.lock" {
			t.Fatalf("the apply commands do not take the shared lock: %q and %q", host, broker)
		}
	}
	// The broker config waits longer for the lock than an apply of the
	// host instance may run, so its apply and its rollback do not fail
	// while a long update holds the lock.
	var hostCfg struct {
		Commands struct {
			ApplyTimeout string `toml:"apply_timeout"`
		} `toml:"commands"`
	}
	if _, err := toml.Decode(strings.ReplaceAll(string(readFile(t, filepath.Join("contrib", "pullgate", "nodkey-host.toml.in"))), "@", "x"), &hostCfg); err != nil {
		t.Fatal(err)
	}
	limit, err := time.ParseDuration(hostCfg.Commands.ApplyTimeout)
	wait, err2 := strconv.Atoi(broker[2])
	if err != nil || err2 != nil || time.Duration(wait)*time.Second <= limit {
		t.Errorf("the broker config waits %q s for the lock, the host apply may run %q", broker[2], hostCfg.Commands.ApplyTimeout)
	}
	// The same command with a lock of the test and a stub that logs.
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	stub := filepath.Join(dir, "stub")
	writeFile(t, stub, []byte("#!/bin/sh\necho \"$1 start\" >> \""+log+"\"\nsleep 1\necho \"$1 end\" >> \""+log+"\"\n"), 0o700)
	lock := filepath.Join(dir, "lock")
	var wg sync.WaitGroup
	run := func(argv []string, who string, delay time.Duration) {
		defer wg.Done()
		time.Sleep(delay)
		args := append([]string{}, argv[1:3]...)
		args = append(args, lock, stub, who)
		if out, err := exec.CommandContext(t.Context(), "flock", args...).CombinedOutput(); err != nil { //nolint:gosec // G204: the test's own stub.
			t.Errorf("%s: %v: %s", who, err, out)
		}
	}
	wg.Add(2)
	go run(host, "host", 0)
	go run(broker, "broker", 300*time.Millisecond)
	wg.Wait()
	got := strings.TrimSpace(string(readFile(t, log)))
	if got != "host start\nhost end\nbroker start\nbroker end" {
		t.Errorf("the two applies overlap:\n%s", got)
	}
}

// TestPullgateSetup: setup.sh passes on a host that is ready, and says
// what to fix when it is not.
func TestPullgateSetup(t *testing.T) {
	pg := newPGEnv(t)
	e := newHostEnv(t)
	// The version of the manifest of contrib/pullgate.
	e.recipe(t, "0.0.0")
	pgWrite(t, filepath.Join(e.fake, "version"), "0.0.0\n")
	unit := readFile(t, filepath.Join(e.recipes["0.0.0"], "roles", "nodkey", "files", "nodkey.service"))
	pgWrite(t, filepath.Join(e.dir, "nodkey.service"), string(unit))
	run := func(t *testing.T, role string) (int, string) {
		t.Helper()
		code, out := e.run(t, "setup.sh", hostRun{args: []string{role}, env: []string{
			"PATH=" + pg.bin + ":" + e.bin + ":/usr/local/bin:/usr/bin:/bin",
			"PULLGATE_INSTANCE=nodkey-" + role,
			"NKP_ETC=" + pg.etc, "NKP_UNIT=nodkey.service", "NKP_HEALTH_TIMEOUT=2",
		}})
		return code, out
	}
	// The check user is the user of the test: setup.sh reads it from the
	// config of the instance.
	me, err := exec.CommandContext(t.Context(), "id", "-un").Output()
	if err != nil {
		t.Fatal(err)
	}
	user := string(bytes.TrimSpace(me))
	for _, role := range []string{"broker", "host"} {
		pgWrite(t, filepath.Join(e.pgetc, "nodkey-"+role+".toml"), "[commands]\ncheck_user = \""+user+"\"\n")
	}
	for _, role := range []string{"broker", "host"} {
		if code, out := run(t, role); code != 0 || !strings.Contains(out, "every check passed") {
			t.Errorf("%s on a host that is ready: exit %d, output:\n%s", role, code, out)
		}
	}
	for _, c := range []struct {
		name, role string
		change     func(t *testing.T)
		want       string
	}{
		{"another version", "host", func(t *testing.T) { pgWrite(t, filepath.Join(e.fake, "version"), hostOld+"\n") },
			"this is the recipe of nodkey 0.0.0, but nodkey " + hostOld + " is installed"},
		{"another unit", "host", func(t *testing.T) { pgWrite(t, filepath.Join(e.dir, "nodkey.service"), "[Unit]\n") },
			"is not the unit of nodkey 0.0.0"},
		{"no known_hosts line", "broker", func(t *testing.T) {
			pgWrite(t, filepath.Join(pg.etc, "broker.toml"), strings.Replace(pg.pgConfig(t), "known_hosts = ", "# known_hosts = ", 1))
		}, "broker.toml needs the line known_hosts"},
		{"no known_hosts file", "broker", func(t *testing.T) {
			if err := os.Remove(filepath.Join(pg.etc, "known_hosts")); err != nil {
				t.Fatal(err)
			}
		}, "set up the broker config first"},
		{"a broker that does not run", "broker", func(t *testing.T) {
			if err := os.Remove(filepath.Join(pg.fake, "active")); err != nil {
				t.Fatal(err)
			}
		}, "health.sh: no good answer"},
		{"no check user", "host", func(t *testing.T) {
			pgWrite(t, filepath.Join(e.pgetc, "nodkey-host.toml"), "[commands]\ncheck_user = \"nodkey-no-such-user\"\n")
		}, "the check user nodkey-no-such-user does not exist"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Each case on a host that is ready again.
			pgWrite(t, filepath.Join(e.fake, "version"), "0.0.0\n")
			pgWrite(t, filepath.Join(e.dir, "nodkey.service"), string(unit))
			pgWrite(t, filepath.Join(pg.etc, "broker.toml"), pg.pgConfig(t))
			pgWrite(t, filepath.Join(pg.etc, "known_hosts"), "")
			pgWrite(t, filepath.Join(pg.fake, "active"), "")
			pg.runFake(t, "status", "started")
			pgWrite(t, filepath.Join(e.pgetc, "nodkey-host.toml"), "[commands]\ncheck_user = \""+user+"\"\n")
			c.change(t)
			code, out := run(t, c.role)
			if code != 1 || !strings.Contains(out, "PROBLEM: ") || !strings.Contains(out, c.want) ||
				!strings.Contains(out, "Fix") || !strings.Contains(out, "pullgate wrote no config and enabled no unit") {
				t.Errorf("exit %d, output:\n%s\nwant exit 1 and %q", code, out, c.want)
			}
		})
	}
	if code, out := run(t, "other"); code != 64 {
		t.Errorf("an unknown role: exit %d, output:\n%s", code, out)
	}
}
