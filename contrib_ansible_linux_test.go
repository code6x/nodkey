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
	"testing"
)

// The tests of the Ansible recipe in contrib/ansible: check-data, the
// check of a data file of the playbooks, and build.sh, which makes the
// recipe of a release. contrib/ansible/test/ci.sh runs the role itself in
// a container with systemd; CI runs it in the job "ansible".

// ansiblePython is python3 with PyYAML, or it skips the test. In CI, it
// fails instead.
func ansiblePython(t *testing.T) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err == nil {
		err = exec.CommandContext(context.Background(), py, "-c", "import yaml").Run() //nolint:gosec // G204: a fixed program.
	}
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("python3 with PyYAML is needed for the tests of check-data: %v", err)
		}
		t.Skipf("no python3 with PyYAML: %v", err)
	}
	return py
}

// checkData runs check-data on a file with this text, and returns its
// exit code and its output.
func checkData(t *testing.T, text string, args ...string) (int, string) {
	t.Helper()
	py := ansiblePython(t)
	file := filepath.Join(t.TempDir(), "host.yml")
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := append([]string{"-I", "contrib/ansible/check-data"}, args...)
	argv = append(argv, file)
	out, err := exec.CommandContext(context.Background(), py, argv...).CombinedOutput() //nolint:gosec // G204: the test's own script.
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("run check-data: %v", err)
	}
	return 0, string(out)
}

func TestCheckDataGood(t *testing.T) {
	cases := []struct {
		name, side, installed, text string
	}{
		{"broker, all keys", "broker", "0.7.0", "nodkey_version: \"0.8.0\"\nnodkey_restart: false\nnodkey_broker_config: /etc/nodkey/broker.toml\n"},
		{"broker, the same version", "broker", "0.8.0", "nodkey_version: \"0.8.0\"\n"},
		{"broker, no config", "broker", "none", "nodkey_version: 0.8.0\nnodkey_broker_config: \"\"\n"},
		{"broker, SSH keys", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_key_with_key: host\nnodkey_ssh_keys:\n  - name: deploy\n  - name: backup-2\n    type: ecdsa-p384\n  - {name: 0ops, type: ed25519}\n"},
		{"broker, no SSH keys", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: []\nnodkey_ssh_key_with_key: auto\n"},
		{"broker, a name of 32 characters", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: " + strings.Repeat("a", 32) + "}]\n"},
		{"agent, all keys", "agent", "none", "nodkey_version: \"0.8.0\"\nnodkey_restart: true\nnodkey_ssh_agent_user: example-user\nnodkey_ssh_agent_linger: false\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := checkData(t, c.text, "--side", c.side, "--installed", c.installed)
			if code != 0 || !strings.Contains(out, "good for the "+c.side+" side") {
				t.Fatalf("exit %d, want 0; output:\n%s", code, out)
			}
		})
	}
}

func TestCheckDataBad(t *testing.T) {
	cases := []struct {
		name, side, installed, text, want string
	}{
		{"unknown key", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_install_sh_sha256: \"00\"\n", "the key nodkey_install_sh_sha256 is not a key of the broker side"},
		{"a key of the other side", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_agent_user: example-user\n", "the key nodkey_ssh_agent_user is not a key of the broker side"},
		{"a broker key on the agent side", "agent", "none", "nodkey_version: \"0.8.0\"\nnodkey_broker_config: /etc/x\n", "the key nodkey_broker_config is not a key of the agent side"},
		{"wrong type of restart", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_restart: \"no\"\n", "nodkey_restart must be true or false"},
		{"wrong type of version", "broker", "none", "nodkey_version: 1.0\n", "nodkey_version must be a version X.Y.Z"},
		{"version with a v", "broker", "none", "nodkey_version: \"v0.8.0\"\n", "nodkey_version must be a version X.Y.Z"},
		{"version with a leading zero", "broker", "none", "nodkey_version: \"0.08.0\"\n", "nodkey_version must be a version X.Y.Z"},
		{"version as a list", "broker", "none", "nodkey_version: [\"0.8.0\"]\n", "nodkey_version must be a version X.Y.Z"},
		{"older than installed", "broker", "0.8.1", "nodkey_version: \"0.8.0\"\n", "nodkey_version 0.8.0 is older than the installed nodkey 0.8.1"},
		{"older minor than installed", "agent", "0.10.0", "nodkey_version: \"0.9.9\"\n", "is older than the installed nodkey 0.10.0"},
		{"no version", "broker", "none", "nodkey_restart: true\n", "it has no nodkey_version"},
		{"a key twice", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_version: \"0.9.0\"\n", "the key nodkey_version is there twice"},
		{"not a map", "broker", "none", "- nodkey_version\n", "it must be a map of keys"},
		{"empty", "broker", "none", "", "it must be a map of keys"},
		{"not YAML", "broker", "none", "nodkey_version: [\n", "it is not valid YAML (line"},
		{"relative config path", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_broker_config: etc/broker.toml\n", "nodkey_broker_config must be the path of a file in /etc/nodkey/"},
		{"config path outside /etc/nodkey", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_broker_config: /root/secret.txt\n", "nodkey_broker_config must be the path of a file in /etc/nodkey/"},
		{"config path with ..", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_broker_config: /etc/nodkey/../shadow\n", "must not have . or .. in it"},
		{"a template", "agent", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_agent_user: \"{{ lookup('pipe', 'id') }}\"\n", "nodkey_ssh_agent_user must be the name of an account"},
		{"a template in the path", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_broker_config: \"/etc/nodkey/{{ x }}\"\n", "nodkey_broker_config must be the path"},
		{"user root", "agent", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_agent_user: root\n", "nodkey_ssh_agent_user must not be root"},
		{"user with a space", "agent", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_agent_user: \"a b\"\n", "nodkey_ssh_agent_user must be the name of an account"},
		{"SSH keys not a list", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: deploy\n", "nodkey_ssh_keys must be a list"},
		{"SSH key not a map", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [deploy]\n", "nodkey_ssh_keys, item 1 must be a map with a name"},
		{"SSH key without a name", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{type: ed25519}]\n", "item 1: the name must have 1 to 32 characters"},
		{"SSH key name with a capital", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: Deploy}]\n", "item 1: the name must have 1 to 32 characters"},
		{"SSH key name starts with -", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: -x}]\n", "the name must have 1 to 32 characters"},
		{"SSH key name with a dot", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: a.b}]\n", "the name must have 1 to 32 characters"},
		{"SSH key name with a slash", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: ../x}]\n", "the name must have 1 to 32 characters"},
		{"SSH key name too long", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: " + strings.Repeat("a", 33) + "}]\n", "the name must have 1 to 32 characters"},
		{"SSH key name a number", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: 7}]\n", "the name must have 1 to 32 characters"},
		{"SSH key name a template", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: \"{{ x }}\"}]\n", "the name must have 1 to 32 characters"},
		{"SSH key name twice", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: deploy}, {name: deploy, type: ecdsa-p256}]\n", "item 2: the name deploy is there twice"},
		{"SSH key unknown type", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: deploy, type: rsa}]\n", "item 1: the type must be one of ed25519, ecdsa-p256, ecdsa-p384, ecdsa-p521"},
		{"SSH key empty type", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: deploy, type: null}]\n", "item 1: the type must be one of"},
		{"SSH key unknown field", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: deploy, comment: x}]\n", "item 1 has the key comment"},
		{"too many SSH keys", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [" + strings.Repeat("{name: a},", 65) + "]\n", "has more than 64 keys"},
		{"SSH keys on the agent side", "agent", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: deploy}]\n", "the key nodkey_ssh_keys is not a key of the agent side"},
		{"wrong with_key", "broker", "none", "nodkey_version: \"0.8.0\"\nnodkey_ssh_key_with_key: tpm2\n", "nodkey_ssh_key_with_key must be auto, host or host+tpm2"},
		{"a Python tag", "broker", "none", "nodkey_version: !!python/object/apply:os.system [\"true\"]\n", "it is not valid YAML"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := checkData(t, c.text, "--side", c.side, "--installed", c.installed)
			if code != 1 || !strings.Contains(out, c.want) {
				t.Fatalf("exit %d, want 1 and %q; output:\n%s", code, c.want, out)
			}
			if !strings.HasSuffix(strings.TrimSpace(out), "(exit 1)") {
				t.Fatalf("the error does not end with (exit 1):\n%s", out)
			}
		})
	}
}

// The error never shows a value of the file, only the names of keys.
func TestCheckDataPrintsNoValue(t *testing.T) {
	const marker = "secret-looking-value-1234"
	for _, text := range []string{
		"nodkey_version: \"" + marker + "\"\n",
		"nodkey_version: \"0.8.0\"\nnodkey_restart: " + marker + "\n",
		"nodkey_version: \"0.8.0\"\nnodkey_broker_config: \"" + marker + "\"\n",
		"nodkey_version: [\"" + marker + "\"\n",
		"nodkey_version: \"0.8.0\"\n\"\\e[31m" + marker + "\\nx\": 1\n",
		"nodkey_version: \"0.8.0\"\n\"" + marker + " \": 1\n\"" + marker + " \": 2\n",
		"nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: \"" + marker + "X\"}]\n",
		"nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: a, type: \"" + marker + "\"}]\n",
		"nodkey_version: \"0.8.0\"\nnodkey_ssh_keys: [{name: a, \"" + marker + " \": 1}]\n",
		"nodkey_version: \"0.8.0\"\nnodkey_ssh_key_with_key: \"" + marker + "\"\n",
	} {
		code, out := checkData(t, text, "--side", "broker", "--installed", "none")
		if code != 1 || strings.Contains(out, marker) {
			t.Fatalf("exit %d, want 1 and no value in the output:\n%s", code, out)
		}
	}
}

func TestCheckDataUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--installed", "none"},
		{"--side", "both", "--installed", "none"},
		{"--side", "broker", "--installed", "latest"},
		{"--side", "broker", "--installed", "none", "--force"},
		{"--side", "broker"},
	} {
		code, out := checkData(t, "nodkey_version: \"0.8.0\"\n", args...)
		if code != 64 || strings.Count(strings.TrimSpace(out), "\n") != 0 || !strings.HasSuffix(strings.TrimSpace(out), "(exit 64)") {
			t.Fatalf("%v: exit %d, want 64 and one line; output:\n%s", args, code, out)
		}
	}
}

// build.sh copies the install.sh and the unit of the tag into the role,
// and pins their SHA-256 in vars/main.yml.
func TestAnsibleBuild(t *testing.T) {
	tag := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tag, "contrib", "systemd"), 0o750); err != nil {
		t.Fatal(err)
	}
	installSh := []byte("#!/bin/sh\necho the install.sh of the tag\n")
	unit := []byte("[Unit]\nDescription=the unit of the tag\n")
	if err := os.WriteFile(filepath.Join(tag, "install.sh"), installSh, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tag, "contrib", "systemd", "nodkey.service"), unit, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "recipe")
	if b, err := exec.CommandContext(context.Background(), "sh", "contrib/ansible/build.sh", "1.2.3", tag, out).CombinedOutput(); err != nil { //nolint:gosec // G204: the test's own script.
		t.Fatalf("build.sh: %v\n%s", err, b)
	}
	for _, f := range []string{"README.md", "LICENSE", "check-data", "playbooks/broker-host.yml", "playbooks/agent-host.yml", "roles/nodkey/tasks/main.yml"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("the recipe has no %s: %v", f, err)
		}
	}
	for name, want := range map[string][]byte{"install.sh": installSh, "nodkey.service": unit} {
		got, err := os.ReadFile(filepath.Join(out, "roles", "nodkey", "files", name)) //nolint:gosec // G304: the test's own file.
		if err != nil || string(got) != string(want) {
			t.Errorf("files/%s is not the file of the tag: %v", name, err)
		}
	}
	vars, err := os.ReadFile(filepath.Join(out, "roles", "nodkey", "vars", "main.yml")) //nolint:gosec // G304: the test's own file.
	if err != nil {
		t.Fatal(err)
	}
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	for _, line := range []string{
		`nodkey_role_version: "1.2.3"`,
		`nodkey_install_sh_sha256: "` + sum(installSh) + `"`,
		`nodkey_unit_sha256: "` + sum(unit) + `"`,
	} {
		if !strings.Contains(string(vars), line+"\n") {
			t.Errorf("vars/main.yml has no line %s:\n%s", line, vars)
		}
	}

	// The source of the role has no pins and no files of a tag.
	for _, f := range []string{"vars/main.yml", "files/install.sh", "files/nodkey.service"} {
		if _, err := os.Stat(filepath.Join("contrib", "ansible", "roles", "nodkey", f)); err == nil {
			t.Errorf("contrib/ansible/roles/nodkey/%s is in the repository; only build.sh makes it", f)
		}
	}
}

func TestAnsibleBuildRefuses(t *testing.T) {
	tag := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tag, "contrib", "systemd"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"install.sh", "contrib/systemd/nodkey.service"} {
		if err := os.WriteFile(filepath.Join(tag, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	there := t.TempDir()
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"bad version", []string{"1.2", tag, filepath.Join(t.TempDir(), "o")}, 64, `VERSION "1.2" is not X.Y.Z`},
		{"no tag dir", []string{"1.2.3", filepath.Join(t.TempDir(), "none"), filepath.Join(t.TempDir(), "o")}, 1, "install.sh is not there"},
		{"out exists", []string{"1.2.3", tag, there}, 1, "is there already"},
		{"too few", []string{"1.2.3"}, 64, "give VERSION, TAGDIR and OUTDIR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := exec.CommandContext(context.Background(), "sh", append([]string{"contrib/ansible/build.sh"}, c.args...)...).CombinedOutput() //nolint:gosec // G204: the test's own script.
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != c.code || !strings.Contains(string(b), c.want) {
				t.Fatalf("err %v, want exit %d and %q; output:\n%s", err, c.code, c.want, b)
			}
		})
	}
}
