package nodkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The tests of scripts/build-release.sh and scripts/release-check/ (the
// Release check workflow, docs/releasing.md). The checks themselves run
// in that workflow, with real releases; here are the parts that decide:
// the arguments, N-1 and N-2, and the changelog rules.

// runScript runs sh SCRIPT ARGS in dir with stdin, and returns the
// output and the exit code.
func runScript(t *testing.T, dir, stdin, script string, args ...string) (string, int) {
	t.Helper()
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "/bin/sh", append([]string{abs}, args...)...) //nolint:gosec // G204: the test runs a script of the repository.
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok { //nolint:errorlint // the error of Run is an *exec.ExitError or another.
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), code
}

func TestBuildReleaseRefuses(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dist")
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "give VERSION and OUT_DIR"},
		{"a v before the version", []string{"v1.2.3", out}, "is not X.Y.Z"},
		{"two parts", []string{"1.2", out}, "is not X.Y.Z"},
		{"a leading zero", []string{"01.2.3", out}, "is not X.Y.Z"},
		{"a second line", []string{"1.2.3\nx", out}, "line break"},
		{"an existing folder", []string{"1.2.3", t.TempDir()}, "exists already"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, code := runScript(t, ".", "", "scripts/build-release.sh", c.args...)
			if code != 1 || !strings.Contains(got, c.want) {
				t.Errorf("exit %d, output %q; want exit 1 and %q", code, got, c.want)
			}
		})
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("a refused build made %s", out)
	}
}

func TestPreviousReleases(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		skipOrFail(t, "jq is missing: %v", err)
	}
	const list = `[{"tag_name":"v0.9.0","draft":true,"prerelease":false,"published_at":null},
{"tag_name":"v0.8.1","draft":false,"prerelease":true,"published_at":"2026-01-02T00:00:00Z"},
{"tag_name":"v0.10.0","draft":false,"prerelease":false,"published_at":"2026-01-03T00:00:00Z"},
{"tag_name":"v0.2.0","draft":false,"prerelease":false,"published_at":"2026-01-01T00:00:00Z"}]
[{"tag_name":"v0.9.1","draft":false,"prerelease":false,"published_at":"2026-01-04T00:00:00Z"},
{"tag_name":"v0.12.0","draft":false,"prerelease":false,"published_at":"2026-01-05T00:00:00Z"},
{"tag_name":"v0.11.0-rc.1","draft":false,"prerelease":false,"published_at":"2026-01-05T00:00:00Z"},
{"tag_name":"0.10.5","draft":false,"prerelease":false,"published_at":"2026-01-05T00:00:00Z"}]`
	for _, c := range []struct {
		name, version, stdin, want string
		code                       int
	}{
		// A draft, a prerelease, a newer release and odd tags do not count;
		// 0.10.0 is above 0.9.1 (numbers, not text).
		{"two below", "0.11.0", list, "0.10.0 0.9.1\n", 0},
		{"one below", "0.9.0", list, "0.2.0\n", 0},
		{"the candidate is published already", "0.10.0", list, "0.9.1 0.2.0\n", 0},
		{"none below", "0.1.0", list, "no published release below 0.1.0", 1},
		{"no releases", "1.0.0", "[]", "no published release below 1.0.0", 1},
		{"a bad version", "v1.0.0", list, "is not X.Y.Z", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, code := runScript(t, ".", c.stdin, "scripts/release-check/previous.sh", c.version)
			if code != c.code || !strings.Contains(got, c.want) {
				t.Errorf("exit %d, output %q; want exit %d and %q", code, got, c.code, c.want)
			}
		})
	}
}

// changelogRepo makes a git repository with the tag v0.1.0, then the
// commits with the subjects, and CHANGELOG.md and docs/updating.md.
func changelogRepo(t *testing.T, notes, updating string, subjects ...string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // G204: git with the arguments of the test.
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %q: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	git("commit", "-q", "--allow-empty", "-m", "feat: the first release (#1)")
	git("tag", "v0.1.0")
	for _, s := range subjects {
		git("commit", "-q", "--allow-empty", "-m", s)
	}
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "CHANGELOG.md"), []byte("# Changelog\n\n## [0.2.0](https://example.com) (2026-01-02)\n\n"+notes+
		"\n## [0.1.0](https://example.com) (2026-01-01)\n\n* the first release ([#1](https://example.com/1))\n"), 0o600)
	writeFile(t, filepath.Join(dir, "docs", "updating.md"), []byte("# Updating nodkey\n\n"+updating), 0o600)
	git("add", "CHANGELOG.md", "docs/updating.md")
	git("commit", "-q", "-m", "chore(main): release 0.2.0")
	return dir
}

func TestChangelogCheck(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		skipOrFail(t, "git is missing: %v", err)
	}
	script, err := filepath.Abs("scripts/release-check/changelog.sh")
	if err != nil {
		t.Fatal(err)
	}
	const notes = "### Features\n\n* a feature ([#2](https://example.com/2))\n* a change ([#4](https://example.com/4))\n"
	const updating = "## Updating from 0.1.0\n\n**What changed (0.2.0, #4).** Something.\n"
	for _, c := range []struct {
		name     string
		notes    string
		updating string
		subjects []string
		want     string
		code     int
	}{
		{"all good", notes, updating,
			[]string{"feat: a feature (#2)", "ci: a hidden change (#3)", "feat(run)!: a change (#4)"}, "ok: #4 has its section", 0},
		{"a feature is missing in the notes", notes, updating,
			[]string{"feat: a feature (#2)", "fix: a fix (#5)"}, "FAILED: #5 (fix) is not in the notes of 0.2.0", 1},
		{"no section for a ! change", notes, "",
			[]string{"feat(run)!: a change (#4)"}, `has ! but docs/updating.md has no section "## Updating from 0.1.0"`, 1},
		{"the section does not name the change", notes, "## Updating from 0.1.0\n\nOther.\n",
			[]string{"feat(run)!: a change (#4)"}, "does not name #4", 1},
		{"a hidden type with !", notes, updating,
			[]string{"ci!: a hidden break (#6)"}, "FAILED: #6 has ! but is not in the notes", 1},
		{"a commit without a pull request", notes, updating,
			[]string{"feat: pushed to main"}, "has no (#N) at the end", 1},
		{"a subject that is not a Conventional Commit", "* x (#7)\n", updating,
			[]string{"Add a thing (#7)"}, "not a Conventional Commit title", 1},
		{"#2 does not count for #20", notes, updating,
			[]string{"feat: another feature (#20)"}, "FAILED: #20 (feat)", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := changelogRepo(t, c.notes, c.updating, c.subjects...)
			got, code := runScript(t, dir, "", script, "0.1.0", "0.2.0")
			if code != c.code || !strings.Contains(got, c.want) {
				t.Errorf("exit %d, output:\n%s\nwant exit %d and %q", code, got, c.code, c.want)
			}
		})
	}
	t.Run("no tag of N-1", func(t *testing.T) {
		dir := changelogRepo(t, notes, updating, "feat: a feature (#2)")
		got, code := runScript(t, dir, "", script, "0.0.9", "0.2.0")
		if code != 2 || !strings.Contains(got, "no tag v0.0.9") {
			t.Errorf("exit %d, output %q", code, got)
		}
	})
	t.Run("no section of the version", func(t *testing.T) {
		dir := changelogRepo(t, notes, updating, "feat: a feature (#2)")
		got, code := runScript(t, dir, "", script, "0.1.0", "0.3.0")
		if code != 2 || !strings.Contains(got, "no section for 0.3.0") {
			t.Errorf("exit %d, output %q", code, got)
		}
	})
}

func TestConfigsCheckRefusesAWrongCorpus(t *testing.T) {
	// Fake nodkeys: "old" accepts every config, "new" refuses every one.
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "old"), []byte("#!/bin/sh\nexit 0\n"), 0o700)
	writeFile(t, filepath.Join(bin, "new"), []byte("#!/bin/sh\nexit 1\n"), 0o700)
	corpus := t.TempDir()
	writeFile(t, filepath.Join(corpus, "ok-a.toml"), []byte("x = 1\n"), 0o600)
	writeFile(t, filepath.Join(corpus, "bad-b.toml"), []byte("x = 1\n"), 0o600)
	writeFile(t, filepath.Join(corpus, "c.toml"), []byte("x = 1\n"), 0o600)
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, code := runScript(t, ".", "", "scripts/release-check/configs.sh",
		filepath.Join(bin, "old"), filepath.Join(bin, "new"), corpus)
	for _, want := range []string{
		"FAILED: ok-a.toml: the old nodkey exits with 0, the new one with 1",
		"FAILED: bad-b.toml: the old nodkey exits with 0, want 1; fix the corpus",
		"FAILED: c.toml: the name must start with ok- or bad-",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the output has no %q:\n%s", want, got)
		}
	}
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if left, _ := filepath.Glob(filepath.Join(home, "nodkey-configs.*")); len(left) > 0 {
		t.Errorf("the check left %q", left)
	}
}

func TestFragmentRefusesAnUnknownResult(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.json")
	got, code := runScript(t, ".", "", "scripts/release-check/fragment.sh", "1 build", "maybe", "/nonexistent", out)
	if code != 2 || !strings.Contains(got, "RESULT must be pass, fail or report") {
		t.Errorf("exit %d, output %q", code, got)
	}
}

// recipeTarGz returns the pullgate recipe of contrib/pullgate as the
// release build makes it, with the version in the manifest, and edit
// applied to each file (name, data) first.
func recipeTarGz(t *testing.T, version string, edit func(name string, data []byte) []byte) []byte {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("contrib", "pullgate"))
	if err != nil {
		t.Fatal(err)
	}
	var files []tarFile
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		data := readFile(t, filepath.Join("contrib", "pullgate", e.Name()))
		if e.Name() == "pullgate-recipe.toml" {
			data = []byte(strings.Replace(string(data), "\nversion = \"0.0.0\"\n", "\nversion = \""+version+"\"\n", 1))
		}
		if edit != nil {
			data = edit(e.Name(), data)
		}
		files = append(files, tarFile{name: e.Name(), mode: int64(info.Mode().Perm() &^ 0o022), data: data})
	}
	return tarGz(t, files...)
}

// verifyFixture makes the files of a release 1.2.3 in a new folder, and
// fake gh, go and docker programs in another, for verify-release.sh. The
// nodkey of each tarball is a script that prints "nodkey 1.2.3"; the
// pullgate tarball is the recipe of contrib/pullgate.
type verifyFixture struct {
	dir, bin, commit string
	head             bool // run without NODKEY_VERIFY_COMMIT
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	f := &verifyFixture{dir: t.TempDir(), bin: t.TempDir(), commit: strings.Repeat("ab", 20)}
	nodkey := []byte("#!/bin/sh\necho \"nodkey ${FAKE_VERSION:-1.2.3}\"\n")
	var sums, subjects strings.Builder
	for _, kind := range []string{"ansible", "linux_amd64", "linux_arm64", "pullgate"} {
		name := "nodkey_1.2.3_" + kind + ".tar.gz"
		data := tarGz(t, tarFile{name: "nodkey", mode: 0o755, data: nodkey})
		if kind == "pullgate" {
			data = recipeTarGz(t, "1.2.3", nil)
		}
		writeFile(t, filepath.Join(f.dir, name), data, 0o600)
		sum := sha256.Sum256(data)
		fmt.Fprintf(&sums, "%x  %s\n", sum, name)
		if subjects.Len() > 0 {
			subjects.WriteString(",")
		}
		fmt.Fprintf(&subjects, `{"name":%q,"digest":{"sha256":"%x"}}`, name, sum)
	}
	writeFile(t, filepath.Join(f.dir, "SHA256SUMS"), []byte(sums.String()), 0o600)
	payload := base64.StdEncoding.EncodeToString([]byte(`{"subject":[` + subjects.String() + `]}`))
	writeFile(t, filepath.Join(f.dir, "nodkey_1.2.3.sigstore.json"), []byte(`{"dsseEnvelope":{"payload":"`+payload+`"}}`), 0o600)
	writeFile(t, filepath.Join(f.dir, "nodkey_1.2.3_pullgate.sigstore.json"), []byte(`{"dsseEnvelope":{"payload":"`+payload+`"}}`), 0o600)
	writeFile(t, filepath.Join(f.bin, "gh"), []byte("#!/bin/sh\n[ ! -e \"$FAKE_FAIL/gh\" ]\n"), 0o700)
	// go version -m: the arch is in the name of the folder of the binary.
	writeFile(t, filepath.Join(f.bin, "go"), []byte(`#!/bin/sh
arch=$(basename "$(dirname "$3")")
printf '%s\n\tmod\tgithub.com/code6x/nodkey\tv1.2.3\t\n\tbuild\tGOARCH=%s\n\tbuild\tvcs.revision=%s\n\tbuild\tvcs.modified=false\n' "$3" "$arch" "$(cat "$FAKE_FAIL/../commit")"
`), 0o700)
	writeFile(t, filepath.Join(f.bin, "docker"), []byte("#!/bin/sh\n[ ! -e \"$FAKE_FAIL/docker\" ] || exit 1\necho \"nodkey ${FAKE_DOCKER_VERSION:-1.2.3}\"\n"), 0o700)
	return f
}

// setPullgate puts data as the pullgate tarball, with its SHA-256 in
// SHA256SUMS and in the bundles, so that only the recipe check sees it.
func (f *verifyFixture) setPullgate(t *testing.T, data []byte) {
	t.Helper()
	name := "nodkey_1.2.3_pullgate.tar.gz"
	old := sha256.Sum256(readFile(t, filepath.Join(f.dir, name)))
	sum := sha256.Sum256(data)
	writeFile(t, filepath.Join(f.dir, name), data, 0o600)
	p := filepath.Join(f.dir, "SHA256SUMS")
	writeFile(t, p, []byte(strings.Replace(string(readFile(t, p)), fmt.Sprintf("%x", old), fmt.Sprintf("%x", sum), 1)), 0o600)
	for _, b := range []string{"nodkey_1.2.3.sigstore.json", "nodkey_1.2.3_pullgate.sigstore.json"} {
		p := filepath.Join(f.dir, b)
		var env struct {
			DSSE struct {
				Payload string `json:"payload"`
			} `json:"dsseEnvelope"`
		}
		if err := json.Unmarshal(readFile(t, p), &env); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(env.DSSE.Payload)
		if err != nil {
			t.Fatal(err)
		}
		payload := base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), fmt.Sprintf("%x", old), fmt.Sprintf("%x", sum), 1)))
		writeFile(t, p, []byte(`{"dsseEnvelope":{"payload":"`+payload+`"}}`), 0o600)
	}
}

// run runs verify-release.sh with the fakes first in PATH.
func (f *verifyFixture) run(t *testing.T, fail ...string) (string, int) {
	t.Helper()
	state := t.TempDir()
	failDir := filepath.Join(state, "fail")
	mkdir(t, failDir, 0o700)
	writeFile(t, filepath.Join(state, "commit"), []byte(f.commit), 0o600)
	for _, name := range fail {
		writeFile(t, filepath.Join(failDir, name), nil, 0o600)
	}
	gh := filepath.Join(t.TempDir(), "gh.tar.gz")
	writeFile(t, gh, []byte("gh"), 0o600)
	t.Setenv("PATH", f.bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_FAIL", failDir)
	t.Setenv("NODKEY_VERIFY_COMMIT", strings.Repeat("ab", 20))
	if f.head {
		// The script then takes the commit of HEAD.
		if err := os.Unsetenv("NODKEY_VERIFY_COMMIT"); err != nil {
			t.Fatal(err)
		}
	}
	return runScript(t, ".", "", "scripts/verify-release.sh", f.dir, "1.2.3", gh)
}

func TestVerifyRelease(t *testing.T) {
	for _, p := range []string{"jq", "openssl", "base64"} {
		if _, err := exec.LookPath(p); err != nil {
			skipOrFail(t, "%s is missing: %v", p, err)
		}
	}
	t.Run("the default commit is HEAD", func(t *testing.T) {
		head, err := exec.CommandContext(t.Context(), "git", "rev-parse", "HEAD").Output()
		if err != nil {
			skipOrFail(t, "git rev-parse HEAD: %v", err)
		}
		f := newVerifyFixture(t)
		f.commit, f.head = strings.TrimSpace(string(head)), true
		got, code := f.run(t)
		if code != 0 || !strings.Contains(got, "commit "+f.commit) {
			t.Errorf("exit %d, output:\n%s", code, got)
		}
	})
	t.Run("an older release has no recipe", func(t *testing.T) {
		// The dry run of a release before the recipe: no pullgate_recipe,
		// no second bundle, and a pullgate tarball that is no recipe.
		f := newVerifyFixture(t)
		f.setPullgate(t, tarGz(t, tarFile{name: "apply.sh", mode: 0o755, data: []byte("#!/bin/sh\n")}))
		if err := os.Remove(filepath.Join(f.dir, "nodkey_1.2.3_pullgate.sigstore.json")); err != nil {
			t.Fatal(err)
		}
		t.Setenv("NODKEY_VERIFY_KINDS", "ansible linux_amd64 linux_arm64 pullgate")
		got, code := f.run(t)
		if code != 0 || strings.Contains(got, "FAILED") || strings.Count(got, "ok: ") != 7 {
			t.Errorf("exit %d, output:\n%s", code, got)
		}
	})
	t.Run("good files pass", func(t *testing.T) {
		got, code := newVerifyFixture(t).run(t)
		if code != 0 || strings.Contains(got, "FAILED") || strings.Count(got, "ok: ") != 9 {
			t.Errorf("exit %d, output:\n%s", code, got)
		}
	})
	for _, c := range []struct {
		name   string
		change func(t *testing.T, f *verifyFixture) []string // returns the fakes that fail
		want   string
	}{
		{"an extra file", func(t *testing.T, f *verifyFixture) []string {
			writeFile(t, filepath.Join(f.dir, "extra.txt"), nil, 0o600)
			return nil
		}, "FAILED: 1 the files of the draft are not the expected ones"},
		{"a missing file", func(t *testing.T, f *verifyFixture) []string {
			if err := os.Remove(filepath.Join(f.dir, "nodkey_1.2.3_pullgate.tar.gz")); err != nil {
				t.Fatal(err)
			}
			return nil
		}, "FAILED: 1 the files"},
		{"a changed tarball", func(t *testing.T, f *verifyFixture) []string {
			p := filepath.Join(f.dir, "nodkey_1.2.3_pullgate.tar.gz")
			writeFile(t, p, append(readFile(t, p), 'x'), 0o600)
			return nil
		}, "FAILED: 2 a tarball does not match SHA256SUMS"},
		{"SHA256SUMS without a tarball", func(t *testing.T, f *verifyFixture) []string {
			p := filepath.Join(f.dir, "SHA256SUMS")
			lines := strings.SplitAfter(string(readFile(t, p)), "\n")
			writeFile(t, p, []byte(strings.Join(lines[1:], "")), 0o600)
			return nil
		}, "FAILED: 2 SHA256SUMS does not name each tarball exactly once"},
		{"the attestation fails", func(*testing.T, *verifyFixture) []string { return []string{"gh"} },
			"FAILED: 3 the attestation does not verify"},
		{"the bundle names other files", func(t *testing.T, f *verifyFixture) []string {
			payload := base64.StdEncoding.EncodeToString([]byte(`{"subject":[{"name":"other.tar.gz","digest":{"sha256":"00"}}]}`))
			writeFile(t, filepath.Join(f.dir, "nodkey_1.2.3.sigstore.json"), []byte(`{"dsseEnvelope":{"payload":"`+payload+`"}}`), 0o600)
			return nil
		}, "FAILED: 3 the bundle does not name exactly the tarballs"},
		{"a binary of another commit", func(_ *testing.T, f *verifyFixture) []string {
			f.commit = strings.Repeat("cd", 20)
			return nil
		}, "FAILED: 4 nodkey_1.2.3_linux_amd64.tar.gz: the build info does not say"},
		{"the install fails", func(*testing.T, *verifyFixture) []string { return []string{"docker"} },
			"FAILED: 5 install.sh does not install"},
		{"the install gives another version", func(t *testing.T, _ *verifyFixture) []string {
			t.Setenv("FAKE_DOCKER_VERSION", "1.2.4")
			return nil
		}, "FAILED: 5 install.sh does not install"},
		{"no bundle for the recipe", func(t *testing.T, f *verifyFixture) []string {
			if err := os.Remove(filepath.Join(f.dir, "nodkey_1.2.3_pullgate.sigstore.json")); err != nil {
				t.Fatal(err)
			}
			return nil
		}, "FAILED: 6 nodkey_1.2.3_pullgate.sigstore.json is missing, or is not the same file"},
		{"another bundle for the recipe", func(t *testing.T, f *verifyFixture) []string {
			writeFile(t, filepath.Join(f.dir, "nodkey_1.2.3_pullgate.sigstore.json"), []byte("{}"), 0o600)
			return nil
		}, "FAILED: 6 nodkey_1.2.3_pullgate.sigstore.json is missing, or is not the same file"},
		{"a recipe of another version", func(t *testing.T, f *verifyFixture) []string {
			f.setPullgate(t, recipeTarGz(t, "1.2.2", nil))
			return nil
		}, "FAILED: 6 the pullgate tarball is not a good recipe: FAILED: recipe: pullgate-recipe.toml: version is '1.2.2', not '1.2.3'"},
		{"a template that sets the mode", func(t *testing.T, f *verifyFixture) []string {
			f.setPullgate(t, recipeTarGz(t, "1.2.3", func(name string, data []byte) []byte {
				if name == "nodkey-host.toml.in" {
					return append([]byte("mode = \"auto\"\n"), data...)
				}
				return data
			}))
			return nil
		}, "nodkey-host.toml.in sets mode, which pullgate sets itself"},
		{"a template that names a missing program", func(t *testing.T, f *verifyFixture) []string {
			f.setPullgate(t, recipeTarGz(t, "1.2.3", func(name string, data []byte) []byte {
				return []byte(strings.ReplaceAll(string(data), "@RECIPE_DIR@/host-check.sh", "@RECIPE_DIR@/no-such.sh"))
			}))
			return nil
		}, "names @RECIPE_DIR@/no-such.sh, which is not a program of the tarball"},
		{"the amd64 binary says another version", func(t *testing.T, _ *verifyFixture) []string {
			t.Setenv("FAKE_VERSION", "1.2.4")
			return nil
		}, "FAILED: 4 the amd64 binary says 'nodkey 1.2.4'"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newVerifyFixture(t)
			got, code := f.run(t, c.change(t, f)...)
			if code != 1 || !strings.Contains(got, c.want) {
				t.Errorf("exit %d, output:\n%s\nwant exit 1 and %q", code, got, c.want)
			}
		})
	}
	for _, c := range []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"a bad version", nil, []string{"v1.2.3"}, "is not X.Y.Z"},
		{"a bad commit", []string{"NODKEY_VERIFY_COMMIT=abc"}, nil, "is not a full SHA-1"},
		{"an unknown kind", []string{"NODKEY_VERIFY_KINDS=linux_amd64 windows"}, nil, "unknown kind 'windows'"},
		{"no amd64", []string{"NODKEY_VERIFY_KINDS=pullgate"}, nil, "must have linux_amd64"},
		{"a recipe without its tarball", []string{"NODKEY_VERIFY_KINDS=linux_amd64 pullgate_recipe"}, nil, "pullgate_recipe needs pullgate"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newVerifyFixture(t)
			gh := filepath.Join(t.TempDir(), "gh.tar.gz")
			writeFile(t, gh, []byte("gh"), 0o600)
			args := []string{f.dir, "1.2.3", gh}
			if c.args != nil {
				args[1] = c.args[0]
			}
			t.Setenv("NODKEY_VERIFY_COMMIT", strings.Repeat("ab", 20))
			for _, kv := range c.env {
				k, v, _ := strings.Cut(kv, "=")
				t.Setenv(k, v)
			}
			got, code := runScript(t, ".", "", "scripts/verify-release.sh", args...)
			if code != 2 || !strings.Contains(got, c.want) {
				t.Errorf("exit %d, output %q; want exit 2 and %q", code, got, c.want)
			}
		})
	}
}
