package nodkey

import (
	"bytes"
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
