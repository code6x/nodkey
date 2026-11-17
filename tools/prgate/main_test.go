package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func newPR(title, body string) pullRequest {
	var pr pullRequest
	pr.Title = title
	pr.Body = body
	pr.User.Login = "someone"
	pr.User.Type = "User"
	pr.Head.Ref = "feature"
	return pr
}

const (
	bodyNo  = "Fixes #1\n\nChanges behavior for existing callers: no\n"
	bodyYes = "Fixes #1\n\nChanges behavior for existing callers: yes\n"
)

var (
	codeFile     = changedFile{Filename: "internal/client/run.go", Patch: ptr("@@ -1 +1 @@\n-a\n+b")}
	updatingNote = changedFile{Filename: "docs/updating.md", Patch: ptr("@@ -1,2 +1,8 @@\n # Updating nodkey\n \n+## Updating from 0.7.0 or older\n+\n+Who is affected: ...")}
	contractFile = changedFile{Filename: "test/contract/pipe_test.go", Patch: ptr("@@ -1 +1 @@\n-a\n+b")}
)

func TestCheck(t *testing.T) {
	type tc struct {
		name   string
		pr     pullRequest
		files  []changedFile
		pass   bool
		reason string // a part of the problem, for a fail
	}
	tests := []tc{
		// Pass.
		{name: "no", pr: newPR("fix: a bug", bodyNo), files: []changedFile{codeFile}, pass: true},
		{name: "yes with ! and note", pr: newPR("feat(run)!: new default", bodyYes), files: []changedFile{codeFile, updatingNote}, pass: true},
		{name: "yes without scope", pr: newPR("feat!: new default", bodyYes), files: []changedFile{updatingNote}, pass: true},
		{name: "contract change with yes", pr: newPR("test!: pin the pipe", bodyYes), files: []changedFile{contractFile, updatingNote}, pass: true},
		{name: "CRLF body", pr: newPR("fix: a bug", "a\r\nChanges behavior for existing callers: no\r\nb"), files: []changedFile{codeFile}, pass: true},
		{name: "spaces around answer", pr: newPR("fix: a bug", "  Changes behavior for existing callers:   no  \n"), files: []changedFile{codeFile}, pass: true},
		{name: "line in a comment is ignored", pr: newPR("fix: a bug", "<!-- Changes behavior for existing callers: yes -->\nChanges behavior for existing callers: no"), files: []changedFile{codeFile}, pass: true},

		// Fail: the line is missing or has another value.
		{name: "empty body", pr: newPR("fix: a bug", ""), files: []changedFile{codeFile}, reason: "has no line"},
		{name: "missing", pr: newPR("fix: a bug", "Fixes #1"), files: []changedFile{codeFile}, reason: "has no line"},
		{name: "only in a comment", pr: newPR("fix: a bug", "<!--\nChanges behavior for existing callers: no\n-->"), files: []changedFile{codeFile}, reason: "has no line"},
		{name: "only in an open comment", pr: newPR("fix: a bug", "<!--\nChanges behavior for existing callers: no\n"), files: []changedFile{codeFile}, reason: "has no line"},
		{name: "template placeholder", pr: newPR("fix: a bug", "Changes behavior for existing callers: yes or no"), files: []changedFile{codeFile}, reason: `must end in "yes" or "no"`},
		{name: "empty answer", pr: newPR("fix: a bug", "Changes behavior for existing callers:"), files: []changedFile{codeFile}, reason: `must end in "yes" or "no"`},
		{name: "capital No", pr: newPR("fix: a bug", "Changes behavior for existing callers: No"), files: []changedFile{codeFile}, reason: `must end in "yes" or "no"`},
		{name: "bold no", pr: newPR("fix: a bug", "Changes behavior for existing callers: **no**"), files: []changedFile{codeFile}, reason: `must end in "yes" or "no"`},
		{name: "no with more text", pr: newPR("fix: a bug", "Changes behavior for existing callers: no, I think"), files: []changedFile{codeFile}, reason: `must end in "yes" or "no"`},
		{name: "twice", pr: newPR("fix: a bug", bodyNo+bodyYes), files: []changedFile{codeFile}, reason: "more than once"},
		{name: "twice the same", pr: newPR("fix: a bug", bodyNo+bodyNo), files: []changedFile{codeFile}, reason: "more than once"},
		{name: "in a list item", pr: newPR("fix: a bug", "- Changes behavior for existing callers: no"), files: []changedFile{codeFile}, reason: "has no line"},

		// Fail: yes without "!" or without a note.
		{name: "yes without !", pr: newPR("feat(run): new default", bodyYes), files: []changedFile{codeFile, updatingNote}, reason: `has no "!"`},
		{name: "yes with ! in the text only", pr: newPR("feat: new default!: really", bodyYes), files: []changedFile{updatingNote}, reason: `has no "!"`},
		{name: "yes with ! before the scope", pr: newPR("feat!(run): new default", bodyYes), files: []changedFile{updatingNote}, reason: `has no "!"`},
		{name: "yes without docs/updating.md", pr: newPR("feat!: new default", bodyYes), files: []changedFile{codeFile}, reason: "adds no"},
		{name: "yes with a note that is not added", pr: newPR("feat!: new default", bodyYes), files: []changedFile{{Filename: "docs/updating.md", Patch: ptr("@@ -1,3 +1,3 @@\n ## Updating from 0.5.0 or older\n-old\n+new")}}, reason: "adds no"},
		{name: "yes with a removed note", pr: newPR("feat!: new default", bodyYes), files: []changedFile{{Filename: "docs/updating.md", Patch: ptr("@@ -1,3 +1,1 @@\n-## Updating from 0.5.0 or older\n x")}}, reason: "adds no"},
		{name: "yes with a level 3 heading", pr: newPR("feat!: new default", bodyYes), files: []changedFile{{Filename: "docs/updating.md", Patch: ptr("@@ -1 +1,2 @@\n x\n+### Updating from 0.7.0")}}, reason: "adds no"},
		{name: "yes with the note in another file", pr: newPR("feat!: new default", bodyYes), files: []changedFile{{Filename: "docs/setup.md", Patch: ptr("@@ -1 +1,2 @@\n x\n+## Updating from 0.7.0")}}, reason: "adds no"},
		{name: "yes with no patch from GitHub", pr: newPR("feat!: new default", bodyYes), files: []changedFile{{Filename: "docs/updating.md"}}, reason: "sent no diff"},
		{name: "yes without both", pr: newPR("feat: new default", bodyYes), files: []changedFile{codeFile}, reason: `has no "!"`},

		// Fail: "!" with no.
		{name: "! with no", pr: newPR("feat(run)!: new default", bodyNo), files: []changedFile{codeFile, updatingNote}, reason: `the answer is "no"`},

		// Fail: a contract test changes and the answer is no.
		{name: "contract change with no", pr: newPR("test: pin the pipe", bodyNo), files: []changedFile{codeFile, contractFile}, reason: "under test/contract/"},
		{name: "contract file renamed away with no", pr: newPR("test: move", bodyNo), files: []changedFile{{Filename: "test/other/pipe_test.go", PreviousFilename: "test/contract/pipe_test.go"}}, reason: "under test/contract/"},
		{name: "contract README with no", pr: newPR("docs: fix a word", bodyNo), files: []changedFile{{Filename: "test/contract/README.md"}}, reason: "under test/contract/"},
	}

	// Bots.
	release := newPR("chore(main): release 0.8.0", "generated text")
	release.User.Login, release.User.Type, release.Head.Ref = releaseBot, "Bot", releaseBranch
	releaseFilesOK := []changedFile{{Filename: "CHANGELOG.md"}, {Filename: ".release-please-manifest.json"}}
	tests = append(tests, tc{name: "release pull request", pr: release, files: releaseFilesOK, pass: true})
	tests = append(tests, tc{name: "release pull request with another file", pr: release, files: append([]changedFile{codeFile}, releaseFilesOK...), reason: "has no line"})
	tests = append(tests, tc{name: "release pull request with no files", pr: release, reason: "has no line"})
	tests = append(tests, tc{name: "release pull request with a renamed file", pr: release, files: []changedFile{{Filename: "CHANGELOG.md", PreviousFilename: "install.sh"}}, reason: "has no line"})
	otherBranch := release
	otherBranch.Head.Ref = "release-please--branches--other"
	tests = append(tests, tc{name: "release bot on another branch", pr: otherBranch, files: releaseFilesOK, reason: "has no line"})
	notBot := release
	notBot.User.Type = "User"
	tests = append(tests, tc{name: "release login that is not a bot", pr: notBot, files: releaseFilesOK, reason: "has no line"})

	dep := newPR("chore(deps): bump a module", "generated text")
	dep.User.Login, dep.User.Type = dependabotBot, "Bot"
	tests = append(tests, tc{name: "dependabot", pr: dep, files: []changedFile{{Filename: "go.mod"}, {Filename: "go.sum"}}, pass: true})
	tests = append(tests, tc{name: "dependabot in test/contract", pr: dep, files: []changedFile{contractFile}, reason: "has no line"})
	tests = append(tests, tc{name: "dependabot actions and image", pr: dep, files: []changedFile{{Filename: ".github/workflows/ci.yml"}, {Filename: "test/e2e/testdata/sshd/Dockerfile"}}, pass: true})
	tests = append(tests, tc{name: "dependabot with code", pr: dep, files: []changedFile{{Filename: "go.mod"}, codeFile}, reason: "has no line"})
	tests = append(tests, tc{name: "dependabot with no files", pr: dep, reason: "has no line"})
	tests = append(tests, tc{name: "dependabot rename from code", pr: dep, files: []changedFile{{Filename: "go.sum", PreviousFilename: "install.sh"}}, reason: "has no line"})
	depBreaking := dep
	depBreaking.Title = "feat(deps)!: bump a module"
	tests = append(tests, tc{name: "dependabot with !", pr: depBreaking, files: []changedFile{{Filename: "go.mod"}}, reason: "has no line"})
	depUser := dep
	depUser.User.Type = "User"
	tests = append(tests, tc{name: "dependabot login that is not a bot", pr: depUser, files: []changedFile{{Filename: "go.mod"}}, reason: "has no line"})
	otherBot := dep
	otherBot.User.Login = "other[bot]"
	tests = append(tests, tc{name: "another bot", pr: otherBot, files: []changedFile{{Filename: "go.mod"}}, reason: "has no line"})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			note, problems := check(tt.pr, tt.files)
			if tt.pass {
				if len(problems) > 0 || note == "" {
					t.Fatalf("want a pass, got problems %q", problems)
				}
				return
			}
			if len(problems) == 0 {
				t.Fatalf("want a fail with %q, got a pass: %s", tt.reason, note)
			}
			if note != "" {
				t.Errorf("a fail has the note %q", note)
			}
			found := false
			for _, p := range problems {
				if strings.Contains(p, tt.reason) {
					found = true
				}
				// Every problem says how to fix it.
				if !strings.Contains(p, ":") {
					t.Errorf("problem %q says no fix", p)
				}
			}
			if !found {
				t.Errorf("problems %q, want one with %q", problems, tt.reason)
			}
		})
	}
}

// TestCheckYesReportsBothProblems: a "yes" with no "!" and no note gets
// both problems, so the author fixes both at once.
func TestCheckYesReportsBothProblems(t *testing.T) {
	_, problems := check(newPR("feat: x", bodyYes), []changedFile{codeFile})
	if len(problems) != 2 {
		t.Fatalf("got %d problems, want 2: %q", len(problems), problems)
	}
}

// TestProblemsQuoteNoText: no problem repeats text of the pull request.
// A line such as "::stop-commands::" in the log is a command to the
// runner.
func TestProblemsQuoteNoText(t *testing.T) {
	const evil = "::error::EVIL-MARKER"
	cases := []pullRequest{
		newPR("feat: "+evil, "Changes behavior for existing callers: "+evil),
		newPR("feat: "+evil, "Changes behavior for existing callers: yes\n"+evil),
		newPR("feat!: "+evil, "Changes behavior for existing callers: no\n"+evil),
	}
	files := []changedFile{{Filename: "test/contract/" + evil, Patch: ptr("+" + evil)}}
	for _, pr := range cases {
		note, problems := check(pr, files)
		for _, s := range append(problems, note) {
			if strings.Contains(s, "EVIL-MARKER") {
				t.Errorf("output quotes the pull request: %q", s)
			}
		}
	}
}

// TestTemplate: the template has the line once, with a placeholder that
// fails until the author answers, and passes with a real answer.
func TestTemplate(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "pull_request_template.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if _, problems := check(newPR("fix: x", body), []changedFile{codeFile}); len(problems) == 0 {
		t.Fatal("the template passes as it is; it must fail until the author answers")
	}
	for _, answer := range []string{"yes", "no"} {
		filled := strings.Replace(body, answerPrefix+" yes or no", answerPrefix+" "+answer, 1)
		if filled == body {
			t.Fatal("the template has no line with the placeholder \"yes or no\"")
		}
		got, problem := parseAnswer(filled)
		if problem != "" || got != answer {
			t.Errorf("template with %q: got %q, problem %q", answer, got, problem)
		}
	}
}

// TestUpdatingDoc: every second-level section of docs/updating.md is an
// "Updating from X" note, so the gate's pattern matches what the doc uses.
func TestUpdatingDoc(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "updating.md"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	inCode := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
		}
		if inCode || !strings.HasPrefix(line, "## ") {
			continue
		}
		n++
		if !updatingHead.MatchString(line) {
			t.Errorf("docs/updating.md: section %q must start with \"## Updating from \"", line)
		}
	}
	if n == 0 {
		t.Error("docs/updating.md has no \"## Updating from X\" section")
	}
}

func writeRun(t *testing.T, event any, files string, args ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	ev := filepath.Join(dir, "event.json")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ev, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fl := filepath.Join(dir, "files.jsonl")
	if err := os.WriteFile(fl, []byte(files), 0o600); err != nil {
		t.Fatal(err)
	}
	if args == nil {
		args = []string{"--event", ev, "--files", fl}
	}
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func event(title, body string, changed int) map[string]any {
	return map[string]any{"pull_request": map[string]any{
		"title": title, "body": body, "changed_files": changed,
		"user": map[string]any{"login": "someone", "type": "User"},
		"head": map[string]any{"ref": "feature"},
	}}
}

const filesJSONL = `{"filename":"internal/client/run.go","previous_filename":null,"patch":"@@ -1 +1 @@\n-a\n+b"}
{"filename":"docs/updating.md","previous_filename":null,"patch":"@@ -1 +1,2 @@\n x\n+## Updating from 0.7.0"}
`

func TestRun(t *testing.T) {
	code, out, errOut := writeRun(t, event("feat(run)!: x", bodyYes, 2), filesJSONL)
	if code != exitOK || !strings.Contains(out, "ok") || errOut != "" {
		t.Errorf("yes: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	code, _, errOut = writeRun(t, event("feat(run): x", bodyYes, 2), filesJSONL)
	if code != exitFail || !strings.Contains(errOut, `has no "!"`) || !strings.Contains(errOut, "docs/releasing.md") {
		t.Errorf("yes without !: exit %d, stderr %q", code, errOut)
	}
	// Fewer files than GitHub says: fail closed.
	code, _, errOut = writeRun(t, event("feat(run)!: x", bodyYes, 3), filesJSONL)
	if code != exitFail || !strings.Contains(errOut, "listed 2") {
		t.Errorf("missing files: exit %d, stderr %q", code, errOut)
	}
	code, _, _ = writeRun(t, event("fix: x", bodyNo, 0), "")
	if code != exitOK {
		t.Errorf("no files: exit %d", code)
	}
	for name, files := range map[string]string{
		"bad JSON":    "{",
		"no filename": `{"patch":"x"}`,
		"wrong type":  `{"filename":3}`,
	} {
		code, _, errOut = writeRun(t, event("fix: x", bodyNo, 1), files)
		if code != exitUsage || !strings.HasSuffix(errOut, "(exit 2)\n") {
			t.Errorf("%s: exit %d, stderr %q", name, code, errOut)
		}
	}
	code, _, errOut = writeRun(t, map[string]any{"issue": map[string]any{}}, "")
	if code != exitUsage || !strings.Contains(errOut, "no pull_request") {
		t.Errorf("no pull_request: exit %d, stderr %q", code, errOut)
	}
	code, _, errOut = writeRun(t, event("fix: x", bodyNo, 0), "", "--event", "x")
	if code != exitUsage || strings.Count(errOut, "\n") != 1 {
		t.Errorf("usage: exit %d, stderr %q", code, errOut)
	}
	code, _, _ = writeRun(t, event("fix: x", bodyNo, 0), "", "--event", "/nonexistent/event.json", "--files", "/nonexistent/files")
	if code != exitUsage {
		t.Errorf("missing event file: exit %d", code)
	}
}
