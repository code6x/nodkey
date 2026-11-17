// Command prgate is the behavior-change gate for pull requests (issue
// #197, docs/releasing.md "Changes in behavior for callers").
//
// Every pull request body has the line
//
//	Changes behavior for existing callers: yes
//
// or the same line with "no". prgate fails when:
//   - the line is missing, is there more than once, or has another value;
//   - the answer is "yes" and the title has no "!" (such as "feat(run)!: ...");
//   - the answer is "yes" and the pull request adds no "## Updating from X"
//     section to docs/updating.md;
//   - the answer is "no" and the title has a "!";
//   - the pull request changes a file under test/contract/ and the answer
//     is "no".
//
// The workflow runs prgate from main, never from the pull request. prgate
// reads only the event file of GitHub (title, body, author, branch name,
// number of changed files) and the list of changed files from the GitHub
// API (names, and the added lines of docs/updating.md as text). It never
// prints the title, the body or a file name: the author chose that text,
// and a line such as "::stop-commands::" in the log is a command to the
// runner.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2

	answerPrefix = "Changes behavior for existing callers:"
	contractDir  = "test/contract/"
	updatingFile = "docs/updating.md"

	// The release pull request of release-please only collects commits
	// that passed this gate one by one.
	releaseBot    = "code6x-release[bot]"
	releaseBranch = "release-please--branches--main"
	dependabotBot = "dependabot[bot]"
)

// The files that a release pull request may change.
var releaseFiles = map[string]bool{
	"CHANGELOG.md":                  true,
	".release-please-manifest.json": true,
}

// The files that Dependabot changes for this repository
// (.github/dependabot.yml): Go modules, GitHub Actions and the image of
// the end-to-end test.
func dependabotFile(name string) bool {
	return name == "go.mod" || name == "go.sum" ||
		strings.HasPrefix(name, ".github/workflows/") ||
		strings.HasPrefix(name, "test/e2e/testdata/sshd/")
}

var (
	// A Conventional Commits title of a breaking change: "feat!: ..." or
	// "feat(run)!: ...". Only these forms make release-please list the
	// commit under "⚠ BREAKING CHANGES".
	breakingTitle = regexp.MustCompile(`^[a-z]+(\([^()\r\n]*\))?!: `)
	answerLine    = regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(answerPrefix) + `[ \t]*(.*?)[ \t]*$`)
	htmlComment   = regexp.MustCompile(`(?s)<!--.*?(-->|\z)`)
	updatingHead  = regexp.MustCompile(`^## Updating from \S`)
)

// pullRequest is what prgate reads from the event of GitHub.
type pullRequest struct {
	Title        string `json:"title"`
	Body         string `json:"body"`
	ChangedFiles int    `json:"changed_files"`
	User         struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
	Head struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

// changedFile is one entry of GET /repos/{owner}/{repo}/pulls/{n}/files.
type changedFile struct {
	Filename         string  `json:"filename"`
	PreviousFilename string  `json:"previous_filename"`
	Patch            *string `json:"patch"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("prgate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	eventPath := fs.String("event", "", "")
	filesPath := fs.String("files", "", "")
	if err := fs.Parse(args); err != nil || *eventPath == "" || *filesPath == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, `prgate: give --event FILE (the GitHub event) and --files FILE (JSON lines of the changed files); see .github/workflows/pr-title.yml (exit 2)`)
		return exitUsage
	}
	pr, err := readEvent(*eventPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "prgate: %v (exit 2)\n", err)
		return exitUsage
	}
	files, err := readFiles(*filesPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "prgate: %v (exit 2)\n", err)
		return exitUsage
	}
	if len(files) != pr.ChangedFiles {
		_, _ = fmt.Fprintf(stderr, "prgate: the pull request changes %d files, but the GitHub API listed %d; GitHub lists at most 3000. Split the pull request, or push again to run the check again (exit 1)\n",
			pr.ChangedFiles, len(files))
		return exitFail
	}
	note, problems := check(pr, files)
	if len(problems) > 0 {
		for _, p := range problems {
			_, _ = fmt.Fprintf(stderr, "prgate: %s\n", p)
		}
		_, _ = fmt.Fprintln(stderr, `prgate: see docs/releasing.md, "Changes in behavior for callers" (exit 1)`)
		return exitFail
	}
	_, _ = fmt.Fprintf(stdout, "prgate: ok: %s\n", note)
	return exitOK
}

func readEvent(path string) (pullRequest, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the event file that GitHub names in GITHUB_EVENT_PATH.
	if err != nil {
		return pullRequest{}, fmt.Errorf("cannot read the event file: %w; the workflow must pass GITHUB_EVENT_PATH", err)
	}
	var event struct {
		PullRequest *pullRequest `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return pullRequest{}, fmt.Errorf("the event file is not valid JSON: %w; run the check only on pull_request_target events", err)
	}
	if event.PullRequest == nil {
		return pullRequest{}, errors.New("the event file has no pull_request; run the check only on pull_request_target events")
	}
	return *event.PullRequest, nil
}

func readFiles(path string) ([]changedFile, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the file that the workflow wrote with gh api.
	if err != nil {
		return nil, fmt.Errorf("cannot read the list of changed files: %w; the workflow must write it with gh api", err)
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	var files []changedFile
	for {
		var cf changedFile
		err := dec.Decode(&cf)
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("the list of changed files is not valid JSON: %w; the workflow must write it with gh api --jq", err)
		}
		if cf.Filename == "" {
			return nil, errors.New("an entry in the list of changed files has no file name; the workflow must write it with gh api --jq")
		}
		files = append(files, cf)
	}
}

// check returns a short note when the pull request passes, or the
// problems that make it fail. No problem quotes text of the pull request.
func check(pr pullRequest, files []changedFile) (string, []string) {
	touchesContract := false
	for _, f := range files {
		if strings.HasPrefix(f.Filename, contractDir) || strings.HasPrefix(f.PreviousFilename, contractDir) {
			touchesContract = true
		}
	}
	if isBot(pr, releaseBot) && pr.Head.Ref == releaseBranch && onlyReleaseFiles(files) {
		return "the release pull request of release-please needs no answer", nil
	}
	breaking := breakingTitle.MatchString(pr.Title)
	if isBot(pr, dependabotBot) && !breaking && onlyDependabotFiles(files) {
		return "a Dependabot pull request that changes only dependency files needs no answer", nil
	}

	answer, problem := parseAnswer(pr.Body)
	if problem != "" {
		return "", []string{problem}
	}

	var problems []string
	switch answer {
	case "yes":
		if !breaking {
			problems = append(problems, `the answer is "yes", but the title has no "!": add it after the type or the scope, such as "feat(run)!: ...", so that release-please lists the change under "⚠ BREAKING CHANGES"`)
		}
		if !addsUpdatingNote(files, &problems) {
			problems = append(problems, `the answer is "yes", but the pull request adds no "## Updating from X" section to `+updatingFile+`: add one that says who is affected, what to do, and a command that shows the new way`)
		}
	case "no":
		if breaking {
			problems = append(problems, `the title has a "!" (a breaking change), but the answer is "no": answer "yes" and add a note to `+updatingFile+`, or take the "!" out of the title`)
		}
		if touchesContract {
			problems = append(problems, `the pull request changes a file under `+contractDir+`, but the answer is "no": a change to a contract test is a change in behavior for callers; answer "yes", add "!" to the title and a note to `+updatingFile)
		}
	}
	if len(problems) > 0 {
		return "", problems
	}
	return fmt.Sprintf("changes behavior for existing callers: %s", answer), nil
}

// isBot reports whether the author is the GitHub App with this login. A
// person cannot have a login that ends in "[bot]", and the type says
// "Bot" only for an App.
func isBot(pr pullRequest, login string) bool {
	return pr.User.Type == "Bot" && pr.User.Login == login
}

func onlyDependabotFiles(files []changedFile) bool {
	if len(files) == 0 {
		return false
	}
	for _, f := range files {
		if !dependabotFile(f.Filename) || (f.PreviousFilename != "" && !dependabotFile(f.PreviousFilename)) {
			return false
		}
	}
	return true
}

func onlyReleaseFiles(files []changedFile) bool {
	if len(files) == 0 {
		return false
	}
	for _, f := range files {
		if !releaseFiles[f.Filename] || (f.PreviousFilename != "" && f.PreviousFilename != f.Filename) {
			return false
		}
	}
	return true
}

// parseAnswer finds the one answer line in the body, outside HTML
// comments, and returns "yes" or "no", or a problem.
func parseAnswer(body string) (string, string) {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = htmlComment.ReplaceAllString(body, "")
	matches := answerLine.FindAllStringSubmatch(body, -1)
	switch {
	case len(matches) == 0:
		return "", `the description has no line "` + answerPrefix + ` yes" or "... no": add it as in .github/pull_request_template.md`
	case len(matches) > 1:
		return "", `the description has the line "` + answerPrefix + `" more than once: keep one`
	}
	switch v := matches[0][1]; v {
	case "yes", "no":
		return v, ""
	default:
		return "", `the line "` + answerPrefix + `" must end in "yes" or "no", in small letters and with nothing else: edit the description`
	}
}

// addsUpdatingNote reports whether the patch of docs/updating.md adds a
// line "## Updating from X". It adds a problem when GitHub sent no patch.
func addsUpdatingNote(files []changedFile, problems *[]string) bool {
	for _, f := range files {
		if f.Filename != updatingFile {
			continue
		}
		if f.Patch == nil {
			*problems = append(*problems, `GitHub sent no diff of `+updatingFile+` (it is too large or binary): make the change of this file smaller`)
			return true
		}
		for _, line := range strings.Split(*f.Patch, "\n") {
			if strings.HasPrefix(line, "+++") || !strings.HasPrefix(line, "+") {
				continue
			}
			if updatingHead.MatchString(strings.TrimSuffix(line[1:], "\r")) {
				return true
			}
		}
	}
	return false
}
