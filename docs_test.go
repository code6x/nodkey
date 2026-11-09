package nodkey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocsShellLinesHaveNoTrailingComment checks the shell blocks of the
// docs (issue #92). Interactive zsh does not treat "#" as the start of a
// comment unless the option interactivecomments is on, and it is off by
// default. A reader who pastes "cmd   # note" into zsh passes "#" and the
// words after it to cmd. So a note goes on its own line above the command.
func TestDocsShellLinesHaveNoTrailingComment(t *testing.T) {
	files, err := filepath.Glob("docs/*.md")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "README.md", "AGENTS.md")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range trailingShellComments(string(data)) {
			t.Errorf("%s:%d: a shell line ends in a # comment; put the note on its own line above the command (issue #92): %s",
				f, bad.line, bad.text)
		}
	}
}

// TestTrailingShellComments checks the finder itself, so that the test
// above cannot pass because the finder sees nothing.
func TestTrailingShellComments(t *testing.T) {
	doc := strings.Join([]string{
		"text # not code",
		"```sh",
		"# a note on its own line",
		"read -rs TOKEN    # paste the token",
		`echo "a # in quotes" 'and # here'`,
		"curl https://example.com/#anchor",
		"echo $# ${#x}",
		"```",
		"```toml",
		"key = 1   # TOML comment",
		"```",
		"   ```bash",
		"   VERSION=0.2.0   # the version",
		"   ```",
		"```",
		"plain block   # not shell",
		"```",
	}, "\n")
	got := trailingShellComments(doc)
	want := []int{4, 13}
	if len(got) != len(want) {
		t.Fatalf("found %v, want lines %v", got, want)
	}
	for i := range want {
		if got[i].line != want[i] {
			t.Errorf("finding %d is on line %d, want %d", i, got[i].line, want[i])
		}
	}
}

type shellLine struct {
	line int
	text string
}

// trailingShellComments returns the lines of the sh, bash, shell, zsh and
// console blocks of a Markdown text that have a "#" comment after a
// command.
func trailingShellComments(doc string) []shellLine {
	var out []shellLine
	inBlock, isShell := false, false
	for i, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			if inBlock {
				inBlock, isShell = false, false
				continue
			}
			inBlock = true
			switch strings.TrimSpace(strings.TrimPrefix(trimmed, "```")) {
			case "sh", "bash", "shell", "zsh", "console":
				isShell = true
			}
			continue
		}
		if isShell && hasTrailingComment(trimmed) {
			out = append(out, shellLine{line: i + 1, text: trimmed})
		}
	}
	return out
}

// hasTrailingComment reports whether a shell line has a word that starts
// with "#" after some other word, outside quotes.
func hasTrailingComment(line string) bool {
	var quote rune
	prev := ' '
	seenWord := false
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
			seenWord = true
		case r == '#' && (prev == ' ' || prev == '\t'):
			return seenWord
		case r != ' ' && r != '\t':
			seenWord = true
		}
		prev = r
	}
	return false
}
