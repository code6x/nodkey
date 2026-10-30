package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/code6x/nodkey"
)

// testChangelog is a changelog in the form of release-please, with a
// security fix in 0.3.1 and in 0.2.1.
const testChangelog = `# Changelog

## [0.3.1](https://github.com/code6x/nodkey/compare/v0.3.0...v0.3.1) (2026-11-20)


### Security

* refuse a bad pin ([#140](https://example.com/140))

## [0.3.0](https://github.com/code6x/nodkey/compare/v0.2.1...v0.3.0) (2026-11-10)


### Features

* a new command ([#130](https://example.com/130))


### Bug Fixes

* a fix in 0.3.0

## [0.2.1](https://github.com/code6x/nodkey/compare/v0.2.0...v0.2.1) (2026-11-01)


### Security

* close a hole in 0.2.0


### Bug Fixes

* a fix in 0.2.1

## [0.2.0](https://github.com/code6x/nodkey/compare/v0.1.0...v0.2.0) (2026-10-17)


### Security

* an old fix that is installed already

### Features

* an old feature

## 0.1.0 (2026-10-15)


### Features

* the first release
`

func changes(t *testing.T, text string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = changesOf(text, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// TestChanges: the security fixes of all newer releases come first, then
// the other changes; the installed release and older ones are left out.
func TestChanges(t *testing.T) {
	code, out, errOut := changes(t, testChangelog, "--since", "0.2.0")
	if code != exitOK || errOut != "" {
		t.Fatalf("code %d, stderr %q", code, errOut)
	}
	want := `Changes after nodkey 0.2.0, from the changelog of this nodkey.

# SECURITY FIXES

## [0.3.1](https://github.com/code6x/nodkey/compare/v0.3.0...v0.3.1) (2026-11-20)

* refuse a bad pin ([#140](https://example.com/140))

## [0.2.1](https://github.com/code6x/nodkey/compare/v0.2.0...v0.2.1) (2026-11-01)

* close a hole in 0.2.0

# OTHER CHANGES

## [0.3.1](https://github.com/code6x/nodkey/compare/v0.3.0...v0.3.1) (2026-11-20)

No other changes.

## [0.3.0](https://github.com/code6x/nodkey/compare/v0.2.1...v0.3.0) (2026-11-10)

### Features

* a new command ([#130](https://example.com/130))

### Bug Fixes

* a fix in 0.3.0

## [0.2.1](https://github.com/code6x/nodkey/compare/v0.2.0...v0.2.1) (2026-11-01)

### Bug Fixes

* a fix in 0.2.1
`
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

// TestChangesNoSecurity: without security fixes, there is no security
// part; a heading without [ ] counts too.
func TestChangesNoSecurity(t *testing.T) {
	_, out, _ := changes(t, testChangelog, "--since", "0.0.9")
	if !strings.Contains(out, "## 0.1.0 (2026-10-15)") || !strings.Contains(out, "* the first release") {
		t.Errorf("0.1.0 is missing:\n%s", out)
	}
	_, out, _ = changes(t, testChangelog, "--since", "0.3.0")
	if strings.Contains(out, "0.2.1") || strings.Contains(out, "a new command") || !strings.Contains(out, "refuse a bad pin") {
		t.Errorf("wrong releases:\n%s", out)
	}
	_, out, _ = changes(t, strings.ReplaceAll(testChangelog, "### Security", "### Other"), "--since", "0.2.0")
	if strings.Contains(out, "SECURITY") {
		t.Errorf("a security part without security fixes:\n%s", out)
	}
}

// TestChangesNoSecurityText: without security fixes, one line says so,
// and the changes come under # CHANGES, not # OTHER CHANGES; an entry
// without items does not say "No other changes".
func TestChangesNoSecurityText(t *testing.T) {
	text := "## [0.4.0](x) (2026-12-01)\n\n" +
		"## [0.3.0](x) (2026-11-10)\n\n### Features\n\n* a new command\n\n" +
		"## [0.2.0](x) (2026-10-17)\n\n### Security\n\n* an old fix\n"
	code, out, errOut := changes(t, text, "--since", "0.2.0")
	if code != exitOK || errOut != "" {
		t.Fatalf("code %d, stderr %q", code, errOut)
	}
	want := `Changes after nodkey 0.2.0, from the changelog of this nodkey.

No security fixes after nodkey 0.2.0.

# CHANGES

## [0.4.0](x) (2026-12-01)

The changelog lists no changes for this release.

## [0.3.0](x) (2026-11-10)

### Features

* a new command
`
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
}

// TestChangesNothingNewer: one line when no release is newer.
func TestChangesNothingNewer(t *testing.T) {
	for _, since := range []string{"0.3.1", "1.0.0"} {
		code, out, _ := changes(t, testChangelog, "--since", since)
		if want := "No release in the changelog of this nodkey is newer than " + since + ".\n"; code != exitOK || out != want {
			t.Errorf("--since %s: code %d, got %q, want %q", since, code, out, want)
		}
	}
	code, out, _ := changes(t, "", "--since", "0.1.0")
	if code != exitOK || !strings.HasPrefix(out, "No release") {
		t.Errorf("empty changelog: code %d, got %q", code, out)
	}
}

// TestChangesBadUsage: --since is strict and needed, once.
func TestChangesBadUsage(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--since"},
		{"--since", "0.2"},
		{"--since", "v0.2.0"},
		{"--since", "0.02.0"},
		{"--since", "0.2.0-rc.1"},
		{"--since", "0.2.0 "},
		{"--since", "dev"},
		{"--since", ""},
		{"--since", "0.2.0", "--since", "0.1.0"},
		{"--since", "0.2.0", "extra"},
	} {
		code, out, _ := changes(t, testChangelog, args...)
		if code != exitUsage || out != "" {
			t.Errorf("%q: code %d, stdout %q", args, code, out)
		}
	}
}

// TestChangesOddChangelog: a changelog with odd or hostile lines does not
// crash, sends no control codes, and leaves out entries without a valid
// version.
func TestChangesOddChangelog(t *testing.T) {
	odd := "## \n##\n### Security\n* before any release\n" +
		"## [0.9.0\n* no closing bracket\n" +
		"## [v0.9.0](x) (date)\n### Security\n* a v in the version\n" +
		"## [0.09.0](x)\n### Security\n* leading zero\n" +
		"## [9999999.0.0](x)\n### Security\n* too big\n" +
		"## [0.5.0](x) (2026-11-30)\n### Security\n* escape \x1b[31mred\x1b]0;title\x07 \x9b and \xff bad\r\n" +
		"* hidden \u202e\u200b\u2028 end\n" +
		"### \n* empty title\n### Security\n### Security\n* again\n" +
		"* " + strings.Repeat("long ", 100000) + "\n" +
		"## [0.4.0](x)"
	code, out, _ := changes(t, odd, "--since", "0.3.0")
	if code != exitOK {
		t.Fatalf("code %d", code)
	}
	for _, bad := range []string{"\x1b", "\x07", "\r", "\x9b", "\xff", "\u202e", "\u200b", "\u2028", "before any release", "no closing", "a v in", "leading zero", "too big"} {
		if strings.Contains(out, bad) {
			t.Errorf("output has %q", bad)
		}
	}
	for _, want := range []string{"## [0.5.0](x) (2026-11-30)", "* escape ?[31mred?]0;title? ? and ? bad\n", "* again", "* hidden ??? end", "## [0.4.0](x)", "* empty title"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

// TestChangesBuiltIn: the changelog of the repository is built in, and
// its entries are read.
func TestChangesBuiltIn(t *testing.T) {
	if !strings.Contains(nodkey.Changelog, "## 0.1.0") {
		t.Fatal("CHANGELOG.md is not built in")
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"changes", "--since", "0.1.0"}, nil, &out, &errOut); code != exitOK {
		t.Fatalf("code %d, stderr %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "## [0.2.0]") {
		t.Errorf("no 0.2.0 entry:\n%s", out.String())
	}
}
