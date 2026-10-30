package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// canary stands for a secret in the log. nodkey must never print it.
const canary = "CANARY-made-up-token-31c9"

// zeros is the prev of the first entry.
var zeros = strings.Repeat("0", 64)

// auditLines returns n entries that follow the entry with seq after and
// hash prev, and the hash of each line, in hex. It builds the lines by
// hand, so it also checks the format that the audit package writes. word
// goes into each entry, so the entries of two broker runs differ.
func auditLines(after int, prev string, n int, word string) ([]string, []string) {
	var lines, hashes []string
	for seq := after + 1; seq <= after+n; seq++ {
		line := fmt.Sprintf(`{"seq":%d,"time":"2026-10-14T12:00:00.000Z","event":"broker_started","prev":"%s",`+
			`"version":"%s","reason":"%s"}`, seq, prev, word, canary)
		sum := sha256.Sum256([]byte(line))
		prev = hex.EncodeToString(sum[:])
		lines = append(lines, line)
		hashes = append(hashes, prev)
	}
	return lines, hashes
}

// writeLines writes lines, each with a newline, to a new file and returns
// its path.
func writeLines(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var data []byte
	for _, line := range lines {
		data = append(append(data, line...), '\n')
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// journal returns the journal lines of the anchors of hashes, the first
// one for entry first.
func journal(first int, hashes ...string) string {
	var b strings.Builder
	for i, h := range hashes {
		fmt.Fprintf(&b, "audit anchor %d:%s\n", first+i, h)
	}
	return b.String()
}

func TestAuditVerify(t *testing.T) {
	lines, hashes := auditLines(0, zeros, 3, "dev")
	path := writeLines(t, lines...)
	changed := slices.Clone(lines)
	changed[1] = strings.Replace(changed[1], "12:00:00.000Z", "12:00:01.000Z", 1)
	broken := writeLines(t, changed...)

	// A broker run wrote entries 1 to 4. Someone cut the log after entry 2
	// while the broker was stopped, and the next run wrote entries 3 and 4
	// again.
	run1, h1 := auditLines(0, zeros, 4, "run-1")
	run2, h2 := auditLines(2, h1[1], 2, "run-2")
	cut := writeLines(t, append(slices.Clone(run1[:2]), run2...)...)
	cutJournal := journal(1, h1...) + "nodkey: broker started\n" + journal(3, h2...)

	// A copy of the journal, as journalctl -o cat prints it, with other
	// lines of the broker, and lines that only look like anchors.
	journalText := "nodkey: listening on 192.0.2.10:7743\n" + journal(1, hashes...) +
		"audit anchor 4:" + hashes[2] + " (not exactly an anchor line)\n" +
		"Oct 14 12:00:00 broker nodkey[1]: audit anchor 1:" + hashes[0] + "\n" +
		" audit anchor 2:" + hashes[1] + "\n"
	anchorsFile := filepath.Join(t.TempDir(), "journal.txt")
	if err := os.WriteFile(anchorsFile, []byte(journalText), 0o600); err != nil {
		t.Fatal(err)
	}
	noAnchors := filepath.Join(t.TempDir(), "journal.txt")
	if err := os.WriteFile(noAnchors, []byte("Oct 14 12:00:00 broker nodkey[1]: audit anchor 1:"+hashes[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ok := "ok: 3 entries (torn lines: 0)\n"
	last := "last entry: 3:" + hashes[2] + "\n"
	tests := []struct {
		name       string
		args       []string
		stdin      string
		wantCode   int
		wantStdout string
		wantStderr string // a part of stderr; "" means stderr must be empty
	}{
		{name: "ok", args: []string{"audit", "verify", path}, wantCode: exitOK,
			wantStdout: ok + "anchors: none checked\n" + last},
		{name: "anchor after the file", args: []string{"audit", "verify", path, "--anchor", "2:" + hashes[1]}, wantCode: exitOK,
			wantStdout: ok + "anchors: 1 checked, all match; the newest is entry 2\n" + last},
		{name: "anchor before the file", args: []string{"audit", "verify", "-anchor=3:" + hashes[2], path}, wantCode: exitOK,
			wantStdout: ok + "anchors: 1 checked, all match; the newest is entry 3\n" + last},
		{name: "two anchors", args: []string{"audit", "verify", "--anchor", "3:" + hashes[2], path, "--anchor", "1:" + hashes[0]},
			wantCode: exitOK, wantStdout: ok + "anchors: 2 checked, all match; the newest is entry 3\n" + last},
		{name: "one anchor twice", args: []string{"audit", "verify", path, "--anchor", "2:" + hashes[1], "--anchor", "2:" + hashes[1]},
			wantCode: exitOK, wantStdout: ok + "anchors: 1 checked, all match; the newest is entry 2\n" + last},
		{name: "anchors from a file", args: []string{"audit", "verify", path, "--anchors", anchorsFile}, wantCode: exitOK,
			wantStdout: ok + "anchors: 3 checked, all match; the newest is entry 3\n" + last},
		{name: "anchors from stdin", args: []string{"audit", "verify", "--anchors", "-", path}, stdin: journalText, wantCode: exitOK,
			wantStdout: ok + "anchors: 3 checked, all match; the newest is entry 3\n" + last},
		{name: "anchors from stdin and an anchor", stdin: journal(1, hashes[0]), wantCode: exitOK,
			args:       []string{"audit", "verify", path, "--anchors=-", "--anchor", "3:" + hashes[2]},
			wantStdout: ok + "anchors: 2 checked, all match; the newest is entry 3\n" + last},
		{name: "wrong anchor", args: []string{"audit", "verify", path, "--anchor", "2:" + hashes[2]}, wantCode: exitDataErr,
			wantStderr: "nodkey: audit log " + strconv.Quote(path) + ": line 2: is entry 2, and its hash is not the hash in the anchor\n"},
		{name: "two anchors for one entry", args: []string{"audit", "verify", path, "--anchor", "2:" + hashes[1], "--anchor", "2:" + hashes[2]},
			wantCode: exitDataErr, wantStderr: "nodkey: audit log " + strconv.Quote(path) + ": two anchors for entry 2 have different hashes"},
		{name: "anchor after the end", args: []string{"audit", "verify", path, "--anchor", "4:" + hashes[2]}, wantCode: exitDataErr,
			wantStderr: "nodkey: audit log " + strconv.Quote(path) + ": no entry 4: the log ends at entry 3\n"},
		{name: "changed line", args: []string{"audit", "verify", broken}, wantCode: exitDataErr,
			wantStderr: "nodkey: audit log " + strconv.Quote(broken) + ": line 3: has a prev that is not the hash of the entry before it, on line 2\n"},
		// The newest anchor alone does not find the cut: the second run
		// wrote it. Every anchor since the log began finds it.
		{name: "cut and written again, newest anchor only", args: []string{"audit", "verify", cut, "--anchor", "4:" + h2[1]},
			wantCode: exitOK, wantStdout: "ok: 4 entries (torn lines: 0)\nanchors: 1 checked, all match; the newest is entry 4\n" +
				"last entry: 4:" + h2[1] + "\n"},
		{name: "cut and written again, every anchor", args: []string{"audit", "verify", cut, "--anchors", "-"}, stdin: cutJournal,
			wantCode: exitDataErr, wantStderr: "nodkey: audit log " + strconv.Quote(cut) + ": two anchors for entry 3 have different hashes"},
		{name: "missing file", args: []string{"audit", "verify", path + ".missing"}, wantCode: exitNoInput,
			wantStderr: "no such file or directory"},
		{name: "a directory", args: []string{"audit", "verify", filepath.Dir(path)}, wantCode: exitNoInput,
			wantStderr: "is a directory"},
		{name: "missing anchors file", args: []string{"audit", "verify", path, "--anchors", anchorsFile + ".missing"},
			wantCode: exitNoInput, wantStderr: "nodkey: audit verify: --anchors \""},
		{name: "anchors file without an anchor line", args: []string{"audit", "verify", path, "--anchors", noAnchors},
			wantCode: exitUsage, wantStderr: `no line is exactly "audit anchor " and an anchor; use journalctl -o cat`},
		{name: "empty stdin for anchors", args: []string{"audit", "verify", path, "--anchors", "-"}, wantCode: exitUsage,
			wantStderr: `--anchors "-": no line is exactly`},
		{name: "anchors twice", args: []string{"audit", "verify", path, "--anchors", anchorsFile, "--anchors", "-"},
			wantCode: exitUsage, wantStderr: "give it once"},
		{name: "no file", args: []string{"audit", "verify"}, wantCode: exitUsage, wantStderr: "name the log FILE"},
		{name: "two files", args: []string{"audit", "verify", path, path}, wantCode: exitUsage, wantStderr: "give one FILE only"},
		{name: "bad anchor", args: []string{"audit", "verify", path, "--anchor", "2"}, wantCode: exitUsage,
			wantStderr: `as in the journal's "audit anchor" lines; see "nodkey audit verify --help"`},
		{name: "missing log with a strange name", args: []string{"audit", "verify", "gone\u202e\nx"}, wantCode: exitNoInput,
			wantStderr: `nodkey: audit log "gone\u202e\nx": no such file or directory` + "\n"},
		{name: "unknown flag", args: []string{"audit", "verify", path, "--bogus"}, wantCode: exitUsage,
			wantStderr: "unknown option"},
		{name: "help of verify", args: []string{"audit", "verify", "-h"}, wantCode: exitOK, wantStderr: auditUsageText},
		{name: "audit alone", args: []string{"audit"}, wantCode: exitUsage, wantStderr: `nodkey audit: give a command: "verify"; see "nodkey audit --help"`},
		{name: "audit help", args: []string{"audit", "help"}, wantCode: exitOK, wantStdout: auditUsageText},
		{name: "unknown audit command", args: []string{"audit", "bogus"}, wantCode: exitUsage,
			wantStderr: `nodkey audit: unknown command "bogus"; see "nodkey audit --help"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, strings.NewReader(tt.stdin), &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d; stderr: %q", code, tt.wantCode, stderr.String())
			}
			if got := stdout.String(); got != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", got, tt.wantStdout)
			}
			got := stderr.String()
			if tt.wantStderr == "" && got != "" {
				t.Errorf("stderr = %q, want it empty", got)
			}
			if !strings.Contains(got, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", got, tt.wantStderr)
			}
			if strings.Contains(stdout.String()+got, "CANARY") {
				t.Errorf("nodkey printed text from the log: %q %q", stdout.String(), got)
			}
		})
	}
}

func TestAuditVerifyReportsFailedOutput(t *testing.T) {
	lines, _ := auditLines(0, zeros, 1, "dev")
	path := writeLines(t, lines...)
	var stderr bytes.Buffer
	if code := run([]string{"audit", "verify", path}, strings.NewReader(""), failingWriter{}, &stderr); code != exitFailure {
		t.Errorf("exit code with a failing stdout = %d, want %d", code, exitFailure)
	}
}
