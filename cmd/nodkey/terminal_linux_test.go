package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestIsTerminal: only a terminal is one. A pipe, a regular file,
// /dev/null (a character device) and a writer that is not a file are
// not. The master side of a new pseudo-terminal is a terminal.
func TestIsTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	file, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	for name, w := range map[string]io.Writer{
		"a pipe": w, "a file": file, "/dev/null": null, "a closed file": closed, "a buffer": &bytes.Buffer{},
	} {
		if isTerminal(w) {
			t.Errorf("%s is a terminal", name)
		}
	}

	// A container may have no pseudo-terminals.
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	defer func() { _ = ptmx.Close() }()
	if !isTerminal(ptmx) {
		t.Error("a pseudo-terminal is not a terminal")
	}
}
