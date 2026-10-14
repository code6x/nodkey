package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

// madeUpPin is a pin of no real key.
var madeUpPin = config.Pin(sha256.Sum256([]byte("made-up key")))

func TestKeygenUsage(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		code int
	}{
		{"no --out", []string{"keygen"}, exitUsage},
		{"an empty --out", []string{"keygen", "--out="}, exitUsage},
		{"an extra argument", []string{"keygen", "--out", "client.key", "extra"}, exitUsage},
		{"the file without --out", []string{"keygen", "client.key"}, exitUsage},
		{"an unknown flag", []string{"keygen", "--force", "--out", "client.key"}, exitUsage},
		{"-h", []string{"keygen", "-h"}, exitOK},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(tt.args, strings.NewReader(""), &stdout, &stderr); code != tt.code {
			t.Errorf("%s: exit code %d, want %d", tt.name, code, tt.code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: stdout = %q, want it empty", tt.name, stdout.String())
		}
		if !strings.Contains(stderr.String(), "Usage: nodkey keygen --out FILE") {
			t.Errorf("%s: stderr = %q, want the usage", tt.name, stderr.String())
		}
	}
	// The command list names keygen.
	var stdout bytes.Buffer
	if run([]string{"help"}, strings.NewReader(""), &stdout, &bytes.Buffer{}); !strings.Contains(stdout.String(), "keygen") {
		t.Errorf("help does not list keygen: %q", stdout.String())
	}
}

func TestKeygenPrintsOnlyThePin(t *testing.T) {
	for _, args := range [][]string{{"--out", "/x/client.key"}, {"-out=/x/client.key"}} {
		var got string
		write := func(path string) (config.Pin, error) {
			got = path
			return madeUpPin, nil
		}
		var stdout, stderr bytes.Buffer
		if code := runKeygen(args, &stdout, &stderr, write); code != exitOK {
			t.Errorf("%q: exit code %d, want 0; stderr %q", args, code, stderr.String())
		}
		if got != "/x/client.key" {
			t.Errorf("%q: the key went to %q", args, got)
		}
		// Exactly the pin, in the form that the config reads, and a newline.
		if want := madeUpPin.String() + "\n"; stdout.String() != want {
			t.Errorf("%q: stdout = %q, want %q", args, stdout.String(), want)
		}
		if p, err := config.ParsePin(strings.TrimSuffix(stdout.String(), "\n")); err != nil || p != madeUpPin {
			t.Errorf("%q: the printed pin does not parse: %v", args, err)
		}
		if stderr.Len() != 0 {
			t.Errorf("%q: stderr = %q, want it empty", args, stderr.String())
		}
	}
}

func TestKeygenFails(t *testing.T) {
	// The writer's error goes to stderr, in the form of DESIGN.md section
	// 15; stdout stays empty.
	write := func(path string) (config.Pin, error) {
		return config.Pin{}, errors.New(path + ": a file or link with this name exists")
	}
	var stdout, stderr bytes.Buffer
	if code := runKeygen([]string{"--out", "/x/client.key"}, &stdout, &stderr, write); code != exitFailure {
		t.Errorf("exit code %d, want %d", code, exitFailure)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want it empty", stdout.String())
	}
	if want := "nodkey: /x/client.key: a file or link with this name exists (exit 1)\n"; stderr.String() != want {
		t.Errorf("stderr = %q, want %q", stderr.String(), want)
	}
}

func TestKeygenRemovesTheKeyIfThePinCannotBePrinted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.key")
	write := func(path string) (config.Pin, error) {
		return madeUpPin, os.WriteFile(path, []byte("made-up key\n"), 0o600)
	}
	var stderr bytes.Buffer
	if code := runKeygen([]string{"--out", path}, failingWriter{}, &stderr, write); code != exitFailure {
		t.Errorf("exit code %d, want %d", code, exitFailure)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the key file is still there: %v", err)
	}
	if !strings.Contains(stderr.String(), "cannot print the pin, so the new key file was removed (exit 1)") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// TestKeygenChecksTheDirectories runs the real keygen: it refuses a
// directory that others can write to, and makes no file.
func TestKeygenChecksTheDirectories(t *testing.T) {
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0o777)
	if err := os.Chmod(open, mode); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(open, "client.key")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"keygen", "--out", path}, strings.NewReader(""), &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code %d, want %d", code, exitFailure)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want it empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "group or others can write") || !strings.HasSuffix(stderr.String(), "(exit 1)\n") {
		t.Errorf("stderr = %q", stderr.String())
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("keygen made a file: %v", err)
	}
}
