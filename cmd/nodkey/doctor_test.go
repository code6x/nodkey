package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/doctor"
)

// fakeDoctorEnv is a ClientEnv whose config is missing, so that no check
// reaches a network or a file. It records offline.
func fakeDoctorEnv(gotOffline *bool) func(bool) doctor.ClientEnv {
	return func(offline bool) doctor.ClientEnv {
		*gotOffline = offline
		return doctor.ClientEnv{
			Version:    "dev",
			ConfigPath: "/home/agent/.config/nodkey/client.toml",
			Load:       func(string) (doctor.Prober, error) { return nil, fs.ErrNotExist },
			SSHVersion: func() (string, error) { return "OpenSSH_9.6p1", nil },
			Getenv:     func(string) string { return "" },
			Lstat:      func(string) (fs.FileInfo, error) { return nil, errors.New("no") },
		}
	}
}

func TestDoctorText(t *testing.T) {
	var offline bool
	var stdout, stderr bytes.Buffer
	code := runDoctor([]string{"--offline"}, &stdout, &stderr, fakeDoctorEnv(&offline))
	if code != exitFailure || !offline {
		t.Errorf("exit %d, offline %v; want 1 and true", code, offline)
	}
	out := stdout.String()
	for _, want := range []string{"ok   version", "FAIL config", "     fix: ", "skip broker: needs config", "ok   ssh: OpenSSH 9.6", "FAIL ssh agent"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestDoctorJSON(t *testing.T) {
	var offline bool
	var stdout, stderr bytes.Buffer
	if code := runDoctor([]string{"--json"}, &stdout, &stderr, fakeDoctorEnv(&offline)); code != exitFailure || offline {
		t.Errorf("exit %d, offline %v; want 1 and false", code, offline)
	}
	var got struct {
		OK     bool `json:"ok"`
		Checks []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Fix    string `json:"fix"`
			Docs   string `json:"docs"`
		} `json:"checks"`
	}
	dec := json.NewDecoder(&stdout)
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.OK || len(got.Checks) != 6 || got.Checks[1].Status != "FAIL" || got.Checks[1].Docs == "" {
		t.Errorf("JSON %+v", got)
	}
}

func TestDoctorUsage(t *testing.T) {
	var offline bool
	for _, args := range [][]string{{"extra"}, {"--nope"}, {"broker", "x"}} {
		var stdout, stderr bytes.Buffer
		if code := runDoctor(args, &stdout, &stderr, fakeDoctorEnv(&offline)); code != exitUsage {
			t.Errorf("%q: exit %d, want 64", args, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%q: stdout %q", args, stdout.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := runDoctor([]string{"--help"}, &stdout, &stderr, fakeDoctorEnv(&offline)); code != exitOK ||
		!strings.Contains(stderr.String(), "Usage: nodkey doctor") {
		t.Errorf("--help: exit %d, %q", code, stderr.String())
	}
}
