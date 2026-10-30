package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/client"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/doctor"
	"github.com/code6x/nodkey/internal/release"
	nodkeyversion "github.com/code6x/nodkey/internal/version"
)

// sshVersionTimeout bounds ssh -V.
const sshVersionTimeout = 5 * time.Second

const doctorUsage = `Usage: nodkey doctor [--offline] [--json]
       nodkey doctor broker [--config FILE] [--json]

Check the setup of this client, read only, as the user of the agent:
this nodkey's version and a newer release, the client config and the
TLS key, the call to the broker (the key list of nodkey ssh-agent, which
needs no tap on the phone), the broker's version, ssh and SSH_AUTH_SOCK.

It prints one line per check: ok, FAIL, or skip when a check that it
needs failed. Each FAIL says what is wrong, why it matters, how to fix
it, and the docs section. It changes nothing, and reads no secret value.

  --offline  do not ask GitHub for a newer release
  --json     print the result as JSON (DESIGN.md section 15)

nodkey doctor broker checks the broker host, as root: the broker config
(default /etc/nodkey/broker.toml), loaded as nodkey broker loads it but
without starting anything; the unit nodkey.service, its user and its
encrypted credentials (nothing is decrypted); the files that the broker
reads, with the broker's own checks for the user of the unit; systemd,
cgroup v2, swap and kernel.core_pattern; and whether the service runs,
with the error lines of its last start from the journal. It never calls
Telegram.

  --config FILE  the broker config

The exit code is 0 when every check passes, 1 otherwise, and 64 on
wrong usage.
`

// runDoctor runs nodkey doctor with args (after "doctor") and returns the
// exit code. env makes the checks; tests give fakes.
func runDoctor(args []string, stdout, stderr io.Writer, env func(offline bool) doctor.ClientEnv,
	brokerEnv func(path string) doctor.BrokerEnv) int {
	if len(args) > 0 && args[0] == "broker" {
		return runDoctorBroker(args[1:], stdout, stderr, brokerEnv)
	}
	fs := flag.NewFlagSet("nodkey doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	offline := fs.Bool("offline", false, "do not ask GitHub")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stderr, doctorUsage)
		}
		return parseErrorCode(stderr, "doctor", err)
	}
	if fs.NArg() > 0 {
		return usageFail(stderr, "doctor", fmt.Sprintf("unexpected argument %.64q", fs.Arg(0)))
	}
	r := doctor.Run(doctor.ClientChecks(context.Background(), env(*offline)))
	return writeReport(r, *asJSON, stdout)
}

// runDoctorBroker runs nodkey doctor broker with args (after "broker").
func runDoctorBroker(args []string, stdout, stderr io.Writer, env func(path string) doctor.BrokerEnv) int {
	fs := flag.NewFlagSet("nodkey doctor broker", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", defaultBrokerConfig, "the broker config")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stderr, doctorUsage)
		}
		return parseErrorCode(stderr, "doctor", err)
	}
	if fs.NArg() > 0 {
		return usageFail(stderr, "doctor", fmt.Sprintf("unexpected argument %.64q", fs.Arg(0)))
	}
	r := doctor.Run(doctor.BrokerChecks(env(*path)))
	return writeReport(r, *asJSON, stdout)
}

// writeReport writes r as text or JSON, and returns the exit code.
func writeReport(r doctor.Report, asJSON bool, stdout io.Writer) int {
	write := r.WriteText
	if asJSON {
		write = r.WriteJSON
	}
	if err := write(stdout); err != nil || !r.OK() {
		return exitFailure
	}
	return exitOK
}

// realDoctorEnv is the ClientEnv of a real client.
func realDoctorEnv(offline bool) doctor.ClientEnv {
	env := doctor.ClientEnv{
		Version: version,
		Load: func(path string) (doctor.Prober, error) {
			b, err := client.Load(path)
			if err != nil {
				return nil, err
			}
			return b, nil
		},
		SSHVersion: func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), sshVersionTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, "ssh", "-V")
			cmd.WaitDelay = time.Second
			out, err := cmd.CombinedOutput()
			return string(out), err
		},
		Getenv: os.Getenv,
		Lstat:  os.Lstat,
	}
	if !offline {
		env.Lookup = func(ctx context.Context, own nodkeyversion.Release) (release.Info, error) {
			return release.New(own).Lookup(ctx)
		}
	}
	if path, err := client.ConfigPath(); err == nil {
		env.ConfigPath = path
	}
	return env
}

// systemdTimeout bounds each call of systemctl and journalctl.
const systemdTimeout = 10 * time.Second

// systemPath is the PATH of the programs that nodkey doctor broker runs
// as root: never the PATH of root's shell, where a directory may be
// writable by others.
const systemPath = "/usr/bin:/bin:/usr/sbin:/sbin"

// output runs a program of systemd, found in systemPath, with a timeout,
// and returns its stdout.
func output(name string, args ...string) (string, error) {
	path := ""
	for _, dir := range filepath.SplitList(systemPath) {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && fi.Mode().IsRegular() {
			path = filepath.Join(dir, name)
			break
		}
	}
	if path == "" {
		return "", errors.New(name + " is not in " + systemPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), systemdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: path is systemctl or journalctl from systemPath; the arguments are fixed.
	cmd.Env = []string{"PATH=" + systemPath, "LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	return string(out), err
}

// realBrokerDoctorEnv is the BrokerEnv of a real broker host, for the
// config at path. Outside the unit, ${CREDENTIALS_DIRECTORY} is not set:
// it stands for the directory where systemd puts the credentials, and
// no check reads a file in it.
func realBrokerDoctorEnv(path string) doctor.BrokerEnv {
	// Only this process sees it: config.ExpandPath reads it. A value
	// that root's shell has is not trusted.
	credDir := "/run/credentials/" + doctor.Unit
	_ = os.Setenv("CREDENTIALS_DIRECTORY", credDir)
	return doctor.BrokerEnv{
		ConfigPath: path,
		CredDir:    credDir,
		ReadConfig: config.ReadBroker,
		UnitText:   func() (string, error) { return output("systemctl", "cat", "--", doctor.Unit) },
		LookupUser: func(name string) (uint32, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, err
			}
			id, err := strconv.ParseUint(u.Uid, 10, 32)
			return uint32(id), err
		},
		CheckFiles: func(b *config.Broker, self uint32, skip func(string) bool) error {
			return b.CheckFilesAs(self, skip)
		},
		Stat:     os.Stat,
		ReadFile: os.ReadFile,
		ReadDir: func(path string) ([]string, error) {
			entries, err := os.ReadDir(path)
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			return names, err
		},
		SystemdVersion: func() (string, error) { return output("systemctl", "--version") },
		Service: func() (string, []string, error) {
			state, err := output("systemctl", "show", "--property=ActiveState", "--value", "--", doctor.Unit)
			state = strings.TrimSpace(state)
			if err != nil || state == "active" {
				return state, nil, err
			}
			out, err := output("journalctl", "--unit="+doctor.Unit, "--boot", "--priority=err",
				"--lines=5", "--output=cat", "--no-pager", "--quiet")
			if err != nil {
				return state, nil, nil
			}
			return state, strings.Split(strings.TrimSpace(out), "\n"), nil
		},
	}
}
