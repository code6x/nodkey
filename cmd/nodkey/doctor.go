package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/code6x/nodkey/internal/client"
	"github.com/code6x/nodkey/internal/doctor"
	"github.com/code6x/nodkey/internal/release"
	nodkeyversion "github.com/code6x/nodkey/internal/version"
)

// sshVersionTimeout bounds ssh -V.
const sshVersionTimeout = 5 * time.Second

const doctorUsage = `Usage: nodkey doctor [--offline] [--json]

Check the setup of this client, read only, as the user of the agent:
this nodkey's version and a newer release, the client config and the
TLS key, the call to the broker (the key list of nodkey ssh-agent, which
needs no tap on the phone), the broker's version, ssh and SSH_AUTH_SOCK.

It prints one line per check: ok, FAIL, or skip when a check that it
needs failed. Each FAIL says what is wrong, why it matters, how to fix
it, and the docs section. It changes nothing, and reads no secret value.

  --offline  do not ask GitHub for a newer release
  --json     print the result as JSON (DESIGN.md section 15)

The exit code is 0 when every check passes, 1 otherwise, and 64 on
wrong usage.
`

// runDoctor runs nodkey doctor with args (after "doctor") and returns the
// exit code. env makes the checks; tests give fakes.
func runDoctor(args []string, stdout, stderr io.Writer, env func(offline bool) doctor.ClientEnv) int {
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
			out, err := exec.CommandContext(ctx, "ssh", "-V").CombinedOutput()
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
