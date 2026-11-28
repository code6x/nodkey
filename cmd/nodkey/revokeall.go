package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/doctor"
)

// The emergency stop (DESIGN.md section 8, "Revoke all"). Scheduled and
// standing grants survive a restart, so a restart no longer ends every
// grant. SIGUSR1 asks the broker to end every grant at once. The broker
// writes the count to the status file of the reload (brokerreload.go),
// and nodkey revoke --all sends the signal and reads the result there.

// brokerSignal is what signalBroker asks the broker for.
type brokerSignal int

const (
	sigReload    brokerSignal = iota // SIGHUP: load the config again
	sigRevokeAll                     // SIGUSR1: end every grant
)

// revokeAllBy is who asked, for the log and the alert of the broker.
const revokeAllBy = "nodkey revoke --all on the broker host"

// revokeAll ends every grant, as SIGUSR1 asked, and writes the count to
// the status file. On an error it logs why; the count stays 0, and the
// status file holds the error.
func (b *brokerParts) revokeAll() {
	b.revokes++
	b.revoked, b.revokeErr = 0, ""
	b.log.Info("nodkey broker: ending every grant, as SIGUSR1 asked")
	if b.svc == nil {
		b.revokeErr = "the broker has not started; start it (systemctl start nodkey), as root"
	} else if n, err := b.svc.RevokeAll(revokeAllBy); err != nil {
		b.revokeErr = err.Error()
	} else {
		b.revoked = n
	}
	if b.revokeErr != "" {
		b.log.Error("nodkey broker: cannot end the grants", slog.String("error", b.revokeErr))
	}
	// The result of the last reload stays in the file.
	b.writeReloadStatus(b.status)
}

const revokeUsage = `Usage: nodkey revoke --all [--config FILE] [--timeout DURATION]

End every grant of the running broker at once, of every client: the
grants of "Approve N min" and of nodkey ssh-grant, the scheduled grants,
the login pre-approvals and the standing grants. It is the emergency
stop. A restart of the broker does not end the scheduled and the
standing grants: the next start opens them again. Run it on the broker
host, as root, or as the broker's user. It sends SIGUSR1 to the broker
and waits for the result. Each grant gets a grant_ended entry in the
audit log, and the approver gets one alert. A request that waits for a
tap still waits.

  --all               end every grant; it must be given
  --config FILE       the broker config (default /etc/nodkey/broker.toml)
  --timeout DURATION  how long to wait for the result (default 60s)

Exit codes: 0 the broker ended every grant, 1 the broker could not end
them, or did not answer in time, or the result cannot be read, 64 wrong
usage.
`

// runRevoke runs nodkey revoke.
func runRevoke(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "end every grant")
	path := fs.String("config", defaultBrokerConfig, "the broker config")
	timeout := fs.Duration("timeout", 60*time.Second, "how long to wait")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, revokeUsage)
			return exitOK
		}
		return parseErrorCode(stderr, "revoke", err)
	}
	if fs.NArg() > 0 {
		return usageFail(stderr, "revoke",
			fmt.Sprintf("unexpected argument %.64q; it takes only --all, --config FILE and --timeout DURATION", fs.Arg(0)))
	}
	if !*all {
		return usageFail(stderr, "revoke", "give --all: it ends every grant of every client")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return usageFail(stderr, "revoke", "--timeout must be more than 0 and at most 1h, such as 60s")
	}
	fail := func(msg string) int {
		_, _ = fmt.Fprintf(stderr, "nodkey revoke: %s\n", msg)
		return exitFailure
	}
	// As in nodkey broker reload: only the path of the audit log is
	// needed, and no file in CREDENTIALS_DIRECTORY is read.
	if os.Getenv("CREDENTIALS_DIRECTORY") == "" {
		_ = os.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/"+doctor.Unit)
	}
	cfg, err := config.ReadBroker(*path)
	if err != nil {
		return fail(err.Error() + "; fix the config, then run nodkey revoke --all again")
	}
	statusPath := reloadStatusPath(cfg)
	before, uid, err := readReloadStatus(statusPath)
	if err != nil {
		return fail(err.Error())
	}
	if !before.RevokeAll {
		// SIGUSR1 would stop a broker from before this command.
		return fail("the broker is older than nodkey revoke --all; update it (nodkey update), as root, " +
			"then run nodkey revoke --all again; until then, systemctl stop nodkey, as root, ends every grant")
	}
	if err := signalBroker(before, uid, sigRevokeAll); err != nil {
		return fail(err.Error())
	}
	deadline := time.Now().Add(*timeout)
	for {
		time.Sleep(reloadPoll)
		st, _, err := readReloadStatus(statusPath)
		switch {
		case err == nil && (st.PID != before.PID || st.Start != before.Start):
			return fail("the broker restarted; the grants from before may be open again; check that it runs, " +
				"then run nodkey revoke --all again")
		case err == nil && st.Revokes > before.Revokes && st.RevokeError != "":
			return fail("the broker did not end the grants: " + claim.Line(st.RevokeError, 1000))
		case err == nil && st.Revokes > before.Revokes:
			_, _ = fmt.Fprintf(stdout, "nodkey revoke: the broker ended every grant: %d grant(s)\n", st.GrantsRevoked)
			return exitOK
		case time.Now().After(deadline):
			return fail(fmt.Sprintf("the broker did not write the result to %s within %s; read its journal "+
				"(journalctl -u nodkey), and run nodkey revoke --all again", statusPath, *timeout))
		}
	}
}
