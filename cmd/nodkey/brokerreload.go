package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/code6x/nodkey/internal/broker"
	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/doctor"
)

// The reload of the broker config without a restart (DESIGN.md section 14,
// "Reload"). SIGHUP asks the broker to load its config file again. The
// broker writes the result to the status file, next to the audit log.
// nodkey broker reload sends the signal and reads the result from there.

// reloadStatusName is the name of the status file in the directory of the
// audit log.
const reloadStatusName = "reload-status.json"

// maxReloadStatus is the largest status file that nodkey broker reload
// reads.
const maxReloadStatus = 64 << 10

// The results in the status file.
const (
	reloadStarted = "started" // the broker started; no reload yet
	reloadLoaded  = "loaded"  // the reload took the new config
	reloadRefused = "refused" // the reload refused the new config; the old one stays
)

// reloadStatus is the content of the status file.
type reloadStatus struct {
	// PID is the broker's process ID, and Start the start time of the
	// process from /proc/PID/stat (field 22). With both, nodkey broker
	// reload signals only the broker that wrote the file.
	PID   int    `json:"pid"`
	Start uint64 `json:"start"`
	// Reloads counts the reloads since the start. It is 0 at the start.
	Reloads uint64 `json:"reloads"`
	// Result is reloadStarted, reloadLoaded or reloadRefused.
	Result string `json:"result"`
	// Error says why a reload was refused. It is the broker's own text
	// about the config, never a value of a secret.
	Error string `json:"error,omitempty"`
	// ConfigSHA256 is the SHA-256 of the config file that the broker uses
	// now, in hex.
	ConfigSHA256 string `json:"config_sha256"`
	// GrantsEnded is how many grants the last reload ended.
	GrantsEnded int `json:"grants_ended"`
	// At is when the broker wrote the file, in RFC 3339.
	At string `json:"at"`
}

// reloadStatusPath returns the path of the status file of cfg.
func reloadStatusPath(cfg *config.Broker) string {
	return filepath.Join(filepath.Dir(cfg.AuditLog), reloadStatusName)
}

// writeReloadStatus writes st to the status file of b: to a new file first,
// then it renames it, so a reader never sees half a file. An error is
// logged: the broker goes on, and nodkey broker reload waits in vain and
// says so.
func (b *brokerParts) writeReloadStatus(st reloadStatus) {
	st.PID, st.Start = os.Getpid(), b.procStart
	st.At = time.Now().UTC().Format(time.RFC3339)
	data, err := json.Marshal(st)
	if err == nil {
		err = writeFileAtomic(reloadStatusPath(b.cfg), append(data, '\n'))
	}
	if err != nil {
		b.log.Error("nodkey broker: cannot write the reload status file; nodkey broker reload cannot see the "+
			"result; check the directory of the audit log", slog.String("error", err.Error()))
	}
}

// writeFileAtomic writes data to path with mode 0600 through a new file in
// the same directory, then renames it to path.
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600) //nolint:gosec // G304: the status file next to the audit log of the config.
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, path)
	}
	if werr != nil {
		_ = os.Remove(tmp)
	}
	return werr
}

// reload loads the config file again and makes it the config of the
// broker, after the checks of a start and ReloadFixed. On any error it
// changes nothing, logs why, and the broker goes on with the config it
// has. It writes the result to the status file.
func (b *brokerParts) reload(path string) {
	b.reloads++
	b.log.Info("nodkey broker: reloading the config, as SIGHUP asked", slog.String("config", path))
	cfg, ended, err := b.loadNew(path)
	if err != nil {
		b.log.Error("nodkey broker: refused the new config; the broker goes on with the config it has",
			slog.String("error", err.Error()))
		b.writeReloadStatus(reloadStatus{Reloads: b.reloads, Result: reloadRefused, Error: err.Error(),
			ConfigSHA256: b.cfg.Sum})
		return
	}
	b.cfg = cfg
	b.log.Info("nodkey broker: the new config is loaded; the grants that it still allows stay",
		slog.String("config_sha256", cfg.Sum), slog.Int("grants_ended", ended))
	b.writeReloadStatus(reloadStatus{Reloads: b.reloads, Result: reloadLoaded, ConfigSHA256: cfg.Sum,
		GrantsEnded: ended})
}

// loadNew loads the config at path and the SSH keys that it names, as a
// start does, and hands them to the server and the service. It returns the
// new config and how many grants ended.
func (b *brokerParts) loadNew(path string) (*config.Broker, int, error) {
	if b.svc == nil || b.srv == nil {
		return nil, 0, errors.New("the broker has not started")
	}
	cfg, err := config.LoadBroker(path) // it runs CheckFiles
	if err != nil {
		return nil, 0, err
	}
	if err := b.cfg.ReloadFixed(cfg); err != nil {
		return nil, 0, fmt.Errorf("config %s: %w", path, err)
	}
	keys, err := loadSSHKeys(cfg, config.ReadPrivateFile)
	if err != nil {
		return nil, 0, err
	}
	// The server first: a removed key gets no new request from now on. A
	// new client is refused by the service until it has the new config.
	if err := b.srv.SetClients(cfg.Clients); err != nil {
		return nil, 0, fmt.Errorf("config %s: %w", path, err)
	}
	ended, err := b.svc.Reload(cfg, keys, cfg.Sum)
	if err != nil && !errors.Is(err, broker.ErrNotRecorded) {
		// Nothing changed in the service: the server gets the old clients
		// back. They passed this check at the start or the last reload.
		if rerr := b.srv.SetClients(b.cfg.Clients); rerr != nil {
			b.log.Error("nodkey broker: cannot give the server its old clients back", slog.String("error", rerr.Error()))
		}
		return nil, 0, err
	}
	if err != nil {
		b.log.Error("nodkey broker: the new config is in use, but its audit entry is missing",
			slog.String("error", err.Error()))
	}
	return cfg, ended, nil
}

const brokerReloadUsage = `Usage: nodkey broker reload [--config FILE] [--timeout DURATION]

Ask the running broker to load its config again, without a restart, and
wait for the result. Run it as root, or as the broker's user, after you
changed the config. The broker loads the config file and the files that
it names, and checks them as at a start. A reload can change the
clients, the secrets, the SSH keys and known_hosts. A change of any
other part needs a restart: the reload refuses it.

When the new config is good, the broker uses it at once. Grants that the
new config still allows stay, with the same uses left and the same end.
Grants for a removed or changed client, secret or key end. When the new
config is not good, the broker goes on with the old one, and this
command prints why.

  --config FILE       the broker config (default /etc/nodkey/broker.toml)
  --timeout DURATION  how long to wait for the result (default 60s)

Exit codes: 0 the broker loaded the config that is in FILE now, 1 the
broker refused it, or did not answer in time, or the result cannot be
read, 64 wrong usage.
`

// reloadPoll is how often nodkey broker reload reads the status file.
var reloadPoll = 200 * time.Millisecond

// runBrokerReload runs nodkey broker reload.
func runBrokerReload(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey broker reload", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", defaultBrokerConfig, "the broker config")
	timeout := fs.Duration("timeout", 60*time.Second, "how long to wait")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, brokerReloadUsage)
			return exitOK
		}
		return parseErrorCode(stderr, "broker reload", err)
	}
	if fs.NArg() > 0 {
		return usageFail(stderr, "broker reload",
			fmt.Sprintf("unexpected argument %.64q; it takes only --config FILE and --timeout DURATION", fs.Arg(0)))
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return usageFail(stderr, "broker reload", "--timeout must be more than 0 and at most 1h, such as 60s")
	}
	fail := func(msg string) int {
		_, _ = fmt.Fprintf(stderr, "nodkey broker reload: %s\n", msg)
		return exitFailure
	}
	// Only the path of the audit log and the SHA-256 are needed here: the
	// broker checks the config itself. Root may not pass the checks of the
	// files that are for the broker's user.
	if os.Getenv("CREDENTIALS_DIRECTORY") == "" {
		// Outside the unit it is not set. Only this process sees the
		// value, and no file in it is read here (as in nodkey doctor
		// broker).
		_ = os.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/"+doctor.Unit)
	}
	cfg, err := config.ReadBroker(*path)
	if err != nil {
		return fail(err.Error() + "; fix the config, then run nodkey broker reload again")
	}
	statusPath := reloadStatusPath(cfg)
	before, uid, err := readReloadStatus(statusPath)
	if err != nil {
		return fail(err.Error())
	}
	if err := signalBroker(before, uid); err != nil {
		return fail(err.Error())
	}
	deadline := time.Now().Add(*timeout)
	for {
		time.Sleep(reloadPoll)
		st, _, err := readReloadStatus(statusPath)
		switch {
		case err == nil && (st.PID != before.PID || st.Start != before.Start):
			return fail("the broker restarted during the reload; check that it runs, then run nodkey broker " +
				"reload again")
		case err == nil && st.Reloads > before.Reloads:
			return reloadResult(st, cfg.Sum, *path, stdout, fail)
		case time.Now().After(deadline):
			return fail(fmt.Sprintf("the broker did not write the result to %s within %s; read its journal "+
				"(journalctl -u nodkey)", statusPath, *timeout))
		}
	}
}

// reloadResult prints the result of a reload and returns the exit code.
// want is the SHA-256 of the config file at path when the command began.
func reloadResult(st reloadStatus, want, path string, stdout io.Writer, fail func(string) int) int {
	switch {
	case st.Result == reloadRefused:
		return fail("the broker refused the new config and goes on with the old one: " + claim.Line(st.Error, 1000) +
			"; fix the config, then run nodkey broker reload again")
	case st.Result != reloadLoaded:
		return fail("the status file of the broker has a result that is not known; read its journal " +
			"(journalctl -u nodkey)")
	case st.ConfigSHA256 != want:
		return fail("the broker loaded a config that is not the one in " + path + " now: the file changed " +
			"during the reload; run nodkey broker reload again")
	}
	_, _ = fmt.Fprintf(stdout, "nodkey broker reload: the broker loaded the new config (sha256 %s); %d grant(s) "+
		"ended, the others stay\n", st.ConfigSHA256, st.GrantsEnded)
	return exitOK
}
