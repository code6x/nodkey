package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/doctor"
)

const brokerCheckUsage = `Usage: nodkey broker check [--config FILE] [--files DIR] [--credentials DIR]

Check a broker config without starting the broker: the config file, and
the files that it names, get the same checks as at a start. It starts
nothing, opens no port, and uses no network. Run it as the broker's user
(on the broker host), or as any user with --files (such as in CI).

  --config FILE       the broker config (default /etc/nodkey/broker.toml,
                      or DIR/broker.toml with --files DIR)
  --files DIR         read known_hosts from DIR, by the base name of its
                      path in the config, and not from that path; so a new
                      config is checked with its own known_hosts. The files
                      of the broker host (the TLS key, the token and key
                      files, the store programs, the audit log) are then
                      not checked
  --credentials DIR   check that each ${CREDENTIALS_DIRECTORY}/NAME of the
                      config has a file NAME or NAME.cred in DIR; nothing
                      in it is read. Without it, these files are skipped

Exit codes: 0 the config is good, 1 it is not, 64 wrong usage.
`

// checkLineMax is the most runes of one cleaned line of the output.
const checkLineMax = 2000

// runBrokerCheck runs nodkey broker check (DESIGN.md section 15).
func runBrokerCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey broker check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "the broker config")
	files := fs.String("files", "", "the directory of known_hosts")
	creds := fs.String("credentials", "", "the directory of the credentials")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, brokerCheckUsage)
			return exitOK
		}
		return parseErrorCode(stderr, "broker check", err)
	}
	if fs.NArg() > 0 {
		return usageFail(stderr, "broker check", fmt.Sprintf(
			"unexpected argument %.64q; it takes only --config FILE, --files DIR and --credentials DIR", fs.Arg(0)))
	}
	for _, f := range []struct{ name, dir string }{{"--files", *files}, {"--credentials", *creds}} {
		if f.dir == "" {
			continue
		}
		if fi, err := os.Stat(f.dir); err != nil || !fi.IsDir() {
			return usageFail(stderr, "broker check", f.name+" must name a directory that exists")
		}
	}
	if *path == "" {
		*path = defaultBrokerConfig
		if *files != "" {
			*path = filepath.Join(*files, "broker.toml")
		}
	}
	res, err := checkBrokerConfig(*path, *files, *creds)
	// A config from a pull request may hold any text, such as a line
	// break in a path. Each line is cleaned, so that it cannot add lines
	// to a CI log or change the terminal.
	for _, s := range res.skipped {
		_, _ = fmt.Fprintf(stdout, "skipped: %s\n", claim.Line(s, checkLineMax))
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey broker check: %s; fix it as the error says (docs/setup.md section 7), "+
			"then run nodkey broker check again\n", claim.Line(err.Error(), checkLineMax))
		return exitFailure
	}
	_, _ = fmt.Fprintf(stdout, "nodkey broker check: %s passed the checks of a start\n", claim.Line(*path, checkLineMax))
	return exitOK
}

// checkResult is what checkBrokerConfig did not check, in plain words.
type checkResult struct {
	skipped []string
}

// checkBrokerConfig makes the config checks of a start on the config at
// path: config.ReadBrokerFiles parses it, as config.LoadBroker does for
// the start and a reload, and (*config.Broker).CheckFilesAs checks the
// files it names, as the user that runs this command. It reads no
// credential: a ${CREDENTIALS_DIRECTORY}/ file is skipped, or with
// credDir only found in credDir. With filesDir, known_hosts comes from
// filesDir, and the files of the broker host are not checked.
func checkBrokerConfig(path, filesDir, credDir string) (checkResult, error) {
	var res checkResult
	// ${CREDENTIALS_DIRECTORY} stands for credDir, or for the directory
	// of the unit. Only this process sees the value; a value from the
	// environment is not trusted (as in nodkey doctor broker).
	dir := "/run/credentials/" + doctor.Unit
	if credDir != "" {
		abs, err := filepath.Abs(credDir)
		if err != nil {
			return res, fmt.Errorf("--credentials %s: %w", credDir, err)
		}
		dir = abs
	}
	if err := os.Setenv("CREDENTIALS_DIRECTORY", dir); err != nil {
		return res, fmt.Errorf("cannot set CREDENTIALS_DIRECTORY: %w", err)
	}
	cfg, err := config.ReadBrokerFiles(path, filesDir)
	if err != nil {
		return res, err
	}
	private, err := cfg.PrivateFiles()
	if err != nil {
		return res, err
	}
	inCreds := func(p string) (string, bool) { return strings.CutPrefix(p, dir+"/") }
	for _, f := range private {
		name, ok := inCreds(f.Path)
		switch {
		case !ok:
			if filesDir != "" {
				res.skipped = append(res.skipped, f.Where+": a file of the broker host; --files checks only the "+
					"config and known_hosts")
			}
		case !filepath.IsLocal(name):
			return res, fmt.Errorf("config %s: %s: the path leaves ${CREDENTIALS_DIRECTORY}; write it as "+
				"${CREDENTIALS_DIRECTORY}/NAME, with no \"..\"", path, f.Where)
		case credDir == "":
			res.skipped = append(res.skipped, fmt.Sprintf("%s: needs the credential %q; give --credentials DIR "+
				"to check that it is there", f.Where, name))
		default:
			if err := credentialThere(dir, name); err != nil {
				return res, fmt.Errorf("config %s: %s: %w", path, f.Where, err)
			}
		}
	}
	if filesDir != "" {
		res.skipped = append(res.skipped, "the store programs and audit_log: files of the broker host; "+
			"--files checks only the config and known_hosts")
		return res, nil
	}
	self := uint32(os.Getuid()) //nolint:gosec // G115: a user ID fits in 32 bits on Linux.
	skip := func(p string) bool { _, ok := inCreds(p); return ok }
	return res, cfg.CheckFilesAs(self, skip)
}

// credentialThere checks that dir has a regular file name or name.cred.
// It reads nothing in it. name must pass filepath.IsLocal.
func credentialThere(dir, name string) error {
	for _, n := range []string{name, name + ".cred"} {
		fi, err := os.Stat(filepath.Join(dir, n))
		switch {
		case err == nil && fi.Mode().IsRegular():
			return nil
		case err == nil:
			return fmt.Errorf("the credential %q in %s is not a regular file; put the encrypted credential there", n, dir)
		case !errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("cannot look for the credential %q in %s as this user (%w); give --credentials a "+
				"directory that this user can enter, or check the credentials with nodkey doctor broker, as root",
				n, dir, errors.Unwrap(err))
		}
	}
	return fmt.Errorf("the credential %q is not in %s: there is no file %q or %q; make it as docs/setup.md "+
		"section 3 shows", name, dir, name, name+".cred")
}
