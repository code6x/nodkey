package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/code6x/nodkey"
)

const updateUsage = `Usage: nodkey update [--version X.Y.Z] [--gh PATH] [--reinstall | --notes]

Install the newest release of nodkey in place of the file of this nodkey,
or the release X.Y.Z. Run it as root.

It runs the install script that is built into this nodkey (install.sh of
the repository). So the code that checks the new release comes from the
build that you installed and checked before, not fresh from the network.
Before it replaces the file, the script checks the SHA-256 and the build
attestation of the release, and the version of the new nodkey. It
restarts nothing. Then restart the broker (systemctl restart nodkey,
which ends all grants) and each nodkey ssh-agent. After an update to a
newer version, it prints the changes since the old version.

With --notes, it downloads and checks the release in the same way, but
installs nothing: it runs the new, checked nodkey to print the changes
since this version (nodkey changes), with the security fixes first.

  --version X.Y.Z  install this release, also one older than this nodkey
  --gh PATH        check the attestation with this gh, 2.93.0 or newer,
                   which only root can change (default: download gh and
                   check its SHA-256)
  --reinstall      install also when this version is installed already
  --notes          install nothing; print the changes of the checked
                   release since this version

Exit codes: 0 done or nothing to do, 1 failure, 64 wrong usage.
`

// scriptPath is the PATH of the install script: only the programs of the
// system.
const scriptPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// proxyVars are the only variables of the environment of nodkey that the
// install script gets, if they are set: curl and gh may need a proxy to
// reach GitHub.
var proxyVars = []string{"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"}

// The parts of nodkey update that a test replaces. nodkey never changes
// them.
var (
	// geteuid returns the effective user ID, so that a test can run
	// nodkey update as if it were root.
	geteuid = os.Geteuid
	// executable returns the path of this program, as os.Executable does.
	executable = os.Executable
	// runInstallScript runs the install script with the arguments and the
	// environment, and returns its exit code, as runScript does.
	runInstallScript = runScript
)

// versionPattern is a version X.Y.Z, as install.sh accepts it: three
// numbers of at most 9 digits, without a leading zero.
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// checkedFlag is a flag of nodkey update that may be given once, and
// whose value must pass check.
type checkedFlag struct {
	value string
	set   bool
	check func(string) error
}

func (f *checkedFlag) String() string { return f.value }

func (f *checkedFlag) Set(s string) error {
	if f.set {
		return errors.New("give it once")
	}
	if err := f.check(s); err != nil {
		return err
	}
	f.value, f.set = s, true
	return nil
}

// runUpdate runs nodkey update (DESIGN.md section 15). As root, it runs
// the install script that is built into this binary, so that the script
// replaces the file of this program with a release.
func runUpdate(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("nodkey update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	want := checkedFlag{check: func(s string) error {
		if !versionPattern.MatchString(s) {
			return errors.New("want X.Y.Z, such as 0.2.0")
		}
		return nil
	}}
	flags.Var(&want, "version", "install the release `X.Y.Z`")
	gh := checkedFlag{check: func(s string) error {
		if !filepath.IsAbs(s) {
			return errors.New("want an absolute path")
		}
		return nil
	}}
	flags.Var(&gh, "gh", "check the attestation with the gh at `PATH`")
	reinstall := flags.Bool("reinstall", false, "install also when this version is installed already")
	notes := flags.Bool("notes", false, "install nothing; print the changes of the checked release")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stderr, updateUsage)
		}
		return parseErrorCode(stderr, "update", err)
	}
	if flags.NArg() > 0 {
		return usageFail(stderr, "update", fmt.Sprintf("unexpected argument %.64q", flags.Arg(0)))
	}
	if *reinstall && *notes {
		return usageFail(stderr, "update", "--notes installs nothing, so it does not go with --reinstall")
	}
	if geteuid() != 0 {
		return fail(stderr, exitFailure, "nodkey update must run as root: run it as root")
	}
	exe, err := executable()
	if err != nil {
		return fail(stderr, exitFailure, fmt.Sprintf("cannot find the file of this program: %v", err))
	}
	// The script replaces DIR/nodkey. When the program was started
	// through a link, that is the file that the link points to.
	path, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fail(stderr, exitFailure, fmt.Sprintf("cannot find the file of this program: %v", err))
	}
	if filepath.Base(path) != "nodkey" {
		return fail(stderr, exitFailure, fmt.Sprintf("nodkey update replaces only a file named nodkey, and this program is %s", path))
	}
	// Only these arguments go to the script, and nothing from the
	// environment. The script checks that only root can change the
	// directory, the old file and the gh.
	scriptArgs := []string{"--bin-dir", filepath.Dir(path)}
	if want.set {
		scriptArgs = append(scriptArgs, "--version", want.value)
	}
	if gh.set {
		scriptArgs = append(scriptArgs, "--gh", gh.value)
	}
	if *reinstall {
		scriptArgs = append(scriptArgs, "--reinstall")
	}
	if *notes {
		scriptArgs = append(scriptArgs, "--notes")
	}
	return runInstallScript(nodkey.InstallScript, scriptArgs, scriptEnv(), stdout, stderr)
}

// scriptEnv returns the environment of the install script. It is fixed:
// with sudo -E, or after su without -, the environment of root can come
// from another user, and variables such as TAR_OPTIONS, LD_PRELOAD or
// TMPDIR would change what the programs of the script do as root. Only
// the proxy variables of nodkey go on, if they are set.
func scriptEnv() []string {
	env := []string{"PATH=" + scriptPath, "LC_ALL=C", "HOME=/root"}
	for _, name := range proxyVars {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// runScript runs script with /bin/sh, with "nodkey-install" as $0, args as
// its arguments and env as its environment. stdin is /dev/null, and stdout
// and stderr are those of nodkey. It returns the exit code of the script.
func runScript(script string, args, env []string, stdout, stderr io.Writer) int {
	cmd := exec.CommandContext(context.Background(), "/bin/sh", append([]string{"-c", script, "nodkey-install"}, args...)...) //nolint:gosec // G204: the script is built into nodkey; the arguments are --bin-dir with the directory of this program, and the checked flags.
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &exit) && exit.ExitCode() >= 0:
		return exit.ExitCode()
	case errors.As(err, &exit):
		return fail(stderr, exitFailure, "a signal stopped the install script")
	default:
		return fail(stderr, exitFailure, fmt.Sprintf("cannot run the install script: %v", err))
	}
}
