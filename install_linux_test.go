package nodkey

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The tests of install.sh run it with /bin/sh against fakes, and never use
// the network:
//
//   - a fake curl, first in PATH, serves https://HOST/PATH from the file
//     web/HOST/PATH of the test, and writes down each call;
//   - a fake uname says which system and CPU this is;
//   - a fake gh, given with --gh, writes down its arguments and its
//     environment, and says that the attestation is valid or not.
//
// After a run that fails, the bin directory must be as before, and the
// temporary directory of the script must be gone.
//
// As root, the script runs only the programs of the system, so the fakes
// in PATH would not count, and curl would use the network. So these tests
// do not run as root. The checks that only root makes are tested with the
// functions of the script (TestInstallChecksAsRoot).

// Paths on the fake GitHub, without "https://".
const (
	latestPath  = "api.github.com/repos/code6x/nodkey/releases/latest"
	releasePath = "github.com/code6x/nodkey/releases/download/v" // and VERSION/FILE
	ghPath      = "github.com/cli/cli/releases/download/v"       // and VERSION/FILE
)

// certIdentity is the identity of the release workflow (docs/releasing.md).
const certIdentity = "https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main"

// tokenVars are the variables that must not reach gh.
var tokenVars = []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// unsafeVars are variables that change what the programs of the script do.
// The script removes them (clean_env). LD_PRELOAD and LD_AUDIT are on the
// list of the script too, but the dynamic loader would complain about the
// made-up values here, so the tests leave them out.
var unsafeVars = []string{"GZIP", "POSIXLY_CORRECT", "CURL_HOME", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
	"SSLKEYLOGFILE", "OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "LD_LIBRARY_PATH", "GCONV_PATH", "CDPATH"}

// The size limits of the downloads in install.sh.
const (
	maxSmall = "1048576"  // the answer of the API, SHA256SUMS, the bundle
	maxBig   = "67108864" // the tarballs
)

const fakeCurl = `#!/bin/sh
# A fake curl. It serves https://HOST/PATH from $FAKE_WEB/HOST/PATH into the
# file of --output, at most --max-filesize bytes. It writes down its
# arguments: one call, one line.
printf '%s\n' "$*" >>"$FAKE_LOGS/curl"
out=
max=
url=
while [ "$#" -gt 0 ]; do
	case $1 in
	--output)
		out=$2
		shift
		;;
	--max-filesize)
		max=$2
		shift
		;;
	esac
	url=$1
	shift
done
case $url in
https://*) ;;
*)
	echo "fake curl: not HTTPS: $url" >&2
	exit 1
	;;
esac
file=$FAKE_WEB/${url#https://}
if [ ! -f "$file" ]; then
	echo "curl: (22) The requested URL returned error: 404" >&2
	exit 22
fi
if [ -n "$max" ] && [ "$(wc -c <"$file")" -gt "$max" ]; then
	echo "curl: (63) Maximum file size exceeded" >&2
	exit 63
fi
cp "$file" "$out"
`

const fakeUname = `#!/bin/sh
# A fake uname: the system and the CPU of the test.
case $1 in
-s) echo "${FAKE_UNAME_S:-Linux}" ;;
-m) echo "${FAKE_UNAME_M:-x86_64}" ;;
*) exit 1 ;;
esac
`

const fakeGh = `#!/bin/sh
# A fake gh. It writes down each call, one a line, its own path, and the
# environment of each kind of call. For --version, it prints the version
# $FAKE_GH_VERSION, or exits with $FAKE_GH_VERSION_EXIT. For attestation
# verify, it writes down its arguments, keeps a copy of the file and of the
# bundle to check, and exits with $FAKE_GH_EXIT. With $FAKE_GH_WAIT, it
# makes that file instead, and waits.
printf '%s\n' "$*" >>"$FAKE_LOGS/gh"
printf '%s\n' "$0" >"$FAKE_LOGS/gh-path"
env >"$FAKE_LOGS/gh-env-$1"
if [ "$1" = --version ]; then
	if [ -n "${FAKE_GH_VERSION_EXIT:-}" ]; then
		exit "$FAKE_GH_VERSION_EXIT"
	fi
	echo "gh version ${FAKE_GH_VERSION:-2.102.0} (2026-09-30)"
	echo "https://github.com/cli/cli/releases/tag/v${FAKE_GH_VERSION:-2.102.0}"
	exit 0
fi
printf '%s\n' "$@" >"$FAKE_LOGS/gh-args"
cp "$3" "$FAKE_LOGS/gh-file" || exit 2
cp "$5" "$FAKE_LOGS/gh-bundle" || exit 2
if [ -n "${FAKE_GH_WAIT:-}" ]; then
	: >"$FAKE_GH_WAIT"
	exec sleep 60
fi
exit "${FAKE_GH_EXIT:-0}"
`

// fakeNodkey returns a fake nodkey. "nodkey version" prints the lines.
// The note tells copies apart, such as the CPU of a tarball. Each run
// writes the note to $FAKE_LOGS/nodkey-runs, so a test can see which
// copies ran.
func fakeNodkey(note string, lines ...string) []byte {
	return fmt.Appendf(nil, "#!/bin/sh\n# A fake nodkey (%s).\necho '%s' >>\"$FAKE_LOGS/nodkey-runs\"\n"+
		"if [ \"$1\" = version ]; then\n\tprintf '%%s\\n' '%s'\nfi\n",
		note, note, strings.Join(lines, "' '"))
}

// failingNodkey is a fake nodkey that does not run.
var failingNodkey = []byte("#!/bin/sh\necho 'cannot run' >&2\nexit 1\n")

// says returns the fake nodkey of each CPU of a release, for
// installer.release.
func says(lines ...string) func(arch string) []byte {
	return func(arch string) []byte { return fakeNodkey(arch, lines...) }
}

// tarFile is a file in a tarball of tarGz.
type tarFile struct {
	name string
	mode int64
	data []byte
}

// tarGz returns a tar.gz file with these files.
func tarGz(t *testing.T, files ...tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		hdr := &tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.data)), ModTime: time.Unix(1_760_000_000, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// installer runs install.sh against fakes.
type installer struct {
	t      *testing.T
	dir    string   // the working directory of the script
	script string   // the path of the script
	web    string   // the files of the fake GitHub
	bin    string   // the directory of --bin-dir
	tmp    string   // TMPDIR of the script: it must be empty after each run
	logs   string   // what the fake programs write down
	fakes  string   // the fake curl and uname, first in PATH
	gh     string   // the fake gh, for --gh
	binArg string   // the value of --bin-dir, if it is not bin
	env    []string // more environment for the script
}

func newInstaller(t *testing.T) *installer {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("as root, install.sh runs only the programs of the system, not the fakes of the test")
	}
	for _, name := range []string{"sed", "tar", "gzip", "sha256sum", "install", "mktemp", "id", "stat", "cp", "env", "wc", "sleep"} {
		if _, err := exec.LookPath(name); err != nil {
			skipOrFail(t, "%s is not installed", name)
		}
	}
	script, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	// The script refuses a directory that group or others can write to.
	// Under a umask such as 002, t.TempDir is one.
	dir := privateDir(t)
	in := &installer{
		t:      t,
		dir:    dir,
		script: script,
		web:    filepath.Join(dir, "web"),
		bin:    filepath.Join(dir, "bin"),
		tmp:    filepath.Join(dir, "tmp"),
		logs:   filepath.Join(dir, "logs"),
		fakes:  filepath.Join(dir, "fakes"),
		gh:     filepath.Join(dir, "gh"),
	}
	for _, d := range []string{in.web, in.bin, in.tmp, in.logs, in.fakes} {
		mkdir(t, d, 0o700)
	}
	writeFile(t, filepath.Join(in.fakes, "curl"), []byte(fakeCurl), 0o700)
	writeFile(t, filepath.Join(in.fakes, "uname"), []byte(fakeUname), 0o700)
	writeFile(t, in.gh, []byte(fakeGh), 0o700)
	if exec.CommandContext(t.Context(), filepath.Join(in.fakes, "uname"), "-s").Run() != nil { //nolint:gosec // G204: a program that the test wrote.
		skipOrFail(t, "a program in the temporary directory %s cannot run", dir)
	}
	return in
}

// privateDir returns a new temporary directory with mode 0700, by its path
// without links: the script prints such paths.
func privateDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory, private to its owner.
		t.Fatal(err)
	}
	return dir
}

// mkdir makes the directory path with exactly mode.
func mkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// latest makes the answer of the fake GitHub API for the newest release,
// in the form of the real one.
func (in *installer) latest(tag string) {
	in.serve(latestPath, fmt.Appendf(nil, "{\n  \"url\": \"https://api.github.com/repos/code6x/nodkey/releases/1\",\n"+
		"  \"tag_name\": %q,\n  \"name\": %q,\n  \"draft\": false\n}\n", tag, tag))
}

// release puts a release on the fake GitHub: for each CPU a tarball with
// nodkey, LICENSE and README.md, and SHA256SUMS and the bundle. nodkey
// returns the file nodkey of each CPU. release returns the tarballs.
func (in *installer) release(version string, nodkey func(arch string) []byte) map[string][]byte {
	tarballs := map[string][]byte{}
	var sums strings.Builder
	for _, arch := range []string{"amd64", "arm64"} {
		name := "nodkey_" + version + "_linux_" + arch + ".tar.gz"
		tarballs[arch] = tarGz(in.t,
			tarFile{"nodkey", 0o755, nodkey(arch)},
			tarFile{"LICENSE", 0o644, []byte("a made-up license\n")},
			tarFile{"README.md", 0o644, []byte("# a made-up readme\n")})
		in.serve(releasePath+version+"/"+name, tarballs[arch])
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(tarballs[arch]), name)
	}
	in.serve(releasePath+version+"/SHA256SUMS", []byte(sums.String()))
	in.serve(releasePath+version+"/nodkey_"+version+".sigstore.json", []byte(bundle(version)))
	return tarballs
}

// bundle is the made-up bundle of a release.
func bundle(version string) string {
	return `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "release": "` + version + `"}` + "\n"
}

// ghRelease puts a tarball of gh 2.102.0 for amd64 on the fake GitHub,
// with the fake gh in it. It returns the SHA-256 of the tarball, in hex.
func (in *installer) ghRelease() string {
	data := tarGz(in.t,
		tarFile{"gh_2.102.0_linux_amd64/LICENSE", 0o644, []byte("a made-up license\n")},
		tarFile{"gh_2.102.0_linux_amd64/bin/gh", 0o755, []byte(fakeGh)})
	in.serve(ghPath+"2.102.0/gh_2.102.0_linux_amd64.tar.gz", data)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// serve puts a file at https://path on the fake GitHub.
func (in *installer) serve(path string, data []byte) {
	in.t.Helper()
	file := filepath.Join(in.web, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		in.t.Fatal(err)
	}
	writeFile(in.t, file, data, 0o600)
}

// unserve removes the file at https://path from the fake GitHub.
func (in *installer) unserve(path string) {
	in.t.Helper()
	if err := os.Remove(filepath.Join(in.web, filepath.FromSlash(path))); err != nil {
		in.t.Fatal(err)
	}
}

// installed makes data the installed nodkey.
func (in *installer) installed(data []byte) {
	writeFile(in.t, filepath.Join(in.bin, "nodkey"), data, 0o755)
}

// result is the end of a run of the script.
type result struct {
	code           int
	stdout, stderr string
}

// run runs the script with the arguments.
func (in *installer) run(args ...string) result {
	in.t.Helper()
	return runCmd(in.t, in.command(args...))
}

// runCmd runs cmd, and returns its exit code and output.
func runCmd(t *testing.T, cmd *exec.Cmd) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("cannot run %s: %v", cmd.Path, err)
	}
	return result{cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()}
}

// command returns the command that runs the script with --bin-dir of the
// test and then args, with stdin from /dev/null. A --bin-dir in args
// comes later, so it counts.
func (in *installer) command(args ...string) *exec.Cmd {
	bin := in.bin
	if in.binArg != "" {
		bin = in.binArg
	}
	cmd := exec.CommandContext(in.t.Context(), "/bin/sh", append([]string{in.script, "--bin-dir", bin}, args...)...) //nolint:gosec // G204: the test runs install.sh with its own arguments.
	cmd.Dir = in.dir
	cmd.Env = append([]string{
		"PATH=" + in.fakes + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + in.dir,
		"TMPDIR=" + in.tmp,
		"FAKE_WEB=" + in.web,
		"FAKE_LOGS=" + in.logs,
	}, in.env...)
	return cmd
}

// files returns the mode and the content of each file in dir, by name: a
// link has its target, and a directory or another kind of file has only
// its mode.
func files(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, e.Name())
		got[e.Name()] = info.Mode().String()
		switch {
		case info.Mode().IsRegular():
			got[e.Name()] += " " + string(readFile(t, path))
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				t.Fatal(err)
			}
			got[e.Name()] += " -> " + target
		}
	}
	return got
}

// checkTmpGone checks that the temporary directory of the script is gone.
func (in *installer) checkTmpGone() {
	in.t.Helper()
	if left := files(in.t, in.tmp); len(left) != 0 {
		in.t.Errorf("the temporary directory is still there: %v", slices.Sorted(maps.Keys(left)))
	}
}

// checkFailed checks a run that must fail with code and a last line that
// holds want, and that it changed nothing in the bin directory.
func (in *installer) checkFailed(r result, code int, want string, before map[string]string) {
	in.t.Helper()
	end := " (exit " + strconv.Itoa(code) + ")\n"
	if code == 1 {
		end = "; nothing was installed" + end
	}
	last := lastLine(r.stderr)
	if r.code != code || !strings.HasPrefix(last, "nodkey: ") || !strings.Contains(last, want) || !strings.HasSuffix(last, end) {
		in.t.Errorf("exit code %d, last line %q; want %d and a line with %q and %q\nstdout:\n%s\nstderr:\n%s",
			r.code, last, code, want, end, r.stdout, r.stderr)
	}
	if after := files(in.t, in.bin); !maps.Equal(after, before) {
		in.t.Errorf("the bin directory changed: %v, before %v", slices.Sorted(maps.Keys(after)), slices.Sorted(maps.Keys(before)))
	}
	in.checkTmpGone()
}

// curlCalls returns the arguments of each call of curl.
func (in *installer) curlCalls() [][]string {
	in.t.Helper()
	var calls [][]string
	for _, line := range in.log("curl") {
		calls = append(calls, strings.Fields(line))
	}
	return calls
}

// urls returns the URL of each call of curl, in order.
func (in *installer) urls() []string {
	in.t.Helper()
	var urls []string
	for _, call := range in.curlCalls() {
		urls = append(urls, call[len(call)-1])
	}
	return urls
}

// log returns the lines that a fake wrote to the log name, or none.
func (in *installer) log(name string) []string {
	in.t.Helper()
	data, err := os.ReadFile(filepath.Join(in.logs, name)) //nolint:gosec // G304: a file in the test's own directory.
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		in.t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// ghChecked reports whether gh attestation verify ran.
func (in *installer) ghChecked() bool {
	return in.log("gh-args") != nil
}

// releaseURLs are the URLs of the files of a release, for amd64.
func releaseURLs(version string) []string {
	base := "https://" + releasePath + version + "/"
	return []string{base + "nodkey_" + version + "_linux_amd64.tar.gz", base + "SHA256SUMS", base + "nodkey_" + version + ".sigstore.json"}
}

const latestURL = "https://" + latestPath

// TestInstall installs a release where no nodkey is, and checks how the
// script ran curl and gh.
func TestInstall(t *testing.T) {
	in := newInstaller(t)
	in.latest("v0.2.0")
	in.release("0.2.0", says("nodkey 0.2.0"))
	// Tokens, a host and other places for the config of gh: none of them
	// may reach gh.
	token := "made-up-token-" + rand.Text()
	for _, name := range tokenVars {
		in.env = append(in.env, name+"="+token)
	}
	in.env = append(in.env, "GH_CONFIG_DIR=/nonexistent/gh", "XDG_CONFIG_HOME=/nonexistent/config",
		"XDG_CACHE_HOME=/nonexistent/cache", "XDG_DATA_HOME=/nonexistent/data", "XDG_STATE_HOME=/nonexistent/state")
	// Variables that change what the programs do: the script removes
	// them. Through TAR_OPTIONS, tar would run a command.
	ran := filepath.Join(in.dir, "tar-ran-a-command")
	in.env = append(in.env, "TAR_OPTIONS=--checkpoint=1 --checkpoint-action=exec=touch "+ran, "LC_ALL=de_DE.UTF-8")
	for _, name := range unsafeVars {
		in.env = append(in.env, name+"=/nonexistent/made-up")
	}

	r := in.run("--gh", in.gh)
	if r.code != 0 {
		t.Fatalf("exit code %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	// Only nodkey of amd64 is in the bin directory, with mode 0755.
	want := map[string]string{"nodkey": "-rwxr-xr-x " + string(fakeNodkey("amd64", "nodkey 0.2.0"))}
	if got := files(t, in.bin); !maps.Equal(got, want) {
		t.Errorf("the bin directory holds %q, want %q", got, want)
	}
	in.checkTmpGone()
	for _, s := range []string{"Installing nodkey 0.2.0 as " + in.bin + "/nodkey.", "version says: nodkey 0.2.0",
		"systemctl restart nodkey", "A restart ends all grants", "each nodkey ssh-agent"} {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("stdout does not say %q:\n%s", s, r.stdout)
		}
	}
	if _, err := os.Lstat(ran); err == nil {
		t.Error("tar ran the command of TAR_OPTIONS")
	}

	// curl: the newest release, then the files of the release, each with
	// no .curlrc, over HTTPS only, with TLS 1.2 or newer, failing on an
	// HTTP error, with retries, a time limit and a size limit.
	wantURLs := append([]string{latestURL}, releaseURLs("0.2.0")...)
	if got := in.urls(); !slices.Equal(got, wantURLs) {
		t.Errorf("curl got the URLs\n%q\nwant\n%q", got, wantURLs)
	}
	for i, call := range in.curlCalls() {
		if call[0] != "-q" {
			t.Errorf("a call of curl does not start with -q, so curl reads .curlrc: %q", call)
		}
		limit := maxSmall
		if strings.HasSuffix(call[len(call)-1], ".tar.gz") {
			limit = maxBig
		}
		for _, want := range [][]string{{"--proto", "=https"}, {"--proto-redir", "=https"}, {"--tlsv1.2"}, {"--fail"},
			{"--retry", "3"}, {"--max-time", "600"}, {"--max-filesize", limit}} {
			if !slices.ContainsFunc(windows(call, len(want)), func(w []string) bool { return slices.Equal(w, want) }) {
				t.Errorf("call %d of curl has no %q: %q", i, want, call)
			}
		}
	}

	// gh: its version, then the check with the identity of
	// docs/releasing.md, of the file that the script downloaded.
	if got, want := in.log("gh"), []string{"--version", "attestation verify"}; len(got) != 2 || got[0] != want[0] || !strings.HasPrefix(got[1], want[1]) {
		t.Fatalf("calls of gh: %q, want --version and then attestation verify", got)
	}
	args := in.log("gh-args")
	if len(args) < 3 {
		t.Fatalf("gh got %q", args)
	}
	tmp := filepath.Dir(args[2]) // the temporary directory of the script
	if filepath.Dir(tmp) != in.tmp || !strings.HasPrefix(filepath.Base(tmp), "nodkey-install.") {
		t.Errorf("gh checked %s, not a file in a new directory in TMPDIR %s", args[2], in.tmp)
	}
	wantArgs := []string{"attestation", "verify", filepath.Join(tmp, "nodkey_0.2.0_linux_amd64.tar.gz"),
		"--bundle", filepath.Join(tmp, "nodkey_0.2.0.sigstore.json"),
		"--repo", "code6x/nodkey", "--cert-identity", certIdentity, "--deny-self-hosted-runners"}
	if !slices.Equal(args, wantArgs) {
		t.Errorf("gh got the arguments\n%q\nwant\n%q", args, wantArgs)
	}
	served := readFile(t, filepath.Join(in.web, releasePath+"0.2.0", "nodkey_0.2.0_linux_amd64.tar.gz"))
	if checked := readFile(t, filepath.Join(in.logs, "gh-file")); !bytes.Equal(checked, served) {
		t.Error("gh checked another file than the tarball of the release")
	}
	if checked := readFile(t, filepath.Join(in.logs, "gh-bundle")); string(checked) != bundle("0.2.0") {
		t.Errorf("gh checked with the bundle %q, want %q", checked, bundle("0.2.0"))
	}

	// The environment of gh, for both calls: no token and no host, its
	// home, config and XDG directories in the temporary directory, no
	// update notices, prompts or telemetry, LC_ALL=C, and none of the
	// unsafe variables.
	for _, call := range []string{"--version", "attestation"} {
		env := readEnv(t, filepath.Join(in.logs, "gh-env-"+call))
		for _, name := range append(slices.Clone(tokenVars), append([]string{"TAR_OPTIONS"}, unsafeVars...)...) {
			if v, ok := env[name]; ok {
				t.Errorf("gh %s got %s (%d bytes)", call, name, len(v))
			}
		}
		for name, value := range env {
			if strings.Contains(value, token) {
				t.Errorf("gh %s got the token in %s", call, name)
			}
		}
		if env["HOME"] != filepath.Join(tmp, "home") {
			t.Errorf("gh %s got HOME=%q, want %q", call, env["HOME"], filepath.Join(tmp, "home"))
		}
		for _, name := range []string{"GH_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"} {
			if !strings.HasPrefix(env[name], tmp+"/") {
				t.Errorf("gh %s got %s=%q, want a directory in %s", call, name, env[name], tmp)
			}
		}
		for name, want := range map[string]string{"GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
			"GH_PROMPT_DISABLED": "1", "GH_TELEMETRY": "false", "LC_ALL": "C"} {
			if env[name] != want {
				t.Errorf("gh %s got %s=%q, want %q", call, name, env[name], want)
			}
		}
	}
}

// TestInstallReplaces replaces an installed nodkey: an older version, one
// whose version is not known, the same one with --reinstall, and with
// --version an older one. It also installs with paths that the script
// takes as safe.
func TestInstallReplaces(t *testing.T) {
	all := append([]string{latestURL}, releaseURLs("0.2.0")...)
	for _, tt := range []struct {
		name      string
		installed []byte              // the nodkey that is installed before
		setup     func(in *installer) // more changes before the run
		args      []string            // after --gh
		arch      string              // the CPU of the tarball that must be installed
		say       string              // a part of stdout
		urls      []string            // what curl gets
	}{
		{name: "an older version", installed: fakeNodkey("installed", "nodkey 0.1.0"), arch: "amd64",
			say: "Updating BIN/nodkey from nodkey 0.1.0 to nodkey 0.2.0.", urls: all},
		{name: "a build from the source", installed: fakeNodkey("installed", "nodkey dev"), arch: "amd64",
			say: "BIN/nodkey has an unknown version. nodkey 0.2.0 will replace it.", urls: all},
		{name: "a build of a commit", installed: fakeNodkey("installed", "nodkey 1a2b3c4"), arch: "amd64",
			say: "has an unknown version", urls: all},
		{name: "a file that does not run", installed: failingNodkey, arch: "amd64", say: "has an unknown version", urls: all},
		{name: "the same version, with --reinstall", installed: fakeNodkey("installed", "nodkey 0.2.0"),
			args: []string{"--reinstall"}, arch: "amd64",
			say: "Installing nodkey 0.2.0 again as BIN/nodkey, as --reinstall asks.", urls: all},
		{name: "a newer version, with --version", installed: fakeNodkey("installed", "nodkey 0.3.0"),
			args: []string{"--version", "0.2.0"}, arch: "amd64",
			say: "Replacing nodkey 0.3.0 with the older nodkey 0.2.0, as --version asks.", urls: releaseURLs("0.2.0")},
		{name: "on arm64", setup: env("FAKE_UNAME_M=aarch64"), arch: "arm64", say: "Installing nodkey 0.2.0",
			urls: []string{latestURL, "https://" + releasePath + "0.2.0/nodkey_0.2.0_linux_arm64.tar.gz",
				"https://" + releasePath + "0.2.0/SHA256SUMS", "https://" + releasePath + "0.2.0/nodkey_0.2.0.sigstore.json"}},
		{name: "on amd64, when uname -m says amd64", setup: env("FAKE_UNAME_M=amd64"), arch: "amd64",
			say: "Installing nodkey 0.2.0", urls: all},
		{name: "with gh 2.93.0, the oldest that counts", setup: env("FAKE_GH_VERSION=2.93.0"), arch: "amd64",
			say: "with gh 2.93.0.", urls: all},
		// A directory with the sticky bit, as /tmp, may let others write.
		{name: "a TMPDIR with the sticky bit", setup: func(in *installer) {
			in.tmp = filepath.Join(in.dir, "shared-tmp")
			mkdir(in.t, in.tmp, 0o777|os.ModeSticky)
		}, arch: "amd64", say: "Installing nodkey 0.2.0", urls: all},
		{name: "a bin directory in a directory with the sticky bit", setup: func(in *installer) {
			mkdir(in.t, filepath.Join(in.dir, "shared"), 0o777|os.ModeSticky)
			in.bin = filepath.Join(in.dir, "shared", "bin")
			mkdir(in.t, in.bin, 0o755)
		}, arch: "amd64", say: "Installing nodkey 0.2.0", urls: all},
		// A link in the path of the bin directory is followed once, and the
		// script uses the real path from then on.
		{name: "a bin directory behind a link", setup: func(in *installer) {
			in.binArg = filepath.Join(in.dir, "bin-link")
			if err := os.Symlink(in.bin, in.binArg); err != nil {
				in.t.Fatal(err)
			}
		}, arch: "amd64", say: "Installing nodkey 0.2.0 as BIN/nodkey.", urls: all},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := newInstaller(t)
			in.latest("v0.2.0")
			in.release("0.2.0", says("nodkey 0.2.0"))
			if tt.installed != nil {
				in.installed(tt.installed)
			}
			if tt.setup != nil {
				tt.setup(in)
			}
			r := in.run(append([]string{"--gh", in.gh}, tt.args...)...)
			if r.code != 0 {
				t.Fatalf("exit code %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
			}
			want := map[string]string{"nodkey": "-rwxr-xr-x " + string(fakeNodkey(tt.arch, "nodkey 0.2.0"))}
			if got := files(t, in.bin); !maps.Equal(got, want) {
				t.Errorf("the bin directory holds %q, want %q", got, want)
			}
			if say := strings.ReplaceAll(tt.say, "BIN", in.bin); !strings.Contains(r.stdout, say) {
				t.Errorf("stdout does not say %q:\n%s", say, r.stdout)
			}
			if got := in.urls(); !slices.Equal(got, tt.urls) {
				t.Errorf("curl got the URLs\n%q\nwant\n%q", got, tt.urls)
			}
			in.checkTmpGone()
		})
	}
}

// TestInstallNothingToDo: the version is installed already, or the
// installed one is newer and --version does not ask for the older one.
// The script exits with 0, downloads no release and changes nothing. It
// says that it did not check the installed file.
func TestInstallNothingToDo(t *testing.T) {
	for _, tt := range []struct {
		name      string
		installed string
		args      []string
		say       string
		urls      []string
	}{
		{"the newest release", "0.2.0", nil, "BIN/nodkey says that it is nodkey 0.2.0 already. Nothing to do.\n" +
			"This did not check the installed file. To replace it with a checked copy, run this again with --reinstall.",
			[]string{latestURL}},
		{"the version of --version", "0.2.0", []string{"--version", "0.2.0"}, "says that it is nodkey 0.2.0 already", nil},
		{"a newer version", "0.3.0", nil,
			"BIN/nodkey says that it is nodkey 0.3.0, which is newer than 0.2.0, the newest release. Nothing to do.\n" +
				"This did not check the installed file. To install 0.2.0 anyway, run this again with --version 0.2.0.",
			[]string{latestURL}},
		{"a newer version in the second number", "0.10.0", nil, "which is newer than 0.2.0", []string{latestURL}},
		{"a newer version in the first number", "1.0.0", nil, "which is newer than 0.2.0", []string{latestURL}},
		{"a newer version, with --reinstall", "0.3.0", []string{"--reinstall"}, "which is newer than 0.2.0", []string{latestURL}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := newInstaller(t)
			in.latest("v0.2.0")
			in.release("0.2.0", says("nodkey 0.2.0"))
			in.installed(fakeNodkey("installed", "nodkey "+tt.installed))
			before := files(t, in.bin)
			r := in.run(append([]string{"--gh", in.gh}, tt.args...)...)
			if r.code != 0 || r.stderr != "" {
				t.Errorf("exit code %d, stderr %q; want 0 and nothing", r.code, r.stderr)
			}
			if say := strings.ReplaceAll(tt.say, "BIN", in.bin); !strings.Contains(r.stdout, say) {
				t.Errorf("stdout does not say %q:\n%s", say, r.stdout)
			}
			if got := in.urls(); !slices.Equal(got, tt.urls) {
				t.Errorf("curl got the URLs %q, want %q", got, tt.urls)
			}
			if in.ghChecked() {
				t.Error("gh checked an attestation")
			}
			if after := files(t, in.bin); !maps.Equal(after, before) {
				t.Errorf("the bin directory changed")
			}
			in.checkTmpGone()
		})
	}
}

// TestInstallDenies: each failed step stops the script with exit code 1
// and a last line that says why. Nothing is installed: the old nodkey
// stays, and no new file is left next to it.
func TestInstallDenies(t *testing.T) {
	const tarball = "nodkey_0.2.0_linux_amd64.tar.gz"
	sums := func(lines ...string) func(in *installer) {
		return func(in *installer) {
			in.serve(releasePath+"0.2.0/SHA256SUMS", []byte(strings.Join(lines, "")))
		}
	}
	sumOf := func(in *installer, arch string) string {
		data := readFile(in.t, filepath.Join(in.web, releasePath+"0.2.0", "nodkey_0.2.0_linux_"+arch+".tar.gz"))
		return fmt.Sprintf("%x", sha256.Sum256(data))
	}
	for _, tt := range []struct {
		name    string
		setup   func(in *installer) // after the newest release 0.2.0 is on the fake GitHub
		args    []string            // nil: --gh with the fake gh
		want    string              // a part of the last line
		checked bool                // whether gh attestation verify ran
		noCurl  bool                // whether the script must stop before any download
		noRun   bool                // whether the script must run no nodkey and no gh
	}{
		{name: "another system", setup: env("FAKE_UNAME_S=Darwin"), noCurl: true, want: "nodkey runs on Linux only, and this is Darwin"},
		{name: "another CPU", setup: env("FAKE_UNAME_M=riscv64"), noCurl: true, want: "amd64 and arm64 only, and this machine is riscv64"},

		// The paths that the script runs programs from and writes to.
		{name: "no bin directory", args: []string{"--bin-dir", "/nonexistent/bin"}, noCurl: true, noRun: true,
			want: "/nonexistent/bin is not a directory"},
		{name: "a bin directory that cannot be written", setup: func(in *installer) { chmod(in.t, in.bin, 0o500) },
			noCurl: true, noRun: true, want: "cannot write to BIN; run this as root"},
		{name: "a bin directory that others can write to", setup: func(in *installer) { chmod(in.t, in.bin, 0o777) },
			noCurl: true, noRun: true, want: "group or others can write to BIN; only root or user"},
		{name: "a bin directory that its group can write to", setup: func(in *installer) { chmod(in.t, in.bin, 0o770) },
			noCurl: true, noRun: true, want: "group or others can write to BIN;"},
		{name: "a bin directory with the sticky bit", setup: func(in *installer) { chmod(in.t, in.bin, 0o777|os.ModeSticky) },
			noCurl: true, noRun: true, want: "group or others can write to BIN;"},
		{name: "a bin directory in a directory that others can write to", setup: func(in *installer) {
			open := filepath.Join(in.dir, "open")
			mkdir(in.t, open, 0o777)
			in.bin = filepath.Join(open, "bin")
			mkdir(in.t, in.bin, 0o700)
			in.installed(fakeNodkey("installed", "nodkey 0.1.0"))
		}, noCurl: true, noRun: true, want: "group or others can write to DIR/open;"},
		{name: "an old file that others can write to", setup: func(in *installer) { chmod(in.t, filepath.Join(in.bin, "nodkey"), 0o777) },
			noCurl: true, noRun: true, want: "group or others can write to BIN/nodkey;"},
		{name: "an old file that is a link", setup: func(in *installer) {
			mkdir(in.t, filepath.Join(in.dir, "elsewhere"), 0o700)
			writeFile(in.t, filepath.Join(in.dir, "elsewhere", "nodkey"), fakeNodkey("elsewhere", "nodkey 0.1.0"), 0o755)
			replace(in.t, filepath.Join(in.bin, "nodkey"), func(path string) error {
				return os.Symlink(filepath.Join(in.dir, "elsewhere", "nodkey"), path)
			})
		}, noCurl: true, noRun: true, want: "BIN/nodkey is a link; the script replaces only a file"},
		{name: "an old file that is a directory", setup: func(in *installer) {
			replace(in.t, filepath.Join(in.bin, "nodkey"), func(path string) error { return os.Mkdir(path, 0o700) })
		}, noCurl: true, noRun: true, want: "BIN/nodkey is not a file"},
		{name: "an old file that is a pipe", setup: func(in *installer) {
			replace(in.t, filepath.Join(in.bin, "nodkey"), func(path string) error { return syscall.Mkfifo(path, 0o600) })
		}, noCurl: true, noRun: true, want: "BIN/nodkey is not a file"},
		{name: "a TMPDIR that others can write to", setup: func(in *installer) {
			in.tmp = filepath.Join(in.dir, "open-tmp")
			mkdir(in.t, in.tmp, 0o777)
		}, noCurl: true, noRun: true, want: "group or others can write to DIR/open-tmp;"},
		{name: "a TMPDIR in a directory that others can write to", setup: func(in *installer) {
			mkdir(in.t, filepath.Join(in.dir, "open"), 0o777)
			in.tmp = filepath.Join(in.dir, "open", "tmp")
			mkdir(in.t, in.tmp, 0o700)
		}, noCurl: true, noRun: true, want: "group or others can write to DIR/open;"},
		{name: "no TMPDIR", setup: env("TMPDIR=/nonexistent/tmp"), noCurl: true, noRun: true,
			want: "cannot find the directory /nonexistent/tmp"},
		{name: "a gh that others can write to", setup: func(in *installer) { chmod(in.t, in.gh, 0o777) },
			noCurl: true, noRun: true, want: "group or others can write to DIR/gh;"},
		{name: "a gh in a directory that others can write to", setup: func(in *installer) {
			mkdir(in.t, filepath.Join(in.dir, "open"), 0o777)
			in.gh = filepath.Join(in.dir, "open", "gh")
			writeFile(in.t, in.gh, []byte(fakeGh), 0o700)
		}, noCurl: true, noRun: true, want: "group or others can write to DIR/open;"},
		{name: "a gh that is a link", setup: func(in *installer) {
			link := filepath.Join(in.dir, "gh-link")
			if err := os.Symlink(in.gh, link); err != nil {
				in.t.Fatal(err)
			}
			in.gh = link
		}, noCurl: true, noRun: true, want: "--gh DIR/gh-link is not a program file; name the file itself, not a link"},
		{name: "a gh that is not there", args: []string{"--gh", "/nonexistent/gh"}, noCurl: true, noRun: true,
			want: "--gh /nonexistent/gh is not a program file"},

		// The newest release, and the files of the release.
		{name: "no answer from the API", setup: func(in *installer) { in.unserve(latestPath) }, want: "cannot ask GitHub for the newest release"},
		{name: "an answer of the API that is too big", setup: func(in *installer) {
			in.serve(latestPath, bytes.Repeat([]byte(" "), 1<<20+1))
		}, want: "cannot ask GitHub for the newest release"},
		{name: "a tag without v", setup: latest("0.2.0"), want: "GitHub does not name the newest release in the form vX.Y.Z"},
		{name: "a tag with two numbers", setup: latest("v0.2"), want: "in the form vX.Y.Z"},
		{name: "a tag with four numbers", setup: latest("v0.2.0.1"), want: "in the form vX.Y.Z"},
		{name: "a tag with a leading zero", setup: latest("v0.02.0"), want: "in the form vX.Y.Z"},
		{name: "a tag of a pre-release", setup: latest("v0.2.0-rc.1"), want: "in the form vX.Y.Z"},
		{name: "a tag with a long number", setup: latest("v0.2.1234567890"), want: "in the form vX.Y.Z"},
		{name: "a tag with a space", setup: latest("v0.2.0 "), want: "in the form vX.Y.Z"},
		{name: "two tags", setup: func(in *installer) {
			in.serve(latestPath, []byte("{\n  \"tag_name\": \"v0.2.0\",\n  \"tag_name\": \"v0.3.0\"\n}\n"))
		}, want: "in the form vX.Y.Z"},
		{name: "no tag", setup: func(in *installer) {
			in.serve(latestPath, []byte("{\n  \"name\": \"v0.2.0\"\n}\n"))
		}, want: "in the form vX.Y.Z"},
		{name: "no tarball", setup: func(in *installer) { in.unserve(releasePath + "0.2.0/" + tarball) },
			want: "cannot download https://" + releasePath + "0.2.0/" + tarball},
		{name: "no SHA256SUMS", setup: func(in *installer) { in.unserve(releasePath + "0.2.0/SHA256SUMS") },
			want: "cannot download https://" + releasePath + "0.2.0/SHA256SUMS"},
		{name: "a SHA256SUMS that is too big", setup: func(in *installer) {
			sums(sumOf(in, "amd64")+"  "+tarball+"\n", strings.Repeat("#", 1<<20))(in)
		}, want: "cannot download https://" + releasePath + "0.2.0/SHA256SUMS"},
		{name: "no bundle", setup: func(in *installer) { in.unserve(releasePath + "0.2.0/nodkey_0.2.0.sigstore.json") },
			want: "cannot download https://" + releasePath + "0.2.0/nodkey_0.2.0.sigstore.json (0.1.0 has no such file"},
		{name: "a bad checksum", setup: func(in *installer) {
			sums(sumOf(in, "arm64")+"  "+tarball+"\n", sumOf(in, "arm64")+"  nodkey_0.2.0_linux_arm64.tar.gz\n")(in)
		}, want: "the SHA-256 of " + tarball + " is not the one in SHA256SUMS"},
		{name: "no line in SHA256SUMS", setup: func(in *installer) {
			sums(sumOf(in, "arm64") + "  nodkey_0.2.0_linux_arm64.tar.gz\n")(in)
		}, want: "SHA256SUMS has no line for " + tarball},
		{name: "a line for a longer name", setup: func(in *installer) {
			sums(sumOf(in, "amd64") + "  " + tarball + ".old\n")(in)
		}, want: "SHA256SUMS has no line for " + tarball},
		{name: "two lines in SHA256SUMS", setup: func(in *installer) {
			sums(sumOf(in, "amd64")+"  "+tarball+"\n", sumOf(in, "amd64")+" *"+tarball+"\n")(in)
		}, want: "SHA256SUMS has more than one line for " + tarball},

		// gh and the attestation.
		{name: "a failed check of the attestation", setup: env("FAKE_GH_EXIT=1"), checked: true,
			want: "gh attestation verify failed, so it is not proven that the release workflow built " + tarball},
		{name: "a gh that is too old", setup: env("FAKE_GH_VERSION=2.92.0"), want: " is gh 2.92.0; it must be gh 2.93.0 or newer"},
		{name: "a gh of a pre-release", setup: env("FAKE_GH_VERSION=2.93.0-rc.1"), want: "cannot tell the version of "},
		{name: "a gh of a version with more", setup: env("FAKE_GH_VERSION=2.102.0+ds1"), want: "cannot tell the version of "},
		{name: "a gh of no version", setup: env("FAKE_GH_VERSION=DEV"), want: "cannot tell the version of "},
		{name: "a gh whose --version fails", setup: env("FAKE_GH_VERSION_EXIT=1"), want: "/gh --version; nothing"},
		{name: "a downloaded gh with another SHA-256", setup: func(in *installer) { in.ghRelease() }, args: []string{},
			want: "the SHA-256 of gh_2.102.0_linux_amd64.tar.gz is not the one in this script"},
		{name: "no gh to download", args: []string{}, want: "cannot download gh_2.102.0_linux_amd64.tar.gz"},

		// The new nodkey. The attestation proves which workflow built a
		// file, not which version it is. A release 0.3.0 with an attested
		// build of 0.2.0 passes the checksum and the attestation, and must
		// still fail.
		{name: "an attested older build under a newer name", setup: func(in *installer) {
			in.latest("v0.3.0")
			in.release("0.3.0", says("nodkey 0.2.0"))
		}, checked: true, want: "the new nodkey does not say that it is nodkey 0.3.0"},
		{name: "a new nodkey of another version", setup: rel(says("nodkey 0.1.0")), checked: true,
			want: "the new nodkey does not say that it is nodkey 0.2.0"},
		{name: "a new nodkey with more output", setup: rel(says("nodkey 0.2.0", "nodkey 0.3.0")), checked: true,
			want: "the new nodkey does not say that it is nodkey 0.2.0"},
		{name: "a new nodkey with a v", setup: rel(says("nodkey v0.2.0")), checked: true,
			want: "the new nodkey does not say that it is nodkey 0.2.0"},
		{name: "a new nodkey that does not run", setup: rel(func(string) []byte { return failingNodkey }), checked: true,
			want: "the new nodkey does not run"},
		{name: "a tarball without nodkey", setup: func(in *installer) {
			data := tarGz(in.t, tarFile{"LICENSE", 0o644, []byte("a made-up license\n")})
			in.serve(releasePath+"0.2.0/"+tarball, data)
			sums(fmt.Sprintf("%x  %s\n", sha256.Sum256(data), tarball))(in)
		}, checked: true, want: "cannot take nodkey out of " + tarball},
	} {
		// Each check denies in the same way with --notes, which installs
		// nothing and must run no new nodkey before the checks pass.
		for _, notes := range []bool{false, true} {
			name := tt.name
			if notes {
				name += ", with --notes"
			}
			t.Run(name, func(t *testing.T) {
				in := newInstaller(t)
				in.latest("v0.2.0")
				in.release("0.2.0", says("nodkey 0.2.0"))
				in.installed(fakeNodkey("installed", "nodkey 0.1.0"))
				if tt.setup != nil {
					tt.setup(in)
				}
				args := tt.args
				if args == nil {
					args = []string{"--gh", in.gh}
				}
				if notes {
					args = append(slices.Clone(args), "--notes")
				}
				before := files(t, in.bin)
				r := in.run(args...)
				want := strings.NewReplacer("BIN", in.bin, "DIR", in.dir).Replace(tt.want)
				in.checkFailed(r, 1, want, before)
				if in.ghChecked() != tt.checked {
					t.Errorf("gh attestation verify ran: %v, want %v", in.ghChecked(), tt.checked)
				}
				if urls := in.urls(); tt.noCurl && len(urls) != 0 {
					t.Errorf("curl got %q, want no call", urls)
				}
				if runs := append(in.log("nodkey-runs"), in.log("gh")...); tt.noRun && len(runs) != 0 {
					t.Errorf("the script ran a nodkey or a gh: %q", runs)
				}
				// The new nodkey runs only after the attestation passed.
				if ranNew := slices.ContainsFunc(in.log("nodkey-runs"), func(s string) bool { return s == "amd64" }); ranNew && !tt.checked {
					t.Error("the new nodkey ran, but the attestation was not checked")
				}
			})
		}
	}
}

// TestInstallRunsNoNewFileBeforeTheCheck: when the attestation fails, the
// new nodkey never runs, not even for its version.
func TestInstallRunsNoNewFileBeforeTheCheck(t *testing.T) {
	in := newInstaller(t)
	in.latest("v0.2.0")
	in.release("0.2.0", says("nodkey 0.2.0"))
	in.installed(fakeNodkey("installed", "nodkey 0.1.0"))
	in.env = append(in.env, "FAKE_GH_EXIT=1")
	for i, args := range [][]string{{"--gh", in.gh}, {"--gh", in.gh, "--notes"}} {
		before := files(t, in.bin)
		r := in.run(args...)
		in.checkFailed(r, 1, "gh attestation verify failed", before)
		// Only the installed nodkey ran, for its version.
		want := slices.Repeat([]string{"installed"}, i+1)
		if runs := in.log("nodkey-runs"); !slices.Equal(runs, want) {
			t.Errorf("%q: these copies of nodkey ran: %q, want only the installed one", args, runs)
		}
	}
}

// changesNodkey is a fake nodkey of version that logs each run with its
// arguments, and for "changes" prints a line with them and exits with
// code.
func changesNodkey(note, version string, code int) []byte {
	return fmt.Appendf(nil, "#!/bin/sh\n# A fake nodkey (%[1]s).\n"+
		"echo \"%[1]s $*\" >>\"$FAKE_LOGS/nodkey-runs\"\n"+
		"case $1 in\nversion) echo 'nodkey %[2]s' ;;\nchanges) echo \"CHANGES $*\"; exit %[3]d ;;\nesac\n",
		note, version, code)
}

// TestInstallNotes: --notes checks the release as an install does, runs
// the new nodkey from the temporary directory to print its changes, and
// installs nothing.
func TestInstallNotes(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string // a part of stdout
	}{
		{name: "the newest release", want: "Nothing was installed. To install it, run as root: nodkey update\n"},
		{name: "a release with --version", args: []string{"--version", "0.2.0"},
			want: "Nothing was installed. To install it, run as root: nodkey update --version 0.2.0\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := newInstaller(t)
			in.latest("v0.2.0")
			in.release("0.2.0", func(arch string) []byte { return changesNodkey(arch, "0.2.0", 0) })
			in.installed(fakeNodkey("installed", "nodkey 0.1.0"))
			before := files(t, in.bin)
			r := in.run(append([]string{"--gh", in.gh, "--notes"}, tt.args...)...)
			if r.code != 0 {
				t.Fatalf("exit code %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
			}
			for _, want := range []string{"This installs nothing.", "The checked nodkey 0.2.0 says what is new:\n\nCHANGES changes --since 0.1.0\n", tt.want} {
				if !strings.Contains(r.stdout, want) {
					t.Errorf("stdout does not say %q:\n%s", want, r.stdout)
				}
			}
			if after := files(t, in.bin); !maps.Equal(after, before) {
				t.Errorf("the bin directory changed: %v", slices.Sorted(maps.Keys(after)))
			}
			if !in.ghChecked() {
				t.Error("gh attestation verify did not run")
			}
			if runs, want := in.log("nodkey-runs"), []string{"installed", "amd64 version", "amd64 changes --since 0.1.0"}; !slices.Equal(runs, want) {
				t.Errorf("runs of nodkey %q, want %q", runs, want)
			}
			in.checkTmpGone()
		})
	}
}

// TestInstallNotesDenies: --notes shows nothing for an installed version
// that is unknown, the same or newer; and fails when the new nodkey
// cannot print its changes. It installs nothing.
func TestInstallNotesDenies(t *testing.T) {
	for _, tt := range []struct {
		name      string
		installed []byte
		args      []string
		code      int
		want      string // a part of stdout, or of the last line of stderr
	}{
		{name: "the same version", installed: fakeNodkey("installed", "nodkey 0.2.0"),
			want: "BIN/nodkey says that it is nodkey 0.2.0, and nodkey 0.2.0 is not newer. No changes to show."},
		{name: "a newer version", installed: fakeNodkey("installed", "nodkey 0.3.0"),
			want: "and nodkey 0.2.0 is not newer"},
		{name: "an older --version", installed: fakeNodkey("installed", "nodkey 0.3.0"), args: []string{"--version", "0.2.0"},
			want: "and nodkey 0.2.0 is not newer"},
		{name: "an unknown version", installed: fakeNodkey("installed", "nodkey dev"), code: 1,
			want: "BIN/nodkey has an unknown version, so it is not known which changes are new"},
		{name: "no installed file", code: 1, want: "BIN/nodkey has an unknown version"},
		{name: "a failed changes", installed: fakeNodkey("installed", "nodkey 0.1.0"), code: 1,
			want: "the new nodkey cannot print its changes"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := newInstaller(t)
			in.latest("v0.2.0")
			in.release("0.2.0", func(arch string) []byte { return changesNodkey(arch, "0.2.0", 3) })
			if tt.installed != nil {
				in.installed(tt.installed)
			}
			before := files(t, in.bin)
			r := in.run(append([]string{"--gh", in.gh, "--notes"}, tt.args...)...)
			want := strings.ReplaceAll(tt.want, "BIN", in.bin)
			if tt.code != 0 {
				in.checkFailed(r, tt.code, want, before)
				return
			}
			if r.code != 0 || !strings.Contains(r.stdout, want) {
				t.Errorf("exit code %d, stdout:\n%s\nwant 0 and %q", r.code, r.stdout, want)
			}
			if after := files(t, in.bin); !maps.Equal(after, before) {
				t.Errorf("the bin directory changed: %v", slices.Sorted(maps.Keys(after)))
			}
			if in.ghChecked() || slices.ContainsFunc(in.log("nodkey-runs"), func(s string) bool { return strings.HasPrefix(s, "amd64") }) {
				t.Error("the release was checked or run, with nothing to show")
			}
			in.checkTmpGone()
		})
	}
	// --notes and --reinstall do not go together.
	in := newInstaller(t)
	in.installed(fakeNodkey("installed", "nodkey 0.1.0"))
	in.checkFailed(in.run("--gh", in.gh, "--notes", "--reinstall"), 64, "--notes installs nothing", files(t, in.bin))
}

// TestInstallPrintsChanges: after an update to a newer version, the new
// file prints its changes since the old version. If it cannot, a note
// says so and the update still succeeds. A reinstall or a downgrade prints
// no changes.
func TestInstallPrintsChanges(t *testing.T) {
	for _, tt := range []struct {
		name      string
		installed string
		args      []string
		code      int // the exit code of the new nodkey changes
		want      string
		runs      []string // the runs of the new file
	}{
		{name: "an update", installed: "0.1.0", want: "What is new since nodkey 0.1.0:\n\nCHANGES changes --since 0.1.0\n",
			runs: []string{"amd64 version", "amd64 changes --since 0.1.0", "amd64 version"}},
		{name: "a failed changes", installed: "0.1.0", code: 64,
			want: "The new nodkey cannot print its changes. Read the release notes: https://github.com/code6x/nodkey/releases/tag/v0.2.0\n",
			runs: []string{"amd64 version", "amd64 changes --since 0.1.0", "amd64 version"}},
		{name: "a reinstall", installed: "0.2.0", args: []string{"--reinstall"},
			runs: []string{"amd64 version", "amd64 version"}},
		{name: "a downgrade", installed: "0.3.0", args: []string{"--version", "0.2.0"},
			runs: []string{"amd64 version", "amd64 version"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := newInstaller(t)
			in.latest("v0.2.0")
			in.release("0.2.0", func(arch string) []byte { return changesNodkey(arch, "0.2.0", tt.code) })
			in.installed(fakeNodkey("installed", "nodkey "+tt.installed))
			r := in.run(append([]string{"--gh", in.gh}, tt.args...)...)
			if r.code != 0 || !strings.Contains(r.stdout, tt.want) || !strings.Contains(r.stdout, "Restart what still runs the old version") {
				t.Errorf("exit code %d, stdout:\n%s\nwant 0 and %q", r.code, r.stdout, tt.want)
			}
			if tt.want == "" && strings.Contains(r.stdout, "CHANGES") {
				t.Errorf("changes were printed:\n%s", r.stdout)
			}
			if got := readFile(t, filepath.Join(in.bin, "nodkey")); string(got) != string(changesNodkey("amd64", "0.2.0", tt.code)) {
				t.Error("the new nodkey is not installed")
			}
			runs := slices.DeleteFunc(in.log("nodkey-runs"), func(s string) bool { return s == "installed" })
			if !slices.Equal(runs, tt.runs) {
				t.Errorf("runs of the new nodkey %q, want %q", runs, tt.runs)
			}
			in.checkTmpGone()
		})
	}
}

// env returns a setup that adds the variables to the environment of the
// script.
func env(vars ...string) func(in *installer) {
	return func(in *installer) { in.env = append(in.env, vars...) }
}

// latest returns a setup that makes tag the newest release.
func latest(tag string) func(in *installer) {
	return func(in *installer) { in.latest(tag) }
}

// rel returns a setup that makes the release 0.2.0 again, with these
// files nodkey.
func rel(nodkey func(arch string) []byte) func(in *installer) {
	return func(in *installer) { in.release("0.2.0", nodkey) }
}

// chmod sets the mode of path, and sets it back to 0700 at the end of the
// test, so that the temporary directory can be removed.
func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o700) }) //nolint:gosec // G302: back to private, so that the test can remove it.
}

// replace removes the file path and makes something else there with
// create.
func replace(t *testing.T, path string, create func(path string) error) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := create(path); err != nil {
		t.Fatal(err)
	}
}

// TestInstallUsage: wrong arguments stop the script with exit code 64,
// before it downloads anything.
func TestInstallUsage(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"--bogus"}, "unknown argument: --bogus"},
		{[]string{"0.2.0"}, "unknown argument: 0.2.0"},
		{[]string{"--version=0.2.0"}, "unknown argument: --version=0.2.0"},
		{[]string{"--reinstall=yes"}, "unknown argument: --reinstall=yes"},
		{[]string{"--version"}, "--version needs a version, such as 0.2.0"},
		{[]string{"--version", "0.2"}, "--version must be X.Y.Z, such as 0.2.0"},
		{[]string{"--version", "v0.2.0"}, "--version must be X.Y.Z"},
		{[]string{"--version", "0.2.0.1"}, "--version must be X.Y.Z"},
		{[]string{"--version", "00.2.0"}, "--version must be X.Y.Z"},
		{[]string{"--version", "0.-2.0"}, "--version must be X.Y.Z"},
		{[]string{"--version", ""}, "--version must be X.Y.Z"},
		{[]string{"--version", "--bin-dir"}, "--version must be X.Y.Z"},
		{[]string{"--bin-dir"}, "--bin-dir needs a directory"},
		{[]string{"--bin-dir", "bin"}, "--bin-dir must be an absolute path"},
		{[]string{"--gh"}, "--gh needs the path of gh"},
		{[]string{"--gh", "gh"}, "--gh must be an absolute path"},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			in := newInstaller(t)
			in.latest("v0.2.0")
			in.release("0.2.0", says("nodkey 0.2.0"))
			in.installed(fakeNodkey("installed", "nodkey 0.1.0"))
			before := files(t, in.bin)
			r := in.run(tt.args...)
			in.checkFailed(r, 64, tt.want, before)
			if !strings.HasPrefix(r.stderr, "Usage: sh install.sh ") || r.stdout != "" {
				t.Errorf("stdout %q, stderr %q; want the usage on stderr", r.stdout, r.stderr)
			}
			if urls := in.urls(); len(urls) != 0 {
				t.Errorf("curl got %q", urls)
			}
		})
	}
	for _, help := range []string{"--help", "-h"} {
		in := newInstaller(t)
		r := in.run(help)
		if r.code != 0 || !strings.HasPrefix(r.stdout, "Usage: sh install.sh ") || !strings.Contains(r.stdout, "--reinstall") || r.stderr != "" {
			t.Errorf("%s: exit code %d, stdout %q, stderr %q; want 0 and the usage on stdout", help, r.code, r.stdout, r.stderr)
		}
	}
}

// TestInstallDownloadsGh runs a copy of the script whose SHA-256 of gh is
// the one of a fake gh: the script downloads the tarball of gh, checks it,
// takes gh out of it and checks the attestation with it.
func TestInstallDownloadsGh(t *testing.T) {
	in := newInstaller(t)
	in.latest("v0.2.0")
	in.release("0.2.0", says("nodkey 0.2.0"))
	sum := in.ghRelease()
	script := string(readFile(t, in.script))
	pin := regexp.MustCompile(`(?m)^gh_sha256_amd64=[0-9a-f]{64}$`)
	if n := len(pin.FindAllString(script, -1)); n != 1 {
		t.Fatalf("install.sh has %d lines gh_sha256_amd64=, want 1", n)
	}
	in.script = filepath.Join(in.dir, "install-with-fake-gh.sh")
	writeFile(t, in.script, []byte(pin.ReplaceAllString(script, "gh_sha256_amd64="+sum)), 0o600)

	r := in.run()
	if r.code != 0 {
		t.Fatalf("exit code %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	want := append([]string{latestURL}, releaseURLs("0.2.0")...)
	want = append(want, "https://"+ghPath+"2.102.0/gh_2.102.0_linux_amd64.tar.gz")
	if got := in.urls(); !slices.Equal(got, want) {
		t.Errorf("curl got the URLs\n%q\nwant\n%q", got, want)
	}
	if last := in.curlCalls()[len(want)-1]; !slices.Contains(last, maxBig) {
		t.Errorf("the download of gh has no size limit %s: %q", maxBig, last)
	}
	// The gh that ran is the one from the tarball, in the temporary
	// directory.
	args := in.log("gh-args")
	if !in.ghChecked() || len(args) < 3 {
		t.Fatalf("gh attestation verify did not run: %q", args)
	}
	tmp := filepath.Dir(args[2])
	if got, want := in.log("gh-path"), filepath.Join(tmp, "gh", "gh_2.102.0_linux_amd64", "bin", "gh"); len(got) != 1 || got[0] != want {
		t.Errorf("the gh that ran is %q, want %s", got, want)
	}
	if got := files(t, in.bin); got["nodkey"] != "-rwxr-xr-x "+string(fakeNodkey("amd64", "nodkey 0.2.0")) {
		t.Errorf("the bin directory holds %q", got)
	}
	in.checkTmpGone()
}

// TestInstallStopsOnSIGTERM sends SIGTERM to the script and its programs,
// as Ctrl-C does with SIGINT, while gh checks the attestation. The script
// exits with 1, installs nothing, and removes its temporary directory.
func TestInstallStopsOnSIGTERM(t *testing.T) {
	in := newInstaller(t)
	in.latest("v0.2.0")
	in.release("0.2.0", says("nodkey 0.2.0"))
	in.installed(fakeNodkey("installed", "nodkey 0.1.0"))
	before := files(t, in.bin)
	marker := filepath.Join(in.dir, "gh-waits")
	in.env = append(in.env, "FAKE_GH_WAIT="+marker)
	cmd := in.command("--gh", in.gh)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the script ended before gh waited: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("gh did not start to wait")
		}
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatal("the script did not stop on SIGTERM")
	}
	if code := cmd.ProcessState.ExitCode(); code != 1 {
		t.Errorf("exit code %d, want 1\nstderr:\n%s", code, stderr.String())
	}
	if after := files(t, in.bin); !maps.Equal(after, before) {
		t.Errorf("the bin directory changed")
	}
	in.checkTmpGone()
}

// functions writes install.sh without its last line, which starts main,
// into dir, so that a test can load its functions with ".". It returns the
// path of the copy.
func functions(t *testing.T, dir string) string {
	t.Helper()
	body, ok := strings.CutSuffix(string(readFile(t, "install.sh")), "\nmain \"$@\"\n")
	if !ok {
		t.Fatal(`install.sh does not end with the line main "$@"`)
	}
	path := filepath.Join(dir, "functions.sh")
	writeFile(t, path, []byte(body+"\n"), 0o600)
	return path
}

// runFunctions runs code with /bin/sh, after it loaded the functions of
// install.sh, with the environment env.
func runFunctions(t *testing.T, lib string, env []string, code string) result {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", ". \"$0\"\n"+code, lib) //nolint:gosec // G204: the test runs the functions of install.sh.
	cmd.Env = env
	return runCmd(t, cmd)
}

// TestInstallChecksAsRoot runs the checks of the paths as the script runs
// them as root, with uid 0: then only root may own a path. A test cannot
// make files of root, so it checks that its own files are refused, and
// that the directories of the system pass.
func TestInstallChecksAsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test needs files that root does not own")
	}
	dir := privateDir(t)
	lib := functions(t, dir)
	own := filepath.Join(dir, "own")
	writeFile(t, own, []byte("#!/bin/sh\n"), 0o755)
	env := []string{"PATH=" + os.Getenv("PATH")}
	asRoot := "uid=0\nowners=root\n"
	for _, tt := range []struct {
		code string
		want string // the last line, or "" for exit code 0
	}{
		{"check_tree " + own + " own", "nodkey: " + own + " is owned by user " + strconv.Itoa(os.Geteuid()) +
			"; it must be owned by root; nothing was installed (exit 1)\n"},
		{"check_tree " + dir + " shared", "it must be owned by root;"},
		{"check_entry /tmp own", "nodkey: group or others can write to /tmp; only root may; nothing was installed (exit 1)\n"},
	} {
		r := runFunctions(t, lib, env, asRoot+tt.code)
		if r.code != 1 || !strings.Contains(lastLine(r.stderr), tt.want) {
			t.Errorf("%s: exit code %d, stderr %q; want 1 and %q", tt.code, r.code, r.stderr, tt.want)
		}
	}
	// The directories of the system: root owns them, and only /tmp, with
	// the sticky bit, lets others write.
	for _, code := range []string{"check_tree /usr/bin own", "check_tree /tmp shared", "check_tree / own"} {
		path := strings.Fields(code)[1]
		if info, err := os.Lstat(path); err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 {
			skipOrFail(t, "%s is not a directory of root", path)
		}
		if r := runFunctions(t, lib, env, asRoot+code); r.code != 0 {
			t.Errorf("%s: exit code %d, stderr %q; want 0", code, r.code, r.stderr)
		}
	}
}

// TestInstallCleansTheEnvironment runs clean_env of the script. It removes
// the variables that change what the programs of the script do, and sets
// LC_ALL=C. As root (a fake id says 0), it also sets the fixed PATH, which
// here is a directory of the test.
func TestInstallCleansTheEnvironment(t *testing.T) {
	dir := privateDir(t)
	lib := functions(t, dir)
	all := append([]string{"TAR_OPTIONS", "LD_PRELOAD", "LD_AUDIT"}, unsafeVars...)
	env := []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=de_DE.UTF-8", "IFS=x"}
	for _, name := range all {
		env = append(env, name+"=/nonexistent/made-up")
	}
	show := `printf '%s|%s|' "$uid" "$owners"; printf '%s|' "$LC_ALL" "${IFS-unset}"`
	for _, name := range all {
		show += `; printf '%s|' "${` + name + `-unset}"`
	}
	wantVars := "C|unset|" + strings.Repeat("unset|", len(all))

	// As this user: PATH stays.
	r := runFunctions(t, lib, env, "clean_env\n"+show+`; printf '%s' "$PATH"`)
	uid := strconv.Itoa(os.Geteuid())
	if want := uid + "|root or user " + uid + "|" + wantVars + os.Getenv("PATH"); r.code != 0 || r.stdout != want {
		t.Errorf("as user %s: exit code %d, stdout %q, stderr %q; want %q", uid, r.code, r.stdout, r.stderr, want)
	}

	// As root: PATH is root_path.
	fakeRoot := filepath.Join(dir, "root-bin")
	mkdir(t, fakeRoot, 0o700)
	writeFile(t, filepath.Join(fakeRoot, "id"), []byte("#!/bin/sh\necho 0\n"), 0o700)
	r = runFunctions(t, lib, env, "root_path="+fakeRoot+"\nclean_env\n"+show+`; printf '%s' "$PATH"`)
	if want := "0|root|" + wantVars + fakeRoot; r.code != 0 || r.stdout != want {
		t.Errorf("as root: exit code %d, stdout %q, stderr %q; want %q", r.code, r.stdout, r.stderr, want)
	}
	// The real script uses the directories of the system.
	if !strings.Contains(string(readFile(t, "install.sh")), "\nroot_path=/usr/sbin:/usr/bin:/sbin:/bin\n") {
		t.Error("install.sh does not set root_path=/usr/sbin:/usr/bin:/sbin:/bin")
	}
}

// TestPinnedGh: the gh that the script downloads is 2.93.0 or newer, and
// the script has a SHA-256 for each CPU.
func TestPinnedGh(t *testing.T) {
	script := string(readFile(t, "install.sh"))
	value := func(name, pattern string) string {
		m := regexp.MustCompile(`(?m)^`+name+`=(`+pattern+`)$`).FindAllStringSubmatch(script, -1)
		if len(m) != 1 {
			t.Fatalf("install.sh has %d lines %s=%s, want 1", len(m), name, pattern)
		}
		return m[0][1]
	}
	num := `(0|[1-9][0-9]*)`
	version := value("gh_version", num+`\.`+num+`\.`+num)
	if minVersion := value("gh_min_version", num+`\.`+num+`\.`+num); minVersion != "2.93.0" {
		t.Errorf("gh_min_version is %s, want 2.93.0", minVersion)
	}
	var parts [3]int
	for i, s := range strings.Split(version, ".") {
		parts[i], _ = strconv.Atoi(s)
	}
	if parts[0] < 2 || (parts[0] == 2 && parts[1] < 93) {
		t.Errorf("the pinned gh is %s, want 2.93.0 or newer", version)
	}
	if value("gh_sha256_amd64", "[0-9a-f]{64}") == value("gh_sha256_arm64", "[0-9a-f]{64}") {
		t.Error("gh has the same SHA-256 for amd64 and arm64")
	}
}

// skipOrFail skips the test, or fails it when the CI environment variable
// is set: CI has every program that the tests need.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf("CI is set, so this test must run, but: "+format, args...)
	}
	t.Skipf(format, args...)
}

// writeFile writes data to path with mode. It holds syscall.ForkLock while
// the file is open, so that no child process that starts at that time
// gets a copy of the descriptor: then running the file would fail with
// "text file busy" (go.dev/issue/22315).
func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	syscall.ForkLock.RLock()
	err := os.WriteFile(path, data, 0o600)
	syscall.ForkLock.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: a file of the test.
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// readEnv reads the output of env into a map.
func readEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	env := map[string]string{}
	for line := range strings.Lines(string(readFile(t, path))) {
		if name, value, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "="); ok {
			env[name] = value
		}
	}
	return env
}

// lastLine returns the last line of s, with its newline.
func lastLine(s string) string {
	body := strings.TrimSuffix(s, "\n")
	return s[strings.LastIndex(body, "\n")+1:]
}

// windows returns each run of n elements of s.
func windows(s []string, n int) [][]string {
	var w [][]string
	for i := 0; i+n <= len(s); i++ {
		w = append(w, s[i:i+n])
	}
	return w
}
