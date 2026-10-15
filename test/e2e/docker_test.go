//go:build e2e

package e2e

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The containers of the test. Every container, network and image that the
// test makes has a name with runID, and every container and network has
// the label runLabel, so that TestMain can check at the end that none is
// left. The container of the SSH targets ends on its own after
// containerLifetime, in case the test process ends without its cleanups,
// such as when go test kills it after its -timeout. A later run removes
// what is left (removeStale).

// runLabel is the label of every container and network of this run.
var runLabel = "nodkey-e2e=" + runID

// imageTag is the tag of the image of testdata/sshd that this run builds.
// TestMain removes it after the tests.
var imageTag = "nodkey-e2e-sshd:" + runID

// containerLifetime is how long a container may run: it ends on its own
// after this time.
const containerLifetime = 15 * time.Minute

// Time limits of the docker commands. The build installs packages with
// apt-get, unless Docker's build cache has them.
const (
	dockerBuildLimit = 10 * time.Minute
	dockerLimit      = 2 * time.Minute
)

// runDocker runs docker with args and the time limit limit, and returns
// what it wrote to stdout and to stderr. It does not use the test's
// context, so that it also works in the cleanups.
func runDocker(limit time.Duration, args ...string) (string, string, error) {
	return runDockerWith(limit, nil, args...)
}

// runDockerWith is runDocker with stdin.
func runDockerWith(limit time.Duration, stdin io.Reader, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: the test runs docker with its own arguments.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// copyIn copies the files of the directory dir into the directory /e2e of
// the container id, as files of root, with their modes. docker cp would
// keep the owner of each file, this user, and root without capabilities
// cannot read a file of another user with mode 0600, such as a host key.
// So it sends docker cp a tar archive whose files belong to root.
func copyIn(t *testing.T, id, dir string) {
	t.Helper()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		info, err := en.Info()
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file: %v", en.Name(), err)
		}
		data := readFile(t, filepath.Join(dir, en.Name()))
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: en.Name(), Mode: int64(info.Mode().Perm()), Size: int64(len(data)),
			ModTime: info.ModTime()}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if stdout, stderr, err := runDockerWith(dockerLimit, &archive, "cp", "-", id+":/e2e"); err != nil {
		t.Fatalf("docker cp: %v\n%s%s", err, stdout, stderr)
	}
}

// mustDocker runs docker with args, and fails the test on an error. It
// returns stdout without the space around it.
func mustDocker(t *testing.T, limit time.Duration, args ...string) string {
	t.Helper()
	stdout, stderr, err := runDocker(limit, args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, stdout, stderr)
	}
	return strings.TrimSpace(stdout)
}

// requireDocker fails the test when Docker cannot be used. The test is run
// only on purpose, with the build tag e2e, so it never skips.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, stderr, err := runDocker(dockerLimit, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Fatalf("the end-to-end test needs Docker: docker version: %v\n%s", err, stderr)
	}
}

// image is the image of testdata/sshd, built once per test process.
var image struct {
	once  sync.Once
	built bool   // the build ran and made imageTag
	err   string // why the build failed
}

// sshdImage builds the image of testdata/sshd once, and returns its tag.
// The Dockerfile pins its base image by digest. Before the build, it
// removes what earlier runs left (removeStale).
func sshdImage(t *testing.T) string {
	t.Helper()
	requireDocker(t)
	image.once.Do(func() {
		removeStale(t)
		stdout, stderr, err := runDocker(dockerBuildLimit, "build", "--quiet", "--tag", imageTag, "testdata/sshd")
		image.built = true // remove the tag at the end, also after a failed build
		if err != nil {
			image.err = fmt.Sprintf("docker build: %v\n%s%s", err, stdout, stderr)
		}
	})
	if image.err != "" {
		t.Fatal(image.err)
	}
	return imageTag
}

// removeImage removes the image of this test process, if it was built. It
// reports what it could not remove.
func removeImage() error {
	if !image.built {
		return nil
	}
	if _, stderr, err := runDocker(dockerLimit, "image", "rm", imageTag); err != nil &&
		!strings.Contains(stderr, "No such image") {
		return fmt.Errorf("docker image rm %s: %w: %s", imageTag, err, strings.TrimSpace(stderr))
	}
	return nil
}

// leftovers returns the containers, networks and images of this test
// process that are still there.
func leftovers() ([]string, error) {
	var left []string
	for _, args := range [][]string{
		{"ps", "--all", "--quiet", "--filter", "label=" + runLabel},
		{"network", "ls", "--quiet", "--filter", "label=" + runLabel},
		{"image", "ls", "--quiet", imageTag},
	} {
		stdout, stderr, err := runDocker(dockerLimit, args...)
		if err != nil {
			return nil, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr))
		}
		for id := range strings.FieldsSeq(stdout) {
			left = append(left, args[0]+" "+id)
		}
	}
	return left, nil
}

// removeContainer removes the container id, and waits until it is gone.
// The root container runs with --rm, so Docker may already be removing it
// when it has ended.
func removeContainer(id string) error {
	_, stderr, err := runDocker(dockerLimit, "rm", "--force", id)
	switch {
	case err == nil, strings.Contains(stderr, "No such container"):
		return nil
	case !strings.Contains(stderr, "already in progress"):
		return fmt.Errorf("docker rm %s: %w: %s", id, err, strings.TrimSpace(stderr))
	}
	for deadline := time.Now().Add(dockerLimit); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, stderr, err := runDocker(dockerLimit, "container", "inspect", id); err != nil &&
			strings.Contains(stderr, "No such container") {
			return nil
		}
	}
	return fmt.Errorf("docker did not remove the container %s within %s", id, dockerLimit)
}

// hardening are the options of every container of the test: no
// capability but those that a container adds, no new privileges through
// a program file, and limits on processes and memory.
var hardening = []string{
	"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256", "--memory", "512m",
}

// targets is the container of the SSH targets: one sshd for each target,
// each with its own port and host key.
type targets struct {
	id    string
	ports map[string]int // the port of each target on 127.0.0.1 of this machine
}

// startTargets starts the container of the SSH targets on a network of its
// own, until the test ends. files is a directory with the files of
// entrypoint.sh; names are the targets, in the order of the lines of its
// file "targets", whose ports in the container start at 2201. Each port
// is published on 127.0.0.1 only. startTargets waits until each sshd
// answers.
func startTargets(t *testing.T, img, files string, names []string) *targets {
	t.Helper()
	network := "nodkey-e2e-" + runID
	mustDocker(t, dockerLimit, "network", "create", "--label", runLabel, network)
	t.Cleanup(func() {
		if _, stderr, err := runDocker(dockerLimit, "network", "rm", network); err != nil {
			t.Errorf("docker network rm %s: %v: %s", network, err, stderr)
		}
	})
	// No --rm: when sshd stops at once, its log stays for the failure.
	args := append([]string{"create", "--label", runLabel, "--name", "nodkey-e2e-" + runID, "--network", network,
		// sshd runs the part before the login as its own user in a chroot,
		// and then changes to the remote user. Nothing else in the
		// container needs a capability: the test passes without
		// AUDIT_WRITE and KILL, which Docker gives by default.
		"--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SYS_CHROOT"}, hardening...)
	for i := range names {
		args = append(args, "--publish", "127.0.0.1::"+strconv.Itoa(2201+i))
	}
	args = append(args, img, strconv.Itoa(int(containerLifetime/time.Second)))
	tg := &targets{id: mustDocker(t, dockerLimit, args...), ports: make(map[string]int)}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the log of the SSH targets:\n%s", tg.logs(t))
		}
		if err := removeContainer(tg.id); err != nil {
			t.Error(err)
		}
	})
	copyIn(t, tg.id, files)
	mustDocker(t, dockerLimit, "start", tg.id)

	// Lines such as "2201/tcp -> 127.0.0.1:32768".
	published := mustDocker(t, dockerLimit, "port", tg.id)
	for i, name := range names {
		prefix := strconv.Itoa(2201+i) + "/tcp -> 127.0.0.1:"
		for line := range strings.Lines(published) {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
				port, err := strconv.Atoi(rest)
				if err != nil {
					t.Fatalf("docker port: %q", line)
				}
				tg.ports[name] = port
			}
		}
		if tg.ports[name] == 0 {
			t.Fatalf("docker port has no port for %s:\n%s\nthe log of the targets:\n%s", name, published, tg.logs(t))
		}
	}
	for _, name := range names {
		tg.waitSSHD(t, name)
	}
	return tg
}

// waitSSHD waits until the sshd of the target name sends its banner. A
// connection to a published port can open before sshd listens, so only
// the banner counts.
func (tg *targets) waitSSHD(t *testing.T, name string) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tg.ports[name]))
	deadline := time.Now().Add(waitLimit)
	for {
		if bannerOf(t, addr) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sshd of %s does not answer on %s; the log of the targets:\n%s", name, addr, tg.logs(t))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// bannerOf reports whether an SSH server answers on addr with its banner.
func bannerOf(t *testing.T, addr string) bool {
	t.Helper()
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && strings.HasPrefix(line, "SSH-2.0-")
}

// logs returns the log of the container: the lines of each sshd.
func (tg *targets) logs(t *testing.T) string {
	t.Helper()
	stdout, stderr, err := runDocker(dockerLimit, "logs", tg.id)
	if err != nil {
		return fmt.Sprintf("(docker logs: %v: %s)", err, stderr)
	}
	return stdout + stderr
}

// runAsRoot runs the program bin in a new container of img, as root,
// without a network, with args. It returns what the program wrote and its
// exit code.
func runAsRoot(t *testing.T, img, bin string, args ...string) (string, int) {
	t.Helper()
	name := "nodkey-e2e-root-" + runID
	create := append([]string{"create", "--rm", "--label", runLabel, "--name", name, "--network", "none",
		"--user", "0:0", "--entrypoint", "/e2e/" + filepath.Base(bin),
		// The test starts a child as another user (65534).
		"--cap-add", "SETUID", "--cap-add", "SETGID"}, hardening...)
	create = append(append(create, img), args...)
	id := mustDocker(t, dockerLimit, create...)
	t.Cleanup(func() {
		if err := removeContainer(id); err != nil {
			t.Error(err)
		}
	})
	copyIn(t, id, filepath.Dir(bin))
	stdout, stderr, err := runDocker(dockerLimit, "start", "--attach", id)
	var exit *exec.ExitError
	switch {
	case err == nil:
		return stdout + stderr, 0
	case errors.As(err, &exit):
		return stdout + stderr, exit.ExitCode()
	}
	t.Fatalf("docker start: %v\n%s%s", err, stdout, stderr)
	return "", -1
}
