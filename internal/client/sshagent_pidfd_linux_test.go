package client

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/transport"
)

// pidfdOf returns a pidfd of a process of the test (pidfd_open(2), Linux
// 5.3).
func pidfdOf(t *testing.T, pid int) *os.File {
	t.Helper()
	const sysPidfdOpen = 434 // the same on amd64 and arm64
	fd, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(pid), 0, 0)
	if errno != 0 {
		t.Skipf("pidfd_open: %v", errno)
	}
	f := os.NewFile(fd, "pidfd")
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestPeerExitedBeforeRead: ssh connects and ends before the agent reads
// /proc, and a new process gets its ID. The sign request goes without
// claimed context: nothing of the new process is sent (issue #61). The
// same holds when the kernel has pidfds but gave none.
func TestPeerExitedBeforeRead(t *testing.T) {
	t.Parallel()
	sleep := needProgram(t, "sleep")
	cmd := exec.CommandContext(t.Context(), sleep, "60") //nolint:gosec // G204: the test runs sleep.
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	pidfd := pidfdOf(t, pid)
	if !processRuns(pidfd) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("processRuns reports false for a process that runs")
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if processRuns(pidfd) {
		t.Fatal("processRuns reports true for a process that ended")
	}
	// The new process with the same ID, in a /proc tree of the test.
	canary := madeUp("canary")
	p := newFakeProc(t)
	p.add(t, pid, 1, []string{"new-process", canary}, []string{"NODKEY_REASON=" + canary})
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		peer peer
	}{
		{"the pidfd says it ended", peer{uid: self, pid: int32(pid), pidfd: pidfd}}, //nolint:gosec // G115: a process ID fits in an int32.
		{"no pidfd", peer{uid: self, pid: int32(pid), gone: true}},                  //nolint:gosec // G115: a process ID fits in an int32.
	} {
		t.Run(tt.name, func(t *testing.T) {
			bodies := make(chan []byte, 1)
			fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
				bodies <- readBody(t, r)
				transport.WriteError(w, http.StatusForbidden)
			})
			au := startAgent(t, fb.b, agentOptions{proc: p.fs(), peer: func(*net.UnixConn) (peer, error) {
				p := tt.peer
				if p.pidfd != nil { // the agent closes its pidfd: it gets a copy
					fd, err := syscall.Dup(int(p.pidfd.Fd()))
					if err == nil {
						syscall.CloseOnExec(fd)
					}
					if err != nil {
						return peer{}, err
					}
					p.pidfd = os.NewFile(uintptr(fd), "pidfd")
				}
				return p, nil
			}})
			if signatureOf(t, rawCall(t, au.conn(t), signRequestMessage([]byte("key"), []byte("data"), 0))) != nil {
				t.Fatal("the agent gave ssh a signature")
			}
			var req api.SignRequest
			if err := req.UnmarshalJSON(<-bodies); err != nil {
				t.Fatal(err)
			}
			if len(req.Commands) != 0 || req.Reason != "" {
				t.Errorf("the request has %d command lines and a reason of %d bytes; want none", len(req.Commands),
					len(req.Reason))
			}
			ended := "sent a sign request without the command lines and the reason: ssh has ended"
			if countLines(au.log.String(), ended) != 1 || strings.Contains(au.log.String(), canary) {
				t.Errorf("the agent wrote %q; want one line that ssh has ended", au.lines())
			}
		})
	}
}
