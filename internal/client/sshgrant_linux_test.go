package client

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/transport"
)

// The variables of a child that runs as nodkey ssh-grant. The child is
// the test binary again, which runs only TestSSHGrantInterrupted: with
// these variables, that test is nodkey ssh-grant with grantArgs, with the
// broker of the parent test, the real signals and the real exit.
const (
	grantChildAddr = "NODKEY_TEST_GRANT_BROKER"     // the broker's address
	grantChildPin  = "NODKEY_TEST_GRANT_BROKER_PIN" // the pin of the broker's key
	grantChildKey  = "NODKEY_TEST_GRANT_KEY"        // the client's key file
)

// grantChild runs nodkey ssh-grant as SSHGrant does, but with the key file
// and the broker of the parent test: Load would refuse the system
// temporary directory, which everyone can write to.
func grantChild() int {
	load := func(string) (*Broker, error) {
		pin, err := config.ParsePin(os.Getenv(grantChildPin))
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(os.Getenv(grantChildKey)) //nolint:gosec // G703: the parent test wrote this key file, and passes its path.
		if err != nil {
			return nil, err
		}
		key, err := transport.ParseKeyFile(data)
		if err != nil {
			return nil, err
		}
		return newBroker(os.Getenv(grantChildAddr), key, pin)
	}
	g := granter{load: load, configPath: func() (string, error) { return "test", nil }, environ: os.Environ,
		now: time.Now}
	return g.main(grantArgs(), os.Stderr) //nolint:forbidigo // the child is nodkey ssh-grant, which writes to stderr.
}

// TestSSHGrantInterrupted: SIGINT or SIGTERM while nodkey ssh-grant waits.
// It closes the connection, so the broker cancels the request, prints its
// last line with the status that a shell shows (130 or 143), and then
// ends with the same signal, so that a shell stops a loop or a script
// too. No grant starts.
func TestSSHGrantInterrupted(t *testing.T) {
	if os.Getenv(grantChildAddr) != "" {
		os.Exit(grantChild())
	}
	t.Parallel()
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			t.Parallel()
			if sig == syscall.SIGINT {
				needSIGINT(t)
			}
			gb := newGrantBroker(t)
			keyFile := filepath.Join(t.TempDir(), "client.key")
			if err := os.WriteFile(keyFile, gb.clients["laptop"].file, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), self(t), "-test.run=^TestSSHGrantInterrupted$") //nolint:gosec // G204: the test runs its own binary again.
			cmd.Env = withEnv(os.Environ(), []string{
				grantChildAddr + "=" + gb.addr, grantChildPin + "=" + gb.key.pin.String(), grantChildKey + "=" + keyFile,
			})
			var stdout bytes.Buffer
			cmd.Stdout = &stdout
			pipe, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := make(chan string, 16)
			go func() {
				defer close(lines)
				r := bufio.NewReader(pipe)
				for {
					line, err := r.ReadString('\n')
					if line != "" {
						lines <- line
					}
					if err != nil {
						return
					}
				}
			}()
			var stderr strings.Builder
			select {
			case line := <-lines:
				stderr.WriteString(line)
				if len(waitingCodes(line)) != 1 {
					t.Fatalf("the first line is %q, want the waiting line", line)
				}
			case <-time.After(waitLimit):
				t.Fatal("no waiting line")
			}
			p := gb.waitAsked(t, 1)[0].Prompt
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			for line := range lines {
				stderr.WriteString(line)
			}
			err = cmd.Wait()
			name := map[syscall.Signal]string{syscall.SIGINT: "SIGINT", syscall.SIGTERM: "SIGTERM"}[sig]
			want := fmt.Sprintf("nodkey: cancelled by %s (exit %d)", name, 128+int(sig))
			if !diedOf(err, sig) || lastLine(stderr.String()) != want {
				t.Errorf("%v; stderr %q; want an end by %s and the last line %q", err, stderr.String(), sig, want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want it empty", stdout.String())
			}
			ended, err := gb.approver.WaitEnded(1, waitLimit)
			if err != nil || ended[0].Ending.Cause != audit.CauseCancelled {
				t.Errorf("the broker did not cancel the request: %+v, %v", ended, err)
			}
			gb.waitEvents(t, p.RequestID, "request denied:cancelled")
			gb.mustAsk(t, gb.client(t, "laptop"), gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
		})
	}
}
