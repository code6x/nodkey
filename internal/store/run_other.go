//go:build !linux

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
)

// Version 1 runs on Linux only (DESIGN.md section 3). Elsewhere a store
// fails closed: no program runs, and the home directory check fails.

const supported = false

func setProcessGroup(*exec.Cmd) {}

func killProcessGroup(*os.Process) error { return errors.ErrUnsupported }

func exitDetail(exit *exec.ExitError) string { return fmt.Sprintf("exit code %d", exit.ExitCode()) }

func fileOwner(fs.FileInfo) (uint32, bool) { return 0, false }
