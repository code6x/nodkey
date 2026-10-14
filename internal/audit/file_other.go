//go:build !linux

package audit

import (
	"errors"
	"io/fs"
	"os"
)

// Version 1 runs on Linux only (DESIGN.md section 3). Elsewhere Open
// fails closed. Verify works everywhere.

const supported = false

const (
	writeFlags = os.O_WRONLY | os.O_APPEND | os.O_CREATE
	readFlags  = os.O_RDONLY
)

func fileOwner(fs.FileInfo) (uint32, bool) { return 0, false }

func clearNonblock(*os.File) error { return errors.ErrUnsupported }

func lockFile(*os.File) error { return errors.ErrUnsupported }
