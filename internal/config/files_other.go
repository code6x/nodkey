//go:build !linux

package config

import (
	"errors"
	"io/fs"
	"os"
)

// Version 1 runs on Linux only (DESIGN.md section 3). Elsewhere the file
// checks fail closed: fileOwner reports no owner, so ReadPrivateFile,
// CheckPrivateFile, ReadConfigFile and CheckFiles always return an error.

const openFlags = os.O_RDONLY

func fileOwner(fs.FileInfo) (uint32, bool) { return 0, false }

func checkFileSystem(*os.File) error { return errors.ErrUnsupported }

func fileACL(*os.File) ([]byte, error) { return nil, errors.ErrUnsupported }
