//go:build !linux

package transport

import (
	"errors"
	"os"
)

// Version 1 runs on Linux only (DESIGN.md section 3). Elsewhere nodkey
// keygen fails closed: it makes no file.
func createKeyFile(string) (*os.File, error) {
	return nil, errors.New("nodkey keygen runs on Linux only")
}
