package main

import (
	"io"

	"github.com/code6x/nodkey/internal/client"
)

// runPreapprove runs nodkey preapprove (package client): it asks once for
// a scheduled grant of secrets or SSH logins, to use later, and prints the
// ID of the grant (DESIGN.md section 8).
func runPreapprove(args []string, stdout, stderr io.Writer) int {
	return client.Preapprove(args, stdout, stderr, version)
}
