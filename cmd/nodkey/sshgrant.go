package main

import (
	"io"

	"github.com/code6x/nodkey/internal/client"
)

// runSSHGrant runs nodkey ssh-grant (package client): it asks once for SSH
// logins as one user to a list of hosts, for some minutes (DESIGN.md
// section 13).
func runSSHGrant(args []string, stderr io.Writer) int {
	return client.SSHGrant(args, stderr, version)
}
