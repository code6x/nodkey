//go:build !linux

package client

import (
	"errors"
	"io/fs"
	"net"
	"os"
)

// peerCredentials refuses every connection here: version 1 runs on Linux
// only (DESIGN.md section 3), and nodkey ssh-agent checks the user of
// each connection with SO_PEERCRED.
func peerCredentials(*net.UnixConn) (peer, error) {
	return peer{}, errors.New("client: the user of a connection cannot be checked on this system")
}

// ownerOf cannot tell the owner of a file here, so every check of an
// owner fails.
func ownerOf(fs.FileInfo) (uint32, bool) { return 0, false }

// lockFile cannot lock a file here, so the agent does not start.
func lockFile(*os.File) error {
	return errors.New("client: the socket cannot be locked on this system")
}

// waitHangUp cannot watch a connection here: it reports false at once, so
// a request is not cancelled when ssh hangs up.
func waitHangUp(*net.UnixConn) bool { return false }
