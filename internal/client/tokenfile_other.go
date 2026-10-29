//go:build !unix

package client

import "io/fs"

// ownedByUser fails closed where the owner cannot be checked.
func ownedByUser(fs.FileInfo) bool { return false }

// noFollow is not there; the name is new, and O_EXCL refuses a link.
const noFollow = 0
