// Package nodkey holds the install script of nodkey, install.sh, so that
// nodkey update can run the copy that is built into the binary. The code
// that checks a new release then comes from the build that is installed
// and was checked, not fresh from the network (DESIGN.md section 18).
//
// An embed directive cannot reach a parent directory, so the embed is
// here, next to install.sh, at the root of the module.
package nodkey

import _ "embed" // for go:embed

// InstallScript is the text of install.sh, byte for byte.
//
//go:embed install.sh
var InstallScript string
