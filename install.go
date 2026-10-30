// Package nodkey holds the files of the repository that are built into
// the binary: install.sh, so that nodkey update can run the copy that is
// built into the binary, and CHANGELOG.md, for nodkey changes. The code
// that checks a new release then comes from the build that is installed
// and was checked, not fresh from the network (DESIGN.md section 18).
//
// An embed directive cannot reach a parent directory, so the embeds are
// here, next to the files, at the root of the module.
package nodkey

import _ "embed" // for go:embed

// InstallScript is the text of install.sh, byte for byte.
//
//go:embed install.sh
var InstallScript string

// Changelog is the text of CHANGELOG.md, byte for byte. release-please
// writes it before it tags a release, so a release holds its own entry.
//
//go:embed CHANGELOG.md
var Changelog string
