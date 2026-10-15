package broker

import (
	"strings"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/claim"
)

// The longest claimed text that the broker keeps of each field, in runes,
// for the approval message and the audit log. The Telegram code cuts each
// field shorter again for the message (DESIGN.md section 7). With these
// caps every audit entry fits in audit.MaxLineSize, also with the worst
// characters, which take 4 bytes each: a test checks it.
const (
	// maxCommandRunes is for the command line of nodkey run, and for the
	// command lines of an SSH login together.
	maxCommandRunes = 2000
	// maxLineRunes is for one command line of an SSH login: ssh or one of
	// its parents.
	maxLineRunes = 500
	// maxDirRunes is for the working directory.
	maxDirRunes = 1000
	// maxReasonRunes is for the reason.
	maxReasonRunes = 1000
	// maxVarsRunes is for the variable names together.
	maxVarsRunes = 1000
)

// commandJoin joins the command lines of an SSH login: ssh, then its
// parents, as in "ssh deploy@web-1 ← ansible-playbook site.yml".
const commandJoin = " ← "

// freeText makes claimed free text safe, such as the reason: it masks the
// values that look like secrets, then makes one clean line of at most n
// runes. Mask comes before Line, as package claim says: a secret that was
// cut may not look like a secret any more.
func freeText(s string, n int) string {
	return claim.Line(claim.Mask(s), n)
}

// varsText shows the variables of a request for secrets, as claimed text:
// "GH_TOKEN, NPM_TOKEN". The names are masked too: the agent chooses them,
// and a name can hold a secret by mistake.
func varsText(refs []api.SecretRef) string {
	vars := make([]string, len(refs))
	for i, r := range refs {
		vars[i] = r.Var
	}
	return freeText(strings.Join(vars, ", "), maxVarsRunes)
}

// sshCommands shows the command lines of an SSH login as one line, ssh
// first. claim.Command masks each one and shows at most 8 arguments.
func sshCommands(lines [][]string) string {
	parts := make([]string, 0, len(lines))
	for _, argv := range lines {
		if c := claim.Command(argv, maxLineRunes); c != "" {
			parts = append(parts, c)
		}
	}
	return claim.Line(strings.Join(parts, commandJoin), maxCommandRunes)
}
