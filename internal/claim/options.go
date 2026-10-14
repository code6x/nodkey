package claim

import (
	"slices"
	"strings"
)

// This file reads a command line word by word and finds the option values
// that are secret. Command uses it on the arguments; Mask uses it on the
// words of a free text, such as a shell script.

// pending says what a word asks of the next word.
type pending int

const (
	pendingNone   pending = iota
	pendingSecret         // the next word is secret
	pendingDashP          // after a bare -p: the next word is secret unless it starts with "-"
	pendingUser           // the next word may be USER:PASSWORD; the part after ":" is secret
	pendingEquals         // the next word is KEY=VALUE; the part after "=" is secret, or all of it without "="
	pendingHeader         // the next word is a header, as after curl -H; only Command reads it
)

// optionNames are parts of option names whose value is secret. "pass"
// also covers password and passwd; "key" also covers api-key and
// private-key.
var optionNames = []string{"pass", "pwd", "token", "secret", "auth", "credential", "cookie", "key"}

// valueless lists options whose names contain a part from optionNames but
// which take no value.
var valueless = map[string]bool{
	"--ask-pass":           true, // ansible: ask for the SSH password
	"--ask-become-pass":    true, // ansible: ask for the sudo password
	"--ask-vault-pass":     true, // ansible
	"--ask-vault-password": true, // ansible
	"--askpass":            true, // redis-cli: ask for the password
	"--password-stdin":     true, // docker login: read the password from stdin
	"--with-token":         true, // gh auth login: read the token from stdin
	"--no-password":        true, // psql: never ask for a password
}

// valueKind says which part of an option value is secret.
type valueKind int

const (
	whole  valueKind = iota + 1 // all of it
	user                        // the part after the first ":", as in USER:PASSWORD; nothing without ":"
	equals                      // the part after the first "=", as in KEY=VALUE; all of it without "="
)

// A progRule says which words are secret for one program, or for one of
// its subcommands.
type progRule struct {
	// sub lists subcommand words. The rule counts only after they came,
	// in this order. Other words may come between them.
	sub []string
	// opts lists options whose value is secret: the next word, or
	// attached as --option=VALUE.
	opts map[string]valueKind
	// attached: a one-letter option in opts may hold its value attached,
	// as in -NVALUE.
	attached bool
	// grouped: one-letter options may be grouped, as getopt allows, as in
	// curl -su USER:PASSWORD or curl -suUSER:PASSWORD. The first letter
	// in opts takes the rest of the word as its value, or the next word
	// if the group ends with it.
	grouped bool
	// args says what is secret in each later argument that is not an
	// option: all of it (whole), or the part after "=" (equals).
	args valueKind
	// after lists words after which the next word is secret.
	after []string
}

// programs lists programs whose secret options have short or unusual
// names. The key is the program name without a path, in lower case.
var programs = map[string][]progRule{
	"curl": {{
		opts: map[string]valueKind{
			"-u": user, "--user": user, "-U": user, "--proxy-user": user,
			"-E": user, "--cert": user, "--proxy-cert": user, // CERTIFICATE:PASSWORD
			"-b": whole, "--cookie": whole,
		},
		attached: true,
		grouped:  true,
	}},
	"gh": {{
		sub:      []string{"secret", "set"},
		opts:     map[string]valueKind{"--body": whole, "-b": whole},
		attached: true,
	}},
	"kubectl": {{opts: map[string]valueKind{"--from-literal": equals}}},
	"vault": {
		{sub: []string{"kv", "put"}, args: equals},
		{sub: []string{"kv", "patch"}, args: equals},
		{sub: []string{"write"}, args: equals},
	},
	"openssl": {
		{opts: map[string]valueKind{"-k": whole, "-K": whole}}, // enc: password, key
		{sub: []string{"passwd"}, args: whole},
	},
	"ssh-keygen": {{opts: map[string]valueKind{"-N": whole, "-P": whole}, attached: true, grouped: true}},
	"redis-cli":  {{opts: map[string]valueKind{"-a": whole}}},
	"ldapsearch": ldapRules, "ldapadd": ldapRules, "ldapmodify": ldapRules,
	"ldapdelete": ldapRules, "ldapmodrdn": ldapRules, "ldapcompare": ldapRules,
	"ldapwhoami": ldapRules, "ldapexop": ldapRules,
	"ldappasswd": {{opts: map[string]valueKind{"-w": whole, "-a": whole, "-s": whole}, attached: true, grouped: true}},
	"sqlcmd":     sqlRules, "bcp": sqlRules,
	"mysqladmin": {{after: []string{"password", "old-password"}}},
	"putty":      puttyRules, "plink": puttyRules, "pscp": puttyRules, "psftp": puttyRules,
}

// Rules that several programs share. A program that comes twice, or a
// second program with the same rules, adds nothing (see argState.program).
var (
	ldapRules  = []progRule{{opts: map[string]valueKind{"-w": whole}, attached: true, grouped: true}}
	sqlRules   = []progRule{{opts: map[string]valueKind{"-P": whole}, attached: true}}
	puttyRules = []progRule{{opts: map[string]valueKind{"-pw": whole}}}
)

// argState follows the words of a command line: the programs they belong
// to, and what the last word asked of the next one.
type argState struct {
	pending pending
	// rules holds the rules of the programs from the programs table that
	// came so far: in a command line, since argv[0]; in free text, since
	// the last shell separator (see masker.options). Each rule is in the
	// table, and comes at most once.
	rules []*progRule
	seen  []int // for each rule: how many of its subcommand words came
}

// forWords returns a state for reading the words inside the next word:
// the same programs, but nothing pending, because the next word as a
// whole gets what is pending.
func (st *argState) forWords() argState {
	return argState{rules: slices.Clone(st.rules), seen: slices.Clone(st.seen)}
}

// reset forgets the programs, after a shell separator in free text.
func (st *argState) reset() {
	st.rules, st.seen = nil, nil
}

// next reads the next word. It returns the position in w from which the
// rest of w is secret, or -1.
func (st *argState) next(w string) int {
	isProgram := st.program(w)
	p := st.pending
	st.pending = pendingNone
	cut := -1
	switch {
	case p == pendingSecret:
		cut = 0
		if isOption(w) {
			// Fail safe: a secret value may also be an option that takes
			// a secret, as in --password --token VALUE.
			st.option(w)
		}
	case p == pendingDashP && !strings.HasPrefix(w, "-"):
		cut = 0
	case p == pendingUser && strings.Contains(w, ":"):
		cut = strings.IndexByte(w, ':') + 1
	case p == pendingEquals:
		cut = strings.IndexByte(w, '=') + 1 // 0 without "="
	case !isProgram:
		cut = st.option(w)
	}
	return cut
}

// program notes a word that names a program from the programs table. It
// reports whether w names a program.
//
// The rules of a new program are added to those of the programs before
// it; they do not replace them. A word may only look like a program, as
// the host in redis-cli -h vault -a VALUE, and it must not end the rules
// of the program that runs. A program may also run another one, as in
// sudo redis-cli -a VALUE or ssh web-1 redis-cli -a VALUE.
//
// Only a shell separator in free text ends the rules (see
// masker.options). A command line has none: the shell has already split
// the words, so a ";" in an argument is text, as in curl -H "Cookie:
// a=1;" -E client.pem:VALUE.
func (st *argState) program(w string) bool {
	rules, ok := programs[programName(w)]
	for i := range rules {
		if r := &rules[i]; !slices.Contains(st.rules, r) {
			st.rules = append(st.rules, r)
			st.seen = append(st.seen, 0)
		}
	}
	return ok
}

// programName returns the name of the program that the word w may name,
// in lower case and without a path: redis-cli for /usr/bin/redis-cli,
// "$(which redis-cli)", redis-cli.exe, or /tmp&&redis-cli, where a shell
// separator is glued to the program.
func programName(w string) string {
	w = strings.TrimRight(w, "\"')`};&|")
	if i := strings.LastIndexAny(w, ";&|"); i >= 0 {
		w = w[i+1:]
	}
	w = strings.TrimLeft(w, "\"'($`{")
	if i := strings.LastIndexAny(w, `/\`); i >= 0 {
		w = w[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(w), ".exe")
}

// isOption reports whether w is an option: it starts with "-", maybe
// after a quote.
func isOption(w string) bool {
	w = strings.TrimLeft(w, `"'`)
	return len(w) >= 2 && w[0] == '-'
}

// option reads a word that is not a pending value. It returns the position
// from which the rest of w is secret, or -1.
func (st *argState) option(w string) int {
	lead := 0 // a quote before the option, as in a shell script
	if strings.HasPrefix(w, `"`) || strings.HasPrefix(w, "'") {
		lead = 1
	}
	o := w[lead:]
	if lead == 1 && len(o) > 1 && o[len(o)-1] == w[0] {
		o = o[:len(o)-1] // the closing quote, as in mysql "-p" VALUE
	}
	if len(o) < 2 || o[0] != '-' {
		return shift(st.argument(o), lead)
	}
	if cut, ok := st.programOption(o); ok {
		return shift(cut, lead)
	}
	switch {
	case o == "-p":
		// A bare -p: the next word is its value, as in mysql -p VALUE,
		// unless it is another option. So the port in ssh -p 2222 is
		// hidden too.
		st.pending = pendingDashP
		return -1
	case o == "-H" || o == "--header":
		st.pending = pendingHeader
		return -1
	case o[1] == 'p':
		// -pVALUE. Fail safe: hide it even when it may be a long option
		// such as -passin, or -pw as PuTTY tools use, and then hide the
		// next word too.
		if name, _, attached := strings.Cut(o[1:], "="); !attached && (name == "pw" || secretOption(strings.ToLower(name))) {
			st.pending = pendingSecret
		}
		return lead + 2
	case (o[1] == 'u' || o[1] == 'U') && strings.Contains(o, ":"):
		// -uUSER:PASSWORD. This comes before the names below, so that a
		// user name such as "auth" cannot keep the password visible.
		return lead + strings.IndexByte(o, ':') + 1
	}
	name, value, attached := strings.Cut(strings.TrimLeft(o, "-"), "=")
	name = strings.ToLower(name)
	start := lead + len(o) - len(value) // where an attached value starts
	switch {
	case name == "u" || name == "user" || name == "proxy-user":
		if !attached {
			st.pending = pendingUser
			return -1
		}
		return shift(cutValue(value, user), start)
	case secretOption(name):
		if !attached {
			if !valueless[strings.ToLower(o)] {
				st.pending = pendingSecret
			}
			return -1
		}
		return start
	}
	return -1
}

// programOption checks the option o against the rules of the current
// program. ok is false when no rule knows o.
func (st *argState) programOption(o string) (cut int, ok bool) {
	for i, r := range st.rules {
		if st.seen[i] < len(r.sub) {
			continue // its subcommand has not come yet
		}
		if k, ok := r.opts[o]; ok {
			st.pending = pendingFor(k)
			return -1, true
		}
		if name, value, attached := strings.Cut(o, "="); attached && strings.HasPrefix(o, "--") {
			if k, ok := r.opts[name]; ok {
				return shift(cutValue(value, k), len(name)+1), true
			}
		}
		if cut, ok := st.letters(r, o); ok {
			return cut, true
		}
	}
	return -1, false
}

// letters reads o as one-letter options of the rule r: -NVALUE if r
// allows attached values, and a group such as -xw or -sudeploy:VALUE if r
// allows groups. The first letter in r.opts takes the rest of o as its
// value, or the next word if o ends with it. The letters before it must be
// letters, as options without a value. ok is false when no letter is in
// r.opts.
func (st *argState) letters(r *progRule, o string) (cut int, ok bool) {
	if len(o) < 3 || o[1] == '-' || !r.attached && !r.grouped {
		return -1, false
	}
	for j := 1; j < len(o); j++ {
		name := [2]byte{'-', o[j]}
		if k, ok := r.opts[string(name[:])]; ok {
			if j+1 == len(o) {
				st.pending = pendingFor(k)
				return -1, true
			}
			return shift(cutValue(o[j+1:], k), j+1), true
		}
		if !r.grouped || !isASCIILetter(o[j]) {
			break
		}
	}
	return -1, false
}

// argument reads a word that is not an option: a subcommand, a word after
// which a secret comes, or an argument that is secret itself.
func (st *argState) argument(w string) int {
	lw := strings.ToLower(strings.TrimRight(w, `"'`))
	cut := -1
	for i, r := range st.rules {
		if st.seen[i] < len(r.sub) {
			if lw == r.sub[st.seen[i]] {
				st.seen[i]++
			}
			continue
		}
		switch r.args {
		case whole:
			cut = 0
		case equals:
			if j := strings.IndexByte(w, '='); j >= 0 && cut < 0 {
				cut = j + 1
			}
		}
		if slices.Contains(r.after, lw) {
			st.pending = pendingSecret
		}
	}
	return cut
}

// pendingFor returns what an option whose value is of kind k asks of the
// next word.
func pendingFor(k valueKind) pending {
	switch k {
	case user:
		return pendingUser
	case equals:
		return pendingEquals
	}
	return pendingSecret
}

// cutValue returns the position in the option value v from which it is
// secret, or -1.
func cutValue(v string, k valueKind) int {
	switch k {
	case user:
		if i := strings.IndexByte(v, ':'); i >= 0 {
			return i + 1
		}
		return -1
	case equals:
		return strings.IndexByte(v, '=') + 1 // 0 without "="
	}
	return 0
}

// shift moves a position by n, and keeps -1 as it is.
func shift(cut, n int) int {
	if cut < 0 {
		return -1
	}
	return cut + n
}

// secretOption reports whether the value of the option with this lower
// case name is secret.
func secretOption(name string) bool {
	for _, part := range optionNames {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}
