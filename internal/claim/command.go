package claim

import (
	"strconv"
	"strings"
)

// maxArgs is the most arguments Command shows after the program.
const maxArgs = 8

// Command renders a command line as one safe line of at most maxRunes
// runes. argv[0] is the program. Command shows the program and at most
// maxArgs arguments; if there are more, it adds "… (+N more)". If all the
// arguments together are longer than MaxInput bytes, Command returns
// "[hidden: too long]", cut to maxRunes. Masking is best effort, as for
// Mask. Command hides:
//
//   - the value of an option whose name contains pass (also password and
//     passwd), pwd, token, secret, auth, credential, cookie or key, for
//     example --password, --api-key or --github-token. The value is hidden
//     both as the next argument (--password VALUE) and attached
//     (--password=VALUE). Names with one dash count too (-token VALUE, as
//     Go programs use). A few such options take no value, for example
//     --ask-become-pass and --password-stdin; the next argument after them
//     stays visible.
//   - the value of -p: attached (-pVALUE, as mysql uses), and the next
//     argument after a bare -p, unless that argument starts with "-". So
//     the port in ssh -p 2222 is hidden too. After -pw, as PuTTY tools
//     use, the next argument is hidden too.
//   - the password in USER:PASSWORD after -u, -U, --user and --proxy-user,
//     as curl uses.
//   - the options of the programs in the programs table, whose names do
//     not say "secret": curl -u, -U, -E and --cert (the part after ":"),
//     -b; gh secret set --body and -b; kubectl --from-literal (the part
//     after "="); the KEY=VALUE arguments of vault kv put, vault kv patch
//     and vault write; openssl -k and -K, and the arguments of openssl
//     passwd; ssh-keygen -N and -P; redis-cli -a; -w of ldapsearch and the
//     other OpenLDAP tools, and -a and -s of ldappasswd; sqlcmd -P and bcp
//     -P; the argument after password and old-password for mysqladmin;
//     -pw of putty, plink, pscp and psftp. For curl, ssh-keygen and the
//     OpenLDAP tools, one-letter options may be grouped, as in curl -su
//     USER:PASSWORD, curl -suUSER:PASSWORD or ldapsearch -xw VALUE. A word
//     anywhere before counts as the program, as in sudo redis-cli -a
//     VALUE. The rules of all such programs in the command line count
//     together, so a host named vault in redis-cli -h vault -a VALUE does
//     not end the rules of redis-cli. No argument ends them: the shell has
//     already split the words, so a ";" in an argument is text, as in
//     curl -H "Cookie: a=1;" -E client.pem:VALUE. Inside one argument,
//     such as the script of sh -c, Mask reads the words, and a shell
//     separator outside quotes ends the rules for the rest of it.
//   - the whole value of an argument that is a header with a secret name,
//     such as "Cookie: a=1; b=2", "X-Api-Key: VALUE", or the argument after
//     -H or --header, also without a space after ":".
//   - the whole value of an argument KEY=VALUE whose key has a secret
//     name, as in env "DB_PASSWORD=two words" ./run, also with brackets,
//     as in user[password]=VALUE.
//   - everything Mask finds, in each argument.
//
// An argument that is hidden as an option value may itself be an option
// that takes a secret, so the argument after it is hidden too.
//
// An argument that contains a space, or is empty, is put in single quotes.
// Then the line is made safe and cut as Line does it.
func Command(argv []string, maxRunes int) string {
	if maxRunes <= 0 || len(argv) == 0 {
		return ""
	}
	size := 0
	for _, a := range argv {
		if size += len(a); size > MaxInput {
			return cut(tooLong, maxRunes)
		}
	}
	shown := argv[:min(len(argv), maxArgs+1)]
	words := make([]string, len(shown))
	var st argState
	for i, a := range shown {
		a = clean(a)
		// Mask reads the words inside a, as in sh -c SCRIPT, with the
		// program that a belongs to, so that plink -pw stays -pw.
		inner := st.forWords()
		if i == 0 {
			st.program(a) // argv[0] is the program, not an option
		} else {
			header := st.pending == pendingHeader
			if c := st.next(a); c >= 0 && c < len(a) {
				a = a[:c] + hidden
			}
			a = hideAssignment(hideHeader(a, header))
		}
		words[i] = quote(mask(a, inner))
	}
	line := strings.Join(words, " ")
	if more := len(argv) - len(shown); more > 0 {
		line += " " + ellipsis + " (+" + strconv.Itoa(more) + " more)"
	}
	return cut(clean(line), maxRunes)
}

// hideHeader hides the whole value of an argument that is a header with a
// secret name, as in curl -H "Cookie: a=1; b=2": the argument holds
// nothing else. afterOption says that the argument comes after -H or
// --header. Without it, "name:VALUE" with no space after ":" counts only
// as Mask counts it, so that a host and path such as auth-1:/srv stays.
func hideHeader(a string, afterOption bool) string {
	prefix := ""
	if !afterOption {
		for _, p := range []string{"--header=", "-header=", "-H"} {
			if strings.HasPrefix(a, p) {
				prefix = p
				break
			}
		}
	}
	name, value, ok := strings.Cut(a[len(prefix):], ":")
	if !ok || !isName(name) || !sensitiveRE.MatchString(name) {
		return a
	}
	v := strings.TrimLeft(value, " ")
	if v == "" || v == hidden {
		return a
	}
	if len(v) == len(value) && !afterOption && prefix == "" && (v[0] == '/' || !secretParts(name)) {
		return a
	}
	return a[:len(a)-len(v)] + hidden
}

// hideAssignment hides the whole value of an argument KEY=VALUE whose key
// has a secret name: the argument holds nothing else.
func hideAssignment(a string) string {
	name, value, ok := strings.Cut(a, "=")
	if !ok || value == "" || value == hidden || !isName(name) || name[0] == '-' ||
		!sensitiveRE.MatchString(name) {
		return a
	}
	return name + "=" + hidden
}

// isName reports whether s is not empty and holds only ASCII letters,
// digits, "_", ".", "-" and brackets, as a header name, a variable name or
// a form field such as user[password] does. Inside brackets, ":" and
// quotes count too, as in params[:password] or config['password'].
func isName(s string) bool {
	inBrackets := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isAlnum(c) || c == '_' || c == '.' || c == '-':
		case c == '[':
			inBrackets = true
		case c == ']':
			inBrackets = false
		case inBrackets && (c == ':' || c == '"' || c == '\''):
		default:
			return false
		}
	}
	return s != ""
}

// quote puts a in single quotes, as a shell would, if it is empty or holds
// a space.
func quote(a string) string {
	if a != "" && !strings.Contains(a, " ") {
		return a
	}
	return "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
}
