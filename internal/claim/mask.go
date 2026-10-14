package claim

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
)

// hidden replaces each value that looks like a secret.
const hidden = "***"

// sensitiveNames are parts of a key name that make its value secret, in
// key=value and "key: value". "pass" also covers password and passwd.
const sensitiveNames = `pass|pwd|token|secret|api[_-]?key|access[_-]?key|auth|credential|private[_-]?key|cookie`

// keyChars matches the rest of a key name around a secret name: letters,
// digits, "_", "." and "-", and brackets as in user[password],
// params[:password] or config['password'].
const keyChars = `(?:[a-z0-9_.\]-]|\[["':]?|["']\])*`

var (
	// pemRE finds a PEM block. The BEGIN and END lines stay. A block
	// without an END line goes on to the end of the text.
	pemRE = regexp.MustCompile(`(-----BEGIN [A-Z0-9 ]*-----).*?(-----END [A-Z0-9 ]*-----|$)`)

	// keyRE finds a key with a secret name and the separator after it:
	// "=" (also ":=", "?=", "+=", "==" and "=>", with or without spaces),
	// ":" with or without spaces, or a quoted key and ":" as in JSON. The
	// quotes may be escaped, as in {\"password\":\"VALUE\"}. keyRE does
	// not take the value, so a key inside the value of another key is
	// found too.
	keyRE = regexp.MustCompile(`(?i)` + keyChars + `(?:` + sensitiveNames + `)` + keyChars +
		`(\\*["']\s*:\s*|\\*["']?\s*[:?+!]?={1,3}>?\s*|\s*:\s*)`)

	// sensitiveRE finds a secret name in a key.
	sensitiveRE = regexp.MustCompile(`(?i)` + sensitiveNames)

	// schemeRE finds Bearer or Basic before credentials.
	schemeRE = regexp.MustCompile(`\b(?:[Bb]earer|BEARER|Basic|BASIC)\s+`)

	// tokenRE finds tokens by their known shape: GitHub, GitLab, Slack,
	// OpenAI-style "sk-" keys, AWS access key IDs and JWTs.
	tokenRE = regexp.MustCompile(`\b(?:` +
		`gh[pousr]_[A-Za-z0-9]{10,}` +
		`|github_pat_[A-Za-z0-9_]{10,}` +
		`|glpat-[A-Za-z0-9_-]{10,}` +
		`|xox[abpr]-[A-Za-z0-9-]{8,}` +
		`|sk-[A-Za-z0-9_-]{20,}` +
		`|(?:AKIA|ASIA)[A-Z0-9]{16}` +
		`|eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*` +
		`)`)
)

// Mask hides values that look like secrets in free text, such as a reason,
// a path or a shell script. Each value becomes "***". Masking is best
// effort: it finds common forms only, so the text stays a claim that the
// person must judge.
//
// If s is longer than MaxInput bytes, Mask returns "[hidden: too long]".
// Else Mask first cleans s as Line does, so the result is one line, but
// Mask does not cut it. Then it hides:
//
//   - PEM blocks, between the BEGIN and END lines;
//   - the password in USER:PASSWORD@HOST, with or without a scheme such as
//     https://. The password goes on to the last "@" of the word, so it
//     may hold "@", ":", "/", "?" and "#". Not hidden: HOST:PORT/PATH with
//     an "@" in the path, and an image digest as in app:1.2@sha256:...
//   - the value after a key whose name contains password, passwd, pwd,
//     pass, token, secret, apikey, api_key, api-key, access_key, auth,
//     credential, private_key or cookie, in any case and inside longer
//     names such as GITHUB_TOKEN or db.password. The name may hold
//     brackets, as in user[password], params[:password] or
//     config['password']. Key and value may be joined by "=", ":=", "?=",
//     "+=", "=>" or ": " (key=value, YAML, PHP), or a quoted key and ":"
//     (JSON, also with escaped quotes as in {\"password\":\"VALUE\"}).
//     "key:value" without a space counts only when a part of the name
//     between "-", "_", "." and brackets is a secret word or
//     ends in one, as in X-Api-Key:VALUE, Cookie:VALUE or
//     accessToken:VALUE, and the value does not start with "/". So
//     auth-1.example.com:/srv and https://auth.example.com:8443 stay
//     readable.
//   - the value after Bearer and Basic.
//   - known token shapes: ghp_, gho_, ghu_, ghs_, ghr_, github_pat_,
//     glpat-, xoxa-, xoxb-, xoxp-, xoxr-, sk-, AKIA and ASIA key IDs, JWTs;
//   - command line options in the text, as Command finds them, for example
//     "--password VALUE", "-pVALUE", "-p VALUE" and "redis-cli -a VALUE"
//     in a shell script;
//   - long random-looking words, also as one part of a path or URL (see
//     looksRandom and maskRandomWords).
//
// A value is a whole shell word: quotes may join several parts, as in
// password=""VALUE, and a backslash outside quotes makes the next
// character plain. A value that is a quoted string ends with its quotes,
// and the quotes stay. A value inside quotes goes on to the closing quote,
// as in "PASSWORD=two words". An object or a list ({...}, [...]) is hidden
// whole, as in {"auth": {"user": "x", "pass": "y"}}. After a key whose
// name ends in authorization, the value is an authentication scheme and
// the credentials; after other keys, a scheme word such as Bearer or token
// takes the next word too, as in HTTP_AUTHORIZATION=Bearer VALUE. A Cookie
// value goes on over "; ", as in Cookie: a=1; b=2.
func Mask(s string) string {
	if len(s) > MaxInput {
		return tooLong
	}
	return mask(s, argState{})
}

// mask does what Mask does. st gives the program that the words of s
// belong to; Command passes the program of the argument s.
func mask(s string, st argState) string {
	// Clean first, so that an invisible character cannot split a name
	// such as "password".
	m := &masker{s: clean(s)}
	m.pemBlocks()
	m.urlPasswords()
	m.keyValues()
	m.schemes()
	m.tokens()
	m.options(st)
	return maskRandomWords(m.render())
}

// span is a part s[start:end] of the text to hide.
type span struct{ start, end int }

// masker collects the parts of a clean text to hide. Each rule reads the
// whole text, so one rule cannot hide what another rule needs to see,
// such as a key inside the value of another key.
type masker struct {
	s         string
	spans     []span
	q         *quoting // made when first needed
	brace     span     // the last object or list that was hidden
	cookieEnd int      // the end of the last Cookie value that was hidden
}

func (m *masker) hide(start, end int) {
	if start < end {
		m.spans = append(m.spans, span{start, end})
	}
}

func (m *masker) quoting() *quoting {
	if m.q == nil {
		m.q = newQuoting(m.s)
	}
	return m.q
}

// render returns the text with each hidden part replaced by "***". Parts
// that overlap or touch become one "***".
func (m *masker) render() string {
	if len(m.spans) == 0 {
		return m.s
	}
	slices.SortFunc(m.spans, func(a, b span) int { return cmp.Compare(a.start, b.start) })
	var b strings.Builder
	b.Grow(len(m.s))
	last := 0
	for i := 0; i < len(m.spans); {
		start, end := m.spans[i].start, m.spans[i].end
		for i++; i < len(m.spans) && m.spans[i].start <= end; i++ {
			end = max(end, m.spans[i].end)
		}
		b.WriteString(m.s[last:start])
		b.WriteString(hidden)
		last = end
	}
	b.WriteString(m.s[last:])
	return b.String()
}

func (m *masker) pemBlocks() {
	for _, x := range pemRE.FindAllStringSubmatchIndex(m.s, -1) {
		m.hide(x[3], x[4]) // between the BEGIN line and the END line or the end
	}
}

func (m *masker) schemes() {
	for _, x := range schemeRE.FindAllStringIndex(m.s, -1) {
		start, end, _ := m.valueSpan(x[1])
		m.hide(start, end)
	}
}

func (m *masker) tokens() {
	for _, x := range tokenRE.FindAllStringIndex(m.s, -1) {
		m.hide(x[0], x[1])
	}
}

func (m *masker) keyValues() {
	for _, x := range keyRE.FindAllStringSubmatchIndex(m.s, -1) {
		nameStart, nameEnd, valueStart := x[0], x[2], x[1]
		name, sep := m.s[nameStart:nameEnd], m.s[nameEnd:valueStart]
		if sep == ":" && !m.colonValue(nameStart, name, valueStart) {
			continue
		}
		var quote byte // the quote right before an unquoted key, as in "PASSWORD=two words"
		if nameStart > 0 && !strings.ContainsAny(sep, `"'`) {
			if c := m.s[nameStart-1]; c == '"' || c == '\'' {
				quote = c
			}
		}
		m.hideValue(valueStart, strings.ToLower(name), quote)
	}
}

// colonValue reports whether "name:VALUE", with no space after ":", holds
// a secret value, as in X-Api-Key:VALUE. It is not a host name and a path
// or port, as in auth-1.example.com:/srv or https://auth:8443.
func (m *masker) colonValue(nameStart int, name string, valueStart int) bool {
	if nameStart > 0 && strings.IndexByte("/@.:", m.s[nameStart-1]) >= 0 {
		return false
	}
	if valueStart < len(m.s) && m.s[valueStart] == '/' {
		return false
	}
	return secretParts(name)
}

// secretParts reports whether a whole part of name, between "-", "_",
// "." and brackets, is a secret word, as in X-Api-Key, X-Auth-Token,
// db.password or user[password]. Only the last part after a "." counts,
// so a host name such as auth.example.com does not.
func secretParts(name string) bool {
	name = strings.ToLower(name)
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	parts := strings.FieldsFunc(name, func(r rune) bool { return strings.ContainsRune(`-_[]:"'`, r) })
	for i, p := range parts {
		switch p {
		case "pass", "pwd", "auth", "authorization", "cookie", "cookies",
			"credential", "credentials", "passphrase":
			return true
		case "api", "access", "private":
			if i+1 < len(parts) && parts[i+1] == "key" {
				return true
			}
		}
		for _, end := range []string{"password", "passwd", "token", "tokens", "secret", "secrets", "apikey"} {
			if strings.HasSuffix(p, end) {
				return true
			}
		}
	}
	return false
}

// hideValue hides the value that starts at v, after a key with the lower
// case name lname. quote is the quote right before the key, or 0.
func (m *masker) hideValue(v int, lname string, quote byte) {
	start, end, plain := m.valueSpan(v)
	if quote != 0 {
		// The value goes on to the next same quote, as in
		// "PASSWORD=two words". This holds even when a stray quote
		// earlier in the text makes the shell read the quotes the other
		// way.
		e := strings.IndexByte(m.s[v:], quote)
		if e < 0 {
			e = len(m.s)
		} else {
			e += v
		}
		end = max(end, e)
	}
	if start >= end {
		return
	}
	if plain {
		switch {
		case isScheme(m.s[v:end], lname):
			// The credentials come in the next word, as in
			// HTTP_AUTHORIZATION=Bearer VALUE.
			if end < len(m.s) && m.s[end] == ' ' {
				end = max(end, m.valueEnd(end+1))
			}
		case strings.Contains(lname, "cookie") && v >= m.cookieEnd:
			// A Cookie value goes on over "; ", as in Cookie: a=1; b=2.
			for end < len(m.s) && m.s[end-1] == ';' && m.s[end] == ' ' {
				e := m.valueEnd(end + 1)
				if e <= end+1 {
					break
				}
				end = e
			}
			m.cookieEnd = end
		}
	}
	m.hide(start, end)
}

// valueEnd returns the end of the value that starts at v, with the quotes
// that close it.
func (m *masker) valueEnd(v int) int {
	start, end, _ := m.valueSpan(v)
	if start > v {
		end += start - v // the closing quote, maybe escaped
	}
	return end
}

// isScheme reports whether the word w is an HTTP authentication scheme, so
// that the credentials come in the next word. After a key whose name ends
// in authorization, any word of letters, digits and "-" counts; after
// other keys, only the common schemes.
//
// w may run to the end of a long shell word, as in PASS=PASS=PASS=...,
// where the value of each key is the rest of the word. So that the work
// for all keys stays linear in the length of the text, the loop below
// stops at the first byte that is not a letter, digit or "-" (the
// separator of the next key always holds one), and the switch looks only
// at short words.
func isScheme(w, lname string) bool {
	if strings.HasSuffix(strings.TrimRight(lname, `"']`), "authorization") {
		if w == "" || !isASCIILetter(w[0]) {
			return false
		}
		for i := 1; i < len(w); i++ {
			if c := w[i]; !isAlnum(c) && c != '-' {
				return false
			}
		}
		return true
	}
	if len(w) > len("negotiate") {
		return false // longer than every scheme below
	}
	switch strings.ToLower(w) {
	case "bearer", "basic", "token", "digest", "negotiate", "ntlm", "oauth":
		return true
	}
	return false
}

func isASCIILetter(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// isAlnum reports whether c is an ASCII letter or digit.
func isAlnum(c byte) bool {
	return isASCIILetter(c) || '0' <= c && c <= '9'
}

// valueSpan returns the part of the text to hide for a value that starts
// at v. A quoted string keeps its quotes. plain reports a value that is a
// shell word outside quotes; then the span starts at v.
func (m *masker) valueSpan(v int) (start, end int, plain bool) {
	s, n := m.s, len(m.s)
	if v >= n || s[v] == ' ' {
		return v, v, false
	}
	c := s[v]
	if c == '\\' {
		// A quote escaped with backslashes, as in {\"password\":\"VALUE\"}:
		// the value goes on to the next same escaped quote.
		k := v
		for k < n && s[k] == '\\' {
			k++
		}
		if k < n && (s[k] == '"' || s[k] == '\'') {
			if j := strings.Index(s[k+1:], s[v:k+1]); j >= 0 {
				return k + 1, k + 1 + j, false
			}
			return v, n, false
		}
	}
	q := m.quoting()
	in := q.in[v]
	switch {
	case c == '"' || c == '\'':
		// A quoted string. It keeps its quotes, unless more of the same
		// shell word follows, as in password=""VALUE.
		e := closingQuote(s, v)
		if e < 0 {
			return v, n, false
		}
		if e+1 == n || strings.IndexByte(" ,;)}]&|<>", s[e+1]) >= 0 {
			return v + 1, e, false
		}
		return v, max(e+1, q.wordEnd(e+1)), false
	case (c == '{' || c == '[') && in != '"':
		if m.brace.start < v && v < m.brace.end {
			// Inside an object or list that is already hidden. Not
			// scanning it again keeps the work linear for deep objects.
			return v, v, false
		}
		limit := n
		if in == '\'' {
			limit = q.partEnd(v)
		}
		m.brace = span{v, matchBracket(s, v, limit)}
		return v, m.brace.end, false
	case in != 0:
		// Inside quotes, as in "PASSWORD=two words": up to the closing
		// quote, and on to the end of the shell word if it goes on.
		e := q.partEnd(v)
		if e+1 < n && s[e+1] != ' ' {
			e = q.wordEnd(e + 1)
		}
		return v, e, false
	}
	return v, q.wordEnd(v), true
}

// urlPasswords hides the password in USER:PASSWORD@HOST, in each word of
// the text.
func (m *masker) urlPasswords() {
	s := m.s
	for start := 0; start < len(s); {
		end := strings.IndexByte(s[start:], ' ')
		if end < 0 {
			end = len(s)
		} else {
			end += start
		}
		if from, to := urlPassword(s[start:end]); from < to {
			m.hide(start+from, start+to)
		}
		start = end + 1
	}
}

// urlPassword returns where the password is in the word w, or 0, 0.
func urlPassword(w string) (from, to int) {
	at := strings.LastIndexByte(w, '@')
	if at < 0 {
		return 0, 0
	}
	u := 0 // where USER:PASSWORD starts
	k := strings.Index(w[:at], "://")
	scheme := k > 0 && isSchemeByte(w[k-1])
	if scheme {
		u = k + 3
	} else {
		colon := strings.IndexByte(w[:at], ':')
		if colon < 0 {
			return 0, 0
		}
		u = strings.LastIndexAny(w[:colon], `"'=(<`) + 1
		if strings.HasPrefix(w[at+1:], "sha256:") || strings.HasPrefix(w[at+1:], "sha384:") ||
			strings.HasPrefix(w[at+1:], "sha512:") {
			return 0, 0 // an image digest, as in app:1.2@sha256:...
		}
	}
	userName, password, ok := strings.Cut(w[u:at], ":")
	if !ok || password == "" || strings.ContainsAny(userName, "/?#") {
		return 0, 0
	}
	if !scheme && (userName == "" || !isUserName(userName)) {
		return 0, 0
	}
	if i := strings.IndexAny(password, "/?#"); i >= 0 && isDigits(password[:i]) {
		return 0, 0 // HOST:PORT/PATH, with an "@" later in the path
	}
	return u + len(userName) + 1, at
}

func isSchemeByte(c byte) bool {
	return isAlnum(c) || c == '+' || c == '.' || c == '-'
}

// isUserName reports whether s can be a user name in USER:PASSWORD@HOST
// without a scheme. It may be an e-mail address.
func isUserName(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && strings.IndexByte("._~%+-@", c) < 0 {
			return false
		}
	}
	return true
}

// isDigits reports whether s holds only ASCII digits. It is true for "".
func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// options hides option values in the words of the text, as Command does
// for arguments. st gives the programs the words belong to. A hidden value
// that opens a quote goes on until the quote closes, so --password "two
// words" hides both words.
//
// The words that such a value takes are still read for programs and
// options. So a quote or a backslash cannot hide a program from the rules,
// as in -p\ redis-cli -a VALUE, where the escaped space joins redis-cli to
// the value of -p. A value that starts in one of these words makes the
// hidden part go on until its own quote closes too: the quotes may be read
// in more than one way, and the hidden part ends only when no way leaves a
// quote open.
//
// A shell separator ends the rules of the programs before it: a
// separator as a word of its own, or ";" at the end of a word. So in
// redis-cli ping; tar -a -cf x, the -a of tar does not hide -cf, as the
// -a of redis-cli would. The separator counts only where the
// shell would read it as a separator (see quoting.separatorAt). A ";"
// inside quotes is text, as in sqlcmd -Q "SELECT 1; SELECT 2" -P VALUE,
// and must not end the rules of sqlcmd. When unsure, the rules stay: that
// can hide more, but never less.
func (m *masker) options(st argState) {
	if m.s == "" {
		return
	}
	words := strings.Split(m.s, " ")
	start := 0 // where words[i] starts
	for i := 0; i < len(words); i++ {
		w := words[i]
		if isSeparator(w) && m.quoting().separatorAt(start) {
			st.reset()
		}
		cut := st.next(w)
		end := start + len(w)
		next := end + 1
		if cut >= 0 && cut < len(w) {
			open := openQuotes(0).add(quoteAfter(w, 0))
			for open != 0 && i+1 < len(words) {
				i++
				x := words[i]
				open = open.after(x)
				if c := st.next(x); c >= 0 && c < len(x) {
					open = open.add(quoteAfter(x, 0))
				}
				end = next + len(x)
				next = end + 1
			}
			m.hide(start+cut, end)
		}
		if strings.HasSuffix(words[i], ";") && m.quoting().separatorAt(end-1) {
			st.reset()
		}
		start = next
	}
}
