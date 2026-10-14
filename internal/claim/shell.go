package claim

import (
	"slices"
	"strings"
)

// quoting says how a shell reads the quotes in a clean text. It lets Mask
// find where a value ends: at the closing quote when the value is inside
// quotes, else at the end of its shell word.
//
// Outside quotes, a backslash makes the next byte plain, so \' and \" do
// not open a quote. Inside double quotes, a backslash escapes the next
// byte. Inside single quotes, nothing is escaped.
type quoting struct {
	s string
	// in[i] is the quote that byte i is inside, a single or a double
	// quote, from the byte after the opening quote up to and with the
	// closing quote, else 0.
	in       []byte
	closes   []int // the positions of all closing quotes, in order
	spaces   []int // the positions of all spaces outside quotes, in order
	unclosed bool  // a quote is still open at the end of the text
	subst    int   // where the first substitution starts (see firstSubstitution), or -1
}

func newQuoting(s string) *quoting {
	q := &quoting{s: s, in: make([]byte, len(s)), subst: firstSubstitution(s)}
	var open byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if open != 0 {
			q.in[i] = open
			switch {
			case c == open:
				q.closes = append(q.closes, i)
				open = 0
			case open == '"' && c == '\\' && i+1 < len(s):
				i++
				q.in[i] = open
			}
			continue
		}
		switch c {
		case '\\':
			i++ // the next byte is plain
		case '"', '\'':
			open = c
		case ' ':
			q.spaces = append(q.spaces, i)
		}
	}
	q.unclosed = open != 0
	return q
}

// separatorAt reports whether the shell separator that starts at byte i,
// such as ";" or "&&", ends a command: it is outside quotes and not
// escaped with a backslash, as in \;. If a quote in the text is never
// closed, no separator counts, because the quotes may be apostrophes, as
// in "don't", and then the text inside and outside quotes is not known.
// After a substitution, no separator counts either: a ";" inside
// $(date; hostname) ends a command inside the substitution, not the
// command around it, and the end of the substitution is not looked for.
func (q *quoting) separatorAt(i int) bool {
	if q.unclosed || q.subst >= 0 && q.subst < i || q.in[i] != 0 {
		return false
	}
	n := 0 // the backslashes right before byte i
	for j := i - 1; j >= 0 && q.s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 0
}

// firstSubstitution returns where the first command substitution in s
// starts, $( or a backtick, or the first process substitution, <( or >(,
// or -1 if there is none. It also counts them inside quotes or after a
// backslash: when unsure, separatorAt keeps the rules.
func firstSubstitution(s string) int {
	first := strings.IndexByte(s, '`')
	for _, open := range []string{"$(", "<(", ">("} {
		if i := strings.Index(s, open); i >= 0 && (first < 0 || i < first) {
			first = i
		}
	}
	return first
}

// isSeparator reports whether the word w is a shell separator that ends a
// command.
func isSeparator(w string) bool {
	switch w {
	case ";", "&&", "||", "|", "&", "|&":
		return true
	}
	return false
}

// wordEnd returns the end of the shell word that holds byte i: the first
// space outside quotes at or after i, or the end of the text.
func (q *quoting) wordEnd(i int) int {
	k, _ := slices.BinarySearch(q.spaces, i)
	if k < len(q.spaces) {
		return q.spaces[k]
	}
	return len(q.in)
}

// partEnd returns the position of the quote that closes the quotes byte i
// is inside, or the end of the text if they are not closed.
func (q *quoting) partEnd(i int) int {
	k, _ := slices.BinarySearch(q.closes, i)
	if k < len(q.closes) {
		return q.closes[k]
	}
	return len(q.in)
}

// quoteAfter returns the quote that is still open after the word w, given
// the quote that was open before it (0 for none). It reads quotes and
// backslashes as quoting does. It returns '\\' when w ends with a
// backslash outside quotes: then the space after w is plain, and the next
// word is part of the same shell word.
func quoteAfter(w string, open byte) byte {
	if open == '\\' {
		open = 0 // the backslash was before the space before w
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case c == '\\' && open != '\'':
			if i+1 == len(w) && open == 0 {
				return '\\'
			}
			i++ // the next byte is plain
		case open == 0 && (c == '"' || c == '\''):
			open = c
		case c == open:
			open = 0
		}
	}
	return open
}

// openQuotes is a set of the quotes that are open after a word, one for
// each way of reading the words before it: a single quote, a double quote,
// or a backslash at the end of the word (see quoteAfter). A way of reading
// in which no quote is open is not in the set.
type openQuotes uint8

// quoteKinds are the members that openQuotes can hold, in bit order.
var quoteKinds = [...]byte{'\'', '"', '\\'}

// add returns the set with the quote q added. q == 0 adds nothing.
func (o openQuotes) add(q byte) openQuotes {
	for i, k := range quoteKinds {
		if q == k {
			return o | 1<<i
		}
	}
	return o
}

// after returns the quotes that are open after the word w, for each way
// of reading in the set.
func (o openQuotes) after(w string) openQuotes {
	var next openQuotes
	for i, k := range quoteKinds {
		if o&(1<<i) != 0 {
			next = next.add(quoteAfter(w, k))
		}
	}
	return next
}

// closingQuote returns the position of the quote that closes the one at
// s[v], or -1. Inside double quotes, a backslash escapes the next byte.
func closingQuote(s string, v int) int {
	q := s[v]
	for i := v + 1; i < len(s); i++ {
		switch s[i] {
		case q:
			return i
		case '\\':
			if q == '"' {
				i++
			}
		}
	}
	return -1
}

// matchBracket returns the end of the object or list that opens at s[v]:
// the position after its closing bracket, or limit if it does not close
// before limit. Brackets inside quoted strings do not count.
func matchBracket(s string, v, limit int) int {
	depth := 0
	for i := v; i < limit; i++ {
		switch s[i] {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		case '"', '\'':
			e := closingQuote(s[:limit], i)
			if e < 0 {
				return limit
			}
			i = e
		case '\\':
			i++
		}
	}
	return limit
}
