// Package claim makes claimed text safe to show and to log.
//
// The client sends claimed fields: the command line, the reason, the
// working directory, process names and environment variable names. The
// agent can write anything there. It may try to fake the look of an
// approval message (THREAT-MODEL.md T3), or it may put a secret there by
// mistake (T15). The broker passes every claimed field through this package
// before the field goes into a Telegram message or the audit log:
//
//	reason := claim.HTML(claim.Line(claim.Mask(req.Reason), 200))
//	command := claim.HTML(claim.Command(req.Argv, 300))
//
// Call Mask before Line. Line cuts the text, and a secret that was cut may
// no longer look like a secret.
//
// Masking is best effort. Mask and Command find the common forms that
// they list, not every secret. The text stays a claim: the agent can write
// anything there, and the person must judge it.
//
// A field longer than MaxInput is never cut and masked: Line, Mask and
// Command show "[hidden: too long]" instead.
package claim

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxInput is the longest claimed field, in bytes, that Line, Mask and
// Command show. For a command line it is the sum of the lengths of all
// arguments, also those that Command does not show. A longer field becomes
// "[hidden: too long]". It is not cut first, because a secret that was cut
// may no longer look like a secret. The limit also bounds the work that
// masking does.
const MaxInput = 64 << 10

// tooLong replaces a field that is longer than MaxInput.
const tooLong = "[hidden: too long]"

// ellipsis ends a line that was cut.
const ellipsis = "…"

// maxMarks is the most combining marks kept in a row. Real text needs few
// (Vietnamese uses two, Thai three). Many stacked marks ("Zalgo" text) can
// draw over the lines above and below, for example over the verified lines.
const maxMarks = 4

// Line returns s as one safe line of at most maxRunes runes.
//
//   - Invalid UTF-8 becomes U+FFFD.
//   - Control characters (Cc), line and paragraph separators (Zl, Zp), all
//     other space characters (Zs, for example U+00A0 and U+3000), and
//     symbols that draw nothing (U+2800 BRAILLE PATTERN BLANK and U+1D159
//     MUSICAL SYMBOL NULL NOTEHEAD) become a space.
//   - Invisible characters are removed: format characters (Cf), such as
//     the direction marks U+202A–U+202E and U+2066–U+2069, zero-width
//     characters, U+FEFF and the soft hyphen, and the other
//     default-ignorable characters, such as variation selectors and Hangul
//     fillers.
//   - At most maxMarks combining marks (Mn, Me) are kept in a row.
//     Combining marks (Mn, Mc, Me) at the start are removed, because they
//     would draw on the text before the field.
//   - Runs of spaces become one space. Spaces at the start and the end are
//     removed.
//   - If the result is longer than maxRunes runes, it is cut and ends with
//     "…". The "…" counts toward maxRunes.
//
// If maxRunes <= 0, Line returns "". If s is longer than MaxInput bytes,
// Line returns "[hidden: too long]", cut to maxRunes.
func Line(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	if len(s) > MaxInput {
		s = tooLong
	}
	return cut(clean(s), maxRunes)
}

// HTML escapes s for Telegram's HTML parse mode: &, <, > and " become
// &amp;, &lt;, &gt; and &quot;. It does not clean s. Use it on the result
// of Line or Command, and put the result inside <code>.
func HTML(s string) string {
	return htmlEscaper.Replace(s)
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

// clean does what Line does, except the cut.
func clean(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false // a space waits to be written before the next rune
	marks := 0     // combining marks in a row
	// For invalid UTF-8, range gives utf8.RuneError, which is U+FFFD.
	for _, r := range s {
		switch {
		case isSpace(r):
			space = true
			marks = 0
			continue
		case isInvisible(r):
			continue
		case b.Len() == 0 && unicode.Is(unicode.M, r):
			continue // a mark at the start would draw on the text before the field
		case unicode.In(r, unicode.Mn, unicode.Me):
			if marks >= maxMarks {
				continue
			}
			marks++
		default:
			marks = 0
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// isSpace reports whether r becomes a space. Besides control characters
// and separators, this holds for symbols that draw nothing but take room.
// With many of them in a row, the agent could push its text, such as
// "✅ host: db-1", to the start of a wrapped line (THREAT-MODEL.md T3).
// This blocks only that trick: a long line still wraps, so the message
// marks claimed text by its place and the <code> font.
func isSpace(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp) ||
		r == '\u2800' || r == '\U0001D159' // BRAILLE PATTERN BLANK, MUSICAL SYMBOL NULL NOTEHEAD
}

// isInvisible reports whether r is removed: a format character or another
// default-ignorable code point.
func isInvisible(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}

// cut shortens a clean s to at most maxRunes runes (maxRunes >= 1), with
// "…" at the end when it cuts.
func cut(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	end := 0
	for range maxRunes - 1 {
		_, size := utf8.DecodeRuneInString(s[end:])
		end += size
	}
	return strings.TrimRight(s[:end], " ") + ellipsis
}
