package claim

import (
	"math"
	"strings"
)

// Random-looking words.
//
// A word is a run of at least minWordLen characters from [A-Za-z0-9_+/-],
// the characters of base62, base64, base64url and hex tokens. Base64 "="
// padding at the end is hidden with the word. An "=" inside a run splits
// it, so in --max-old-space-size=4096 each side is judged alone.
//
// A word looks random when all of these are true:
//
//   - Letters and digits are interleaved in at least one part between "_",
//     "+", "-" and "/": the part changes between letter and digit at least
//     twice, as in "a1b" or "1a2". Names such as x86_64-unknown-linux-gnu,
//     kube-prometheus-stack-45 or TEST_CASE_123 change at most once in each
//     part, so they stay readable.
//   - Its Shannon entropy is at least minEntropy bits per character.
//   - If it holds "/", it changes often between lower case, upper case and
//     digit (see minChangeRate).
//
// A word with "/" that does not look random as a whole is judged part by
// part (see maskRandomWords), so a key that is one part of a URL path is
// hidden too.
//
// minEntropy is 3.0, not 3.5. The first rule already keeps names readable,
// so the entropy only has to skip repeated patterns such as a1a1a1 (1 bit)
// or abc123abc123 (2.6 bits). With 3.5,
// random hex would often stay visible: it has only about 3.6 bits per
// character at 32 characters, so about 1 in 5 random 32-character hex keys
// (as "openssl rand -hex 16" makes) would not be hidden. We measured random
// keys on 2026-10-14 (20,000 samples for each alphabet, length and place).
// With 3.0, about 3 % of 20-character hex keys, 4 % of base62 keys and 6
// to 7 % of base64 and base64url keys are missed. At 32 characters, about
// 1 % of base64 and base64url keys, 0.5 % of base62 keys and 0.01 % of hex
// keys are missed. No 40-character hex key was missed, so a full git
// commit ID is hidden too; that is accepted. For hex, base62 and base64url
// keys, the results are the same alone and as one part of a URL path.
// Standard base64 is the exception: its own "/" splits the key into
// shorter parts. In a long URL path, up to 14 % of 32-character and 31 %
// of 20-character standard base64 keys were missed. Such keys are rare in
// URLs, because "/" ends a part of the path.
const (
	minWordLen = 20
	minEntropy = 3.0
)

// minChangeRate is for words with "/". Standard base64 uses "/", so a
// base64 key is one word, not several short ones. But a path is one word
// too, and a path such as /srv/k8s/manifests/app is interleaved (k8s) and
// has a high entropy. So a word with "/" must also change between lower
// case, upper case and digit in at least 3 of 10 pairs of neighbouring
// letters and digits. Random base64 changes in about 6 of 10 pairs; paths
// change in 0 to 3. We measured on 2026-10-14 (20,000 random keys for each
// length, keeping those with "/"): the extra rule misses 0.54 % of
// 40-character keys, the same as without it, 1.48 % instead of 1.44 % at
// 32 characters, and 9.0 % instead of 8.5 % at 20 characters. The AWS
// example secret key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY has 0.34.
const minChangeRate = 0.3

// maskRandomWords hides random-looking words in s. A word with "/" that
// does not look random as a whole is judged part by part: each part
// between "/" with at least minWordLen characters is hidden alone if it
// looks random. A readable path around a key, as in
// https://hooks.example.com/services/T0ABCDEFG/B0HIJKLMN/KEY, lowers the
// change rate of the whole word, but not that of the key.
func maskRandomWords(s string) string {
	var b strings.Builder
	last := 0 // s[:last] is in b
	hide := func(i, j int) {
		for j < len(s) && s[j] == '=' {
			j++ // base64 padding
		}
		b.WriteString(s[last:i])
		b.WriteString(hidden)
		last = j
	}
	for i := 0; i < len(s); {
		if !isWordByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isWordByte(s[j]) {
			j++
		}
		switch {
		case j-i < minWordLen:
		case looksRandom(s[i:j]):
			hide(i, j)
		case strings.IndexByte(s[i:j], '/') >= 0:
			for k := i; k < j; {
				e := strings.IndexByte(s[k:j], '/')
				if e < 0 {
					e = j
				} else {
					e += k
				}
				if e-k >= minWordLen && looksRandom(s[k:e]) {
					hide(k, e)
				}
				k = e + 1
			}
		}
		i = j
	}
	if b.Len() == 0 {
		return s // nothing was hidden
	}
	b.WriteString(s[last:])
	return b.String()
}

// isWordByte reports whether c can be part of a random-looking word.
func isWordByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '_' || c == '+' || c == '-' || c == '/'
}

// looksRandom reports whether the word w looks like a random token.
func looksRandom(w string) bool {
	return interleaved(w) && entropy(w) >= minEntropy &&
		(!strings.Contains(w, "/") || changeRate(w) >= minChangeRate)
}

// interleaved reports whether a part of w between "_", "+", "-" and "/"
// changes between letter and digit at least twice.
func interleaved(w string) bool {
	var last byte // 'a' after a letter, '0' after a digit, 0 after a separator
	changes := 0
	for i := 0; i < len(w); i++ {
		var kind byte
		switch c := w[i]; {
		case '0' <= c && c <= '9':
			kind = '0'
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			kind = 'a'
		default:
			last, changes = 0, 0
			continue
		}
		if last != 0 && kind != last {
			changes++
			if changes == 2 {
				return true
			}
		}
		last = kind
	}
	return false
}

// changeRate returns the share of pairs of neighbouring letters and digits
// in w that change between lower case, upper case and digit.
func changeRate(w string) float64 {
	var last byte // the class of the byte before: 'a', 'A', '0', or 0
	pairs, changes := 0, 0
	for i := 0; i < len(w); i++ {
		var class byte
		switch c := w[i]; {
		case 'a' <= c && c <= 'z':
			class = 'a'
		case 'A' <= c && c <= 'Z':
			class = 'A'
		case '0' <= c && c <= '9':
			class = '0'
		}
		if last != 0 && class != 0 {
			pairs++
			if class != last {
				changes++
			}
		}
		last = class
	}
	if pairs == 0 {
		return 0
	}
	return float64(changes) / float64(pairs)
}

// entropy returns the Shannon entropy of the bytes of w, in bits per
// byte.
func entropy(w string) float64 {
	var counts [256]int
	for i := 0; i < len(w); i++ {
		counts[w[i]]++
	}
	n := float64(len(w))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
