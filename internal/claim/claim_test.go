package claim

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{name: "plain", in: "git push origin main", max: 80, want: "git push origin main"},
		{name: "empty", in: "", max: 80, want: ""},
		{name: "newline", in: "a\nb", max: 80, want: "a b"},
		{name: "CR LF", in: "a\r\nb", max: 80, want: "a b"},
		{name: "tab, VT, FF", in: "a\tb\vc\fd", max: 80, want: "a b c d"},
		{name: "NUL and ESC", in: "a\x00b\x1b[31mc", max: 80, want: "a b [31mc"},
		{name: "DEL and C1 controls", in: "a\x7fb\u0085c\u009bd", max: 80, want: "a b c d"},
		{name: "line and paragraph separators", in: "a\u2028b\u2029c", max: 80, want: "a b c"},
		{name: "other spaces", in: "a\u00a0b\u2003c\u202fd\u3000e", max: 80, want: "a b c d e"},
		{name: "runs of spaces", in: "  a   \n\t  b  ", max: 80, want: "a b"},
		{name: "only spaces", in: " \n\t\u00a0", max: 80, want: ""},
		{name: "right-to-left override", in: "invoice\u202efdp.exe", max: 80, want: "invoicefdp.exe"},
		{name: "embeddings", in: "\u202aa\u202bb\u202cc\u202dd", max: 80, want: "abcd"},
		{name: "isolates", in: "\u2066a\u2067b\u2068c\u2069d", max: 80, want: "abcd"},
		{name: "direction marks", in: "a\u200eb\u200fc\u061cd", max: 80, want: "abcd"},
		{name: "zero width", in: "a\u200bb\u200cc\u200dd\u2060e\ufefff", max: 80, want: "abcdef"},
		{name: "soft hyphen", in: "pass\u00adword", max: 80, want: "password"},
		{name: "Mongolian vowel separator", in: "a\u180eb", max: 80, want: "ab"},
		{name: "Hangul fillers", in: "a\u3164b\u115fc\u1160d\uffa0e", max: 80, want: "abcde"},
		{name: "combining grapheme joiner", in: "a\u034fb", max: 80, want: "ab"},
		{name: "variation selectors", in: "a\ufe0fb\U000E0100c", max: 80, want: "abc"},
		{name: "tag characters", in: "a\U000E0001\U000E0041b", max: 80, want: "ab"},
		{name: "invisible between spaces", in: "a \u200b b", max: 80, want: "a b"},
		{name: "blank symbols", in: "a\u2800\u2800b\U0001D159c\u2800", max: 80, want: "a b c"},
		{name: "few combining marks kept", in: "a\u0301\u0302b", max: 80, want: "a\u0301\u0302b"},
		{name: "combining marks at the start", in: "\u20dd\u0336reason", max: 80, want: "reason"},
		{name: "spacing mark at the start", in: "\u093freason", max: 80, want: "reason"},
		{name: "marks after spaces at the start", in: " \n\u0301\u200b\u0302x", max: 80, want: "x"},
		{name: "mark after a space inside", in: "a \u0301b", max: 80, want: "a \u0301b"},
		{
			name: "stacked combining marks capped",
			in:   "a" + strings.Repeat("\u0301", 50) + "b" + strings.Repeat("\u20dd", 9),
			max:  80,
			want: "a\u0301\u0301\u0301\u0301b\u20dd\u20dd\u20dd\u20dd",
		},
		{name: "invalid byte", in: "a\xffb", max: 80, want: "a\ufffdb"},
		{name: "cut rune", in: "a\xe2\x82", max: 80, want: "a\ufffd\ufffd"},
		{name: "encoded surrogate", in: "\xed\xa0\x80", max: 80, want: "\ufffd\ufffd\ufffd"},
		{name: "overlong encoding", in: "\xc0\xafx", max: 80, want: "\ufffd\ufffdx"},
		{name: "fits exactly", in: "abcdef", max: 6, want: "abcdef"},
		{name: "cut", in: "abcdef", max: 4, want: "abc…"},
		{name: "cut to one", in: "abcdef", max: 1, want: "…"},
		{name: "zero", in: "abcdef", max: 0, want: ""},
		{name: "negative", in: "abcdef", max: -5, want: ""},
		{name: "no space before …", in: "ab cd", max: 4, want: "ab…"},
		{name: "cut counts runes, not bytes", in: "Здравей, свят", max: 8, want: "Здравей…"},
		{name: "cut Japanese", in: "証明書を更新する", max: 5, want: "証明書を…"},
		{name: "cut after cleaning", in: "a\n\n\nb\u200b\u200bc", max: 5, want: "a bc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Line(tt.in, tt.max); got != tt.want {
				t.Errorf("Line(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

// TestNonLatinTextIsKept checks that Bulgarian and Japanese text passes
// through every function unchanged: nothing in it is masked or broken.
func TestNonLatinTextIsKept(t *testing.T) {
	texts := []string{
		"Обнови сертификата на web-1 преди 2026-10-30, защото изтича.",
		"Пусни миграцията на базата за отчетите",
		"Ударение: о\u0300ще и ѝ", // a combining grave accent and a precomposed letter
		"本番サーバーの証明書を更新する",
		"デプロイ前にテストを実行してください（web-1）",
		"Причина: 修正 deploy на web-1",
	}
	for _, s := range texts {
		if got := Line(s, 200); got != s {
			t.Errorf("Line(%q) = %q, want it unchanged", s, got)
		}
		if got := Mask(s); got != s {
			t.Errorf("Mask(%q) = %q, want it unchanged", s, got)
		}
		if got := HTML(s); got != s {
			t.Errorf("HTML(%q) = %q, want it unchanged", s, got)
		}
		want := "echo " + s
		if strings.Contains(s, " ") {
			want = "echo '" + s + "'"
		}
		if got := Command([]string{"echo", s}, 200); got != want {
			t.Errorf("Command(echo, %q) = %q, want %q", s, got, want)
		}
	}
}

func TestHTML(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{in: "", want: ""},
		{in: "plain text", want: "plain text"},
		{in: "a & b", want: "a &amp; b"},
		{in: "<b>bold</b>", want: "&lt;b&gt;bold&lt;/b&gt;"},
		{in: `say "hi"`, want: "say &quot;hi&quot;"},
		{in: "it's", want: "it's"},
		{in: "&amp; stays text", want: "&amp;amp; stays text"},
		{in: "&#60;b&#62;", want: "&amp;#60;b&amp;#62;"},
		{
			in:   `<a href="https://evil.example.com">Approve</a>`,
			want: "&lt;a href=&quot;https://evil.example.com&quot;&gt;Approve&lt;/a&gt;",
		},
		{in: "✅ machine: laptop", want: "✅ machine: laptop"},
	}
	for _, tt := range tests {
		if got := HTML(tt.in); got != tt.want {
			t.Errorf("HTML(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestFakeMessageLines covers THREAT-MODEL.md T3: the agent tries to make
// text that looks like a verified line, a new message part, or a link.
func TestFakeMessageLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // HTML(Line(Mask(in), 200))
	}{
		{
			name: "newline and fake verified line",
			in:   "git status\n✅ machine: trusted\n✅ host: web-1",
			want: "git status ✅ machine: trusted ✅ host: web-1",
		},
		{
			name: "CR LF",
			in:   "git status\r\n✅ machine: trusted",
			want: "git status ✅ machine: trusted",
		},
		{
			name: "Unicode line breaks",
			in:   "git status\u2028✅ machine: trusted\u2029✅ key: deploy\u0085✅ remote user: root",
			want: "git status ✅ machine: trusted ✅ key: deploy ✅ remote user: root",
		},
		{
			name: "fake separator line",
			in:   "make\n— claimed by the agent —\nreason: nothing",
			want: "make — claimed by the agent — reason: nothing",
		},
		{
			name: "terminal escape",
			in:   "\x1b[2J\x1b[1;1H✅ machine: trusted",
			want: "[2J [1;1H✅ machine: trusted",
		},
		{
			name: "right-to-left override",
			in:   "deploy \u202edetsurt :enihcam ✅",
			want: "deploy detsurt :enihcam ✅",
		},
		{
			name: "isolates and zero width",
			in:   "✅\u2066 machine\u200b: lap\u200dtop\u2069",
			want: "✅ machine: laptop",
		},
		{
			name: "close the code tag",
			in:   "</code><b>✅ machine: trusted</b><code>",
			want: "&lt;/code&gt;&lt;b&gt;✅ machine: trusted&lt;/b&gt;&lt;code&gt;",
		},
		{
			name: "link",
			in:   `<a href="https://evil.example.com">Approve once</a>`,
			want: "&lt;a href=&quot;https://evil.example.com&quot;&gt;Approve once&lt;/a&gt;",
		},
		{
			name: "entity that would become a tag",
			in:   "&lt;b&gt;bold&lt;/b&gt;",
			want: "&amp;lt;b&amp;gt;bold&amp;lt;/b&amp;gt;",
		},
		{
			name: "newline inside a tag",
			in:   "<b\n>✅</b\n>",
			want: "&lt;b &gt;✅&lt;/b &gt;",
		},
		{
			// Blank symbols could push the fake line to the start of a
			// wrapped line on the phone.
			name: "blank padding",
			in:   "fix" + strings.Repeat("\u2800", 40) + "✅ host: db-1" + strings.Repeat("\U0001D159", 40) + "✅ key: deploy",
			want: "fix ✅ host: db-1 ✅ key: deploy",
		},
		{
			// Marks at the start would draw on the field label before them.
			name: "combining marks at the start",
			in:   "\u20dd\u0336\u0336\u0336\u0336reason",
			want: "reason",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HTML(Line(Mask(tt.in), 200))
			if got != tt.want {
				t.Errorf("HTML(Line(Mask(%q))) = %q, want %q", tt.in, got, tt.want)
			}
			checkMessageSafe(t, got)
			checkMessageSafe(t, HTML(Command([]string{"sh", "-c", tt.in}, 200)))
		})
	}
}

// checkMessageSafe fails if s, after HTML escaping, could break the
// message layout: a line break, a tag, or an invisible character.
func checkMessageSafe(t *testing.T, s string) {
	t.Helper()
	if strings.ContainsAny(s, "<>\n\r") {
		t.Errorf("%q holds a line break or a tag character", s)
	}
	for _, r := range s {
		if isSpace(r) && r != ' ' || isInvisible(r) {
			t.Errorf("%q holds %U", s, r)
		}
	}
}

// TestLongInput checks long fields up to MaxInput: they are cleaned,
// masked and cut as usual. TestTooLong checks longer fields.
func TestLongInput(t *testing.T) {
	const big = 1 << 15 // inputs of 32 KiB to 64 KiB

	got := Line(strings.Repeat("abc ", MaxInput/4), 100)
	if want := strings.Repeat("abc ", 24) + "abc" + ellipsis; got != want {
		t.Errorf("Line of a long text = %q, want %q", got, want)
	}

	got = Line(strings.Repeat("я", MaxInput/2), 50) // 2 bytes each: exactly MaxInput
	if want := strings.Repeat("я", 49) + ellipsis; got != want {
		t.Errorf("Line of long Cyrillic text = %q, want %q", got, want)
	}

	got = Line(strings.Repeat("\u200b", big/3)+"ok"+strings.Repeat("\n", big/2), 10)
	if got != "ok" {
		t.Errorf("Line of long invisible text = %q, want %q", got, "ok")
	}

	got = Mask(strings.Repeat("password=x ", big/16))
	if want := strings.TrimSpace(strings.Repeat("password=*** ", big/16)); got != want {
		t.Errorf("Mask of many passwords: got %d bytes, want %d", len(got), len(want))
	}

	plain := strings.Repeat("a", big)
	if got := Mask(plain); got != plain {
		t.Errorf("Mask of a long plain word changed it")
	}

	if got := Mask(strings.Repeat("-----BEGIN X-----", big/32)); strings.Count(got, hidden) != 1 {
		t.Errorf("Mask of many PEM starts: got %d masks, want 1", strings.Count(got, hidden))
	}

	argv := make([]string, 60_000) // 60,000 bytes in all
	for i := range argv {
		argv[i] = "x"
	}
	if got, want := Command(argv, 300), "x x x x x x x x x … (+59991 more)"; got != want {
		t.Errorf("Command with many arguments = %q, want %q", got, want)
	}

	got = Command([]string{"echo", strings.Repeat("word ", (MaxInput-4)/5)}, 60)
	if want := "echo '" + strings.Repeat("word ", 10) + "wor" + ellipsis; got != want {
		t.Errorf("Command with a long argument = %q, want %q", got, want)
	}
}

// TestTooLong checks the decision on fields longer than MaxInput: Line,
// Mask and Command return "[hidden: too long]" and never cut the text
// first, so no part of a long secret can show.
func TestTooLong(t *testing.T) {
	const canary = "Cx7canaryLong9"
	// fill returns text of exactly n bytes that ends with a secret.
	fill := func(n int) string {
		tail := " password=" + canary
		return strings.Repeat("a", n-len(tail)) + tail
	}
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "Line", got: Line(fill(MaxInput+1), 100), want: tooLong},
		{name: "Line cut", got: Line(fill(MaxInput+1), 9), want: "[hidden:" + ellipsis},
		{name: "Line of many bytes", got: Line(strings.Repeat("я", MaxInput), 100), want: tooLong},
		{name: "Mask", got: Mask(fill(MaxInput + 1)), want: tooLong},
		{name: "Mask chain", got: HTML(Line(Mask(fill(10*MaxInput)), 200)), want: tooLong},
		{name: "Command", got: Command([]string{"echo", fill(MaxInput)}, 100), want: tooLong},
		{name: "Command cut", got: Command([]string{"echo", fill(MaxInput)}, 5), want: "[hid" + ellipsis},
		{
			name: "Command counts arguments it does not show",
			got:  Command(append(numbered(9), fill(MaxInput)), 100),
			want: tooLong,
		},
		{name: "Command of many short arguments", got: Command(slices.Repeat([]string{"x"}, MaxInput+1), 100), want: tooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", strings.ReplaceAll(tt.got, canary, "<canary>"), tt.want)
			}
		})
	}

	// At the limit, the field is masked as a whole.
	if got := Mask(fill(MaxInput)); strings.Contains(got, canary) || !strings.HasSuffix(got, " password=***") {
		t.Errorf("Mask of exactly MaxInput bytes does not end with the masked password")
	}
	if got := Command([]string{"env", fill(MaxInput - 3)}, 500); strings.Contains(got, canary) || got == tooLong {
		t.Errorf("Command of exactly MaxInput bytes = %q, want it masked", strings.ReplaceAll(got, canary, "<canary>"))
	}
}

// checkSafeLine fails if out is not one safe line of at most maxRunes
// runes, as Line promises.
func checkSafeLine(t *testing.T, out string, maxRunes int) {
	t.Helper()
	if maxRunes <= 0 && out != "" {
		t.Fatalf("got %q for max %d, want \"\"", out, maxRunes)
	}
	if !utf8.ValidString(out) {
		t.Fatalf("%q is not valid UTF-8", out)
	}
	if n := utf8.RuneCountInString(out); n > maxRunes && n > 0 {
		t.Fatalf("%q has %d runes, want at most %d", out, n, maxRunes)
	}
	if strings.HasPrefix(out, " ") || strings.HasSuffix(out, " ") || strings.Contains(out, "  ") {
		t.Fatalf("%q has a space at an end, or two spaces in a row", out)
	}
	if r, _ := utf8.DecodeRuneInString(out); unicode.Is(unicode.M, r) {
		t.Fatalf("%q starts with the combining mark %U", out, r)
	}
	marks := 0
	for _, r := range out {
		switch {
		case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			t.Fatalf("%q holds the control or format character %U", out, r)
		case unicode.Is(unicode.Zs, r) && r != ' ':
			t.Fatalf("%q holds the space character %U", out, r)
		case r == '\u2800' || r == '\U0001D159':
			t.Fatalf("%q holds the blank symbol %U", out, r)
		case unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector):
			t.Fatalf("%q holds the invisible character %U", out, r)
		case unicode.In(r, unicode.Mn, unicode.Me):
			if marks++; marks > maxMarks {
				t.Fatalf("%q holds more than %d combining marks in a row", out, maxMarks)
			}
		default:
			marks = 0
		}
	}
	if again := Line(out, maxRunes); again != out {
		t.Fatalf("Line(%q) = %q, want it unchanged", out, again)
	}
}

func FuzzLine(f *testing.F) {
	seeds := []string{
		"",
		"git push origin main",
		"a\nb\r\nc\u2028d\u0085e",
		"\u202eevil\u2066x\u2069",
		"a\u200b\u200d\ufeff\u00adb",
		"\xff\xfe\xed\xa0\x80\xc0\xaf",
		"Здравей, свят",
		"証明書を更新する",
		"a" + strings.Repeat("\u0301", 30),
		"  spaces   everywhere  ",
		"\u20dd\u0336\u093f mark first",
		"blank\u2800\u2800\U0001D159padding",
	}
	for _, s := range seeds {
		f.Add(s, 20)
		f.Add(s, 1)
	}
	f.Fuzz(func(t *testing.T, s string, maxRunes int) {
		maxRunes %= 300 // negative stays negative
		checkSafeLine(t, Line(s, maxRunes), maxRunes)
	})
}
