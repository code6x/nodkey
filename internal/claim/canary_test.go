package claim

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// defaultCanary is the made-up secret of the canary tests. It is short
// and not random, so only the rule for its shape can hide it, not the
// rule for random-looking words.
const defaultCanary = "Cx7canaryQQ9"

// canaryForms are shapes in which a secret can appear in claimed text,
// at least one for each rule of Mask and Command. SECRET stands for the
// secret.
var canaryForms = []struct {
	text   string   // the shape in free text, or ""
	argv   []string // the shape as a command line, or nil
	canary string   // the made-up secret, if it is not defaultCanary
}{
	// key=value, JSON, YAML, URL query
	{text: "password=SECRET"},
	{text: "export DB_PASSWORD=SECRET && make", argv: []string{"env", "DB_PASSWORD=SECRET", "make"}},
	{text: `{"client_secret": "SECRET"}`},
	{text: "api_key: SECRET"},
	{text: "https://api.example.com/v1?access_token=SECRET&page=2"},

	// Authorization, Bearer and Basic
	{text: "Authorization: Bearer SECRET"},
	{
		text: `curl -H "Authorization: Bearer SECRET" https://example.com`,
		argv: []string{"curl", "-H", "Authorization: Bearer SECRET", "https://example.com"},
	},
	{text: "Basic SECRET"},

	// URL passwords, token shapes, PEM
	{ //nolint:gosec // G101: an invented secret; the test checks that it is masked
		text: "git clone https://deploy:SECRET@git.example.com/app.git",
		argv: []string{"git", "clone", "https://deploy:SECRET@git.example.com/app.git"},
	},
	{text: "use gh" + "p_SECRETabcdefghijklmnopqrstuvwx"},
	{text: "-----BEGIN PRIVATE KEY----- SECRET -----END PRIVATE KEY-----"},

	// Options
	{text: "mysql -uroot -pSECRET appdb", argv: []string{"mysql", "-uroot", "-pSECRET", "appdb"}},
	{text: "app --password SECRET", argv: []string{"app", "--password", "SECRET"}},
	{text: "app --token=SECRET", argv: []string{"app", "--token=SECRET"}},
	{text: `app --password "x SECRET y" next`, argv: []string{"app", "--password", "x SECRET y", "next"}},
	{text: "curl -u deploy:SECRET https://example.com", argv: []string{"curl", "-u", "deploy:SECRET", "https://example.com"}},
	{argv: []string{"env", "DB_PASSWORD=x SECRET", "./run"}},

	// A value that is a key, an object or a scheme
	{text: `{"auth": {"token": "SECRET"}}`},
	{text: `{"secret": {"value": "SECRET"}}`},
	{text: `curl -d '{"credentials": {"pass": "SECRET"}}' https://example.com`},
	{text: "HTTP_AUTHORIZATION=Bearer SECRET"},
	{text: "token: password: SECRET"},
	{text: "AUTH_HEADER=token SECRET"},

	// Escaped JSON, "=>", quotes joined to more
	{text: `{\"password\":\"SECRET\"}`},
	{text: `{\"password\": \"x SECRET\"}`},
	{text: `curl -d "{\"user\":\"admin\",\"password\":\"SECRET\"}" https://example.com`},
	{text: `{ "password" => "SECRET" }`},
	{text: `php -r "User::create(['password' => 'SECRET']);"`},
	{text: "password=''SECRET"},
	{text: `PASSWORD="abc"SECRET make`},
	{text: `env "PASSWORD=x SECRET" ./run`},

	// Standard base64 with "/"
	{text: "key SECRET", canary: "q3T9/xK2+Lm8Rv4/Pz7Wc1Nb6Hj0Ys5Ad2Fg8Ek3Ui="},
	{
		text:   "aws configure set aws_secret_access_key SECRET",
		argv:   []string{"aws", "configure", "set", "aws_secret_access_key", "SECRET"},
		canary: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	},

	// The programs table
	{text: "redis-cli -h db-1 -a SECRET ping", argv: []string{"redis-cli", "-h", "db-1", "-a", "SECRET", "ping"}},
	{text: "curl -E client.pem:SECRET https://example.com", argv: []string{"curl", "-E", "client.pem:SECRET", "https://example.com"}},
	{text: "curl -b sid=SECRET https://example.com", argv: []string{"curl", "-b", "sid=SECRET", "https://example.com"}},
	{text: "curl -su deploy:SECRET https://example.com", argv: []string{"curl", "-su", "deploy:SECRET", "https://example.com"}},
	{text: "gh secret set API_KEY --body SECRET", argv: []string{"gh", "secret", "set", "API_KEY", "--body", "SECRET"}},
	{
		text: "kubectl create secret generic app --from-literal=api=SECRET",
		argv: []string{"kubectl", "create", "secret", "generic", "app", "--from-literal", "api=SECRET"},
	},
	{text: "vault kv put secret/app api=SECRET", argv: []string{"vault", "kv", "put", "secret/app", "api=SECRET"}},
	{text: "openssl enc -aes-256-cbc -k SECRET -in data.txt", argv: []string{"openssl", "enc", "-aes-256-cbc", "-k", "SECRET"}},
	{text: "openssl passwd -6 SECRET", argv: []string{"openssl", "passwd", "-6", "SECRET"}},
	{text: "ssh-keygen -t ed25519 -N SECRET -f key", argv: []string{"ssh-keygen", "-t", "ed25519", "-N", "SECRET", "-f", "key"}},
	{text: "ldapsearch -x -w SECRET", argv: []string{"ldapsearch", "-x", "-w", "SECRET"}},
	{text: "sqlcmd -S db-1 -P SECRET", argv: []string{"sqlcmd", "-S", "db-1", "-PSECRET"}},
	{text: "mysqladmin -u root password SECRET", argv: []string{"mysqladmin", "-u", "root", "password", "SECRET"}},
	{text: "plink -pw SECRET web-1", argv: []string{"plink", "-pw", "SECRET", "web-1"}},

	// Headers
	{text: "X-Api-Key:SECRET", argv: []string{"curl", "-H", "X-Api-Key:SECRET"}},
	{text: "Cookie:sid=SECRET", argv: []string{"curl", "-H", "Cookie:sid=SECRET"}},
	{text: "Cookie: theme=dark; sid=SECRET", argv: []string{"curl", "-H", "Cookie: theme=dark; sid=SECRET"}},
	{text: `curl -H "Cookie: theme=dark; sid=SECRET" https://example.com`},

	// URL passwords with "#", "/", "?", and without a scheme
	{text: "mongodb://admin:Su#SECRET@db-1:27017/app"},
	{text: "postgres://app:ab/SECRET@db-1/app"},
	{text: "redis://:pa?SECRET@db-1:6379/0"},
	{
		text: "curl -x admin:SECRET@proxy.example.com:3128 https://example.com",
		argv: []string{"curl", "-x", "admin:SECRET@proxy.example.com:3128", "https://example.com"},
	},

	// Backslashes outside quotes
	{text: `app --password 'it'\''s SECRET' next`},
	{text: `mysql -p'a b'\''c SECRET' appdb`},
	{text: `app --password x\ SECRET next`},

	// A bare -p
	{text: "mysql -u root -p SECRET appdb", argv: []string{"mysql", "-u", "root", "-p", "SECRET", "appdb"}},

	// Found in the second security review on 2026-10-14. New forms go at
	// the end: the seeds in testdata/fuzz/FuzzCanary pick a form by its
	// index.
	{
		text:   "curl -X POST https://example.com/api/v1/organizations/settings/integrations/webhooks/incoming/SECRET",
		argv:   []string{"curl", "-X", "POST", "https://example.com/api/v1/organizations/settings/integrations/webhooks/incoming/SECRET"},
		canary: "Cx7fakeUrmiOP3wCy5o86XpSWchjZX6Y",
	},
	{text: "redis-cli -h vault -a SECRET ping", argv: []string{"redis-cli", "-h", "vault", "-a", "SECRET", "ping"}},
	{
		text: "gh secret set API_KEY --repo team/vault -b SECRET",
		argv: []string{"gh", "secret", "set", "API_KEY", "--repo", "team/vault", "-b", "SECRET"},
	},
	{text: "cd /tmp&&redis-cli -a SECRET ping"},
	{text: "echo hi|redis-cli -a SECRET"},
	{text: "putty -ssh deploy@web-1 -pw SECRET", argv: []string{"putty", "-ssh", "deploy@web-1", "-pw", "SECRET"}},
	{text: "ldapsearch -xw SECRET -b dc=example,dc=com", argv: []string{"ldapsearch", "-xw", "SECRET", "-b", "dc=example,dc=com"}},
	{text: "ssh-keygen -pP SECRET -f key", argv: []string{"ssh-keygen", "-pP", "SECRET", "-f", "key"}},
	{text: "curl -sudeploy:SECRET https://example.com", argv: []string{"curl", "-sudeploy:SECRET", "https://example.com"}},
	{text: `mysql -u root "-p" SECRET appdb`},
	{text: `curl -d "user[password]=SECRET" https://example.com`, argv: []string{"curl", "-d", "user[password]=SECRET"}},
	{text: `params[:password] = "SECRET"`},

	// Found in the third security review on 2026-10-14: a ";" in an
	// argument is text. Only as a command line: in free text, a quote next
	// to the form can make the shell read the ";" as a separator.
	{argv: []string{"curl", "-H", "Cookie: theme=dark;", "-E", "client.pem:SECRET", "https://example.com"}},
	{argv: []string{"sqlcmd", "-S", "db-1", "-Q", "SELECT 1;", "-P", "SECRET"}},
}

// canaryNeighbours are words placed before and after a form in the seed
// corpus. They try to change how the form is read: open quotes, pending
// options, other programs, objects, separators.
var canaryNeighbours = []string{
	"", `"`, "'", `\`, `\"`, "it's", "-p", "--password", "--user", "-u", "-H", "-a", "-b",
	"token=", "Authorization:", "password", `{"a":`, "{", "[", "|", ";", "&&", "@", "#",
	"https://u:", "-----BEGIN X-----", "sh -c", "redis-cli", "curl", "gh secret set",
	"vault kv put", "--", "x=", "Cookie:", ":", "Bearer",
	"vault", `"-p"`, "-pw", "-xw", "a&&b", "user[password]=",
}

// FuzzCanary checks that the canary never comes out of Mask, Line, HTML
// and Command, whatever words come before and after it. The seed corpus
// runs every form with every neighbour in a normal "go test".
func FuzzCanary(f *testing.F) {
	for k := range canaryForms {
		for _, s := range canaryNeighbours {
			f.Add(uint16(k), s, s)
		}
	}
	f.Fuzz(func(t *testing.T, k uint16, before, after string) {
		form := canaryForms[int(k)%len(canaryForms)]
		canary := form.canary
		if canary == "" {
			canary = defaultCanary
		}
		if hasPiece(before+" "+after, canary) {
			t.Skip("the neighbours hold a piece of the canary")
		}
		if form.text != "" {
			in := before + " " + strings.ReplaceAll(form.text, "SECRET", canary) + " " + after
			checkNoLeak(t, "Mask", Mask(in), canary)
			checkNoLeak(t, "HTML(Line(Mask))", HTML(Line(Mask(in), 1000)), canary)
			checkNoLeak(t, "Command sh -c", Command([]string{"sh", "-c", in}, 1000), canary)
		}
		if form.argv != nil {
			argv := strings.Fields(before)
			for _, a := range form.argv {
				argv = append(argv, strings.ReplaceAll(a, "SECRET", canary))
			}
			argv = append(argv, strings.Fields(after)...)
			checkNoLeak(t, "Command", HTML(Command(argv, 1000)), canary)
		}
	})
}

// hasPiece reports whether s holds an 8-byte piece of the canary.
func hasPiece(s, canary string) bool {
	for i := 0; i+8 <= len(canary); i++ {
		if strings.Contains(s, canary[i:i+8]) {
			return true
		}
	}
	return false
}

// FuzzMask checks the promises of Mask for any input: the result is one
// clean line, and Line and HTML make it safe for a message. It checks the
// form of the result, not leaks, so its seeds hold no canary.
func FuzzMask(f *testing.F) {
	for _, form := range canaryForms {
		if form.text != "" {
			f.Add(strings.ReplaceAll(form.text, "SECRET", "value"), 80)
		}
	}
	for _, s := range canaryNeighbours {
		f.Add(s+" password="+s, 20)
	}
	f.Add("a\u0301\u0301\u0301\u0301 password=x\u0301\u0301\u0301\u0301\u0301", 30)
	f.Add("\xff\xfe password=\"\xed\xa0\x80\" -p \u202ex", 30)
	f.Fuzz(func(t *testing.T, s string, maxRunes int) {
		maxRunes %= 300 // negative stays negative
		out := Mask(s)
		if !utf8.ValidString(out) {
			t.Fatalf("Mask(%q) = %q is not valid UTF-8", s, out)
		}
		if clean(out) != out {
			t.Fatalf("Mask(%q) = %q is not one clean line", s, out)
		}
		line := Line(out, maxRunes)
		checkSafeLine(t, line, maxRunes)
		checkHTML(t, HTML(line))
	})
}

// checkHTML fails if h, the result of HTML, holds a character that
// Telegram reads as markup, or an "&" that does not start an entity.
func checkHTML(t *testing.T, h string) {
	t.Helper()
	if strings.ContainsAny(h, `<>"`) {
		t.Fatalf("%q holds <, > or \"", h)
	}
	for i := 0; i < len(h); i++ {
		if h[i] != '&' {
			continue
		}
		if rest := h[i:]; !strings.HasPrefix(rest, "&amp;") && !strings.HasPrefix(rest, "&lt;") &&
			!strings.HasPrefix(rest, "&gt;") && !strings.HasPrefix(rest, "&quot;") {
			t.Fatalf("%q holds an & that does not start an entity", h)
		}
	}
}
