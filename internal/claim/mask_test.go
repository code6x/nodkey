package claim

import (
	"encoding/base64"
	"math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMask(t *testing.T) {
	// Token bodies here are not random, so only the shape rule can find them.
	a36 := strings.Repeat("a", 36)
	tests := []struct {
		name string
		in   string
		want string
	}{
		// key=value and "key: value"
		{name: "password", in: "password=hunter2", want: "password=***"},
		{name: "upper case", in: "PASSWORD=hunter2", want: "PASSWORD=***"},
		{name: "inside a name", in: "DB_PASSWORD=hunter2 make", want: "DB_PASSWORD=*** make"},
		{name: "passwd", in: "passwd=hunter2", want: "passwd=***"},
		{name: "pwd", in: "MYSQL_PWD=hunter2", want: "MYSQL_PWD=***"},
		{name: "pass", in: "smtp_pass=hunter2", want: "smtp_pass=***"},
		{name: "token", in: "GITHUB_TOKEN=abc123", want: "GITHUB_TOKEN=***"},
		{name: "secret", in: "client_secret=abc123", want: "client_secret=***"},
		{name: "api key forms", in: "apikey=a api_key=b api-key=c APIKEY=d", want: "apikey=*** api_key=*** api-key=*** APIKEY=***"},
		{name: "access key", in: "aws_access_key_id=abc", want: "aws_access_key_id=***"},
		{name: "auth", in: "AUTH=abc oauth_token=def", want: "AUTH=*** oauth_token=***"},
		{name: "credential", in: "credentials=abc", want: "credentials=***"},
		{name: "private key", in: "private_key=abc", want: "private_key=***"},
		{name: "cookie header", in: "Cookie: session=abc", want: "Cookie: ***"},
		{name: "dotted name and colon", in: "db.password: hunter2", want: "db.password: ***"},
		{name: "spaces around =", in: "token = abc123", want: "token = ***"},
		{name: "header", in: "X-Api-Key: abc123", want: "X-Api-Key: ***"},
		{name: "JSON", in: `{"password":"hunter2","user":"deploy"}`, want: `{"password":"***","user":"deploy"}`},
		{name: "JSON with spaces", in: `{"token": "abc", "n": 1}`, want: `{"token": "***", "n": 1}`},
		{name: "Python dict", in: `{'secret': 'abc'}`, want: `{'secret': '***'}`},
		{name: "quoted value with spaces", in: `password="correct horse battery"`, want: `password="***"`},
		{name: "single quoted value", in: `password='correct horse' next`, want: `password='***' next`},
		{name: "escaped quote", in: `password="a\"b c" next`, want: `password="***" next`},
		{name: "unclosed quote", in: `password="a b c`, want: `password=***`},
		{name: "URL query", in: "https://api.example.com/v1?access_token=abc123&page=2", want: "https://api.example.com/v1?access_token=***"},
		{name: "option with =", in: "--db-password=hunter2", want: "--db-password=***"},
		{name: "key inside a value", in: "--from-literal=password=hunter2", want: "--from-literal=password=***"},
		{name: "value on the next line", in: "password=\nhunter2", want: "password= ***"},

		// Authorization headers, Bearer and Basic
		{name: "Bearer header", in: "Authorization: Bearer abc.def", want: "Authorization: ***"},
		{name: "token scheme", in: "authorization: token abc123", want: "authorization: ***"},
		{name: "Proxy and Basic", in: "Proxy-Authorization: Basic dXNlcjpwYXNz", want: "Proxy-Authorization: ***"},
		{name: "no scheme", in: "Authorization: abc123", want: "Authorization: ***"},
		{name: "quoted credentials", in: `Authorization: Bearer "abc def" next`, want: "Authorization: *** next"},
		{name: "quote inside the credentials", in: "Authorization: abc'def", want: "Authorization: ***"},
		{name: "curl header", in: `curl -H "Authorization: Bearer abc" https://example.com`, want: `curl -H "Authorization: ***" https://example.com`},
		{name: "Bearer alone", in: "send Bearer abc123 now", want: "send Bearer *** now"},
		{name: "Basic alone", in: "Basic dXNlcjpwYXNz", want: "Basic ***"},

		// URL passwords
		{name: "URL", in: "https://deploy:hunter2@git.example.com/app.git", want: "https://deploy:***@git.example.com/app.git"}, //nolint:gosec // G101: an invented password; the test checks that it is masked
		{name: "URL without user", in: "redis://:hunter2@db-1:6379/0", want: "redis://:***@db-1:6379/0"},
		{name: "URL password with @ and :", in: "postgres://app:p@ss:w@db-1/app", want: "postgres://app:***@db-1/app"}, //nolint:gosec // G101: an invented password; the test checks that it is masked

		// Known token shapes
		{name: "ghp_", in: "ghp_" + a36, want: "***"},
		{name: "gho_", in: "x gho_" + a36 + " y", want: "x *** y"},
		{name: "ghu_ ghs_ ghr_", in: "ghu_" + a36 + " ghs_" + a36 + " ghr_" + a36, want: "*** *** ***"},
		{name: "github_pat_", in: "github_pat_" + strings.Repeat("b", 22) + "_" + strings.Repeat("c", 59), want: "***"},
		{name: "glpat-", in: "glpat-" + strings.Repeat("d", 20), want: "***"},
		{name: "xoxb-", in: "xox" + "b-1111111111-2222222222-" + strings.Repeat("e", 24), want: "***"},
		{name: "xoxp-", in: "xox" + "p-1111111111-" + strings.Repeat("f", 24), want: "***"},
		{name: "sk-", in: "sk-" + strings.Repeat("g", 48), want: "***"},
		{name: "sk-proj-", in: "sk-proj-" + strings.Repeat("h", 40), want: "***"},
		{name: "AKIA", in: "AKIA" + strings.Repeat("A", 16), want: "***"},
		{name: "ASIA", in: "ASIA" + strings.Repeat("B", 16), want: "***"},
		{name: "JWT", in: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ3ZWItMSJ9.c2lnbmF0dXJl", want: "***"},
		{name: "unsigned JWT", in: "jwt eyJhbGciOiJub25lIn0.eyJzdWIiOiJ3ZWItMSJ9. done", want: "jwt *** done"},
		{name: "token inside a path", in: "/tmp/ghp_" + a36 + "/run", want: "/tmp/***/run"},

		// PEM blocks
		{
			name: "PEM block",
			in:   "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAAAAAA\n-----END OPENSSH PRIVATE KEY-----",
			want: "-----BEGIN OPENSSH PRIVATE KEY-----***-----END OPENSSH PRIVATE KEY-----",
		},
		{
			name: "PEM block without an END line",
			in:   "key -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nAAAA",
			want: "key -----BEGIN RSA PRIVATE KEY-----***",
		},

		// Options in free text, for example in a shell script
		{name: "attached -p", in: "mysql -uroot -phunter2 appdb", want: "mysql -uroot -p*** appdb"},
		{name: "quoted -p", in: `mysql "-phunter2" appdb`, want: `mysql "-p*** appdb`},
		{name: "option and value", in: "run --password hunter2 now", want: "run --password *** now"},
		{name: "option and quoted value", in: `run --password "correct horse battery" now`, want: "run --password *** now"},
		{name: "attached quoted value", in: `mysql -p'correct horse' appdb`, want: "mysql -p*** appdb"},
		{name: "option =", in: "--token=abc", want: "--token=***"},
		{name: "bare -p", in: "mysql -p hunter2 appdb", want: "mysql -p *** appdb"},
		{name: "curl -u", in: "curl -u deploy:hunter2 https://example.com", want: "curl -u deploy:*** https://example.com"},

		// Long random-looking words
		{name: "random base62", in: "Kq8vN3pX9wL2mR7tY4zB6cD1hJ5sF0gA", want: "***"},
		{name: "exactly 20 characters", in: "Kq8vN3pX9wL2mR7tY4zB", want: "***"},
		{name: "random in text", in: "use e8Kq2vN7pX4wL9mR3tY6zB1cD5hJ0sFg now", want: "use *** now"},
		{name: "git commit ID", in: "commit 4f9c2a1b8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b", want: "commit ***"},
		{name: "32 hex", in: "9f86d081884c7d659a2feaa0c55ad015", want: "***"},
		{name: "24 hex with 3.3 bits per character", in: "787f087d5d91cfdd867aef8e", want: "***"},
		{name: "base64 with padding", in: "dGhpcyBpcyBhIHRlc3QgdmFsdWU= ok", want: "*** ok"},
		{name: "base64url", in: "Zm9v_YmFy-3q9X2kL7mN4pR8sT1vW6yZ0", want: "***"},
		{name: "after =", in: "--seed=Kq8vN3pX9wL2mR7tY4zB6cD1", want: "--seed=***"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Mask(tt.in); got != tt.want {
				t.Errorf("Mask(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestMaskKeeps lists ordinary text that must stay readable.
func TestMaskKeeps(t *testing.T) {
	texts := []string{
		"git push origin main",
		"ansible-playbook -i hosts site.yml",
		"ssh -i ~/.ssh/deploy deploy@web-1",
		"make test",
		"apply the nginx fix",
		"the password is in the vault; rotate the token later",
		"user=deploy host=web-1 port=2222",
		"https://auth.example.com:8443/login",
		"deploy@auth-1.example.com:/srv/app",
		"ssh://deploy@web-1:2222/srv/app",
		"/home/dev/src/app",
		"key=value",
		"x86_64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl",
		"kube-prometheus-stack-45",
		"TEST_CASE_NUMBER_123_EXTENDED",
		"ABC-1234-add-oauth2-support",
		"golangci-lint-2-14-0-linux-amd64",
		"node --max-old-space-size=4096 build.js",
		"mysql --default-character-set=utf8mb4 appdb",
		"internationalization-and-localization",
		"a1a1a1a1a1a1a1a1a1a1a1",
		"abc123abc123abc123abc123",
		"2026-10-12T14-03-00Z", // interleaved, but only 2.9 bits per character
		"Kq8vN3pX9wL2mR7tY4z",  // random, but shorter than 20
		"gh release create v1.2.0",
		"docker push registry.example.com/team/app:v1.2.3",
		"task-runner sk-mode",
		// Paths are one word now that "/" is part of a word.
		"kubectl apply -f /srv/k8s/manifests/app.yaml",
		"/usr/local/bin/sha256sum",
		"/Users/dev/src/k8s-demo/app",
		"git push origin refs/heads/feature/k8s-upgrade-v2",
		"/apis/apps/v1/namespaces/k8s-ops/deployments",
		"/opt/i18n/locales/bg",
		"/srv/app/releases/20261012-a1b2c3d4",
	}
	for _, s := range texts {
		if got := Mask(s); got != s {
			t.Errorf("Mask(%q) = %q, want it unchanged", s, got)
		}
	}
}

func TestMaskCleans(t *testing.T) {
	if got, want := Mask(" a\n\u202eb\u200b "), "a b"; got != want {
		t.Errorf("Mask = %q, want %q", got, want)
	}
}

// redact replaces the canary and every 4-byte piece of it in s, so that a
// failure message never shows the canary.
func redact(s, canary string) string {
	if canary == "" {
		return s
	}
	s = strings.ReplaceAll(s, canary, "<canary>")
	for i := 0; i+4 <= len(canary); i++ {
		s = strings.ReplaceAll(s, canary[i:i+4], "<piece>")
	}
	return s
}

// maskCase is a test of Mask with a made-up secret in the input.
type maskCase struct {
	name   string
	in     string
	want   string
	canary string // a made-up secret; it must not come out of Mask, nor out of the chains
}

// checkMaskCases checks Mask on each case. It also checks that the
// canary does not come out of the full chains for free text and for a
// command. Failure messages never show the canary.
func checkMaskCases(t *testing.T, tests []maskCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Mask(tt.in); got != tt.want {
				t.Errorf("Mask = %q, want %q", redact(got, tt.canary), tt.want)
			}
			if tt.canary != "" {
				checkNoLeak(t, "HTML(Line(Mask))", HTML(Line(Mask(tt.in), 500)), tt.canary)
				checkNoLeak(t, "Command sh -c", Command([]string{"sh", "-c", tt.in}, 500), tt.canary)
			}
		})
	}
}

// TestMaskNested covers a value that is itself a key, an object or an
// authentication scheme: the inner value is hidden too.
func TestMaskNested(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{name: "object", in: `{"auth": {"token": "Cx7nest01"}}`, want: `{"auth": ***}`, canary: "Cx7nest01"},
		{
			name:   "object without a secret key inside",
			in:     `{"secret": {"value": "Cx7nest02"}}`,
			want:   `{"secret": ***}`,
			canary: "Cx7nest02",
		},
		{
			name:   "deep object",
			in:     `{"auth": {"identity": {"methods": ["password"], "password": {"user": {"name": "admin", "password": "Cx7nest03"}}}}}`,
			want:   `{"auth": ***}`,
			canary: "Cx7nest03",
		},
		{
			name:   "object in a curl script",
			in:     `curl -d '{"credentials": {"user": "dev", "pass": "Cx7nest04"}}' https://example.com`,
			want:   `curl -d '{"credentials": ***}' https://example.com`,
			canary: "Cx7nest04",
		},
		{name: "list", in: `{"tokens": ["Cx7nest05", "x"], "n": 1}`, want: `{"tokens": ***, "n": 1}`, canary: "Cx7nest05"},
		{name: "Python dict", in: `{'auth': {'pass': 'Cx7nest06'}}`, want: `{'auth': ***}`, canary: "Cx7nest06"},
		{name: "key as the value", in: "token: password: Cx7nest07", want: "token: *** ***", canary: "Cx7nest07"},
		{name: "key in an option value", in: "--password=token=Cx7nest08", want: "--password=***", canary: "Cx7nest08"},
		{name: "Bearer after a key", in: "HTTP_AUTHORIZATION=Bearer Cx7nest09", want: "HTTP_AUTHORIZATION=***", canary: "Cx7nest09"},
		{name: "Bearer in YAML", in: "X_AUTHORIZATION: Bearer Cx7nest10 next", want: "X_AUTHORIZATION: *** next", canary: "Cx7nest10"},
		{name: "token scheme after a key", in: "AUTH_HEADER=token Cx7nest11", want: "AUTH_HEADER=***", canary: "Cx7nest11"},
		{name: "Basic after a key", in: "auth_header: Basic Cx7nest12 next", want: "auth_header: *** next", canary: "Cx7nest12"},
		{
			name:   "any scheme after Authorization",
			in:     "Authorization: AWS4-HMAC-SHA256 Cx7nest13",
			want:   "Authorization: ***",
			canary: "Cx7nest13",
		},
		{name: "no scheme after another key", in: "auth=dev next", want: "auth=*** next"},
		{
			name:   "object after Bearer, before another object",
			in:     `Bearer {Cx7brace01 x} then token: {"a": "b"}`,
			want:   "Bearer *** then token: ***",
			canary: "Cx7brace01",
		},
	})
}

// TestMaskValueForms covers the forms of key and value: escaped JSON,
// "=>", ":=", quotes joined to more of the same shell word, and values
// inside quotes.
func TestMaskValueForms(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{name: "escaped JSON", in: `{\"password\":\"Cx7form01\"}`, want: `{\"password\":\"***\"}`, canary: "Cx7form01"},
		{
			name:   "escaped JSON with spaces",
			in:     `{\"password\": \"Cx7 form02\", \"user\": \"dev\"}`,
			want:   `{\"password\": \"***\", \"user\": \"dev\"}`,
			canary: "Cx7 form02",
		},
		{
			name:   "escaped JSON in a curl script",
			in:     `curl -d "{\"user\":\"admin\",\"password\":\"Cx7form03\"}" https://example.com`,
			want:   `curl -d "{\"user\":\"admin\",\"password\":\"***\"}" https://example.com`,
			canary: "Cx7form03",
		},
		{
			name:   "escaped twice",
			in:     `{\\\"token\\\":\\\"Cx7form04\\\"}`,
			want:   `{\\\"token\\\":\\\"***\\\"}`,
			canary: "Cx7form04",
		},
		{
			name:   "=> in PHP",
			in:     `php -r "User::create(['password' => 'Cx7form05']);"`,
			want:   `php -r "User::create(['password' => '***']);"`,
			canary: "Cx7form05",
		},
		{name: "=> in Ruby", in: `{ "password" => "Cx7form06" }`, want: `{ "password" => "***" }`, canary: "Cx7form06"},
		{name: "empty quotes before the value", in: "password=''Cx7form07 next", want: "password=*** next", canary: "Cx7form07"},
		{name: "quotes and more", in: `PASSWORD="abc"Cx7form08 make`, want: "PASSWORD=*** make", canary: "Cx7form08"},
		{name: "quote inside the word", in: `password=abc"Cx7 form09" next`, want: "password=*** next", canary: "Cx7 form09"},
		{name: ":= in a Makefile", in: "DB_PASSWORD := Cx7form10", want: "DB_PASSWORD := ***", canary: "Cx7form10"},
		{name: "?=", in: "TOKEN ?= Cx7form11", want: "TOKEN ?= ***", canary: "Cx7form11"},
		{name: "space before ':'", in: "password : Cx7form12", want: "password : ***", canary: "Cx7form12"},
		{name: "inside double quotes", in: `env "PASSWORD=Cx7 form13" ./run`, want: `env "PASSWORD=***" ./run`, canary: "Cx7 form13"},
		{
			name:   "inside single quotes",
			in:     `docker run -e 'API_TOKEN=Cx7 form14' app`,
			want:   `docker run -e 'API_TOKEN=***' app`,
			canary: "Cx7 form14",
		},
		{name: "JSON value keeps the rest", in: `{"password":"Cx7form15","user":"dev"}`, want: `{"password":"***","user":"dev"}`, canary: "Cx7form15"},
	})
}

// TestMaskBase64Slash covers standard base64 keys, which may hold "/":
// they are one word, not several short ones.
func TestMaskBase64Slash(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{
			name:   "AWS example secret key",
			in:     "aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			want:   "aws configure set aws_secret_access_key ***",
			canary: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		{
			name:   "with padding",
			in:     "key q3T9/xK2+Lm8Rv4/Pz7Wc1Nb6Hj0Ys5Ad2Fg8Ek3Ui= ok",
			want:   "key *** ok",
			canary: "q3T9/xK2+Lm8Rv4/Pz7Wc1Nb6Hj0Ys5Ad2Fg8Ek3Ui=",
		},
		{name: "starts with /", in: "/9xK2mQ7vL3pR8tZ4wB6nC1hJ5sF0gA", want: "***", canary: "/9xK2mQ7vL3pR8tZ4wB6nC1hJ5sF0gA"},
	})

	// Random keys, as "openssl rand -base64 30" makes them. A fixed seed
	// gives the same keys every time. We measured on 2026-10-14 that about
	// 0.5 % of such keys look too plain to hide.
	src := rand.NewChaCha8([32]byte{1})
	const n = 2000
	visible := 0
	b := make([]byte, 30)
	for range n {
		_, _ = src.Read(b)
		key := base64.StdEncoding.EncodeToString(b)
		if strings.Contains(Mask("key "+key+" ok"), key[:20]) {
			visible++
		}
	}
	if visible > n/100 {
		t.Errorf("%d of %d random base64 keys are visible, want at most 1 %%", visible, n)
	}
}

// TestMaskURLPathKeys covers a random key that is one part of a URL path,
// as in a webhook URL. The readable rest of the path must not keep the key
// visible: such a key must be hidden about as often as a key alone.
// DESIGN.md section 7 says that of random keys with 32 characters, about
// 1 in 100 or fewer stays visible. Found in the second security review on
// 2026-10-14.
func TestMaskURLPathKeys(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{
			name:   "webhook",
			in:     "curl -X POST https://example.com/api/v1/organizations/settings/integrations/webhooks/incoming/Cx7fakeUrmiOP3wCy5o86XpSWchjZX6Y",
			want:   "curl -X POST https://example.com/api/v1/organizations/settings/integrations/webhooks/incoming/***",
			canary: "Cx7fakeUrmiOP3wCy5o86XpSWchjZX6Y",
		},
		{
			name:   "key in the middle",
			in:     "https://example.com/organizations/integrations/downloads/Cx7fakeUrmiOP3wCy5o86XpSWchjZX6Y/release-notes/changelog.txt",
			want:   "https://example.com/organizations/integrations/downloads/***/release-notes/changelog.txt",
			canary: "Cx7fakeUrmiOP3wCy5o86XpSWchjZX6Y",
		},
		{
			// The whole word looks random here, so all of it is hidden.
			name:   "git commit ID",
			in:     "https://git.example.com/team/app/commit/4f9c2a1b8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b",
			want:   "https://git.example.***",
			canary: "4f9c2a1b8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b",
		},
		{
			name: "readable long parts stay",
			in:   "https://example.com/docs/internationalization-and-localization/x86_64-unknown-linux-gnu",
			want: "https://example.com/docs/internationalization-and-localization/x86_64-unknown-linux-gnu",
		},
	})

	shapes := []string{
		"https://hooks.example.com/services/T0ABCDEFG/B0HIJKLMN/KEY",
		"https://example.com/api/webhooks/123456789012345678/KEY",
		"https://example.com/api/v1/organizations/settings/integrations/webhooks/incoming/KEY",
		"https://example.com/download/KEY/release/notes/latest.tar.gz",
	}
	alphabets := []struct {
		name, chars string
		n           int
	}{
		{"base62", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 32},
		{"hex", "0123456789abcdef", 40},
	}
	// A fixed seed gives the same made-up keys every time.
	src := rand.NewChaCha8([32]byte{7})
	const n = 200
	for _, shape := range shapes {
		for _, al := range alphabets {
			visible := 0
			key := make([]byte, al.n)
			for range n {
				for i := range key {
					key[i] = al.chars[src.Uint64()%uint64(len(al.chars))]
				}
				url := strings.ReplaceAll(shape, "KEY", string(key))
				if strings.Contains(Mask("curl -X POST "+url), string(key)) ||
					strings.Contains(Command([]string{"curl", "-X", "POST", url}, 500), string(key)) {
					visible++
				}
			}
			if visible > n/50 {
				t.Errorf("%d of %d random %s keys are visible in %s, want at most 2 %%", visible, n, al.name, shape)
			}
		}
	}
}

// TestMaskCostIsLinear checks that the work of Mask and Command grows
// linearly with the length of the text, for the slowest shapes we know.
// Many keys in one shell word, as in PASS=PASS=..., took quadratic time
// and memory before the second security review on 2026-10-14: 1.4 s and
// 443 MiB for 64 KiB. The other shapes are the slowest that a search over
// pairs and mixes of short units found on 2026-10-14: about 25 ms for
// 64 KiB, without -race.
//
// The test compares 4 KiB with 64 KiB, 16 times as many bytes. Linear work
// costs about 16 times as much, quadratic work 256 times. The limit is 64,
// so a slow or busy machine or -race does not fail the test: under heavy
// load on 2 CPUs, the time ratio stayed below 30. (With -race, regexp
// allocates more, because the race detector makes sync.Pool drop some
// items.) Small costs are not compared, so that noise in short runs
// cannot fail the test.
func TestMaskCostIsLinear(t *testing.T) {
	var progs []string
	for name := range programs {
		progs = append(progs, name)
	}
	slices.Sort(progs)
	shapes := []struct{ prefix, unit string }{
		{unit: "PASS="},
		{unit: "-ppass"},
		{prefix: strings.Join(progs, " ") + " ", unit: "-x "}, // with the rules of every program
	}
	// run returns the time and the bytes allocated by Mask and Command.
	// "echo " keeps Command from hiding the whole script as one KEY=VALUE.
	run := func(s string) (time.Duration, uint64) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		_ = Mask(s)
		_ = Command([]string{"sh", "-c", "echo " + s}, 300)
		d := time.Since(start)
		runtime.ReadMemStats(&after)
		return d, after.TotalAlloc - before.TotalAlloc
	}
	const size = MaxInput - 16 // with "sh", "-c" and "echo ", at most MaxInput in all
	const limit = 64
	for _, sh := range shapes {
		text := func(n int) string { return sh.prefix + fillTo(sh.unit, n-len(sh.prefix)) }
		short, long := text(size/16), text(size)

		shortTime, shortMem := run(short)
		for range 2 {
			d, _ := run(short)
			shortTime = min(shortTime, d)
		}
		longTime, longMem := run(long)
		if longMem > limit*shortMem && longMem > 16<<20 {
			t.Errorf("%q: %d KiB allocated for %d bytes, %d KiB for %d bytes: not linear",
				sh.unit, shortMem>>10, len(short), longMem>>10, len(long))
		}
		for try := 1; try < 3 && longTime > limit*shortTime; try++ {
			d, _ := run(long) // a pause may have slowed the run down
			longTime = min(longTime, d)
		}
		if longTime > limit*shortTime && longTime > 100*time.Millisecond {
			t.Errorf("%q: %v for %d bytes, %v for %d bytes: not linear", sh.unit, shortTime, len(short), longTime, len(long))
		}
	}
}

// fillTo repeats unit up to exactly n bytes.
func fillTo(unit string, n int) string {
	return strings.Repeat(unit, n/len(unit)+1)[:n]
}

// TestMaskBracketKeys covers key names with brackets, as in Rails, PHP and
// Python: the name holds a secret word, so the value is hidden. Found in
// the second security review on 2026-10-14.
func TestMaskBracketKeys(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{
			name:   "form field in a curl script",
			in:     `curl -d "user[password]=Cx7brack01" https://example.com`,
			want:   `curl -d "user[password]=***" https://example.com`,
			canary: "Cx7brack01",
		},
		{name: "form field", in: "user[password]=Cx7brack02", want: "user[password]=***", canary: "Cx7brack02"},
		{name: "Ruby symbol", in: `params[:password] = "Cx7brack03"`, want: `params[:password] = "***"`, canary: "Cx7brack03"},
		{name: "PHP array", in: `$config['db_password'] = 'Cx7brack04';`, want: `$config['db_password'] = '***';`, canary: "Cx7brack04"},
		{name: "Python dict", in: `os.environ["API_TOKEN"] = "Cx7brack05"`, want: `os.environ["API_TOKEN"] = "***"`, canary: "Cx7brack05"},
		{name: "JSON key", in: `{"user[password]": "Cx7brack06"}`, want: `{"user[password]": "***"}`, canary: "Cx7brack06"},
		{name: "no space after ':'", in: "user[password]:Cx7brack07", want: "user[password]:***", canary: "Cx7brack07"},
		{name: "other brackets stay", in: "items[0]=apple matrix[1][2]=5 [auth] enabled", want: "items[0]=apple matrix[1][2]=5 [auth] enabled"},
	})
}

// TestMaskSwallowedWords covers a value that takes the next words, because
// a quote stays open or a backslash escapes the space. Those words must
// still be read for programs and options. FuzzCanary found both inputs on
// 2026-10-14; they are also in testdata/fuzz/FuzzCanary.
func TestMaskSwallowedWords(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{
			name:   "quote before the form",
			in:     `'-p0 mysql -p'a b'\''c Cx7canaryQQ9' appdb 0`,
			want:   `'-p*** appdb 0`,
			canary: "Cx7canaryQQ9",
		},
		{
			name:   "backslash before the program",
			in:     `-p\ redis-cli -h db-1 -a Cx7canaryQQ9 ping 0`,
			want:   "-p*** -h db-1 -a *** ping 0",
			canary: "Cx7canaryQQ9",
		},
		{
			name:   "option inside the taken words",
			in:     `app -p'x --password 'y Cx7swallow1' z`,
			want:   "app -p*** z",
			canary: "Cx7swallow1",
		},
	})
}

// TestMaskSeparatorAsText covers a ";" or "&&" that does not end the
// command that runs: inside quotes, escaped, or inside a substitution. It
// must not end the rules of the program. A separator outside quotes still
// ends them. Found in the third security review on 2026-10-14.
func TestMaskSeparatorAsText(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{
			name:   "cookie in single quotes",
			in:     `curl -H 'Cookie: theme=dark; lang=bg' -E client.pem:Cx7septext1 https://example.com`,
			want:   `curl -H 'Cookie: ***' -E client.pem:*** https://example.com`,
			canary: "Cx7septext1",
		},
		{
			name:   "cookie in double quotes",
			in:     `curl -b "theme=dark; lang=bg" -E client.pem:Cx7septext2 https://example.com`,
			want:   `curl -b *** -E client.pem:*** https://example.com`,
			canary: "Cx7septext2",
		},
		{
			name:   "SQL in quotes",
			in:     `sqlcmd -S db-1 -Q "SELECT 1; SELECT 2" -P Cx7septext3`,
			want:   `sqlcmd -S db-1 -Q "SELECT 1; SELECT 2" -P ***`,
			canary: "Cx7septext3",
		},
		{
			name:   "separator word in quotes",
			in:     `sqlcmd -S db-1 -Q "SELECT 1 ; SELECT 2" -P Cx7septext4`,
			want:   `sqlcmd -S db-1 -Q "SELECT 1 ; SELECT 2" -P ***`,
			canary: "Cx7septext4",
		},
		{
			name:   "&& in quotes",
			in:     `curl -d 'a=1 && b=2' -E client.pem:Cx7septext5 https://example.com`,
			want:   `curl -d 'a=1 && b=2' -E client.pem:*** https://example.com`,
			canary: "Cx7septext5",
		},
		{
			name:   "value in quotes",
			in:     `vault kv put secret/app note='a; b' api=Cx7septext6`,
			want:   `vault kv put secret/app note=*** api=***`,
			canary: "Cx7septext6",
		},
		// A ";" inside a substitution ends a command inside it, not the
		// command around it. Found in the fourth security review on
		// 2026-10-14.
		{
			name:   "command substitution",
			in:     `curl -d $(date; hostname) -E client.pem:Cx7subst01 https://example.com`,
			want:   `curl -d $(date; hostname) -E client.pem:*** https://example.com`,
			canary: "Cx7subst01",
		},
		{
			name:   "backticks",
			in:     "curl -d `date; hostname` -E client.pem:Cx7subst02 https://example.com",
			want:   "curl -d `date; hostname` -E client.pem:*** https://example.com",
			canary: "Cx7subst02",
		},
		{
			name:   "substitution in a value",
			in:     `sqlcmd -S db-1 -v x=$(cat a.txt; echo) -P Cx7subst03`,
			want:   `sqlcmd -S db-1 -v x=$(cat a.txt; echo) -P ***`,
			canary: "Cx7subst03",
		},
		{
			name:   "process substitution",
			in:     `curl -d @<(date; hostname) -E client.pem:Cx7subst04 https://example.com`,
			want:   `curl -d @<(date; hostname) -E client.pem:*** https://example.com`,
			canary: "Cx7subst04",
		},
		{
			// The end of a substitution is not looked for, so no later
			// separator counts either. That is the safe side.
			name: "separator after a substitution",
			in:   `redis-cli ping $(date); tar -a -cf backup.tgz data`,
			want: `redis-cli ping $(date); tar -a *** backup.tgz data`,
		},
		{
			// An apostrophe leaves a quote open, so the quotes are not
			// known, and no separator counts.
			name:   "quote never closed",
			in:     `don't run sqlcmd -Q 'a; b' -P Cx7septext7`,
			want:   `don't run sqlcmd -Q 'a; b' -P ***`,
			canary: "Cx7septext7",
		},
		{
			// \; is text for the shell, as in find -exec, so -a of
			// redis-cli still hides -cf. That is the safe side.
			name: "escaped separator",
			in:   `redis-cli ping \; tar -a -cf backup.tgz data`,
			want: `redis-cli ping \; tar -a *** backup.tgz data`,
		},
		{
			name: "separator after the quotes",
			in:   `redis-cli ping 'a; b'; tar -a -cf backup.tgz data`,
			want: `redis-cli ping 'a; b'; tar -a -cf backup.tgz data`,
		},
		{
			name: "separator after a quoted word",
			in:   `redis-cli ping "x" && tar -a -cf backup.tgz data`,
			want: `redis-cli ping "x" && tar -a -cf backup.tgz data`,
		},
	})
}

// TestMaskHeaders covers headers without a space after ":" and the whole
// value of a Cookie header.
func TestMaskHeaders(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{name: "no space", in: "X-Api-Key:Cx7head01", want: "X-Api-Key:***", canary: "Cx7head01"},
		{name: "cookie without space", in: "Cookie:sid=Cx7head02", want: "Cookie:***", canary: "Cx7head02"},
		{name: "whole cookie", in: "Cookie: theme=dark; sid=Cx7head03; lang=bg", want: "Cookie: ***", canary: "Cx7head03"},
		{
			name:   "cookie in a curl script",
			in:     `curl -H "Cookie: theme=dark; sid=Cx7head04" https://example.com`,
			want:   `curl -H "Cookie: ***" https://example.com`,
			canary: "Cx7head04",
		},
		{name: "Authorization without space", in: "Authorization:Bearer Cx7head05", want: "Authorization:***", canary: "Cx7head05"},
		{
			name:   "token header in a script",
			in:     `curl -H "X-Auth-Token:Cx7head06" https://example.com`,
			want:   `curl -H "X-Auth-Token:***" https://example.com`,
			canary: "Cx7head06",
		},
		{name: "Set-Cookie", in: "Set-Cookie: sid=Cx7head07; Path=/; HttpOnly", want: "Set-Cookie: ***", canary: "Cx7head07"},
		{name: "dotted name", in: "db.password:Cx7head08", want: "db.password:***", canary: "Cx7head08"},
		{name: "host and path stay", in: "rsync -a ./dist/ auth:/srv/app/", want: "rsync -a ./dist/ auth:/srv/app/"},
		{name: "image tag stays", in: "docker run oauth2-proxy:v7.5.1", want: "docker run oauth2-proxy:v7.5.1"},
		{name: "image path stays", in: "registry.example.com/oauth2-proxy:v7.5.1", want: "registry.example.com/oauth2-proxy:v7.5.1"},
		{name: "host name stays", in: "https://auth.example.com:8443/login", want: "https://auth.example.com:8443/login"},
	})
}

// TestMaskURLPasswords covers passwords with "#", "?" or "/", and
// USER:PASSWORD@HOST without a scheme.
func TestMaskURLPasswords(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{name: "# in the password", in: "mongodb://admin:Cx7#url01@db-1:27017/app", want: "mongodb://admin:***@db-1:27017/app", canary: "Cx7#url01"}, //nolint:gosec // G101: an invented secret; the test checks that it is masked
		{name: "/ in the password", in: "postgres://app:Cx7/url02@db-1/app", want: "postgres://app:***@db-1/app", canary: "Cx7/url02"},               //nolint:gosec // G101: an invented secret; the test checks that it is masked
		{name: "? in the password", in: "redis://:Cx7?url03@db-1:6379/0", want: "redis://:***@db-1:6379/0", canary: "Cx7?url03"},
		{
			name:   "e-mail as the user",
			in:     "https://dev@example.com:Cx7url04@git.example.com/app.git",
			want:   "https://dev@example.com:***@git.example.com/app.git",
			canary: "Cx7url04",
		},
		{
			name:   "no scheme",
			in:     "curl -x admin:Cx7url05@proxy.example.com:3128 https://example.com",
			want:   "curl -x admin:***@proxy.example.com:3128 https://example.com",
			canary: "Cx7url05",
		},
		{name: "no scheme after =", in: "--proxy=admin:Cx7url06@192.0.2.10:3128", want: "--proxy=admin:***@192.0.2.10:3128", canary: "Cx7url06"},
		{name: "no scheme in quotes", in: `ssh "deploy:Cx7url07@web-1"`, want: `ssh "deploy:***@web-1"`, canary: "Cx7url07"},
		{
			name: "port and @ in the path stay",
			in:   "https://example.com:8443/login?next=dev@example.com",
			want: "https://example.com:8443/login?next=dev@example.com",
		},
		{name: "user and host stay", in: "rsync -a deploy@web-1:/srv/app/ ./backup/", want: "rsync -a deploy@web-1:/srv/app/ ./backup/"},
		{name: "git over SSH stays", in: "git clone git@git.example.com:team/app.git", want: "git clone git@git.example.com:team/app.git"},
		{
			name: "image digest",
			in:   "docker pull registry.example.com/app:1.2@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			want: "docker pull registry.example.com/app:1.2@sha256:***",
		},
	})
}

// TestMaskBackslash covers a backslash outside quotes: the byte after it
// is plain. So \' opens no quote, a quote right after \' opens new quotes,
// and an escaped space joins two words.
func TestMaskBackslash(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{name: "quote in single quotes", in: `app --password 'it'\''s Cx7bsl01' next`, want: "app --password *** next", canary: "Cx7bsl01"},
		{name: "escaped quote opens nothing", in: `app --password Cx7bsl02\'x next`, want: "app --password *** next", canary: "Cx7bsl02"},
		{name: "escaped quote in double quotes", in: `app --password "a \" Cx7bsl03" next`, want: "app --password *** next", canary: "Cx7bsl03"},
		{name: "attached -p", in: `mysql -p'a b'\''c Cx7bsl04' appdb`, want: "mysql -p*** appdb", canary: "Cx7bsl04"},
		{name: "key and value", in: `password='a'\''b Cx7bsl05' next`, want: "password=*** next", canary: "Cx7bsl05"},
		{name: "escaped space", in: `app --password a\ Cx7bsl06 next`, want: "app --password *** next", canary: "Cx7bsl06"},
	})
}

// TestMaskDashP covers the decision for a bare -p: the next word is its
// value and is hidden, unless it starts with "-".
func TestMaskDashP(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{name: "mysql", in: "mysql -u root -p Cx7dashp1 appdb", want: "mysql -u root -p *** appdb", canary: "Cx7dashp1"},
		{name: "port", in: "ssh -p 2222 deploy@web-1", want: "ssh -p *** deploy@web-1"},
		{name: "option after -p", in: "ssh-keygen -p -f ~/.ssh/id_ed25519", want: "ssh-keygen -p -f ~/.ssh/id_ed25519"},
		{name: "-p at the end", in: "mysql -p", want: "mysql -p"},
		{name: "quoted value", in: `mysql -p "Cx7 dashp2" appdb`, want: "mysql -p *** appdb", canary: "Cx7 dashp2"},
		{name: "attached value", in: "mysql -pCx7dashp3", want: "mysql -p***", canary: "Cx7dashp3"},
	})
}

// TestMaskPrograms covers the programs table in free text, such as a
// shell script.
func TestMaskPrograms(t *testing.T) {
	checkMaskCases(t, []maskCase{
		{name: "redis-cli", in: "redis-cli -h db-1 -a Cx7prog01 ping", want: "redis-cli -h db-1 -a *** ping", canary: "Cx7prog01"},
		{name: "after sudo", in: "sudo -u redis redis-cli -a Cx7prog02", want: "sudo -u redis redis-cli -a ***", canary: "Cx7prog02"},
		{
			name:   "after another command",
			in:     "cd /tmp && openssl enc -aes-256-cbc -k Cx7prog03 -in data.txt",
			want:   "cd /tmp && openssl enc -aes-256-cbc -k *** -in data.txt",
			canary: "Cx7prog03",
		},
		{name: "separator ends the program", in: "redis-cli ping; tar -a -cf backup.tgz data", want: "redis-cli ping; tar -a -cf backup.tgz data"},
		{name: "program name in quotes", in: `sh -c "redis-cli -a Cx7prog04"`, want: `sh -c "redis-cli -a ***`, canary: "Cx7prog04"},

		// Found in the second security review on 2026-10-14.
		{name: "host named like a program", in: "redis-cli -h vault -a Cx7prog05 ping", want: "redis-cli -h vault -a *** ping", canary: "Cx7prog05"},
		{
			name:   "repository named like a program",
			in:     "gh secret set API_KEY --repo team/vault -b Cx7prog06",
			want:   "gh secret set API_KEY --repo team/vault -b ***",
			canary: "Cx7prog06",
		},
		{
			name:   "URL that ends like a program",
			in:     "curl https://example.com/api/vault -E client.pem:Cx7prog07",
			want:   "curl https://example.com/api/vault -E client.pem:***",
			canary: "Cx7prog07",
		},
		{name: "glued &&", in: "cd /tmp&&redis-cli -a Cx7prog08 ping", want: "cd /tmp&&redis-cli -a *** ping", canary: "Cx7prog08"},
		{name: "glued ;", in: "cd /tmp;redis-cli -a Cx7prog09 ping", want: "cd /tmp;redis-cli -a *** ping", canary: "Cx7prog09"},
		{name: "glued |", in: "echo hi|redis-cli -a Cx7prog10", want: "echo hi|redis-cli -a ***", canary: "Cx7prog10"},
		{
			// A glued separator adds the next program, but it does not end
			// the one before, so -cf is hidden too. That is the safe side.
			name: "glued separator keeps the program before",
			in:   "redis-cli ping;tar -a -cf backup.tgz data",
			want: "redis-cli ping;tar -a *** backup.tgz data",
		},
		{
			name:   "ldapsearch grouped",
			in:     "ldapsearch -xw Cx7prog11 -b dc=example,dc=com",
			want:   "ldapsearch -xw *** -b dc=example,dc=com",
			canary: "Cx7prog11",
		},
		{name: "ssh-keygen grouped", in: "ssh-keygen -pP Cx7prog12 -N x -f key", want: "ssh-keygen -pP *** -N *** -f key", canary: "Cx7prog12"},
		{
			name:   "curl grouped with an attached value",
			in:     "curl -sudeploy:Cx7prog13 https://example.com",
			want:   "curl -sudeploy:*** https://example.com",
			canary: "Cx7prog13",
		},
		{name: "groups without a secret stay", in: "ldapsearch -LLL -x && curl -XPUT -sS https://example.com", want: "ldapsearch -LLL -x && curl -XPUT -sS https://example.com"},
		{name: "quoted -p", in: `mysql -u root "-p" Cx7prog14 appdb`, want: `mysql -u root "-p" *** appdb`, canary: "Cx7prog14"},
		{name: "quoted option of a program", in: `redis-cli "-a" Cx7prog15 ping`, want: `redis-cli "-a" *** ping`, canary: "Cx7prog15"},
		{name: "putty -pw", in: "putty -ssh deploy@web-1 -pw Cx7prog16", want: "putty -ssh deploy@web-1 -pw ***", canary: "Cx7prog16"},
		{name: "-pw of another program", in: "kitty -pw Cx7prog17 web-1", want: "kitty -p*** *** web-1", canary: "Cx7prog17"},
	})
}

// checkNoLeak fails if out holds the canary or any 8-byte piece of it.
// The message shows out with every piece of the canary replaced.
func checkNoLeak(t *testing.T, what, out, canary string) {
	t.Helper()
	const piece = 8
	if len(canary) < piece {
		t.Fatalf("a canary of %d bytes is too short for this check", len(canary))
	}
	if strings.Contains(out, canary) {
		t.Errorf("%s: the whole canary is in the output: %q", what, redact(out, canary))
		return
	}
	for i := 0; i+piece <= len(canary); i++ {
		if strings.Contains(out, canary[i:i+piece]) {
			t.Errorf("%s: canary bytes %d-%d are in the output: %q", what, i, i+piece, redact(out, canary))
			return
		}
	}
}

// TestMaskCanaries checks that planted values never come out of Mask, nor
// out of the full chains used for free text and for commands.
func TestMaskCanaries(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		canary string
	}{
		{name: "key=value", in: "export DB_PASSWORD=Cx7-canary-pw1 && make", canary: "Cx7-canary-pw1"},
		{name: "JSON", in: `{"client_secret": "canary value with spaces"}`, canary: "canary value with spaces"},
		{name: "YAML", in: "api_key: Cx7canaryApiKey", canary: "Cx7canaryApiKey"},
		{name: "Authorization", in: "Authorization: Bearer Cx7canary.bearer", canary: "Cx7canary.bearer"},
		{name: "quoted Authorization", in: `Authorization: Bearer "Cx7 canary quoted bearer"`, canary: "Cx7 canary quoted bearer"},
		{name: "quote inside Authorization", in: "Authorization: Cx7canaryQ1'Cx7canaryQ2", canary: "Cx7canaryQ2"},
		{
			name:   "Basic in a curl script",
			in:     `curl -H "Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==" https://example.com`,
			canary: "Y2FuYXJ5OmNhbmFyeQ==",
		},
		{name: "URL", in: "git clone https://deploy:Cx7canaryUrl@git.example.com/app.git", canary: "Cx7canaryUrl"}, //nolint:gosec // G101: an invented password; the test checks that it is masked
		{name: "GitHub token", in: "use gh" + "p_Cx7canary0123456789abcdefghijklmnop", canary: "Cx7canary0123456789abcdefghijklmnop"},
		{name: "GitLab token", in: "glp" + "at-Cx7canaryGitlab0123", canary: "Cx7canaryGitlab0123"},
		{name: "Slack token", in: "xox" + "b-1234567890-Cx7canarySlack", canary: "Cx7canarySlack"},
		{name: "sk- key", in: "OPENAI s" + "k-Cx7canaryOpenAi0123456789abcdefghij", canary: "Cx7canaryOpenAi0123456789abcdefghij"},
		{name: "AWS key ID", in: "id AK" + "IACX7CANARY0000000", canary: "CX7CANARY0000000"},
		{name: "JWT", in: "eyJhbGciOiJIUzI1NiJ9.eyJjYW5hcnkiOiJ5ZXMifQ.Q3g3Y2FuYXJ5U2ln", canary: "eyJjYW5hcnkiOiJ5ZXMifQ"},
		{
			name:   "PEM",
			in:     "-----BEGIN PRIVATE KEY-----\nQ3g3Y2FuYXJ5UGVtQm9keQ\n-----END PRIVATE KEY-----",
			canary: "Q3g3Y2FuYXJ5UGVtQm9keQ",
		},
		{name: "mysql -p", in: "mysql -uroot -pCx7canaryMy appdb", canary: "Cx7canaryMy"},
		{name: "option", in: "deploy --token Cx7canaryOpt", canary: "Cx7canaryOpt"},
		{name: "quoted option value", in: `deploy --password "Cx7 canary quoted" now`, canary: "Cx7 canary quoted"},
		{name: "curl -u", in: "curl -u deploy:Cx7canaryCurl https://example.com", canary: "Cx7canaryCurl"},
		{name: "random token", in: "token is e8Kq2vN7pX4wL9mR3tY6zB1cD5hJ0sFg ok", canary: "e8Kq2vN7pX4wL9mR3tY6zB1cD5hJ0sFg"},
		{name: "hex key", in: "key 9f86d081884c7d659a2feaa0c55ad015 ok", canary: "9f86d081884c7d659a2feaa0c55ad015"},
		{name: "zero width inside the key", in: "pass\u200bword=Cx7canaryZw", canary: "Cx7canaryZw"},
		{name: "direction mark before the key", in: "\u202etoken=Cx7canaryBidi", canary: "Cx7canaryBidi"},
		{name: "value on the next line", in: "password=\nCx7canaryNl", canary: "Cx7canaryNl"},
		{name: "soft hyphen inside the option", in: "app --pass\u00adword Cx7canaryShy", canary: "Cx7canaryShy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkNoLeak(t, "Mask", Mask(tt.in), tt.canary)
			checkNoLeak(t, "HTML(Line(Mask))", HTML(Line(Mask(tt.in), 500)), tt.canary)
			checkNoLeak(t, "Line(Mask) cut", Line(Mask(tt.in), 25), tt.canary)
			checkNoLeak(t, "Command sh -c", Command([]string{"sh", "-c", tt.in}, 500), tt.canary)
			checkNoLeak(t, "Command one argument", Command([]string{"echo", tt.in}, 500), tt.canary)
		})
	}
}
