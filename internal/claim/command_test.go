package claim

import (
	"strconv"
	"strings"
	"testing"
)

func TestCommand(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		// Ordinary commands stay as they are.
		{name: "git push", argv: []string{"git", "push", "origin", "main"}, want: "git push origin main"},
		{name: "ansible", argv: []string{"ansible-playbook", "-i", "hosts", "site.yml"}, want: "ansible-playbook -i hosts site.yml"},
		{name: "make", argv: []string{"make", "test"}, want: "make test"},
		{name: "program only", argv: []string{"make"}, want: "make"},
		{name: "gh release", argv: []string{"gh", "release", "create", "v1.2.0"}, want: "gh release create v1.2.0"},

		// -p (see also TestCommandDashP)
		{name: "bare -p", argv: []string{"mysql", "-p", "hunter2", "appdb"}, want: "mysql -p *** appdb"},
		{name: "attached -p", argv: []string{"mysql", "-uroot", "-phunter2", "appdb"}, want: "mysql -uroot -p*** appdb"},
		{name: "attached -p with spaces", argv: []string{"mysql", "-pcorrect horse", "appdb"}, want: "mysql -p*** appdb"},

		// Long options, next argument and attached
		{name: "--password", argv: []string{"app", "--password", "hunter2", "run"}, want: "app --password *** run"},
		{name: "--password=", argv: []string{"app", "--password=hunter2", "run"}, want: "app --password=*** run"},
		{name: "--passwd", argv: []string{"app", "--passwd", "hunter2"}, want: "app --passwd ***"},
		{name: "--token", argv: []string{"app", "--token", "abc", "--token=def"}, want: "app --token *** --token=***"},
		{name: "--secret", argv: []string{"app", "--secret", "abc"}, want: "app --secret ***"},
		{name: "--api-key", argv: []string{"app", "--api-key", "abc", "--apikey=def"}, want: "app --api-key *** --apikey=***"},
		{name: "--auth", argv: []string{"app", "--auth", "abc"}, want: "app --auth ***"},
		{name: "--key", argv: []string{"app", "--key", "abc", "--key=def"}, want: "app --key *** --key=***"},
		{
			name: "similar names",
			argv: []string{"app", "--github-token", "a", "--client-secret=b", "--DB-PASSWORD", "c", "--private-key", "d"},
			want: "app --github-token *** --client-secret=*** --DB-PASSWORD *** --private-key ***",
		},
		{name: "value with spaces", argv: []string{"app", "--password", "correct horse battery"}, want: "app --password ***"},
		{name: "attached value with spaces", argv: []string{"app", "--secret=correct horse"}, want: "app --secret=***"},
		{name: "empty attached value", argv: []string{"app", "--password=", "run"}, want: "app --password= run"},
		{name: "one dash", argv: []string{"app", "-token", "abc", "-secret=def"}, want: "app -token *** -secret=***"},
		{name: "openssl", argv: []string{"openssl", "rsa", "-in", "key.pem", "-passin", "pass:hunter2"}, want: "openssl rsa -in key.pem -p*** ***"},
		{name: "chained options", argv: []string{"app", "--password", "--token", "abc", "run"}, want: "app --password *** *** run"},
		{name: "option at the end", argv: []string{"app", "--password"}, want: "app --password"},

		// Options that take no value
		{name: "ask-become-pass", argv: []string{"ansible-playbook", "--ask-become-pass", "site.yml"}, want: "ansible-playbook --ask-become-pass site.yml"},
		{
			name: "password-stdin",
			argv: []string{"docker", "login", "--username", "deploy", "--password-stdin", "registry.example.com"},
			want: "docker login --username deploy --password-stdin registry.example.com",
		},

		// USER:PASSWORD
		{name: "curl -u", argv: []string{"curl", "-u", "deploy:hunter2", "https://example.com"}, want: "curl -u deploy:*** https://example.com"},
		{name: "curl --user=", argv: []string{"curl", "--user=deploy:hunter2"}, want: "curl --user=deploy:***"},
		{name: "curl attached -u", argv: []string{"curl", "-udeploy:hunter2"}, want: "curl -udeploy:***"},
		{name: "curl -U", argv: []string{"curl", "-U", "proxy:hunter2"}, want: "curl -U proxy:***"},
		{name: "user name like an option", argv: []string{"curl", "-uauth:hunter2"}, want: "curl -uauth:***"},
		{name: "user without a password", argv: []string{"sudo", "-u", "deploy", "make"}, want: "sudo -u deploy make"},
		{name: "mysql user", argv: []string{"mysql", "-uroot", "appdb"}, want: "mysql -uroot appdb"},
		{name: "git -u", argv: []string{"git", "push", "-u", "origin", "main"}, want: "git push -u origin main"},

		// Mask in each argument
		{name: "environment", argv: []string{"env", "DB_PASSWORD=hunter2", "./migrate"}, want: "env DB_PASSWORD=*** ./migrate"},
		{name: "shell script", argv: []string{"sh", "-c", "mysql -uroot -phunter2 app"}, want: "sh -c 'mysql -uroot -p*** app'"},
		{
			name: "header",
			argv: []string{"curl", "-H", "Authorization: Bearer abc", "https://example.com"},
			want: "curl -H 'Authorization: ***' https://example.com",
		},
		{
			name: "cookie header",
			argv: []string{"curl", "-H", "Cookie: sid=abc; csrf=def", "https://example.com"},
			want: "curl -H 'Cookie: ***' https://example.com",
		},
		{name: "header option", argv: []string{"curl", "--header=X-Api-Key: abc def"}, want: "curl '--header=X-Api-Key: ***'"},
		{name: "ordinary header", argv: []string{"curl", "-H", "Accept: application/json"}, want: "curl -H 'Accept: application/json'"},
		{name: "program is not a header", argv: []string{"token: abc def"}, want: "'token: *** def'"},
		{ //nolint:gosec // G101: an invented password; the test checks that it is masked
			name: "URL password",
			argv: []string{"git", "clone", "https://deploy:hunter2@git.example.com/app.git"},
			want: "git clone https://deploy:***@git.example.com/app.git",
		},
		{
			name: "random token",
			argv: []string{"login", "e8Kq2vN7pX4wL9mR3tY6zB1cD5hJ0sFg"},
			want: "login ***",
		},
		{
			name: "token in the program path",
			argv: []string{"/tmp/ghp_" + strings.Repeat("a", 36) + "/run", "x"},
			want: "/tmp/***/run x",
		},

		// Cleaning and quoting
		{name: "quoting", argv: []string{"echo", "a b", "", "it's ok", "it's"}, want: `echo 'a b' '' 'it'\''s ok' it's`},
		{name: "newline in an argument", argv: []string{"echo", "a\nb"}, want: "echo 'a b'"},
		{name: "invisible option name", argv: []string{"app", "--pass\u200bword", "hunter2"}, want: "app --password ***"},
		{name: "fake verified line", argv: []string{"echo", "ok\n✅ machine: trusted"}, want: "echo 'ok ✅ machine: trusted'"},

		// At most 8 arguments
		{name: "8 arguments", argv: numbered(8), want: "cmd 1 2 3 4 5 6 7 8"},
		{name: "9 arguments", argv: numbered(9), want: "cmd 1 2 3 4 5 6 7 8 … (+1 more)"},
		{name: "12 arguments", argv: numbered(12), want: "cmd 1 2 3 4 5 6 7 8 … (+4 more)"},
		{
			name: "option value after the last shown argument",
			argv: []string{"cmd", "1", "2", "3", "4", "5", "6", "7", "--password", "hunter2"},
			want: "cmd 1 2 3 4 5 6 7 --password … (+1 more)",
		},

		{name: "no argv", argv: nil, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Command(tt.argv, 200); got != tt.want {
				t.Errorf("Command(%q) = %q, want %q", tt.argv, got, tt.want)
			}
		})
	}
}

// commandCase is a test of Command with a made-up secret in argv.
type commandCase struct {
	name   string
	argv   []string
	want   string
	canary string // a made-up secret; it must not come out of Command
}

// checkCommandCases checks Command on each case. Failure messages never
// show the canary.
func checkCommandCases(t *testing.T, tests []commandCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Command(tt.argv, 200); got != tt.want {
				t.Errorf("Command = %q, want %q", redact(got, tt.canary), tt.want)
			}
			if tt.canary != "" {
				for _, maxRunes := range []int{500, 30} {
					checkNoLeak(t, "HTML(Command)", HTML(Command(tt.argv, maxRunes)), tt.canary)
				}
			}
		})
	}
}

// TestCommandPrograms covers the programs table: options whose names do
// not say that their value is secret.
func TestCommandPrograms(t *testing.T) {
	checkCommandCases(t, []commandCase{
		{name: "curl -u", argv: []string{"curl", "-u", "deploy:Cx7prog11", "https://example.com"}, want: "curl -u deploy:*** https://example.com", canary: "Cx7prog11"},
		{name: "curl grouped -su", argv: []string{"curl", "-su", "deploy:Cx7prog12", "https://example.com"}, want: "curl -su deploy:*** https://example.com", canary: "Cx7prog12"},
		{name: "curl -E", argv: []string{"curl", "-E", "client.pem:Cx7prog13", "https://example.com"}, want: "curl -E client.pem:*** https://example.com", canary: "Cx7prog13"},
		{name: "curl --cert=", argv: []string{"curl", "--cert=client.pem:Cx7prog14"}, want: "curl --cert=client.pem:***", canary: "Cx7prog14"},
		{name: "curl -E without a password", argv: []string{"curl", "-E", "client.pem", "https://example.com"}, want: "curl -E client.pem https://example.com"},
		{name: "curl -b", argv: []string{"curl", "-b", "sid=Cx7prog15; theme=dark", "https://example.com"}, want: "curl -b *** https://example.com", canary: "Cx7prog15"},
		{name: "curl -b attached", argv: []string{"curl", "-bsid=Cx7prog16"}, want: "curl -b***", canary: "Cx7prog16"},
		{name: "gh secret set --body", argv: []string{"gh", "secret", "set", "API_KEY", "--body", "Cx7prog17"}, want: "gh secret set API_KEY --body ***", canary: "Cx7prog17"},
		{
			name:   "gh secret set -b",
			argv:   []string{"gh", "secret", "set", "API_KEY", "--repo", "team/app", "-b", "Cx7prog18"},
			want:   "gh secret set API_KEY --repo team/app -b ***",
			canary: "Cx7prog18",
		},
		{name: "gh secret set --body=", argv: []string{"gh", "secret", "set", "API_KEY", "--body=Cx7prog19"}, want: "gh secret set API_KEY --body=***", canary: "Cx7prog19"},
		{name: "gh pr create --body stays", argv: []string{"gh", "pr", "create", "--body", "Fix the login page"}, want: "gh pr create --body 'Fix the login page'"},
		{
			name:   "kubectl --from-literal=",
			argv:   []string{"kubectl", "create", "secret", "generic", "app", "--from-literal=api=Cx7prog20"},
			want:   "kubectl create secret generic app --from-literal=api=***",
			canary: "Cx7prog20",
		},
		{
			name:   "kubectl --from-literal",
			argv:   []string{"kubectl", "create", "secret", "generic", "app", "--from-literal", "api=Cx7prog21"},
			want:   "kubectl create secret generic app --from-literal api=***",
			canary: "Cx7prog21",
		},
		{
			name:   "vault kv put",
			argv:   []string{"vault", "kv", "put", "secret/app", "api=Cx7prog22", "user=deploy"},
			want:   "vault kv put secret/app api=*** user=***",
			canary: "Cx7prog22",
		},
		{
			name:   "vault kv patch",
			argv:   []string{"vault", "kv", "patch", "-mount=secret", "app", "api=Cx7prog23"},
			want:   "vault kv patch -mount=secret app api=***",
			canary: "Cx7prog23",
		},
		{
			name:   "vault write",
			argv:   []string{"vault", "write", "auth/approle/login", "role_id=Cx7prog24"},
			want:   "vault write auth/approle/login role_id=***",
			canary: "Cx7prog24",
		},
		{name: "vault kv get stays", argv: []string{"vault", "kv", "get", "-field=api", "secret/app"}, want: "vault kv get -field=api secret/app"},
		{
			name:   "openssl -k",
			argv:   []string{"openssl", "enc", "-aes-256-cbc", "-k", "Cx7prog25", "-in", "data.txt"},
			want:   "openssl enc -aes-256-cbc -k *** -in data.txt",
			canary: "Cx7prog25",
		},
		{
			name:   "openssl -K",
			argv:   []string{"openssl", "enc", "-aes-256-cbc", "-K", "Cx7prog26", "-iv", "00"},
			want:   "openssl enc -aes-256-cbc -K *** -iv 00",
			canary: "Cx7prog26",
		},
		{name: "openssl -kfile stays", argv: []string{"openssl", "enc", "-kfile", "key.txt"}, want: "openssl enc -kfile key.txt"},
		{name: "openssl passwd", argv: []string{"openssl", "passwd", "-6", "Cx7prog27"}, want: "openssl passwd -6 ***", canary: "Cx7prog27"},
		{
			name:   "ssh-keygen -N",
			argv:   []string{"ssh-keygen", "-t", "ed25519", "-N", "Cx7prog28", "-f", "key"},
			want:   "ssh-keygen -t ed25519 -N *** -f key",
			canary: "Cx7prog28",
		},
		{
			name:   "ssh-keygen -P and -N",
			argv:   []string{"ssh-keygen", "-p", "-P", "Cx7prog29", "-N", "Cx7prog29", "-f", "key"},
			want:   "ssh-keygen -p -P *** -N *** -f key",
			canary: "Cx7prog29",
		},
		{name: "ssh-keygen attached", argv: []string{"ssh-keygen", "-NCx7prog30", "-f", "key"}, want: "ssh-keygen -N*** -f key", canary: "Cx7prog30"},
		{
			name:   "redis-cli -a",
			argv:   []string{"redis-cli", "-h", "db-1", "-a", "Cx7prog31", "ping"},
			want:   "redis-cli -h db-1 -a *** ping",
			canary: "Cx7prog31",
		},
		{
			name:   "ldapsearch -w",
			argv:   []string{"ldapsearch", "-x", "-D", "cn=admin,dc=example,dc=com", "-w", "Cx7prog32"},
			want:   "ldapsearch -x -D cn=admin,dc=example,dc=com -w ***",
			canary: "Cx7prog32",
		},
		{name: "ldapmodify -w attached", argv: []string{"ldapmodify", "-wCx7prog33", "-f", "change.ldif"}, want: "ldapmodify -w*** -f change.ldif", canary: "Cx7prog33"},
		{
			name:   "ldappasswd -a and -s",
			argv:   []string{"ldappasswd", "-a", "Cx7prog34", "-s", "Cx7prog34", "uid=dev"},
			want:   "ldappasswd -a *** -s *** uid=dev",
			canary: "Cx7prog34",
		},
		{name: "sqlcmd -P", argv: []string{"sqlcmd", "-S", "db-1", "-U", "sa", "-P", "Cx7prog35"}, want: "sqlcmd -S db-1 -U sa -P ***", canary: "Cx7prog35"},
		{name: "sqlcmd -P attached", argv: []string{"sqlcmd", "-S", "db-1", "-PCx7prog36"}, want: "sqlcmd -S db-1 -P***", canary: "Cx7prog36"},
		{
			name:   "bcp -P",
			argv:   []string{"bcp", "app.dbo.users", "out", "users.dat", "-P", "Cx7prog37"},
			want:   "bcp app.dbo.users out users.dat -P ***",
			canary: "Cx7prog37",
		},
		{name: "mysqladmin password", argv: []string{"mysqladmin", "-u", "root", "password", "Cx7prog38"}, want: "mysqladmin -u root password ***", canary: "Cx7prog38"},
		{name: "mysqladmin old-password", argv: []string{"mysqladmin", "old-password", "Cx7prog39"}, want: "mysqladmin old-password ***", canary: "Cx7prog39"},
		{name: "plink -pw", argv: []string{"plink", "-ssh", "deploy@web-1", "-pw", "Cx7prog40"}, want: "plink -ssh deploy@web-1 -pw ***", canary: "Cx7prog40"},
		{
			name:   "pscp -pw",
			argv:   []string{"pscp", "-pw", "Cx7prog41", "file.txt", "deploy@web-1:/tmp/"},
			want:   "pscp -pw *** file.txt deploy@web-1:/tmp/",
			canary: "Cx7prog41",
		},
		{name: "program with a path", argv: []string{"/usr/bin/redis-cli", "-a", "Cx7prog42"}, want: "/usr/bin/redis-cli -a ***", canary: "Cx7prog42"},
		{name: "program after sudo", argv: []string{"sudo", "-u", "redis", "redis-cli", "-a", "Cx7prog43"}, want: "sudo -u redis redis-cli -a ***", canary: "Cx7prog43"},
		{name: "program on another host", argv: []string{"ssh", "web-1", "redis-cli", "-a", "Cx7prog44"}, want: "ssh web-1 redis-cli -a ***", canary: "Cx7prog44"},
		{
			name:   "program in a script",
			argv:   []string{"sh", "-c", "redis-cli -a Cx7prog45 ping && tar -a -cf backup.tgz data"},
			want:   "sh -c 'redis-cli -a *** ping && tar -a -cf backup.tgz data'",
			canary: "Cx7prog45",
		},
		{name: "other program keeps -a", argv: []string{"tar", "-a", "-cf", "backup.tgz", "data"}, want: "tar -a -cf backup.tgz data"},
		{name: "program as a hidden value", argv: []string{"app", "--password", "redis-cli", "-a", "Cx7prog46"}, want: "app --password *** -a ***", canary: "Cx7prog46"},

		// Found in the second security review on 2026-10-14.
		{
			name:   "host named like a program",
			argv:   []string{"redis-cli", "-h", "vault", "-a", "Cx7prog47", "ping"},
			want:   "redis-cli -h vault -a *** ping",
			canary: "Cx7prog47",
		},
		{
			name:   "repository named like a program",
			argv:   []string{"gh", "secret", "set", "API_KEY", "--repo", "team/vault", "-b", "Cx7prog48"},
			want:   "gh secret set API_KEY --repo team/vault -b ***",
			canary: "Cx7prog48",
		},
		{
			name:   "URL that ends like a program",
			argv:   []string{"curl", "https://example.com/api/vault", "-E", "client.pem:Cx7prog49"},
			want:   "curl https://example.com/api/vault -E client.pem:***",
			canary: "Cx7prog49",
		},
		{
			name:   "& in a URL does not end the program",
			argv:   []string{"curl", "https://example.com/?a=1&b=2", "-E", "client.pem:Cx7prog50"},
			want:   "curl https://example.com/?a=1&b=2 -E client.pem:***",
			canary: "Cx7prog50",
		},
		{name: "putty -pw", argv: []string{"putty", "-ssh", "deploy@web-1", "-pw", "Cx7prog51"}, want: "putty -ssh deploy@web-1 -pw ***", canary: "Cx7prog51"},
		{name: "-pw of another program", argv: []string{"kitty", "-pw", "Cx7prog52", "web-1"}, want: "kitty -p*** *** web-1", canary: "Cx7prog52"},
		{
			name:   "ldapsearch grouped",
			argv:   []string{"ldapsearch", "-xw", "Cx7prog53", "-b", "dc=example,dc=com"},
			want:   "ldapsearch -xw *** -b dc=example,dc=com",
			canary: "Cx7prog53",
		},
		{name: "ldappasswd grouped", argv: []string{"ldappasswd", "-xs", "Cx7prog54", "uid=dev"}, want: "ldappasswd -xs *** uid=dev", canary: "Cx7prog54"},
		{
			name:   "ssh-keygen grouped",
			argv:   []string{"ssh-keygen", "-pP", "Cx7prog55", "-N", "Cx7prog55", "-f", "key"},
			want:   "ssh-keygen -pP *** -N *** -f key",
			canary: "Cx7prog55",
		},
		{
			name:   "ssh-keygen grouped with an attached value",
			argv:   []string{"ssh-keygen", "-pPCx7prog56", "-f", "key"},
			want:   "ssh-keygen -pP*** -f key",
			canary: "Cx7prog56",
		},
		{
			name:   "curl grouped with an attached value",
			argv:   []string{"curl", "-sudeploy:Cx7prog57", "https://example.com"},
			want:   "curl -sudeploy:*** https://example.com",
			canary: "Cx7prog57",
		},
		{name: "ldapsearch groups without a secret stay", argv: []string{"ldapsearch", "-LLL", "-x", "-b", "dc=example,dc=com"}, want: "ldapsearch -LLL -x -b dc=example,dc=com"},
		{name: "curl groups without a secret stay", argv: []string{"curl", "-XPUT", "-sS", "https://example.com"}, want: "curl -XPUT -sS https://example.com"},
		{name: "ssh-keygen groups without a secret stay", argv: []string{"ssh-keygen", "-lf", "key.pub"}, want: "ssh-keygen -lf key.pub"},
	})
}

// TestCommandSeparatorAsText covers a ";" in an argument. The shell has
// already split the words, so it is text: it must not end the rules of
// the program that runs. Found in the third security review on
// 2026-10-14.
func TestCommandSeparatorAsText(t *testing.T) {
	checkCommandCases(t, []commandCase{
		{
			name:   "cookie header",
			argv:   []string{"curl", "-H", "Cookie: theme=dark;", "-E", "client.pem:Cx7septext8", "https://example.com"},
			want:   "curl -H 'Cookie: ***' -E client.pem:*** https://example.com",
			canary: "Cx7septext8",
		},
		{
			name:   "SQL",
			argv:   []string{"sqlcmd", "-S", "db-1", "-Q", "SELECT 1;", "-P", "Cx7septext9"},
			want:   "sqlcmd -S db-1 -Q 'SELECT 1;' -P ***",
			canary: "Cx7septext9",
		},
		{
			name:   "repository name",
			argv:   []string{"gh", "secret", "set", "API_KEY", "--repo", "a;", "-b", "Cx7septext10"},
			want:   "gh secret set API_KEY --repo a; -b ***",
			canary: "Cx7septext10",
		},
		{
			name:   "separator as an argument of its own",
			argv:   []string{"redis-cli", "--eval", "x.lua", ";", "-a", "Cx7septext11"},
			want:   "redis-cli --eval x.lua ; -a ***",
			canary: "Cx7septext11",
		},
	})
}

// TestCommandDashP covers the decision for a bare -p: the next argument
// is its value and is hidden, unless it starts with "-".
func TestCommandDashP(t *testing.T) {
	checkCommandCases(t, []commandCase{
		{name: "mysql", argv: []string{"mysql", "-u", "root", "-p", "Cx7dashp11", "appdb"}, want: "mysql -u root -p *** appdb", canary: "Cx7dashp11"},
		{name: "port is hidden too", argv: []string{"ssh", "-p", "2222", "deploy@web-1"}, want: "ssh -p *** deploy@web-1"},
		{name: "option after -p", argv: []string{"mkdir", "-p", "-v", "/srv/app"}, want: "mkdir -p -v /srv/app"},
		{name: "-p at the end", argv: []string{"mysql", "-p"}, want: "mysql -p"},
		{name: "value with spaces", argv: []string{"mysql", "-p", "Cx7 dashp12"}, want: "mysql -p ***", canary: "Cx7 dashp12"},
		{name: "after a secret option", argv: []string{"app", "--password", "-p", "Cx7dashp13"}, want: "app --password *** ***", canary: "Cx7dashp13"},
		{
			name:   "value after the last shown argument",
			argv:   []string{"cmd", "1", "2", "3", "4", "5", "6", "7", "-p", "Cx7dashp14"},
			want:   "cmd 1 2 3 4 5 6 7 -p … (+1 more)",
			canary: "Cx7dashp14",
		},
	})
}

// TestCommandHeaders covers header arguments without a space after ":".
func TestCommandHeaders(t *testing.T) {
	checkCommandCases(t, []commandCase{
		{name: "after -H", argv: []string{"curl", "-H", "X-Api-Key:Cx7head11", "https://example.com"}, want: "curl -H X-Api-Key:*** https://example.com", canary: "Cx7head11"},
		{
			name:   "whole cookie",
			argv:   []string{"curl", "-H", "Cookie:theme=dark;sid=Cx7head12", "https://example.com"},
			want:   "curl -H Cookie:*** https://example.com",
			canary: "Cx7head12",
		},
		{
			name:   "after --header",
			argv:   []string{"curl", "--header", "Authorization:Bearer Cx7head13", "https://example.com"},
			want:   "curl --header Authorization:*** https://example.com",
			canary: "Cx7head13",
		},
		{name: "attached -H", argv: []string{"curl", "-HCookie: a=1; sid=Cx7head14"}, want: "curl '-HCookie: ***'", canary: "Cx7head14"},
		{name: "--header=", argv: []string{"curl", "--header=X-Auth-Token:Cx7head15"}, want: "curl --header=X-Auth-Token:***", canary: "Cx7head15"},
		{name: "without -H", argv: []string{"echo", "X-Api-Key:Cx7head16"}, want: "echo X-Api-Key:***", canary: "Cx7head16"},
		{name: "ordinary header", argv: []string{"curl", "-H", "Accept:application/json"}, want: "curl -H Accept:application/json"},
		{name: "host and path stay", argv: []string{"rsync", "-a", "./dist/", "auth:/srv/app/"}, want: "rsync -a ./dist/ auth:/srv/app/"},
		{name: "image tag stays", argv: []string{"docker", "run", "oauth2-proxy:v7.5.1"}, want: "docker run oauth2-proxy:v7.5.1"},
	})
}

// TestCommandAssignment covers an argument KEY=VALUE whose key has a
// secret name: the whole value is hidden, also with spaces.
func TestCommandAssignment(t *testing.T) {
	checkCommandCases(t, []commandCase{
		{name: "env", argv: []string{"env", "DB_PASSWORD=Cx7 assign1", "./migrate"}, want: "env DB_PASSWORD=*** ./migrate", canary: "Cx7 assign1"},
		{name: "docker -e", argv: []string{"docker", "run", "-e", "API_TOKEN=Cx7 assign2 x", "app"}, want: "docker run -e API_TOKEN=*** app", canary: "Cx7 assign2"},
		{name: "form field", argv: []string{"curl", "-d", "user[password]=Cx7 assign3"}, want: "curl -d user[password]=***", canary: "Cx7 assign3"},
		{name: "Ruby symbol", argv: []string{"rails", "runner", "params[:password]=Cx7 assign4"}, want: "rails runner params[:password]=***", canary: "Cx7 assign4"},
		{name: "ordinary assignment", argv: []string{"env", "MODE=two words", "./run"}, want: "env 'MODE=two words' ./run"},
	})
}

// numbered returns "cmd" and n arguments "1" to "n".
func numbered(n int) []string {
	argv := []string{"cmd"}
	for i := 1; i <= n; i++ {
		argv = append(argv, strconv.Itoa(i))
	}
	return argv
}

func TestCommandLength(t *testing.T) {
	argv := []string{"rsync", "-avz", "./build/", "deploy@web-1:/srv/app/releases/2026-10-12/"}
	tests := []struct {
		max  int
		want string
	}{
		{max: 200, want: "rsync -avz ./build/ deploy@web-1:/srv/app/releases/2026-10-12/"},
		{max: 20, want: "rsync -avz ./build/…"},
		{max: 11, want: "rsync -avz…"},
		{max: 1, want: "…"},
		{max: 0, want: ""},
		{max: -1, want: ""},
	}
	for _, tt := range tests {
		if got := Command(argv, tt.max); got != tt.want {
			t.Errorf("Command(%q, %d) = %q, want %q", argv, tt.max, got, tt.want)
		}
	}
}

// TestCommandCanaries checks that planted values never come out of
// Command.
func TestCommandCanaries(t *testing.T) {
	tests := []struct {
		name   string
		argv   []string
		canary string
	}{
		{name: "--password VALUE", argv: []string{"app", "--password", "Cx7canaryA1"}, canary: "Cx7canaryA1"},
		{name: "--password=VALUE", argv: []string{"app", "--password=Cx7canaryB1"}, canary: "Cx7canaryB1"},
		{name: "-pVALUE", argv: []string{"mysql", "-pCx7canaryC1", "appdb"}, canary: "Cx7canaryC1"},
		{name: "value with spaces", argv: []string{"app", "--password", "Cx7 canary D1"}, canary: "Cx7 canary D1"},
		{name: "attached value with spaces", argv: []string{"app", "--secret=Cx7 canary E1"}, canary: "Cx7 canary E1"},
		{name: "chained options", argv: []string{"app", "--password", "--token", "Cx7canaryF1"}, canary: "Cx7canaryF1"},
		{name: "curl -u", argv: []string{"curl", "-u", "deploy:Cx7canaryG1", "https://example.com"}, canary: "Cx7canaryG1"},
		{name: "environment", argv: []string{"env", "API_TOKEN=Cx7canaryH1", "./run"}, canary: "Cx7canaryH1"},
		{name: "shell script", argv: []string{"sh", "-c", "mysql -pCx7canaryI1 app"}, canary: "Cx7canaryI1"},
		{
			name:   "header",
			argv:   []string{"curl", "-H", "Authorization: Bearer Cx7canaryJ1", "https://example.com"},
			canary: "Cx7canaryJ1",
		},
		{name: "URL", argv: []string{"git", "push", "https://x:Cx7canaryK1@git.example.com/a.git"}, canary: "Cx7canaryK1"},
		{name: "cookie header", argv: []string{"curl", "-H", "Cookie: sid=Cx7canaryS1; csrf=Cx7canaryS2"}, canary: "Cx7canaryS2"},
		{name: "header with spaces", argv: []string{"curl", "-H", "X-Api-Key: Cx7 canary T1"}, canary: "Cx7 canary T1"},
		{name: "invisible option name", argv: []string{"app", "--pass\u200bword", "Cx7canaryL1"}, canary: "Cx7canaryL1"},
		{name: "random value", argv: []string{"login", "e8Kq2vN7pX4wL9mR3tY6zB1cD5hJ0sFg"}, canary: "e8Kq2vN7pX4wL9mR3tY6zB1cD5hJ0sFg"},
		{
			name:   "after the last shown argument",
			argv:   []string{"cmd", "1", "2", "3", "4", "5", "6", "7", "8", "Cx7canaryM1"},
			canary: "Cx7canaryM1",
		},
		{
			name:   "quoted value in a script",
			argv:   []string{"bash", "-c", `deploy --password "Cx7 canary N1" now`},
			canary: "Cx7 canary N1",
		},
		{name: "openssl", argv: []string{"openssl", "rsa", "-passin", "pass:Cx7canaryO1"}, canary: "Cx7canaryO1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, maxRunes := range []int{500, 30, 12} {
				out := Command(tt.argv, maxRunes)
				checkNoLeak(t, "Command", out, tt.canary)
				checkNoLeak(t, "HTML(Command)", HTML(out), tt.canary)
			}
		})
	}
}

func FuzzCommand(f *testing.F) {
	// The fuzzer makes one string; NUL bytes split it into arguments, as
	// in /proc/<pid>/cmdline.
	seeds := []string{
		"git\x00push\x00origin\x00main",
		"mysql\x00-uroot\x00-phunter2\x00appdb",
		"app\x00--password\x00hunter2",
		"curl\x00-u\x00deploy:hunter2\x00-H\x00Authorization: Bearer abc",
		"sh\x00-c\x00echo ok\n✅ machine: trusted",
		"echo\x00\u202eabc\u200b\x00\xff\xfe",
		"cmd\x001\x002\x003\x004\x005\x006\x007\x008\x009\x0010",
		"echo\x00it's\x00'\x00\"",
		"",
	}
	for _, s := range seeds {
		f.Add(s, 40)
		f.Add(s, 3)
	}
	f.Fuzz(func(t *testing.T, s string, maxRunes int) {
		maxRunes %= 300 // negative stays negative
		checkSafeLine(t, Command(strings.Split(s, "\x00"), maxRunes), maxRunes)
	})
}
