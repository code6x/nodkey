package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const telegramSectionText = "[telegram]\ntoken_file = \"${CREDENTIALS_DIRECTORY}/telegram-token\"\nuser_id = 123456789\n"

func ntfySectionText(extra string) string {
	return "[ntfy]\nserver = \"https://ntfy.example.com\"\nrequest_topic = \"nodkey-req\"\n" +
		"answer_topic = \"nodkey-ans\"\ntoken_file = \"${CREDENTIALS_DIRECTORY}/telegram-token\"\n" + extra
}

func TestLoadBrokerNtfy(t *testing.T) {
	e := newBrokerEnv(t)
	b, err := LoadBroker(e.write(t, edit{telegramSectionText, ntfySectionText("timeout = \"3m\"\n")}))
	if err != nil {
		t.Fatal(err)
	}
	n := b.Ntfy
	if n == nil {
		t.Fatal("Ntfy is nil")
	}
	if n.Server != "https://ntfy.example.com" || n.RequestTopic != "nodkey-req" || n.AnswerTopic != "nodkey-ans" {
		t.Errorf("Ntfy = %+v", n)
	}
	if n.TokenFile != filepath.Join(e.creds, "telegram-token") {
		t.Errorf("TokenFile = %q", n.TokenFile)
	}
	if got, ssh := b.Timeouts(); got != 3*time.Minute || ssh != 90*time.Second {
		t.Errorf("Timeouts = %v, %v", got, ssh)
	}
	if b.Telegram != (Telegram{}) {
		t.Errorf("Telegram = %+v, want the zero value", b.Telegram)
	}
	if b.ApproverTokenFile() != n.TokenFile {
		t.Error("ApproverTokenFile is not the ntfy token file")
	}
	if err := b.CheckFiles(); err != nil {
		t.Errorf("CheckFiles: %v", err)
	}
	// A path in the server URL is fine.
	if _, err := LoadBroker(e.write(t, edit{telegramSectionText,
		strings.Replace(ntfySectionText(""), "ntfy.example.com", "example.com/ntfy", 1)})); err != nil {
		t.Errorf("server with a path: %v", err)
	}
}

func TestLoadBrokerTelegramTimeouts(t *testing.T) {
	b, err := LoadBroker(newBrokerEnv(t).write(t))
	if err != nil {
		t.Fatal(err)
	}
	if b.Ntfy != nil {
		t.Error("Ntfy is set for a telegram config")
	}
	if got, ssh := b.Timeouts(); got != 120*time.Second || ssh != 90*time.Second {
		t.Errorf("Timeouts = %v, %v", got, ssh)
	}
}

func TestLoadBrokerNtfyErrors(t *testing.T) {
	tests := []struct {
		name  string
		edits func() []edit
		want  string
	}{
		{"both sections", func() []edit {
			return []edit{{telegramSectionText, telegramSectionText + "\n" + ntfySectionText("")}}
		}, "one approval channel"},
		{"none", func() []edit { return []edit{{telegramSectionText, ""}} }, "[telegram] token_file: is missing"},
		{"http server", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "https://", "http://", 1)}}
		}, "[ntfy] server: must start with https://"},
		{"user info", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "https://", "https://u:p@", 1)}}
		}, "no user name, query or fragment"},
		{"query", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "com\"", "com?x=1\"", 1)}}
		}, "no user name, query or fragment"},
		{"empty query", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "com\"", "com?\"", 1)}}
		}, "no user name, query or fragment"},
		{"fragment", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "com\"", "com#x\"", 1)}}
		}, "no user name, query or fragment"},
		{"no server", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "server = \"https://ntfy.example.com\"\n", "", 1)}}
		}, "[ntfy] server: is missing"},
		{"bad topic", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "nodkey-req", "bad/topic", 1)}}
		}, "[ntfy] request_topic: must be 1 to 64"},
		{"long topic", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "nodkey-ans", strings.Repeat("a", 65), 1)}}
		}, "[ntfy] answer_topic: must be 1 to 64"},
		{"no topic", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "request_topic = \"nodkey-req\"\n", "", 1)}}
		}, "[ntfy] request_topic: is missing"},
		{"same topics", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "nodkey-ans", "nodkey-req", 1)}}
		}, "[ntfy] answer_topic: must not be the same"},
		{"no token file", func() []edit {
			return []edit{{telegramSectionText, strings.Replace(ntfySectionText(""), "token_file = \"${CREDENTIALS_DIRECTORY}/telegram-token\"\n", "", 1)}}
		}, "[ntfy] token_file: is missing"},
		{"timeout too short", func() []edit {
			return []edit{{telegramSectionText, ntfySectionText("timeout = \"1s\"\n")}}
		}, "[ntfy] timeout: must be from"},
		{"ssh timeout too long", func() []edit {
			return []edit{{telegramSectionText, ntfySectionText("ssh_timeout = \"5m\"\n")}}
		}, "[ntfy] ssh_timeout: must be from"},
		{"unknown key", func() []edit {
			return []edit{{telegramSectionText, ntfySectionText("user_id = 1\n")}}
		}, "user_id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBrokerEnv(t)
			_, err := LoadBroker(e.write(t, tt.edits()...))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want it to hold %q", err, tt.want)
			}
		})
	}
}

func TestCheckFilesNtfyToken(t *testing.T) {
	e := newBrokerEnv(t)
	b, err := LoadBroker(e.write(t, edit{telegramSectionText, ntfySectionText("")}))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.creds, "telegram-token")
	chmod(t, p, 0o640)
	err = b.CheckFiles()
	if err == nil || !strings.Contains(err.Error(), "[ntfy] token_file: "+p) {
		t.Errorf("open token file: error %v", err)
	}
	chmod(t, p, 0o600)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := b.CheckFiles(); err == nil || !strings.Contains(err.Error(), "[ntfy] token_file: ") {
		t.Errorf("missing token file: error %v", err)
	}
}
