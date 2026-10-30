package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newClientHome makes a home directory with a private TLS key at
// ~/.config/nodkey/client.key, and returns the home and the key's path.
func newClientHome(t *testing.T) (home, key string) {
	t.Helper()
	home = privateTempDir(t)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "nodkey")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return home, writeFile(t, dir, "client.key", "made-up key\n", 0o600)
}

func TestLoadClient(t *testing.T) {
	home, _ := newClientHome(t)
	pin := testPin("broker")
	dir := privateTempDir(t)
	path := writeFile(t, dir, "client.toml", `# A client config for tests.
broker = "192.0.2.10:7743"
broker_pin = "`+pin.String()+`"
tls_key = "~/.config/nodkey/client.key"
`, 0o600)
	c, err := LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	want := ClientConfig{Broker: "192.0.2.10:7743", BrokerPin: pin, TLSKey: home + "/.config/nodkey/client.key"}
	if *c != want {
		t.Errorf("LoadClient = %+v, want %+v", *c, want)
	}
}

func TestLoadClientErrors(t *testing.T) {
	pin := testPin("broker").String()
	valid := map[string]string{
		"broker":     `broker = "192.0.2.10:7743"`,
		"broker_pin": `broker_pin = "` + pin + `"`,
		"tls_key":    `tls_key = "~/.config/nodkey/client.key"`,
	}
	tests := []struct {
		name    string
		change  map[string]string // replaces the line of a key; "" removes it
		extra   string            // added at the end
		unset   string            // an environment variable to unset
		keyMode os.FileMode       // the mode of the TLS key file, when not 0
		noKey   bool              // remove the TLS key file
		setup   func(t *testing.T, key string)
		want    string
		notWant string
	}{
		{name: "broker missing", change: map[string]string{"broker": ""}, want: "broker: is missing"},
		{name: "broker_pin missing", change: map[string]string{"broker_pin": ""}, want: "broker_pin: is missing"},
		{name: "broker_pin not valid", change: map[string]string{"broker_pin": `broker_pin = "sha256:SECRETxyz"`},
			want: `broker_pin: must be "sha256:" and 43 base64 characters`, notWant: "SECRET"},
		{name: "tls_key missing", change: map[string]string{"tls_key": ""}, want: "tls_key: is missing"},
		{name: "tls_key relative", change: map[string]string{"tls_key": `tls_key = "client.key"`},
			want: "tls_key: must be an absolute path"},
		{name: "tls_key with another user's home", change: map[string]string{"tls_key": `tls_key = "~dev/client.key"`},
			want: `tls_key: only "~/" is expanded at the start of a path`},
		{name: "tls_key with $HOME", change: map[string]string{"tls_key": `tls_key = "$HOME/client.key"`},
			want: `tls_key: only "${CREDENTIALS_DIRECTORY}/" at the start of a path is expanded`},
		{name: "tls_key with ~/ and no home", change: map[string]string{"tls_key": `tls_key = "~/client.key"`}, unset: "HOME",
			want: "tls_key: starts with ~/, but the home directory is not known"},
		{name: "unknown key", extra: `brokr = "192.0.2.11:7743"`, want: `unknown key "brokr"`},
		{name: "key in upper case", extra: `Broker = "192.0.2.11:7743"`, want: "1 unknown key;", notWant: "Broker"},
		{name: "table instead of a value", change: map[string]string{"tls_key": ""}, extra: "[tls_key]\npath = \"/x\"",
			want: "incompatible types"},
		{name: "key defined twice", extra: `broker = "192.0.2.11:7743"`, want: "line 4, column", notWant: "broker"},
		{name: "tls_key readable by others", keyMode: 0o644, want: "tls_key: ", notWant: "made-up"},
		{name: "tls_key readable by group", keyMode: 0o640, want: "client.key: its group has access (mode 0640)"},
		{name: "tls_key file missing", noKey: true, want: "tls_key: lstat "},
		{name: "tls_key is a symbolic link", setup: func(t *testing.T, key string) {
			if err := os.Rename(key, key+".real"); err != nil {
				t.Fatal(err)
			}
			symlink(t, key+".real", key)
		}, want: "client.key: is a symbolic link", notWant: "made-up"},
		{name: "tls_key in a directory writable by group", setup: func(t *testing.T, key string) {
			chmod(t, filepath.Dir(key), 0o770)
		}, want: "/.config/nodkey: group or others can write to this directory (mode 0770)", notWant: "made-up"},
		{name: "tls_key below a directory writable by others", setup: func(t *testing.T, key string) {
			chmod(t, filepath.Dir(filepath.Dir(key)), 0o707)
		}, want: "/.config: group or others can write to this directory (mode 0707)"},
		{name: "syntax error", extra: "token = SECRET", want: "line 4, column 9: not valid TOML", notWant: "SECRET"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, keyFile := newClientHome(t)
			if tt.keyMode != 0 {
				if err := os.Chmod(keyFile, tt.keyMode); err != nil {
					t.Fatal(err)
				}
			}
			if tt.noKey {
				if err := os.Remove(keyFile); err != nil {
					t.Fatal(err)
				}
			}
			if tt.setup != nil {
				tt.setup(t, keyFile)
			}
			if tt.unset != "" {
				t.Setenv(tt.unset, "")
				if err := os.Unsetenv(tt.unset); err != nil {
					t.Fatal(err)
				}
			}
			var lines []string
			for _, key := range []string{"broker", "broker_pin", "tls_key"} {
				line := valid[key]
				if l, ok := tt.change[key]; ok {
					line = l
				}
				if line != "" {
					lines = append(lines, line)
				}
			}
			if tt.extra != "" {
				lines = append(lines, tt.extra)
			}
			path := writeFile(t, privateTempDir(t), "client.toml", strings.Join(lines, "\n")+"\n", 0o600)
			c, err := LoadClient(path)
			if c != nil {
				t.Errorf("LoadClient returned a config with the error")
			}
			checkError(t, err, "config "+path+": ", "")
			checkError(t, err, tt.want, tt.notWant)
		})
	}
}

func TestLoadClientMissingFile(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "client.toml")
	_, err := LoadClient(path)
	checkError(t, err, "config: lstat "+path+": no such file or directory; make the client config as in docs/setup.md, section 11 \"A client on the agent machine\"", "")
}

// TestLoadClientChecksTheFile: the client config is read as the broker
// reads its config (ReadConfigFile). broker_pin is the client's only trust
// in the broker, so a file or a directory on the way that others can
// write to is refused. Anyone may read the file, and it may be a symbolic
// link.
func TestLoadClientChecksTheFile(t *testing.T) {
	config := "broker = \"192.0.2.10:7743\"\nbroker_pin = \"" + testPin("broker").String() +
		"\"\ntls_key = \"~/.config/nodkey/client.key\"\n"
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string) string // returns the path to load
		want  string                                // "" when the config loads
	}{
		{"private", func(t *testing.T, dir string) string {
			return writeFile(t, dir, "client.toml", config, 0o600)
		}, ""},
		{"readable by others", func(t *testing.T, dir string) string {
			return writeFile(t, dir, "client.toml", config, 0o644)
		}, ""},
		{"a symbolic link", func(t *testing.T, dir string) string {
			target := writeFile(t, dir, "real.toml", config, 0o600)
			return symlink(t, target, filepath.Join(dir, "client.toml"))
		}, ""},
		{"writable by the group", func(t *testing.T, dir string) string {
			return writeFile(t, dir, "client.toml", config, 0o620)
		}, "client.toml: group or others can write to it (mode 0620)"},
		{"writable by others", func(t *testing.T, dir string) string {
			return writeFile(t, dir, "client.toml", config, 0o602)
		}, "client.toml: group or others can write to it (mode 0602)"},
		{"in a directory that others can write to", func(t *testing.T, dir string) string {
			open := mkdir(t, dir, "open", 0o777)
			return writeFile(t, open, "client.toml", config, 0o600)
		}, "/open: group or others can write to this directory (mode 0777)"},
		{"a link in a directory that others can write to", func(t *testing.T, dir string) string {
			target := writeFile(t, dir, "real.toml", config, 0o600)
			open := mkdir(t, dir, "open", 0o777)
			return symlink(t, target, filepath.Join(open, "client.toml"))
		}, "/open: group or others can write to this directory (mode 0777)"},
		{"a directory", func(t *testing.T, dir string) string {
			return mkdir(t, dir, "client.toml", 0o700)
		}, "client.toml: is not a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newClientHome(t)
			path := tt.setup(t, privateTempDir(t))
			c, err := LoadClient(path)
			if tt.want == "" {
				if err != nil || c == nil || c.BrokerPin != testPin("broker") {
					t.Errorf("LoadClient = %+v, %v; want the config", c, err)
				}
				return
			}
			if c != nil {
				t.Errorf("LoadClient returned a config with the error")
			}
			checkError(t, err, tt.want, "")
		})
	}
}
