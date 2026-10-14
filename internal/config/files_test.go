package config

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

func TestExpandPath(t *testing.T) {
	home := t.TempDir()
	creds := t.TempDir()
	tests := []struct {
		name  string
		path  string
		creds *string // the value of CREDENTIALS_DIRECTORY; nil means unset
		want  string  // the result; "" means an error
	}{
		{name: "plain absolute path", path: "/etc/nodkey/known_hosts", want: "/etc/nodkey/known_hosts"},
		{name: "plain relative path", path: "keys/client.key", want: "keys/client.key"},
		{name: "empty", path: "", want: ""},
		{name: "credentials directory", path: "${CREDENTIALS_DIRECTORY}/broker-tls-key", creds: &creds, want: creds + "/broker-tls-key"},
		{name: "credentials directory unset", path: "${CREDENTIALS_DIRECTORY}/broker-tls-key"},
		{name: "credentials directory empty", path: "${CREDENTIALS_DIRECTORY}/broker-tls-key", creds: ptr("")},
		{name: "credentials directory relative", path: "${CREDENTIALS_DIRECTORY}/broker-tls-key", creds: ptr("run/credentials")},
		{name: "credentials directory alone", path: "${CREDENTIALS_DIRECTORY}", creds: &creds},
		{name: "credentials directory without a slash", path: "${CREDENTIALS_DIRECTORY}broker-tls-key", creds: &creds},
		{name: "credentials directory in the middle", path: "/x/${CREDENTIALS_DIRECTORY}/key", creds: &creds},
		{name: "credentials directory twice", path: "${CREDENTIALS_DIRECTORY}/${CREDENTIALS_DIRECTORY}", creds: &creds},
		{name: "a typo in the variable", path: "${CREDENTIALS_DIR}/broker-tls-key", creds: &creds},
		{name: "the variable in lower case", path: "${credentials_directory}/broker-tls-key", creds: &creds},
		{name: "a variable without braces", path: "$CREDENTIALS_DIRECTORY/broker-tls-key", creds: &creds},
		{name: "a $ after the credentials directory", path: "${CREDENTIALS_DIRECTORY}/key$1", creds: &creds},
		{name: "a $ at the end", path: "/etc/nodkey/$"},
		{name: "a $ after the home directory", path: "~/$HOME/client.key"},
		{name: "another variable", path: "${HOME}/client.key"},
		{name: "home", path: "~/.config/nodkey/client.key", want: home + "/.config/nodkey/client.key"},
		{name: "home alone", path: "~"},
		{name: "another user's home", path: "~dev/client.key"},
		{name: "tilde not at the start", path: "/backup/~/key", want: "/backup/~/key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", home)
			t.Setenv("CREDENTIALS_DIRECTORY", "")
			if tt.creds == nil {
				if err := os.Unsetenv("CREDENTIALS_DIRECTORY"); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv("CREDENTIALS_DIRECTORY", *tt.creds)
			}
			got, err := ExpandPath(tt.path)
			if tt.want == "" && tt.path != "" {
				if err == nil {
					t.Fatalf("ExpandPath(%q) = %q, want an error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExpandPath(%q): %v", tt.path, err)
			}
			if got != tt.want {
				t.Errorf("ExpandPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestCheckPrivatePerm(t *testing.T) {
	const self = 990
	errRead := errors.New("cannot read the ACL")
	acl := func(b []byte, err error) func() ([]byte, error) {
		return func() ([]byte, error) { return b, err }
	}
	noCall := func() ([]byte, error) {
		t.Error("the ACL was read, but the group bits are not set")
		return nil, nil
	}
	tests := []struct {
		name    string
		perm    os.FileMode
		readACL func() ([]byte, error)
		want    string // "" means no error
	}{
		{"0600 without an ACL read", 0o600, noCall, ""},
		{"0604", 0o604, noCall, "others have access (mode 0604)"},
		{"0640 with no ACL", 0o640, acl(nil, nil), "its group has access (mode 0640)"},
		{"0440 when the ACL cannot be read", 0o440, acl(systemdACL(self, 0), errRead), "its group has access (mode 0440)"},
		{"0440 with the systemd ACL", 0o440, acl(systemdACL(self, 0), nil), ""},
		{"0440 with an ACL for another user", 0o440, acl(systemdACL(self+1, 0), nil), "gives user ID 991 access"},
		{"0440 with a broken ACL", 0o440, acl([]byte{1, 2, 3}, nil), "in a form nodkey does not know"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPrivatePerm(tt.perm, tt.readACL, self)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("checkPrivatePerm: %v", err)
				}
				return
			}
			checkError(t, err, tt.want, "")
		})
	}
}

func TestCheckOwner(t *testing.T) {
	tests := []struct {
		owner, self uint32
		ok          bool
	}{
		{owner: 1000, self: 1000, ok: true},
		{owner: 0, self: 1000, ok: true},
		{owner: 0, self: 0, ok: true},
		{owner: 1001, self: 1000, ok: false},
		{owner: 1000, self: 0, ok: false},
	}
	for _, tt := range tests {
		err := checkOwner(tt.owner, tt.self)
		if (err == nil) != tt.ok {
			t.Errorf("checkOwner(%d, %d) = %v, want ok %v", tt.owner, tt.self, err, tt.ok)
		}
	}
}

// aclEntry is one entry of a POSIX ACL, for building test ACLs.
type aclEntry struct {
	tag, perm uint16
	id        uint32
}

const noID = 0xFFFFFFFF // ACL_UNDEFINED_ID

// aclBytes encodes entries as the system.posix_acl_access attribute.
func aclBytes(version uint32, entries ...aclEntry) []byte {
	b := binary.LittleEndian.AppendUint32(nil, version)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

// systemdACL is the ACL that systemd puts on a credential for a service
// that runs as user self: owner root r--, user self r--, mask r--.
func systemdACL(self uint32, groupPerm uint16) []byte {
	return aclBytes(aclVersion,
		aclEntry{aclUserObj, 4, noID},
		aclEntry{aclUser, 4, self},
		aclEntry{aclGroupObj, groupPerm, noID},
		aclEntry{aclMask, 4, noID},
		aclEntry{aclOther, 0, noID},
	)
}

func TestCheckACL(t *testing.T) {
	const self = 990
	tests := []struct {
		name string
		acl  []byte
		want string // "" means no error
	}{
		{name: "systemd credential", acl: systemdACL(self, 0)},
		{name: "owner and self only, no mask", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 6, noID}, aclEntry{aclUser, 6, self}, aclEntry{aclGroupObj, 0, noID}, aclEntry{aclOther, 0, noID})},
		{name: "a group entry the mask turns off", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 6, noID}, aclEntry{aclUser, 4, self}, aclEntry{aclGroupObj, 4, noID},
			aclEntry{aclGroup, 4, 100}, aclEntry{aclMask, 0, noID}, aclEntry{aclOther, 0, noID})},
		{name: "another user", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 6, noID}, aclEntry{aclUser, 4, self + 1}, aclEntry{aclGroupObj, 0, noID},
			aclEntry{aclMask, 4, noID}, aclEntry{aclOther, 0, noID}),
			want: "gives user ID 991 access"},
		{name: "another user with write only", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 6, noID}, aclEntry{aclUser, 2, self + 1}, aclEntry{aclGroupObj, 0, noID},
			aclEntry{aclMask, 6, noID}, aclEntry{aclOther, 0, noID}),
			want: "gives user ID 991 access"},
		{name: "the owning group", acl: systemdACL(self, 4), want: "gives a group access"},
		{name: "a named group", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 6, noID}, aclEntry{aclGroupObj, 0, noID}, aclEntry{aclGroup, 4, 100},
			aclEntry{aclMask, 4, noID}, aclEntry{aclOther, 0, noID}),
			want: "gives a group access"},
		{name: "others", acl: aclBytes(aclVersion,
			aclEntry{aclUserObj, 6, noID}, aclEntry{aclUser, 4, self}, aclEntry{aclGroupObj, 0, noID},
			aclEntry{aclMask, 4, noID}, aclEntry{aclOther, 4, noID}),
			want: "gives others access"},
		{name: "unknown version", acl: aclBytes(1, aclEntry{aclUserObj, 6, noID}), want: "in a form nodkey does not know"},
		{name: "too short", acl: []byte{2, 0}, want: "in a form nodkey does not know"},
		{name: "cut entry", acl: systemdACL(self, 0)[:14], want: "in a form nodkey does not know"},
		{name: "unknown tag", acl: aclBytes(aclVersion, aclEntry{aclUserObj, 6, noID}, aclEntry{0x40, 0, noID}),
			want: "entry nodkey does not know"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkACL(tt.acl, self)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("checkACL: %v", err)
				}
				return
			}
			checkError(t, err, tt.want, "")
		})
	}
}
