package config

import (
	"strings"
	"testing"
)

// dbAlways is the start of the [secret.db-password] section of the valid
// config, a secret of the bw store vault with ask = "always".
const dbAlways = "id = \"00000000-0000-0000-0000-00000000000A\"\nclients = [\"laptop\", \"backup-box\"]\nask = \"always\"\n"

// TestLoadBrokerTOTP: totp = true makes a secret of a bw store a TOTP
// code. It is off by default, and allowed only for a bw store with
// ask = "always" and no standing grants; preapprove = true is fine.
func TestLoadBrokerTOTP(t *testing.T) {
	e := newBrokerEnv(t)
	b, err := LoadBroker(e.write(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range b.Secrets {
		if s.TOTP {
			t.Errorf("secret %s: TOTP is on by default", name)
		}
	}
	b, err = LoadBroker(e.write(t, edit{dbAlways, dbAlways + "totp = true\npreapprove = true\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if s := b.Secrets["db-password"]; !s.TOTP || !s.Rule.Preapprove {
		t.Errorf("totp = true: TOTP = %v, Preapprove = %v", s.TOTP, s.Rule.Preapprove)
	}
	b, err = LoadBroker(e.write(t, edit{dbAlways, dbAlways + "totp = false\n"}))
	if err != nil || b.Secrets["db-password"].TOTP {
		t.Errorf("totp = false: %v", err)
	}
	cases := []struct {
		name string
		ed   edit
		want string
	}{
		{"bws store", edit{"ask = \"window\"\nwindow = \"15m\"\n", "ask = \"always\"\ntotp = true\n"},
			`[secret.github-token] totp: is allowed only with a store of type = "bw"`},
		{"window", edit{dbAlways, strings.Replace(dbAlways, `"always"`, `"window"`, 1) + "window = \"5m\"\ntotp = true\n"},
			`[secret.db-password] ask: a secret with totp = true needs ask = "always" and no standing grants`},
		{"never", edit{dbAlways, "id = \"00000000-0000-0000-0000-00000000000A\"\nclients = [\"laptop\"]\nask = \"never\"\ntotp = true\n"},
			`[secret.db-password] ask: a secret with totp = true needs ask = "always"`},
		{"standing", edit{dbAlways, dbAlways + "standing = true\ntotp = true\n"},
			`[secret.db-password] standing: a secret with totp = true needs ask = "always" and no standing grants`},
		{"not a bool", edit{dbAlways, dbAlways + "totp = \"yes\"\n"}, "destination has type boolean"},
	}
	for _, tc := range cases {
		_, err := LoadBroker(e.write(t, tc.ed))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestDiffTOTP: config-diff shows a new TOTP secret, and a change of
// totp, as a change that widens.
func TestDiffTOTP(t *testing.T) {
	old := &Broker{Secrets: map[string]Secret{"otp": {Name: "otp", Store: "vault", ID: "00000000-0000-0000-0000-00000000000a"}}}
	next := &Broker{Secrets: map[string]Secret{"otp": {Name: "otp", Store: "vault", ID: "00000000-0000-0000-0000-00000000000a", TOTP: true}}}
	if old.SameSecret(next, "otp", "laptop") {
		t.Error("SameSecret ignores totp")
	}
	var found bool
	for _, c := range Diff(old, next) {
		if strings.Contains(c.Text, "totp changed from false to true") && strings.Contains(c.Text, "its TOTP code") {
			found = true
			if !c.Widens {
				t.Errorf("not marked as one that widens: %+v", c)
			}
		}
	}
	if !found {
		t.Errorf("the diff does not show the change of totp: %+v", Diff(old, next))
	}
}
