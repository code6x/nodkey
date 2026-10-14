package sshauth_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
)

// extFixture builds one valid request from outside the package, with only
// the exported API, as the broker will.
type extFixture struct {
	key   sshauth.Key
	priv  ed25519.PrivateKey
	hosts *config.KnownHosts
	req   sshauth.Request
}

func newExtFixture(t *testing.T) *extFixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sshauth.NewKey("deploy", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := config.ParseKnownHosts([]byte("web-1 " + string(ssh.MarshalAuthorizedKey(host.PublicKey()))))
	if err != nil {
		t.Fatal(err)
	}
	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		t.Fatal(err)
	}
	sig, err := host.Sign(rand.Reader, sid)
	if err != nil {
		t.Fatal(err)
	}
	bind := ssh.Marshal(struct {
		HostKey, SID, Sig []byte
		Fwd               bool
	}{host.PublicKey().Marshal(), sid, ssh.Marshal(sig), false})
	data := ssh.Marshal(struct {
		SID                   []byte
		Msg                   byte
		User, Service, Method string
		HasSig                bool
		Algorithm             string
		Key                   []byte
	}{sid, 50, "deploy", "ssh-connection", "publickey", true, ssh.KeyAlgoED25519, key.PublicKey().Marshal()})
	return &extFixture{
		key: key, priv: priv, hosts: hosts,
		req: sshauth.Request{Key: key.PublicKey().Marshal(), Data: data, Flags: 0, Binds: [][]byte{bind}},
	}
}

// TestForgedLoginsDoNotSign tries every way that code outside the package
// has to make a Login that Sign accepts without Check.
func TestForgedLoginsDoNotSign(t *testing.T) {
	f := newExtFixture(t)
	good, err := f.key.Check(f.req, f.hosts)
	if err != nil {
		t.Fatal(err)
	}

	// Login and Key have no exported fields, so no literal, decoder or
	// reflection without unsafe can fill them.
	for _, typ := range []reflect.Type{reflect.TypeOf(sshauth.Login{}), reflect.TypeOf(sshauth.Key{})} {
		for i := range typ.NumField() {
			if typ.Field(i).IsExported() {
				t.Errorf("%s has the exported field %s", typ, typ.Field(i).Name)
			}
		}
	}

	var fromJSON sshauth.Login
	_ = json.Unmarshal([]byte(`{"c":{"user":"root","host":"db-1"}}`), &fromJSON) //nolint:staticcheck // SA9005: the test checks that JSON cannot fill a Login
	var fromGob sshauth.Login
	var buf bytes.Buffer
	gobErr := gob.NewEncoder(&buf).Encode(good)
	if gobErr == nil {
		_ = gob.NewDecoder(&buf).Decode(&fromGob)
	}

	other, err := sshauth.NewKey("deploy", f.priv, nil) // the same private key and name
	if err != nil {
		t.Fatal(err)
	}
	otherLogin, err := other.Check(f.req, f.hosts)
	if err != nil {
		t.Fatal(err)
	}

	forged := map[string]struct {
		k sshauth.Key
		l sshauth.Login
	}{
		"the zero Login":                         {f.key, sshauth.Login{}},
		"a Login from JSON":                      {f.key, fromJSON},
		"a Login from gob":                       {f.key, fromGob},
		"the Login of another Key, same private": {f.key, otherLogin},
		"its own Login, signed by the other Key": {other, good},
		"its own Login, signed by the zero Key":  {sshauth.Key{}, good},
	}
	for name, c := range forged {
		if sig, err := c.k.Sign(c.l); !errors.Is(err, sshauth.ErrNotChecked) || sig != nil {
			t.Errorf("%s: Sign gave %v, %v; want %v", name, sig, err, sshauth.ErrNotChecked)
		}
	}
	if gobErr == nil {
		t.Errorf("gob can encode a Login; it should fail because Login has no exported fields")
	}

	// A refused request gives the zero Login, never a partly filled one.
	bad := f.req
	bad.Flags = agent.SignatureFlagRsaSha256
	if l, err := f.key.Check(bad, f.hosts); err == nil || l != (sshauth.Login{}) {
		t.Errorf("a refused request gave %v, %v", l, err)
	}
	if _, err := f.key.Sign(good); err != nil {
		t.Errorf("Sign of its own Login: %v", err)
	}
}

// TestNoKeyMaterialOutside checks the printed forms, the errors and the
// JSON form of Key and Login from outside the package.
func TestNoKeyMaterialOutside(t *testing.T) {
	f := newExtFixture(t)
	l, err := f.key.Check(f.req, f.hosts)
	if err != nil {
		t.Fatal(err)
	}
	seed := f.priv.Seed()
	forms := []string{string(seed[:8]), fmt.Sprintf("%x", seed[:8]), strings.Trim(fmt.Sprintf("%d", seed[:8]), "[]")}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d", "%T", "%p"} {
		outs = append(outs, fmt.Sprintf(verb, f.key), fmt.Sprintf(verb, l), fmt.Sprintf(verb, &f.key), fmt.Sprintf(verb, []any{f.key, l}))
	}
	j1, _ := json.Marshal(f.key) //nolint:staticcheck // SA9005: the test checks what JSON shows of a Key
	j2, _ := json.Marshal(l)     //nolint:staticcheck // SA9005: the test checks what JSON shows of a Login
	outs = append(outs, string(j1), string(j2))
	if _, err := sshauth.NewKey("bad name\n", f.priv, nil); err != nil {
		outs = append(outs, err.Error())
	}
	short := f.priv[:40]
	if _, err := sshauth.NewKey("deploy", short, nil); err != nil {
		outs = append(outs, err.Error())
	}
	for _, out := range outs {
		for _, form := range forms {
			if strings.Contains(out, form) {
				t.Errorf("key material in %q", out)
			}
		}
	}
}
