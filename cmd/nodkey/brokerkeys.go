package main

import (
	"crypto"
	"errors"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
)

// loadSSHKeys loads the SSH key of each [key.*] section. It reads each
// file with read, which is config.ReadPrivateFile: it checks who can read
// and change the file (DESIGN.md section 14). It makes each key with
// sshauth.NewKey and the hosts of its section; NewKey signs a fixed text
// with the key and checks the signature, so a broken key stops the start,
// not a login after the tap. Two sections must not hold the same public
// key: the config check finds one file named twice, not a copy of a key
// in a second file. Errors name the section and the file, never key
// material.
func loadSSHKeys(cfg *config.Broker, read func(string) ([]byte, error)) (map[string]sshauth.Key, error) {
	keys := make(map[string]sshauth.Key, len(cfg.Keys))
	byPublicKey := make(map[string]string, len(cfg.Keys))
	for _, name := range slices.Sorted(maps.Keys(cfg.Keys)) {
		key, err := loadSSHKey(name, cfg.Keys[name], read)
		if err != nil {
			return nil, err
		}
		blob := string(key.PublicKey().Marshal())
		if other, ok := byPublicKey[blob]; ok {
			return nil, fmt.Errorf("[key.%s] and [key.%s] hold the same public key; each key may have only one "+
				"section, so that its rule and its hosts are clear", other, name)
		}
		byPublicKey[blob] = name
		keys[name] = key
	}
	return keys, nil
}

// loadSSHKey loads the key of the section [key.NAME] k.
func loadSSHKey(name string, k config.Key, read func(string) ([]byte, error)) (sshauth.Key, error) {
	data, err := read(k.File)
	if err != nil {
		return sshauth.Key{}, fmt.Errorf("[key.%s] file: %w", name, err) // it names the path, never the content
	}
	defer clear(data)
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var passphrase *ssh.PassphraseMissingError
		if errors.As(err, &passphrase) {
			return sshauth.Key{}, fmt.Errorf("[key.%s] file %s: the key has a passphrase; store it without one, "+
				"as an encrypted systemd credential (DESIGN.md section 11)", name, k.File)
		}
		// The parser's error can quote the file, so it is left out.
		return sshauth.Key{}, fmt.Errorf("[key.%s] file %s: does not hold an SSH private key in OpenSSH or PEM "+
			"form", name, k.File)
	}
	signer, ok := raw.(crypto.Signer)
	if !ok {
		return sshauth.Key{}, fmt.Errorf("[key.%s] file %s: the key type is not supported; use Ed25519, ECDSA "+
			"or RSA", name, k.File)
	}
	key, err := sshauth.NewKey(name, signer, k.Hosts)
	if err != nil {
		return sshauth.Key{}, fmt.Errorf("[key.%s] file %s: %w", name, k.File, err) // sshauth's errors hold no key material
	}
	return key, nil
}
