package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KnownHosts is the broker's own list of SSH hosts (DESIGN.md section 14).
// Each host key belongs to exactly one name. A name may have several keys,
// at most one of each key type. The broker finds the name of the host in
// an approval message with it. It is safe for use by many goroutines,
// because nothing changes it after parsing.
type KnownHosts struct {
	byName map[string][]ssh.PublicKey
	byKey  map[string]string // the key in SSH wire form → name
}

// LoadKnownHosts reads a known_hosts file with ReadConfigFile and parses it
// with ParseKnownHosts.
func LoadKnownHosts(path string) (*KnownHosts, error) {
	data, err := ReadConfigFile(path)
	if err != nil {
		return nil, err // the error names the path
	}
	k, err := ParseKnownHosts(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// ParseKnownHosts parses known_hosts data. It uses the OpenSSH line form,
// "NAME KEYTYPE BASE64KEY [COMMENT]", with stricter rules, because the
// name is shown as verified in approval messages:
//
//   - Blank lines and lines that start with "#" are skipped.
//   - Each line has exactly one plain host name that matches the name
//     rule. No list with commas, no wildcards ("*", "?") or negation
//     ("!"), no "[host]:port", no hashed names ("|1|..."), and no
//     "@cert-authority" or "@revoked" markers.
//   - The key type must be the type of the key, and the key must not be
//     a certificate.
//   - Each host key appears once: two hosts that share a key (for example
//     cloned machines) cannot be told apart (THREAT-MODEL.md T25).
//   - A name may appear on several lines, with at most one key of each key
//     type, because a host often has several host keys.
//
// An error gives the line number. It never repeats text from the data.
func ParseKnownHosts(data []byte) (*KnownHosts, error) {
	k := &KnownHosts{
		byName: make(map[string][]ssh.PublicKey),
		byKey:  make(map[string]string),
	}
	typeLine := make(map[[2]string]int) // name and key type → line
	keyLine := make(map[string]int)
	for i, line := range strings.Split(string(data), "\n") {
		n := i + 1
		line = strings.Trim(strings.TrimSuffix(line, "\r"), " \t")
		if line == "" || line[0] == '#' {
			continue
		}
		name, key, err := parseKnownHostsLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		nameType := [2]string{name, key.Type()}
		if prev, ok := typeLine[nameType]; ok {
			return nil, fmt.Errorf("line %d: this host name already has a key of this type on line %d; "+
				"a name may have one key of each type", n, prev)
		}
		wire := string(key.Marshal())
		if prev, ok := keyLine[wire]; ok {
			return nil, fmt.Errorf("line %d: this host key is already on line %d; "+
				"each host needs its own host key, or the broker cannot tell them apart", n, prev)
		}
		typeLine[nameType] = n
		keyLine[wire] = n
		k.byName[name] = append(k.byName[name], key)
		k.byKey[wire] = name
	}
	return k, nil
}

// parseKnownHostsLine parses one line that is not blank and not a comment.
func parseKnownHostsLine(line string) (string, ssh.PublicKey, error) {
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(fields) < 3 {
		return "", nil, errors.New("must be a host name, a key type and a key, separated by spaces")
	}
	name, keyType, keyText := fields[0], fields[1], fields[2]
	switch {
	case strings.HasPrefix(name, "@"):
		return "", nil, errors.New("markers such as @cert-authority and @revoked are not allowed")
	case strings.HasPrefix(name, "|"):
		return "", nil, errors.New("hashed host names are not allowed; write the plain name")
	case strings.Contains(name, ","):
		return "", nil, errors.New("only one host name per line is allowed")
	case strings.HasPrefix(name, "["):
		return "", nil, errors.New("a port ([host]:port) is not allowed")
	case strings.ContainsAny(name, "*?!"):
		return "", nil, errors.New("wildcards (*, ?) and negation (!) are not allowed")
	case !namePattern.MatchString(name):
		return "", nil, errors.New("the host name " + nameRule)
	}
	blob, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil {
		return "", nil, errors.New("the key is not valid base64")
	}
	key, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return "", nil, errors.New("the key is not a valid SSH public key")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return "", nil, errors.New("certificates are not allowed; use the host's plain public key")
	}
	if key.Type() != keyType {
		return "", nil, errors.New("the key type does not match the key")
	}
	return name, key, nil
}

// NameFor returns the name of the host with this host key.
func (k *KnownHosts) NameFor(key ssh.PublicKey) (string, bool) {
	if k == nil || key == nil {
		return "", false
	}
	name, ok := k.byKey[string(key.Marshal())]
	return name, ok
}

// KeysFor returns the host keys of the host with this name, in the order
// of the file, or nil if the name is not known. The slice is a copy.
func (k *KnownHosts) KeysFor(name string) []ssh.PublicKey {
	if k == nil {
		return nil
	}
	return slices.Clone(k.byName[name])
}
