package config

import (
	"errors"
	"fmt"
)

// ClientConfig is the client config, such as ~/.config/nodkey/client.toml.
type ClientConfig struct {
	Broker    string // the broker's address, host:port
	BrokerPin Pin    // the broker's TLS key
	TLSKey    string // the client's TLS private key; expanded and absolute
}

// clientFile is the client config as it is written.
type clientFile struct {
	Broker    string `toml:"broker"`
	BrokerPin string `toml:"broker_pin"`
	TLSKey    string `toml:"tls_key"`
}

// LoadClient reads the client config file at path and checks it. It also
// checks the TLS key file with CheckPrivateFile; read that file later with
// ReadPrivateFile, never by path.
func LoadClient(path string) (*ClientConfig, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err) // a *fs.PathError names the path
	}
	var f clientFile
	if err := decode(data, &f); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c, err := newClientConfig(&f)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := CheckPrivateFile(c.TLSKey); err != nil {
		return nil, fmt.Errorf("config %s: tls_key: %w", path, err)
	}
	return c, nil
}

func newClientConfig(f *clientFile) (*ClientConfig, error) {
	if f.Broker == "" {
		return nil, errors.New("broker: is missing")
	}
	if f.BrokerPin == "" {
		return nil, errors.New("broker_pin: is missing")
	}
	pin, err := ParsePin(f.BrokerPin)
	if err != nil {
		return nil, fmt.Errorf("broker_pin: %w", err)
	}
	key, err := parsePath("", "tls_key", f.TLSKey)
	if err != nil {
		return nil, err
	}
	return &ClientConfig{Broker: f.Broker, BrokerPin: pin, TLSKey: key}, nil
}
