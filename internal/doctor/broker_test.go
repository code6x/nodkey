package doctor

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

const goodUnit = `[Service]
User=nodkey
ExecStart=/usr/local/bin/nodkey broker --config /etc/nodkey/broker.toml
LoadCredentialEncrypted=broker-tls-key:/etc/nodkey/credentials/broker-tls-key.cred
LoadCredentialEncrypted=telegram-token
`

// goodBroker returns a BrokerEnv in which every check passes.
func goodBroker() BrokerEnv {
	creds := "/run/credentials/nodkey.service"
	return BrokerEnv{
		ConfigPath: "/etc/nodkey/broker.toml",
		CredDir:    creds,
		ReadConfig: func(string) (*config.Broker, error) {
			return &config.Broker{TLSKey: creds + "/broker-tls-key", AuditLog: "/var/lib/nodkey/audit.log",
				KnownHostsFile: "/etc/nodkey/known_hosts",
				Telegram:       config.Telegram{TokenFile: creds + "/telegram-token"}}, nil
		},
		UnitText:   func() (string, error) { return goodUnit, nil },
		LookupUser: func(string) (uint32, error) { return 990, nil },
		CheckFiles: func(*config.Broker, uint32, func(string) bool) error { return nil },
		Stat: func(p string) (fs.FileInfo, error) {
			switch p {
			case "/sys/fs/cgroup/cgroup.controllers", "/etc/nodkey/credentials/broker-tls-key.cred",
				"/etc/credstore.encrypted/telegram-token":
				return fakeInfo{}, nil
			}
			return nil, fs.ErrNotExist
		},
		ReadFile: func(p string) ([]byte, error) {
			switch p {
			case "/proc/swaps":
				return []byte("Filename Type Size Used Priority\n/dev/zram0 partition 1 0 100\n"), nil
			case "/proc/sys/kernel/core_pattern":
				return []byte("|/usr/lib/systemd/systemd-coredump %P\n"), nil
			}
			return nil, fs.ErrNotExist
		},
		ReadDir:        func(string) ([]string, error) { return nil, fs.ErrNotExist },
		SystemdVersion: func() (string, error) { return "systemd 255 (255.4-1ubuntu8)\n+PAM", nil },
		Service:        func() (string, []string, error) { return "active", nil, nil },
	}
}

func TestBrokerAllPass(t *testing.T) {
	var gotUID uint32
	var skipped []string
	env := goodBroker()
	env.CheckFiles = func(_ *config.Broker, uid uint32, skip func(string) bool) error {
		gotUID = uid
		for _, p := range []string{env.CredDir + "/broker-tls-key", "/etc/nodkey/known_hosts"} {
			if skip(p) {
				skipped = append(skipped, p)
			}
		}
		return nil
	}
	r := Run(BrokerChecks(env))
	if !r.OK() {
		t.Fatalf("not OK: %+v", r.Checks)
	}
	if gotUID != 990 || len(skipped) != 1 || skipped[0] != env.CredDir+"/broker-tls-key" {
		t.Errorf("CheckFiles got uid %d, skipped %q", gotUID, skipped)
	}
}

func TestBrokerUnitSpaces(t *testing.T) {
	env := goodBroker()
	env.UnitText = func() (string, error) {
		return strings.ReplaceAll(goodUnit, "=", " = "), nil
	}
	if res := result(t, Run(BrokerChecks(env)), "unit"); res.Status != OK {
		t.Errorf("unit %+v", res)
	}
}

func TestBrokerLVMOnCryptSwap(t *testing.T) {
	uuids := map[string]string{"dm-1": "LVM-abc", "dm-0": "CRYPT-LUKS2-abc", "dm-2": "LVM-def"}
	for _, tt := range []struct {
		below []string
		ok    bool
	}{{[]string{"dm-0"}, true}, {[]string{"dm-2"}, false}, {[]string{"dm-0", "sda3"}, false}, {nil, false}} {
		env := goodBroker()
		env.ReadFile = func(p string) ([]byte, error) {
			for dev, u := range uuids {
				if p == "/sys/block/"+dev+"/dm/uuid" {
					return []byte(u), nil
				}
			}
			return []byte("Filename\n/dev/dm-1 partition\n"), nil
		}
		env.ReadDir = func(p string) ([]string, error) {
			if p == "/sys/block/dm-1/slaves" {
				return tt.below, nil
			}
			return nil, fs.ErrNotExist
		}
		if res := result(t, Run(BrokerChecks(env)), "swap"); (res.Status == OK) != tt.ok {
			t.Errorf("below %q: swap %+v, want ok %v", tt.below, res, tt.ok)
		}
	}
}

func TestBrokerEncryptedSwap(t *testing.T) {
	env := goodBroker()
	env.ReadFile = func(p string) ([]byte, error) {
		if p == "/sys/block/dm-1/dm/uuid" {
			return []byte("CRYPT-PLAIN-swap\n"), nil
		}
		return []byte("Filename\n/dev/dm-1 partition\n"), nil
	}
	res := result(t, Run(BrokerChecks(env)), "swap")
	if res.Status != OK || !strings.Contains(res.Detail, "encrypted swap on") {
		t.Errorf("swap %+v", res)
	}
}

// TestBrokerFails makes each check of the broker host fail, and checks
// that each FAIL is complete: what, why, the fix and the docs section.
func TestBrokerFails(t *testing.T) {
	unit := func(text string) func(*BrokerEnv) {
		return func(e *BrokerEnv) { e.UnitText = func() (string, error) { return text, nil } }
	}
	read := func(path, data string) func(*BrokerEnv) {
		return func(e *BrokerEnv) {
			old := e.ReadFile
			e.ReadFile = func(p string) ([]byte, error) {
				if p == path {
					return []byte(data), nil
				}
				return old(p)
			}
		}
	}
	tests := []struct {
		name   string
		check  string
		change func(*BrokerEnv)
		what   string
		skips  []string
	}{
		{"bad config", "config", func(e *BrokerEnv) {
			e.ReadConfig = func(string) (*config.Broker, error) { return nil, errors.New("config x: listen: is missing") }
		}, "listen", []string{"unit", "files"}},
		{"no unit", "unit", func(e *BrokerEnv) {
			e.UnitText = func() (string, error) { return "", errors.New("exit status 1") }
		}, "cannot read the unit", []string{"files"}},
		{"no user", "unit", unit(strings.Replace(goodUnit, "User=nodkey\n", "", 1)), "no User=", []string{"files"}},
		{"root", "unit", unit(strings.Replace(goodUnit, "User=nodkey", "User=root", 1)), "runs as root", []string{"files"}},
		{"user with ID 0", "unit", func(e *BrokerEnv) {
			e.LookupUser = func(string) (uint32, error) { return 0, nil }
		}, "user ID 0", []string{"files"}},
		{"unknown user", "unit", func(e *BrokerEnv) {
			e.LookupUser = func(string) (uint32, error) { return 0, errors.New("unknown") }
		}, "is not known", []string{"files"}},
		{"no credential line", "unit", unit(strings.Replace(goodUnit, "LoadCredentialEncrypted=telegram-token\n", "", 1)),
			"no LoadCredentialEncrypted=telegram-token line", []string{"files"}},
		{"plain credential", "unit", unit(strings.Replace(goodUnit, "LoadCredentialEncrypted=telegram-token",
			"LoadCredential=telegram-token:/etc/nodkey/token", 1)), "telegram-token", []string{"files"}},
		{"credential file missing", "unit", func(e *BrokerEnv) {
			old := e.Stat
			e.Stat = func(p string) (fs.FileInfo, error) {
				if strings.HasSuffix(p, "telegram-token") {
					return nil, fs.ErrNotExist
				}
				return old(p)
			}
		}, "is missing", []string{"files"}},
		{"bad file", "files", func(e *BrokerEnv) {
			e.CheckFiles = func(*config.Broker, uint32, func(string) bool) error {
				return errors.New("config x: audit_log: is owned by user ID 1000")
			}
		}, "owned by", nil},
		{"no systemctl", "systemd", func(e *BrokerEnv) {
			e.SystemdVersion = func() (string, error) { return "", errors.New("not found") }
		}, "cannot find the version", nil},
		{"old systemd", "systemd", func(e *BrokerEnv) {
			e.SystemdVersion = func() (string, error) { return "systemd 247 (247.3-7)", nil }
		}, "older than 250", nil},
		{"cgroup v1", "cgroup v2", func(e *BrokerEnv) {
			old := e.Stat
			e.Stat = func(p string) (fs.FileInfo, error) {
				if strings.HasPrefix(p, "/sys/") {
					return nil, fs.ErrNotExist
				}
				return old(p)
			}
		}, "cgroup v2", nil},
		{"LVM swap", "swap", read("/proc/swaps", "Filename\n/dev/dm-0 partition 1 0 -2\n"), "nodkey cannot tell", nil},
		{"plain swap", "swap", read("/proc/swaps", "Filename\n/dev/sda2 partition 1 0 -2\n"), "not encrypted", nil},
		{"no /proc/swaps", "swap", func(e *BrokerEnv) {
			old := e.ReadFile
			e.ReadFile = func(p string) ([]byte, error) {
				if p == "/proc/swaps" {
					return nil, fs.ErrPermission
				}
				return old(p)
			}
		}, "cannot read /proc/swaps", nil},
		{"no core_pattern", "core_pattern", func(e *BrokerEnv) {
			e.ReadFile = func(p string) ([]byte, error) {
				if p == "/proc/swaps" {
					return []byte("Filename\n"), nil
				}
				return nil, fs.ErrPermission
			}
		}, "cannot read", nil},
		{"socket core_pattern", "core_pattern", read("/proc/sys/kernel/core_pattern", "@/run/core.sock\n"), "socket", nil},
		{"service stopped", "service", func(e *BrokerEnv) {
			e.Service = func() (string, []string, error) {
				return "failed", []string{"a", "b", "c", "d", "e", "nodkey broker: listen: bind: address in use\x1b[31m"}, nil
			}
		}, "(failed); journal: b; journal: c; journal: d; journal: e; journal: nodkey broker: listen: bind: address in use?[31m", nil},
		{"no systemd", "service", func(e *BrokerEnv) {
			e.Service = func() (string, []string, error) { return "", nil, errors.New("no bus") }
		}, "cannot get the state", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := goodBroker()
			tt.change(&env)
			r := Run(BrokerChecks(env))
			res := result(t, r, tt.check)
			if res.Status != Fail || !strings.Contains(res.What, tt.what) {
				t.Fatalf("check %q: %+v, want FAIL with %q", tt.check, res, tt.what)
			}
			checkProblem(t, &Problem{What: res.What, Why: res.Why, Fix: res.Fix, Docs: res.Docs})
			for _, s := range tt.skips {
				if st := result(t, r, s).Status; st != Skip {
					t.Errorf("check %q: %s, want skip", s, st)
				}
			}
			for _, c := range r.Checks {
				if c.Status == Fail && c.Name != tt.check {
					t.Errorf("check %q failed too", c.Name)
				}
			}
		})
	}
}
