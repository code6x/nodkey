package doctor

import (
	"bufio"
	"io/fs"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/code6x/nodkey/internal/config"
)

// Unit is the systemd unit of the broker, as in contrib/systemd.
const Unit = "nodkey.service"

// credStores are the directories where systemd looks for an encrypted
// credential whose LoadCredentialEncrypted= line has no path.
var credStores = []string{"/etc/credstore.encrypted", "/run/credstore.encrypted",
	"/usr/local/lib/credstore.encrypted", "/usr/lib/credstore.encrypted"}

// BrokerEnv is what the broker checks use. Tests use fakes, so that no
// test needs root, systemd or the journal.
type BrokerEnv struct {
	ConfigPath string
	// CredDir is what ${CREDENTIALS_DIRECTORY} stands for while ReadConfig
	// runs. The credentials are there only while the service runs, so no
	// check reads them.
	CredDir    string
	ReadConfig func(path string) (*config.Broker, error) // config.ReadBroker
	UnitText   func() (string, error)                    // systemctl cat nodkey.service
	LookupUser func(name string) (uint32, error)
	// CheckFiles is (*config.Broker).CheckFilesAs.
	CheckFiles     func(b *config.Broker, self uint32, skip func(path string) bool) error
	Stat           func(path string) (fs.FileInfo, error)
	ReadFile       func(path string) ([]byte, error) // for files in /proc
	SystemdVersion func() (string, error)            // systemctl --version
	// Service returns the state of the unit, such as "active", and the
	// error lines of its last start in the journal.
	Service func() (state string, errors []string, err error)
}

// BrokerChecks returns the checks of nodkey doctor broker.
func BrokerChecks(env BrokerEnv) []Check {
	var cfg *config.Broker
	var uid uint32
	var user string
	return []Check{
		{Name: "config", Run: func() (string, *Problem) {
			var err error
			if cfg, err = env.ReadConfig(env.ConfigPath); err != nil {
				return "", &Problem{
					What: err.Error(), // the errors of the config never hold a value
					Why:  "the broker does not start with this config",
					Fix:  "fix the config as the error says",
					Docs: "docs/setup.md section 7",
				}
			}
			return env.ConfigPath, nil
		}},
		{Name: "unit", Needs: []string{"config"}, Run: func() (string, *Problem) {
			var p *Problem
			user, uid, p = checkUnit(env, cfg)
			if p != nil {
				return "", p
			}
			return Unit + " runs as " + user + "; its credentials are there", nil
		}},
		{Name: "files", Needs: []string{"unit"}, Run: func() (string, *Problem) {
			inCreds := func(p string) bool { return strings.HasPrefix(p, env.CredDir+"/") }
			if err := env.CheckFiles(cfg, uid, inCreds); err != nil {
				return "", &Problem{
					What: err.Error(),
					Why:  "the broker refuses a file that another user can read or change",
					Fix:  "change the owner or the mode as the error says (chown, chmod)",
					Docs: "docs/setup.md section 7",
				}
			}
			return "the files and the store programs pass the broker's checks for user " + user, nil
		}},
		{Name: "systemd", Run: func() (string, *Problem) { return checkSystemd(env) }},
		{Name: "cgroup v2", Run: func() (string, *Problem) {
			if _, err := env.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
				return "", &Problem{
					What: "the host does not use cgroup v2",
					Why:  "the sandbox of the unit needs cgroup v2",
					Fix:  "boot with cgroup v2 (systemd.unified_cgroup_hierarchy=1), or use a newer distribution",
					Docs: "docs/setup.md section 1",
				}
			}
			return "", nil
		}},
		{Name: "swap", Run: func() (string, *Problem) { return checkSwap(env) }},
		{Name: "core_pattern", Run: func() (string, *Problem) { return checkCorePattern(env) }},
		{Name: "service", Run: func() (string, *Problem) { return checkService(env) }},
	}
}

// credLine is a LoadCredentialEncrypted= line: NAME, or NAME:PATH.
var credLine = regexp.MustCompile(`^LoadCredentialEncrypted=([^:\s]+)(?::(\S+))?$`)

// checkUnit checks that the unit runs as a user that is not root, and
// that each ${CREDENTIALS_DIRECTORY}/NAME of the config has a
// LoadCredentialEncrypted=NAME line whose file exists. It decrypts
// nothing. It returns the user's name and ID.
func checkUnit(env BrokerEnv, cfg *config.Broker) (string, uint32, *Problem) {
	p := &Problem{
		Why:  "the broker gets its keys and tokens from the unit, as encrypted credentials, and must not run as root",
		Docs: "docs/setup.md section 8",
	}
	text, err := env.UnitText()
	if err != nil {
		p.What = "cannot read the unit " + Unit + ": " + err.Error()
		p.Fix = "install the unit from contrib/systemd/nodkey.service"
		return "", 0, p
	}
	user := ""
	creds := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		// systemd allows spaces around "=".
		key, value, _ := strings.Cut(sc.Text(), "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "User" {
			user = value
		}
		if m := credLine.FindStringSubmatch(key + "=" + value); m != nil {
			creds[m[1]] = m[2]
		}
	}
	if user == "" || user == "root" || user == "0" {
		p.What = "the unit has no User=, or runs as root"
		p.Fix = "set User=nodkey in the unit, as in contrib/systemd/nodkey.service"
		return "", 0, p
	}
	uid, err := env.LookupUser(user)
	if err != nil {
		p.What = "the user " + strconv.Quote(user) + " of the unit is not known"
		p.Fix = "make the user: useradd --system --no-create-home nodkey"
		return "", 0, p
	}
	if uid == 0 {
		p.What = "the user " + strconv.Quote(user) + " of the unit has the user ID 0 of root"
		p.Fix = "give the broker a user of its own: useradd --system --no-create-home nodkey"
		return "", 0, p
	}
	for _, name := range credNames(cfg, env.CredDir) {
		file, ok := creds[name]
		if !ok {
			p.What = "the config uses ${CREDENTIALS_DIRECTORY}/" + name + ", but the unit has no LoadCredentialEncrypted=" + name + " line"
			p.Fix = "add LoadCredentialEncrypted=" + name + ":/etc/nodkey/credentials/" + name + ".cred to the unit, " +
				"then systemctl daemon-reload"
			return "", 0, p
		}
		if !credFileExists(env, name, file) {
			p.What = "the encrypted credential " + strconv.Quote(name) + " of the unit is missing"
			p.Fix = "make it with systemd-creds encrypt --name=" + name + " as docs/setup.md section 8 shows"
			return "", 0, p
		}
	}
	return user, uid, nil
}

// credFileExists reports whether the file of the credential name is
// there: file, or name in the directories where systemd looks.
func credFileExists(env BrokerEnv, name, file string) bool {
	paths := []string{file}
	if file == "" {
		paths = nil
		for _, d := range credStores {
			paths = append(paths, filepath.Join(d, name), filepath.Join(d, name+".cred"))
		}
	}
	for _, p := range paths {
		if fi, err := env.Stat(p); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// credNames returns the names of the credentials that the config uses:
// the first part of each path in credDir, sorted, each once.
func credNames(cfg *config.Broker, credDir string) []string {
	paths := []string{cfg.TLSKey, cfg.AuditLog, cfg.KnownHostsFile, cfg.Telegram.TokenFile}
	for _, s := range cfg.Stores {
		paths = append(paths, s.TokenFile, s.PasswordFile, s.Program)
	}
	for _, k := range cfg.Keys {
		paths = append(paths, k.File)
	}
	names := map[string]bool{}
	for _, p := range paths {
		if rest, ok := strings.CutPrefix(p, credDir+"/"); ok {
			name, _, _ := strings.Cut(rest, "/")
			names[name] = true
		}
	}
	return slices.Sorted(maps.Keys(names))
}

// systemdPattern finds the version in the output of systemctl --version.
var systemdPattern = regexp.MustCompile(`^systemd ([0-9]+)`)

// checkSystemd checks for systemd 250 or newer: LoadCredentialEncrypted=
// and the sandbox of the unit need it.
func checkSystemd(env BrokerEnv) (string, *Problem) {
	out, err := env.SystemdVersion()
	m := systemdPattern.FindStringSubmatch(out)
	if err == nil && m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil && v >= 250 {
			return "systemd " + m[1], nil
		}
	}
	what := "cannot find the version of systemd"
	if m != nil {
		what = "systemd " + m[1] + " is older than 250"
	}
	return "", &Problem{
		What: what,
		Why:  "the unit needs systemd 250 or newer for its encrypted credentials and its sandbox",
		Fix:  "use a distribution with systemd 250 or newer, such as Debian 12 or Ubuntu 24.04",
		Docs: "docs/setup.md section 1",
	}
}

// checkSwap checks /proc/swaps. zram keeps its swap in memory, and a
// dm-crypt device is encrypted swap; a plain partition, file or LVM
// volume can keep a page of the memory of the broker on the disk.
func checkSwap(env BrokerEnv) (string, *Problem) {
	data, err := env.ReadFile("/proc/swaps")
	p := &Problem{
		Why:  "swap on a disk can keep secrets from memory after the broker ends",
		Fix:  "turn off the swap (swapoff, and its line in /etc/fstab), or use zram or encrypted swap",
		Docs: "docs/setup.md section 9",
	}
	if err != nil {
		p.What = "cannot read /proc/swaps"
		return "", p
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var crypt []string
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		dev := f[0]
		switch {
		case strings.HasPrefix(dev, "/dev/zram"):
		case strings.HasPrefix(dev, "/dev/dm-") && isCrypt(env, strings.TrimPrefix(dev, "/dev/")):
			crypt = append(crypt, dev)
		default:
			p.What = "swap on " + strconv.Quote(dev) + " is not encrypted, or nodkey cannot tell"
			return "", p
		}
	}
	if len(crypt) > 0 {
		return "encrypted swap on " + strconv.Quote(strings.Join(crypt, ", ")), nil
	}
	return "no swap on a disk", nil
}

// isCrypt reports whether the device-mapper device name, such as "dm-1",
// is a dm-crypt device.
func isCrypt(env BrokerEnv, name string) bool {
	if strings.ContainsAny(name, "/.") {
		return false
	}
	uuid, err := env.ReadFile("/sys/block/" + name + "/dm/uuid")
	return err == nil && strings.HasPrefix(string(uuid), "CRYPT-")
}

// checkCorePattern checks kernel.core_pattern: the socket form ("@")
// passes a core dump to a program whatever the limit of core dumps.
func checkCorePattern(env BrokerEnv) (string, *Problem) {
	data, err := env.ReadFile("/proc/sys/kernel/core_pattern")
	p := &Problem{
		Why:  "a core dump of a store program would hold its token",
		Fix:  "set kernel.core_pattern to a pipe (|) or a file name, such as the default of systemd-coredump",
		Docs: "docs/setup.md section 9",
	}
	if err != nil {
		p.What = "cannot read /proc/sys/kernel/core_pattern"
		return "", p
	}
	if strings.HasPrefix(string(data), "@") {
		p.What = "kernel.core_pattern passes core dumps to a socket"
		return "", p
	}
	return "", nil
}

// maxJournalLines is the most error lines of the journal that the check
// of the service shows, and maxLineLen the most bytes of each.
const (
	maxJournalLines = 5
	maxLineLen      = 300
)

// checkService checks that the unit runs, and shows the error lines of
// its last start when it does not.
func checkService(env BrokerEnv) (string, *Problem) {
	state, lines, err := env.Service()
	if err == nil && state == "active" {
		return Unit + " runs", nil
	}
	what := Unit + " does not run"
	if err != nil {
		what = "cannot get the state of " + Unit
	} else if state != "" {
		what += " (" + printable(state, 32) + ")"
	}
	if len(lines) > maxJournalLines {
		lines = lines[len(lines)-maxJournalLines:]
	}
	for _, l := range lines {
		what += "; journal: " + printable(l, maxLineLen)
	}
	return "", &Problem{
		What: what,
		Why:  "no client gets a secret or a signature while the broker does not run",
		Fix:  "read journalctl -u " + Unit + " -b, fix what it says, then systemctl restart " + Unit,
		Docs: "docs/setup.md section 14",
	}
}

// printable returns s with each byte that is not printable ASCII as "?",
// cut to n bytes.
func printable(s string, n int) string {
	b := []byte(s)
	if len(b) > n {
		b = b[:n]
	}
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}
