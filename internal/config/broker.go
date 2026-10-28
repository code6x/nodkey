package config

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Limits of the [telegram] timeouts.
const (
	defaultTimeout    = 120 * time.Second
	defaultSSHTimeout = 90 * time.Second
	minTimeout        = 15 * time.Second
)

// MaxSSHTimeout is the longest timeout of an SSH request that the broker
// config allows (ssh_timeout in [telegram]). sshd drops a login that does
// not finish within LoginGraceTime, 120 seconds by default (DESIGN.md
// section 6). nodkey ssh-agent does not know the broker's own setting, so
// it waits this long, and a short margin.
const MaxSSHTimeout = 110 * time.Second

// MaxTimeout is the longest timeout of a request for secrets that the
// broker config allows (timeout in [telegram]). nodkey run does not know
// the broker's own setting, so it waits this long, and a margin.
const MaxTimeout = 10 * time.Minute

// Broker is the broker config, such as /etc/nodkey/broker.toml. All paths
// in it are expanded with ExpandPath and absolute.
type Broker struct {
	Path string // the config file it was loaded from
	// Listen is the address to listen on: one IP address, never 0.0.0.0 or
	// ::, never a multicast or broadcast address, never an IPv6 link-local
	// address, with no zone, and a port from 1 to 65535.
	Listen         netip.AddrPort
	TLSKey         string // the broker's TLS private key
	AuditLog       string
	KnownHostsFile string
	KnownHosts     *KnownHosts
	Telegram       Telegram
	Updates        Updates
	Preapprove     PreapproveLimits
	Clients        map[string]Client // by name
	Stores         map[string]Store  // by name
	Secrets        map[string]Secret // by name
	Keys           map[string]Key    // by name
}

// Telegram is the [telegram] section.
type Telegram struct {
	TokenFile    string        // the file that holds the bot token
	UserID       int64         // the approver; only this user's taps count
	NoticeChatID int64         // where notices about "never" uses go; the default is UserID
	Timeout      time.Duration // how long a request for secrets waits; default 120s
	SSHTimeout   time.Duration // how long an SSH request waits; default 90s
}

// Updates is the [updates] section. Without it, each key has its
// default.
type Updates struct {
	// Check turns on the broker's check for a newer release of nodkey
	// (DESIGN.md section 15). The default is true.
	Check bool
}

// PreapproveLimits is the [preapprove] section: the limits of scheduled
// grants (DESIGN.md section 8). Without the section, each key has its
// default. Code that makes a Broker by hand must set them: the zero
// value allows no scheduled grant at all.
type PreapproveLimits struct {
	// MaxAhead is how far in the future a grant may start.
	MaxAhead time.Duration
	// MaxOpen is the longest time from the start to the end of a grant.
	MaxOpen time.Duration
	// MaxUses is the most uses of one grant.
	MaxUses int
	// MaxGrants is the most scheduled grants of one client: those that
	// are approved and not ended, and the requests that wait for a tap.
	MaxGrants int
}

// The defaults and the bounds of the [preapprove] section.
const (
	defaultMaxAhead  = 7 * 24 * time.Hour
	defaultMaxOpen   = 8 * time.Hour
	defaultMaxUses   = 10
	defaultMaxGrants = 5
	maxMaxAhead      = 31 * 24 * time.Hour
	maxMaxOpen       = 24 * time.Hour
	maxMaxUses       = 1000
	maxMaxGrants     = 100
)

// DefaultPreapprove returns the limits that apply without a [preapprove]
// section.
func DefaultPreapprove() PreapproveLimits {
	return PreapproveLimits{
		MaxAhead: defaultMaxAhead, MaxOpen: defaultMaxOpen, MaxUses: defaultMaxUses, MaxGrants: defaultMaxGrants,
	}
}

// Client is a [client.NAME] section: a machine that may ask.
type Client struct {
	Name string
	Pin  Pin // the client's TLS key; the client name comes only from it
}

// StoreType is the program a store runs.
type StoreType string

// The values of StoreType.
const (
	StoreBWS StoreType = "bws" // Bitwarden Secrets Manager; uses Store.TokenFile
	StoreBW  StoreType = "bw"  // Bitwarden Password Manager; uses Store.PasswordFile
)

// Store is a [store.NAME] section: where secret values live.
type Store struct {
	Name         string
	Type         StoreType
	Program      string // the bws or bw program
	TokenFile    string // StoreBWS only: the machine account token
	PasswordFile string // StoreBW only: the master password
}

// Secret is a [secret.NAME] section.
type Secret struct {
	Name    string
	Store   string   // a name in Broker.Stores
	ID      string   // the item's ID in the store, a UUID
	Clients []string // the names in Broker.Clients that may ask for it
	Rule    Rule
}

// Key is a [key.NAME] section: an SSH key the broker signs with.
type Key struct {
	Name    string
	File    string   // the SSH private key
	Clients []string // the names in Broker.Clients that may use it
	// Hosts are the names in KnownHosts it may log in to. Empty means any
	// known host. LoadBroker refuses an empty list with ask = "never", and
	// code that uses a "never" rule must deny when it is empty (see Rule).
	Hosts []string
	Rule  Rule
}

// The broker config as it is written. A nil pointer means the key is not
// in the file.
type (
	brokerFile struct {
		Listen     string                   `toml:"listen"`
		TLSKey     string                   `toml:"tls_key"`
		AuditLog   string                   `toml:"audit_log"`
		KnownHosts string                   `toml:"known_hosts"`
		Telegram   telegramSection          `toml:"telegram"`
		Updates    updatesSection           `toml:"updates"`
		Preapprove preapproveSection        `toml:"preapprove"`
		Client     map[string]clientSection `toml:"client"`
		Store      map[string]storeSection  `toml:"store"`
		Secret     map[string]secretSection `toml:"secret"`
		Key        map[string]keySection    `toml:"key"`
	}
	telegramSection struct {
		TokenFile    string  `toml:"token_file"`
		UserID       *int64  `toml:"user_id"`
		NoticeChatID *int64  `toml:"notice_chat_id"`
		Timeout      *string `toml:"timeout"`
		SSHTimeout   *string `toml:"ssh_timeout"`
	}
	updatesSection struct {
		Check *bool `toml:"check"`
	}
	preapproveSection struct {
		MaxAhead  *string `toml:"max_ahead"`
		MaxOpen   *string `toml:"max_open"`
		MaxUses   *int    `toml:"max_uses"`
		MaxGrants *int    `toml:"max_grants"`
	}
	clientSection struct {
		Pin string `toml:"pin"`
	}
	storeSection struct {
		Type         string  `toml:"type"`
		Program      string  `toml:"program"`
		TokenFile    *string `toml:"token_file"`
		PasswordFile *string `toml:"password_file"`
	}
	secretSection struct {
		Store   string   `toml:"store"`
		ID      string   `toml:"id"`
		Clients []string `toml:"clients"`
		ruleKeys
	}
	keySection struct {
		File    string   `toml:"file"`
		Clients []string `toml:"clients"`
		Hosts   []string `toml:"hosts"`
		ruleKeys
	}
)

// uuidPattern is the form of an item ID in bws and bw. An exact ID also
// keeps "bw get" from searching items by name.
var uuidPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// LoadBroker reads the broker config file at path and checks it. It reads
// the known_hosts file that the config names, and checks the other files
// that it names with CheckFiles. The config file and known_hosts are read
// with ReadConfigFile. A config that LoadBroker returns has passed all
// these checks; on any error it returns no config.
func LoadBroker(path string) (*Broker, error) {
	b, err := loadBroker(path)
	if err != nil {
		return nil, err
	}
	if err := b.CheckFiles(); err != nil {
		return nil, err // the error names the config file
	}
	return b, nil
}

// loadBroker is LoadBroker without CheckFiles.
func loadBroker(path string) (*Broker, error) {
	data, err := ReadConfigFile(path)
	if err != nil {
		// The error can name a directory on the way, so name the file too.
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	var f brokerFile
	if err := decode(data, &f, "client", "store", "secret", "key"); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	b, err := newBroker(&f)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	b.Path = path
	return b, nil
}

func newBroker(f *brokerFile) (*Broker, error) {
	b := &Broker{
		Clients: make(map[string]Client),
		Stores:  make(map[string]Store),
		Secrets: make(map[string]Secret),
		Keys:    make(map[string]Key),
	}
	var err error
	if b.Listen, err = parseListen(f.Listen); err != nil {
		return nil, err
	}
	if b.TLSKey, err = parsePath("", "tls_key", f.TLSKey); err != nil {
		return nil, err
	}
	if b.AuditLog, err = parsePath("", "audit_log", f.AuditLog); err != nil {
		return nil, err
	}
	if b.KnownHostsFile, err = parsePath("", "known_hosts", f.KnownHosts); err != nil {
		return nil, err
	}
	if b.Telegram, err = parseTelegram(&f.Telegram); err != nil {
		return nil, err
	}
	b.Updates.Check = f.Updates.Check == nil || *f.Updates.Check
	if b.Preapprove, err = parsePreapprove(&f.Preapprove); err != nil {
		return nil, err
	}
	if err := b.addClients(f.Client); err != nil {
		return nil, err
	}
	if err := b.addStores(f.Store); err != nil {
		return nil, err
	}
	if err := b.addSecrets(f.Secret); err != nil {
		return nil, err
	}
	if b.KnownHosts, err = LoadKnownHosts(b.KnownHostsFile); err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}
	if err := b.addKeys(f.Key); err != nil {
		return nil, err
	}
	return b, nil
}

// listenRule says what parseListen allows, for error messages.
const listenRule = `must be an IP address and a port, such as "192.0.2.10:7743" or "[2001:db8::10]:7743"`

// ipv4Broadcast is the IPv4 broadcast address, 255.255.255.255.
var ipv4Broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// parseListen parses the listen key: one IP address and a port from 1 to
// 65535. It refuses a host name, an empty address and the unspecified
// address (0.0.0.0 or ::), because the broker must listen on the private
// network only (DESIGN.md section 10). It also refuses a multicast address
// (link-local multicast too) and the IPv4 broadcast address: neither is an
// address of one machine. It refuses an IPv6 zone, such as "%eth0", and an
// IPv6 link-local address (fe80::/10), which works only with a zone: a zone
// is the name of a network interface, and nodkey does not check those
// names. An IPv4 link-local address (169.254.0.0/16) is allowed. An IPv4
// address written in IPv6 form, such as ::ffff:192.0.2.10, is taken as the
// IPv4 address. Errors do not repeat the text.
func parseListen(s string) (netip.AddrPort, error) {
	if s == "" {
		return netip.AddrPort{}, errors.New("listen: is missing")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, errors.New("listen: " + listenRule)
	}
	if host == "" {
		return netip.AddrPort{}, errors.New("listen: the IP address is missing; " +
			"without it, the broker would listen on every network")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, errors.New("listen: " + listenRule + "; a host name is not allowed")
	}
	// Unmap drops the zone of an IPv4 address in IPv6 form
	// (::ffff:192.0.2.10%eth0), so take the zone first.
	zone := addr.Zone()
	addr = addr.Unmap().WithZone("")
	// The zone does not change the address: "::%eth0" listens on every
	// network too. Say that first; it is the bigger problem.
	if addr.IsUnspecified() {
		return netip.AddrPort{}, errors.New("listen: 0.0.0.0 and :: are not allowed, because the broker would " +
			"listen on every network; use one address on your private network")
	}
	if zone != "" {
		return netip.AddrPort{}, errors.New("listen: an IPv6 zone (the part after %) is not allowed; " +
			"use one address on your private network, without a zone")
	}
	// IsMulticast covers every multicast address (224.0.0.0/4, ff00::/8),
	// so link-local multicast (224.0.0.0/24, ff02::/16) too.
	if addr.IsMulticast() || addr == ipv4Broadcast {
		return netip.AddrPort{}, errors.New("listen: a multicast or broadcast address is not allowed; " +
			"use one address of this machine on your private network")
	}
	if addr.Is6() && addr.IsLinkLocalUnicast() {
		return netip.AddrPort{}, errors.New("listen: an IPv6 link-local address (fe80::/10) is not allowed; " +
			"use one address on your private network")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return netip.AddrPort{}, errors.New("listen: the port must be a number from 1 to 65535")
	}
	return netip.AddrPortFrom(addr, uint16(n)), nil
}

func parseTelegram(s *telegramSection) (Telegram, error) {
	const sec = "[telegram]"
	var t Telegram
	var err error
	if t.TokenFile, err = parsePath(sec, "token_file", s.TokenFile); err != nil {
		return Telegram{}, err
	}
	if s.UserID == nil {
		return Telegram{}, fmt.Errorf("%s: is missing; it is the approver's Telegram user ID", place(sec, "user_id"))
	}
	if *s.UserID <= 0 {
		return Telegram{}, fmt.Errorf("%s: must be more than 0", place(sec, "user_id"))
	}
	t.UserID = *s.UserID
	t.NoticeChatID = t.UserID
	if s.NoticeChatID != nil {
		if *s.NoticeChatID == 0 {
			return Telegram{}, fmt.Errorf("%s: must not be 0", place(sec, "notice_chat_id"))
		}
		t.NoticeChatID = *s.NoticeChatID
	}
	if t.Timeout, err = parseTimeout(sec, "timeout", s.Timeout, defaultTimeout, MaxTimeout); err != nil {
		return Telegram{}, err
	}
	if t.SSHTimeout, err = parseTimeout(sec, "ssh_timeout", s.SSHTimeout, defaultSSHTimeout, MaxSSHTimeout); err != nil {
		return Telegram{}, err
	}
	return t, nil
}

// parsePreapprove checks the [preapprove] section and fills in the
// defaults.
func parsePreapprove(s *preapproveSection) (PreapproveLimits, error) {
	const sec = "[preapprove]"
	l := DefaultPreapprove()
	span := func(key string, v *string, most time.Duration, into *time.Duration) error {
		if v == nil {
			return nil
		}
		d, err := parseDuration(sec, key, *v)
		if err != nil {
			return err
		}
		if d < time.Minute || d > most {
			return fmt.Errorf("%s: must be from %s to %s", place(sec, key), formatDuration(time.Minute), formatDuration(most))
		}
		*into = d
		return nil
	}
	count := func(key string, v *int, most int, into *int) error {
		if v == nil {
			return nil
		}
		if *v < 1 || *v > most {
			return fmt.Errorf("%s: must be from 1 to %d", place(sec, key), most)
		}
		*into = *v
		return nil
	}
	for _, err := range []error{
		span("max_ahead", s.MaxAhead, maxMaxAhead, &l.MaxAhead),
		span("max_open", s.MaxOpen, maxMaxOpen, &l.MaxOpen),
		count("max_uses", s.MaxUses, maxMaxUses, &l.MaxUses),
		count("max_grants", s.MaxGrants, maxMaxGrants, &l.MaxGrants),
	} {
		if err != nil {
			return PreapproveLimits{}, err
		}
	}
	return l, nil
}

// parseTimeout parses an optional timeout from minTimeout to most.
func parseTimeout(section, key string, s *string, def, most time.Duration) (time.Duration, error) {
	if s == nil {
		return def, nil
	}
	d, err := parseDuration(section, key, *s)
	if err != nil {
		return 0, err
	}
	if d < minTimeout || d > most {
		return 0, fmt.Errorf("%s: must be from %s to %s", place(section, key),
			formatDuration(minTimeout), formatDuration(most))
	}
	return d, nil
}

// checkName checks the name of a [kind.NAME] section. A name that breaks
// the rule may be pasted text, so the error does not show it.
func checkName(kind, name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("[%s.*]: the name of a section %s; the name is not shown here", kind, nameRule)
	}
	return nil
}

func (b *Broker) addClients(m map[string]clientSection) error {
	byPin := make(map[Pin]string)
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if err := checkName("client", name); err != nil {
			return err
		}
		sec := sectionName("client", name)
		if m[name].Pin == "" {
			return fmt.Errorf("%s: is missing", place(sec, "pin"))
		}
		pin, err := ParsePin(m[name].Pin)
		if err != nil {
			return fmt.Errorf("%s: %w", place(sec, "pin"), err)
		}
		if other, ok := byPin[pin]; ok {
			return fmt.Errorf("%s: is the same as the pin of %s; each client needs its own TLS key",
				place(sec, "pin"), sectionName("client", other))
		}
		byPin[pin] = name
		b.Clients[name] = Client{Name: name, Pin: pin}
	}
	return nil
}

func (b *Broker) addStores(m map[string]storeSection) error {
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if err := checkName("store", name); err != nil {
			return err
		}
		sec := sectionName("store", name)
		s := m[name]
		st := Store{Name: name, Type: StoreType(s.Type)}
		var err error
		switch st.Type {
		case StoreBWS:
			st.TokenFile, err = storeFile(sec, st.Type, "token_file", s.TokenFile, "password_file", s.PasswordFile)
		case StoreBW:
			st.PasswordFile, err = storeFile(sec, st.Type, "password_file", s.PasswordFile, "token_file", s.TokenFile)
		case "":
			err = fmt.Errorf(`%s: is missing; use "bws" or "bw"`, place(sec, "type"))
		default:
			err = fmt.Errorf(`%s: must be "bws" or "bw"`, place(sec, "type"))
		}
		if err != nil {
			return err
		}
		if st.Program, err = parsePath(sec, "program", s.Program); err != nil {
			return err
		}
		b.Stores[name] = st
	}
	return nil
}

// storeFile checks the file keys of a store: the type needs the key need
// and must not have the key never.
func storeFile(section string, t StoreType, need string, file *string, never string, other *string) (string, error) {
	if other != nil {
		return "", fmt.Errorf("%s: is not allowed with type = %q", place(section, never), t)
	}
	if file == nil {
		return "", fmt.Errorf("%s: is missing; type = %q needs it", place(section, need), t)
	}
	return parsePath(section, need, *file)
}

func (b *Broker) addSecrets(m map[string]secretSection) error {
	// never holds the item IDs of "never" secrets: a second "never" secret
	// for one item would give it to a second client without asking. The
	// store does not count: an ID is a UUID, and two [store.*] sections can
	// reach one account.
	never := make(map[string]string)
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if err := checkName("secret", name); err != nil {
			return err
		}
		sec := sectionName("secret", name)
		s := m[name]
		if s.Store == "" {
			return fmt.Errorf("%s: is missing", place(sec, "store"))
		}
		if _, ok := b.Stores[s.Store]; !ok {
			return fmt.Errorf("%s: no [store.*] section has this name", place(sec, "store"))
		}
		if s.ID == "" {
			return fmt.Errorf("%s: is missing", place(sec, "id"))
		}
		if !uuidPattern.MatchString(s.ID) {
			return fmt.Errorf(`%s: must be the item's ID in the store, a UUID such as "00000000-0000-0000-0000-000000000000"`,
				place(sec, "id"))
		}
		clients, err := b.clientList(sec, s.Clients)
		if err != nil {
			return err
		}
		rule, err := parseRule(sec, s.ruleKeys)
		if err != nil {
			return err
		}
		if rule.Ask == AskNever {
			if len(clients) != 1 {
				return fmt.Errorf(`%s: ask = "never" needs exactly one client`, place(sec, "clients"))
			}
			item := strings.ToLower(s.ID)
			if other, ok := never[item]; ok {
				return fmt.Errorf(`%s: %s also has ask = "never" for this item ID; `+
					`one item may have one "never" rule, for one client`, place(sec, "id"), sectionName("secret", other))
			}
			never[item] = name
		}
		b.Secrets[name] = Secret{Name: name, Store: s.Store, ID: s.ID, Clients: clients, Rule: rule}
	}
	return nil
}

func (b *Broker) addKeys(m map[string]keySection) error {
	// files holds the key files: two sections for one key would let its
	// rules and clients add up. CheckFiles also finds one file with two
	// paths. A copy of a key in a second file passes both checks; the
	// broker refuses two sections with the same public key when it loads
	// the keys.
	files := make(map[string]string)
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if err := checkName("key", name); err != nil {
			return err
		}
		sec := sectionName("key", name)
		k := m[name]
		file, err := parsePath(sec, "file", k.File)
		if err != nil {
			return err
		}
		if other, ok := files[filepath.Clean(file)]; ok {
			return fmt.Errorf("%s: %s uses the same file; each key may have one section", place(sec, "file"),
				sectionName("key", other))
		}
		files[filepath.Clean(file)] = name
		clients, err := b.clientList(sec, k.Clients)
		if err != nil {
			return err
		}
		if err := checkList(sec, "hosts", k.Hosts, "is not a host in known_hosts", func(h string) bool {
			return len(b.KnownHosts.KeysFor(h)) > 0
		}); err != nil {
			return err
		}
		rule, err := parseRule(sec, k.ruleKeys)
		if err != nil {
			return err
		}
		if rule.Ask == AskNever {
			if len(clients) != 1 {
				return fmt.Errorf(`%s: ask = "never" needs exactly one client`, place(sec, "clients"))
			}
			if len(k.Hosts) == 0 {
				return fmt.Errorf(`%s: is missing; ask = "never" needs a list of hosts`, place(sec, "hosts"))
			}
		}
		b.Keys[name] = Key{Name: name, File: file, Clients: clients, Hosts: slices.Clone(k.Hosts), Rule: rule}
	}
	return nil
}

// clientList checks the clients key of a section: at least one client,
// each defined in a [client.NAME] section, none twice.
func (b *Broker) clientList(section string, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: is missing or empty; list the clients that may use it", place(section, "clients"))
	}
	err := checkList(section, "clients", names, "is not a [client.*] section", func(n string) bool {
		_, ok := b.Clients[n]
		return ok
	})
	if err != nil {
		return nil, err
	}
	return slices.Clone(names), nil
}

// checkList checks that each item of a list is known and appears once.
// Errors give the item's position, not its text.
func checkList(section, key string, items []string, unknown string, known func(string) bool) error {
	seen := make(map[string]bool, len(items))
	for i, item := range items {
		if !known(item) {
			return fmt.Errorf("%s: item %d %s", place(section, key), i+1, unknown)
		}
		if seen[item] {
			return fmt.Errorf("%s: item %d is listed twice", place(section, key), i+1)
		}
		seen[item] = true
	}
	return nil
}

// CheckFiles checks the files that the config names, except the config
// file and known_hosts, which ReadConfigFile checks; it only finds those
// two again, to compare them with the audit log. LoadBroker calls it, so
// the checks cannot be skipped; the broker may call it again later.
//
//   - Files that hold a key, a token or a password must pass
//     CheckPrivateFile: tls_key, the [telegram] token_file, each store's
//     token_file or password_file, and each key's file. Read them later
//     with ReadPrivateFile, never by path.
//   - Two [key.*] sections must not name one file, also not through two
//     paths (a hard link or a linked directory). A copy of a key in a second
//     file passes this check; the broker refuses two [key.*] sections with
//     the same public key when it loads the keys.
//   - Each store's program gets a token from the broker. It must be a
//     regular file owned by root or by the user that runs nodkey, and group
//     and others must not be able to write to it. Every directory on the
//     way to it must pass the checks of CheckPrivateFile.
//   - The directories on the way to audit_log must pass CheckParentDirs.
//     The audit log may be missing. If it is there, it must be a regular
//     file, not a symbolic link, owned by the user that runs nodkey, and
//     its mode may give only read and write to its owner, such as 0600. It
//     must not be another file that the broker reads or runs: a file above
//     that holds a key, a token or a password, a store's program, the
//     config file or known_hosts. That holds also through a hard link or a
//     linked directory.
func (b *Broker) CheckFiles() error {
	type file struct {
		where, path string
		key         bool
	}
	private := []file{
		{"tls_key", b.TLSKey, false},
		{place("[telegram]", "token_file"), b.Telegram.TokenFile, false},
	}
	for _, name := range slices.Sorted(maps.Keys(b.Stores)) {
		s := b.Stores[name]
		switch s.Type {
		case StoreBWS:
			private = append(private, file{place(sectionName("store", name), "token_file"), s.TokenFile, false})
		case StoreBW:
			private = append(private, file{place(sectionName("store", name), "password_file"), s.PasswordFile, false})
		default:
			return fmt.Errorf("config %s: %s: unknown store type", b.Path, sectionName("store", name))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(b.Keys)) {
		private = append(private, file{place(sectionName("key", name), "file"), b.Keys[name].File, true})
	}
	self, err := currentUser()
	if err != nil {
		return fmt.Errorf("config %s: %w", b.Path, err)
	}
	// checked holds every file that the broker reads or runs, to compare
	// it with the audit log.
	type checkedFile struct {
		where string
		fi    fs.FileInfo
		key   bool
	}
	var checked []checkedFile
	for _, f := range private {
		fi, err := checkPrivateFile(f.path)
		if err != nil {
			return fmt.Errorf("config %s: %s: %w", b.Path, f.where, err)
		}
		for _, c := range checked {
			if f.key && c.key && os.SameFile(c.fi, fi) {
				return fmt.Errorf("config %s: %s: is the same file as %s; each key may have one section",
					b.Path, f.where, c.where)
			}
		}
		checked = append(checked, checkedFile{f.where, fi, f.key})
	}
	for _, name := range slices.Sorted(maps.Keys(b.Stores)) {
		where := place(sectionName("store", name), "program")
		fi, err := checkProgram(b.Stores[name].Program)
		if err != nil {
			return fmt.Errorf("config %s: %s: %w", b.Path, where, err)
		}
		checked = append(checked, checkedFile{where: where, fi: fi})
	}
	// ReadConfigFile checked the config file and known_hosts when they were
	// read. Here they are only found again, the same way.
	for _, f := range []struct{ where, path string }{{"the config file", b.Path}, {"known_hosts", b.KnownHostsFile}} {
		_, fi, err := walkPath(f.path, self, lastFollow)
		if err != nil {
			return fmt.Errorf("config %s: %s: %w", b.Path, f.where, err)
		}
		checked = append(checked, checkedFile{where: f.where, fi: fi})
	}
	audit, err := checkAuditLog(b.AuditLog, self)
	if err != nil {
		return fmt.Errorf("config %s: audit_log: %w", b.Path, err)
	}
	// The broker adds a line to the audit log for each request, and people
	// read and copy the log. A key or a token in the same file would go
	// with it, and a line added to a file that the broker reads or runs
	// would change it.
	for _, c := range checked {
		if audit != nil && os.SameFile(c.fi, audit) {
			return fmt.Errorf("config %s: audit_log: is the same file as %s; the audit log must be a file of its own",
				b.Path, c.where)
		}
	}
	return nil
}
