package client

import (
	"net/http"
	"sync"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/version"
)

// maxVersionWarnings is the most versions of the broker that one Broker
// warns about. The pinned broker sends its version, so a new one comes
// only with an update of the broker. More than this many means that it is
// broken, and the client stops warning.
const maxVersionWarnings = 16

// versions sends this client's version in each request, and warns when
// the broker runs another version (DESIGN.md section 10). Its zero value
// sends no version and warns about nothing.
type versions struct {
	mu   sync.Mutex
	own  string          // this client's version, when version.Valid
	warn func(string)    // gets one line of text; nil warns about nothing
	seen map[string]bool // the versions of the broker that warn got a line about; "" for none
	// security is set once warn got the line about a security release
	// (securityWarning): there is at most one such line.
	security bool
}

// warnVersions makes b send own, the version of this client, in the
// header api.VersionHeader of each request, when own is version.Valid.
// When own is a release, and the broker runs another release or sends no
// version, warn gets one line of text, without "nodkey: " and without a
// line break. It gets at most one line for each version that the broker
// sends, so after an update of the broker it can get one more. nodkey
// run and nodkey ssh-grant send one request, so they print at most one
// such line.
func (b *Broker) warnVersions(own string, warn func(text string)) {
	b.versions.mu.Lock()
	defer b.versions.mu.Unlock()
	b.versions.own, b.versions.warn = "", warn
	if version.Valid(own) {
		b.versions.own = own
	}
}

// setVersion sets the version header of a request.
func (v *versions) setVersion(h http.Header) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.own != "" {
		h.Set(api.VersionHeader, v.own)
	}
}

// check compares the version in h, the header of a final answer of the
// broker, with this client's version, and gives warn a line about a
// difference. The line holds only fixed text and release versions, which
// hold only digits and dots: never a value from the broker that is not a
// release version. Then it looks for a security release in h
// (checkSecurity).
func (v *versions) check(h http.Header) {
	v.checkVersion(h)
	v.checkSecurity(h)
}

// checkSecurity gives warn one line when h, the header of a final answer
// of the broker, names a security release that is newer than this
// client's release (api.SecurityUpdateHeader). It takes the header only
// when it has one value that version.ParseRelease accepts, and it ignores
// any other value, and a client that is not a release. warn gets at most
// one such line, so a process prints it at most once.
func (v *versions) checkSecurity(h http.Header) {
	values := h.Values(api.SecurityUpdateHeader)
	if len(values) != 1 {
		return
	}
	fix, ok := version.ParseRelease(values[0])
	if !ok {
		return
	}
	v.mu.Lock()
	own, isRelease := version.ParseRelease(v.own)
	warn := v.warn
	if warn == nil || v.security || !isRelease || fix.Compare(own) <= 0 {
		v.mu.Unlock()
		return
	}
	v.security = true
	v.mu.Unlock()
	warn(securityWarning(fix, own))
}

// securityWarning returns the line about the security release fix, for a
// client that runs own. It holds fixed text and the two release versions.
func securityWarning(fix, own version.Release) string {
	return "SECURITY UPDATE: nodkey " + fix.String() + " fixes a security problem. This is nodkey " + own.String() +
		". Ask the owner of the broker host to update this host: run nodkey update as root."
}

// checkVersion is the part of check about the version of the broker.
func (v *versions) checkVersion(h http.Header) {
	broker := api.Version(h)
	v.mu.Lock()
	warn := v.warn
	text := versionWarning(v.own, broker, version.Check(v.own, broker))
	if warn == nil || text == "" || v.seen[broker] || len(v.seen) >= maxVersionWarnings {
		v.mu.Unlock()
		return
	}
	if v.seen == nil {
		v.seen = make(map[string]bool)
	}
	v.seen[broker] = true
	v.mu.Unlock()
	warn(text)
}

// versionWarning returns the warning about the version of the broker, or
// "" for none. own and broker are the versions of the client and the
// broker, and diff is how they compare (version.Check). A broker that
// sends no version runs nodkey 0.1, which has no nodkey update: the
// warning points to the steps of docs/setup.md instead.
func versionWarning(own, broker string, diff version.Diff) string {
	switch diff {
	case version.NotSent:
		return "warning: the broker runs an older nodkey that does not send its version, and this machine " +
			"runs nodkey " + own + "; to update the broker, follow section 13 of docs/setup.md"
	case version.OtherOlder:
		return "warning: the broker runs nodkey " + broker + ", which is older than nodkey " + own +
			` on this machine; to update the broker, run "nodkey update" as root on the broker host`
	case version.OtherNewer:
		return "warning: this machine runs nodkey " + own + ", which is older than nodkey " + broker +
			` on the broker; to update this machine, run "nodkey update" as root`
	}
	return ""
}
