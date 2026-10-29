package approval

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/config"
)

// maxStandingWindows is the most windows of a standing grant.
const maxStandingWindows = 7 // api.MaxWindows

// MaxStandingWindows is the most windows of a standing grant.
const MaxStandingWindows = maxStandingWindows

// dayNames are the names of the weekdays, indexed by time.Weekday.
var dayNames = [7]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// clockText shows a time of day as "HH:MM".
func clockText(d time.Duration) string {
	m := int(d / time.Minute)
	return fmt.Sprintf("%02d:%02d", m/60, m%60)
}

// windowText shows a window as the audit log and the message do: "daily
// 03:00-05:00" or "mon,thu 03:00-05:00". Days are in the order of the
// week, Monday first.
func windowText(w window) string {
	days := "daily"
	if w.days != anyDay {
		var names []string
		for _, d := range []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday,
			time.Friday, time.Saturday, time.Sunday} {
			if w.days.has(d) {
				names = append(names, dayNames[d])
			}
		}
		days = strings.Join(names, ",")
	}
	return days + " " + clockText(w.from) + "-" + clockText(w.to)
}

// toWindow converts a spec, and reports whether it is valid. A window with
// days that repeat or are not weekdays is not valid.
func toWindow(s WindowSpec) (window, bool) {
	w := window{days: anyDay, from: s.From, to: s.To}
	if len(s.Days) > 0 {
		w.days = 0
		for _, d := range s.Days {
			if d < time.Sunday || d > time.Saturday || w.days.has(d) {
				return window{}, false
			}
			w.days |= 1 << uint(d)
		}
	}
	// Whole minutes only: a message shows exactly what is granted.
	return w, w.valid() && w.from%time.Minute == 0 && w.to%time.Minute == 0
}

// checkStanding checks a request for a standing grant (DESIGN.md section
// 8): secrets only, each with standing = true in a rule that is not
// "never", the end inside max_days, 1 to 7 valid windows each not longer
// than max_window, and the uses per window inside max_uses. A config without
// [standing] allows nothing. The count of grants is checked in begin.
func (c *Core) checkStanding(r *Request, p *pending) bool {
	lim := c.cfg.Standing
	ok := lim.Enabled && r.HostKey == nil && r.For == 0 && r.Key == "" && r.RemoteUser == "" &&
		len(r.Hosts) == 0 && len(r.Secrets) > 0 && p.client != "" && r.TokenHash != [32]byte{}
	var refs []ref
	seen := make(map[string]bool)
	for _, name := range r.Secrets {
		if seen[name] {
			continue
		}
		seen[name] = true
		s, known := c.cfg.Secrets[name]
		if !known || p.client == "" || !slices.Contains(s.Clients, p.client) ||
			!s.Rule.Standing || s.Rule.Ask == config.AskNever || !validRule(s.Rule, s.Clients) {
			ok = false
			continue
		}
		p.items = append(p.items, item{ref: ref{name: name}, rule: s.Rule})
		p.subject.Secrets = append(p.subject.Secrets, name)
		refs = append(refs, ref{name: name})
	}
	if len(refs) > MaxPreapproveSecrets {
		ok = false
	}
	if len(r.Windows) < 1 || len(r.Windows) > maxStandingWindows {
		ok = false
	}
	var ws []window
	var texts []string
	for _, spec := range r.Windows {
		w, valid := toWindow(spec)
		if !valid || w.to-w.from > lim.MaxWindow {
			ok = false
			continue
		}
		// Windows must not overlap: a use counts in the first window that
		// holds it, so an overlap would give more uses in one span.
		if slices.ContainsFunc(ws, func(o window) bool {
			return o.days&w.days != 0 && o.from < w.to && w.from < o.to
		}) {
			ok = false
			continue
		}
		ws = append(ws, w)
		texts = append(texts, windowText(w))
	}
	// The times are whole seconds. The end is after now and not more than
	// max_days away, and the start is before the end.
	if r.Uses < 1 || r.Uses > lim.MaxUses || r.NotBefore.IsZero() || r.NotAfter.IsZero() ||
		r.NotBefore.Nanosecond() != 0 || r.NotAfter.Nanosecond() != 0 ||
		!r.NotBefore.Before(r.NotAfter) || !p.start.wall.Before(r.NotAfter) ||
		r.NotAfter.Sub(p.start.wall) > time.Duration(lim.MaxDays)*24*time.Hour {
		ok = false
	}
	if !ok || len(refs) == 0 || len(ws) != len(r.Windows) {
		return false
	}
	p.once = true // the one "Approve" button
	p.subject.Uses = r.Uses
	p.subject.NotBefore = r.NotBefore.UTC().Format(time.RFC3339)
	p.subject.NotAfter = r.NotAfter.UTC().Format(time.RFC3339)
	p.subject.Windows = texts
	p.plan = &grant{
		kind: kindStanding, client: p.client, refs: refs,
		start: r.NotBefore, end: moment{wall: r.NotAfter}, uses: noLimit,
		windows: ws, perWindow: r.Uses, tokenHash: r.TokenHash, oldHashes: [][32]byte{},
	}
	return true
}
