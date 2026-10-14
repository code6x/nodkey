package config

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Ask says when the broker asks the approver (DESIGN.md section 8). Only
// AskAlways, AskWindow and AskNever are rules. Any other value, also the
// zero value "", is none of them: code that acts on an Ask must deny it.
type Ask string

// The values of Ask.
const (
	AskAlways Ask = "always" // ask for every request
	AskWindow Ask = "window" // ask; the approver may also allow the next Window
	AskNever  Ask = "never"  // do not ask (DESIGN.md section 12)
)

// MaxWindow is the longest window a "window" rule may have.
const MaxWindow = 8 * time.Hour

// Rule is the rule of one secret or key. Rules come only from LoadBroker,
// which checks them. Do not build one by hand.
//
// The zero values of the fields are the open ones: MaxPerDay 0 means no
// limit, Hours nil means at any time, and Notify false sends no notice.
// For a key, an empty Key.Hosts means any known host. So code that uses a
// rule must fail closed:
//
//   - deny when Ask is not AskAlways, AskWindow or AskNever. The zero Rule
//     has Ask "", which is none of them;
//   - for a key with AskNever, deny when Key.Hosts is empty.
type Rule struct {
	Ask Ask

	// Window is the longest grant an "Approve N min" tap may give. Only
	// for AskWindow: 0 < Window <= MaxWindow.
	Window time.Duration

	// The rest is only for AskNever.

	// Notify sends a silent notice for each use. The default is true.
	Notify bool
	// MaxPerDay is how many uses a day go without asking. Over it, the
	// broker asks. 0 means no limit: max_per_day is not in the file. In
	// the file it must be 1 or more, so that 0 cannot be read as "none".
	MaxPerDay int
	// Hours is the time of day when the rule applies. Outside it, the
	// broker asks. nil means at any time.
	Hours *Hours
}

// ruleKeys holds the rule keys of a [secret.*] or [key.*] section as they
// are written. A nil pointer means the key is not in the file.
type ruleKeys struct {
	Ask       string  `toml:"ask"`
	Window    *string `toml:"window"`
	Notify    *bool   `toml:"notify"`
	MaxPerDay *int    `toml:"max_per_day"`
	Hours     *string `toml:"hours"`
}

// parseRule checks the rule keys of one section. The checks that need the
// rest of the section, such as "never" needing exactly one client, are
// done by the caller.
func parseRule(section string, k ruleKeys) (Rule, error) {
	// The keys each kind of rule allows besides ask.
	allowed := map[Ask]map[string]bool{
		AskAlways: {},
		AskWindow: {"window": true},
		AskNever:  {"notify": true, "max_per_day": true, "hours": true},
	}
	ask := Ask(k.Ask)
	keys, ok := allowed[ask]
	if !ok {
		if k.Ask == "" {
			return Rule{}, fmt.Errorf(`%s: is missing; use "always", "window" or "never"`, place(section, "ask"))
		}
		return Rule{}, fmt.Errorf(`%s: must be "always", "window" or "never"`, place(section, "ask"))
	}
	present := []struct {
		key string
		set bool
	}{
		{"window", k.Window != nil},
		{"notify", k.Notify != nil},
		{"max_per_day", k.MaxPerDay != nil},
		{"hours", k.Hours != nil},
	}
	for _, p := range present {
		if p.set && !keys[p.key] {
			return Rule{}, fmt.Errorf(`%s: is not allowed with ask = %q`, place(section, p.key), ask)
		}
	}

	switch ask {
	case AskAlways:
		return Rule{Ask: AskAlways}, nil
	case AskWindow:
		if k.Window == nil {
			return Rule{}, fmt.Errorf(`%s: is missing; ask = "window" needs it`, place(section, "window"))
		}
		w, err := parseDuration(section, "window", *k.Window)
		if err != nil {
			return Rule{}, err
		}
		if w <= 0 || w > MaxWindow {
			return Rule{}, fmt.Errorf("%s: must be more than 0 and at most %s",
				place(section, "window"), formatDuration(MaxWindow))
		}
		return Rule{Ask: AskWindow, Window: w}, nil
	case AskNever:
		r := Rule{Ask: AskNever, Notify: true}
		if k.Notify != nil {
			r.Notify = *k.Notify
		}
		if k.MaxPerDay != nil {
			if *k.MaxPerDay < 1 {
				return Rule{}, fmt.Errorf("%s: must be 1 or more; for no limit, leave max_per_day out",
					place(section, "max_per_day"))
			}
			r.MaxPerDay = *k.MaxPerDay
		}
		if k.Hours != nil {
			h, err := parseHours(*k.Hours)
			if err != nil {
				return Rule{}, fmt.Errorf("%s: %w", place(section, "hours"), err)
			}
			r.Hours = &h
		}
		return r, nil
	default:
		// Not reached: the allowed map above has every Ask.
		return Rule{}, fmt.Errorf(`%s: must be "always", "window" or "never"`, place(section, "ask"))
	}
}

// Hours is a time of day: from From up to, but not including, To. Both
// are offsets from midnight. When To is before From, the hours wrap past
// midnight: "23:30-00:30" holds 23:45 and 00:15.
type Hours struct {
	From, To time.Duration
}

var hoursPattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])$`)

// parseHours parses "HH:MM-HH:MM", for example "03:00-03:20". The error
// does not repeat the text.
func parseHours(s string) (Hours, error) {
	m := hoursPattern.FindStringSubmatch(s)
	if m == nil {
		return Hours{}, errors.New(`must look like "03:00-03:20" (24-hour clock, HH:MM-HH:MM)`)
	}
	clock := func(hh, mm string) time.Duration {
		h, _ := strconv.Atoi(hh) // the pattern allows only digits
		m, _ := strconv.Atoi(mm)
		return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute
	}
	h := Hours{From: clock(m[1], m[2]), To: clock(m[3], m[4])}
	if h.From == h.To {
		return Hours{}, errors.New("the start and the end must differ")
	}
	return h, nil
}

// Contains reports whether the clock time of t, read in t's own location,
// is inside h. The broker passes the local time, so the hours are broker
// local time. Hours with From equal to To, or with an offset outside one
// day, contain nothing; such a rule then never skips the question.
func (h Hours) Contains(t time.Time) bool {
	const day = 24 * time.Hour
	if h.From == h.To || h.From < 0 || h.To < 0 || h.From >= day || h.To >= day {
		return false
	}
	hh, mm, ss := t.Clock()
	d := time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute +
		time.Duration(ss)*time.Second + time.Duration(t.Nanosecond())
	if h.From < h.To {
		return h.From <= d && d < h.To
	}
	return d >= h.From || d < h.To
}
