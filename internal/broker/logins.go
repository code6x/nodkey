package broker

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/grantkey"
	"github.com/code6x/nodkey/internal/loginmatch"
	"github.com/code6x/nodkey/internal/store"
	"github.com/code6x/nodkey/internal/totp"
	"github.com/code6x/nodkey/internal/transport"
)

// Website logins (DESIGN.md section 21).

const (
	// LoginListRate is the most lists of logins that one client may ask for
	// in a minute. There is no tap for a list, so the rate is limited.
	LoginListRate = 10
	// LoginRequestRate is the most requests for a login, or for a login
	// pre-approval, that one client may make in a minute. Each one runs the
	// store (bw sync and get) before any tap.
	LoginRequestRate = 10
	// LoginTOTPNoTicketRate is the most TOTP requests without a ticket or
	// a window grant that one client may have answered with an audit entry
	// in a minute.
	LoginTOTPNoTicketRate = 10
	// LoginTOTPTime is how long a TOTP code may be asked for after an
	// approved login of the same client, item and origin. One code only.
	LoginTOTPTime = 2 * time.Minute

	// maxLoginTickets is the most tickets the broker keeps.
	maxLoginTickets = 1024
)

// itemIDPattern is a Bitwarden item ID.
var itemIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// loginTicket names the one TOTP code that an approved login allows.
type loginTicket struct {
	client, item, origin string
}

// loginState holds what the broker keeps for website logins in memory.
type loginState struct {
	mu      sync.Mutex
	lists   map[string][]time.Time // when each client asked for a list
	reqs    map[string][]time.Time // when each client asked for a login
	noTotp  map[string][]time.Time // TOTP requests without a ticket
	tickets map[loginTicket]time.Time
}

// nowTime returns the time of the Service.
func (s *Service) nowTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now()
}

// allowIn reports whether client may do one more thing now, with at most
// limit in a minute, and counts it. The caller holds s.logins.mu.
func allowIn(m *map[string][]time.Time, now time.Time, client string, limit int) bool {
	if *m == nil {
		*m = make(map[string][]time.Time)
	}
	recent := slices.DeleteFunc((*m)[client], func(t time.Time) bool { return now.Sub(t) >= time.Minute })
	if len(recent) >= limit {
		(*m)[client] = recent
		return false
	}
	(*m)[client] = append(recent, now)
	return true
}

// allowList reports whether client may ask for one more list now, and
// counts it.
func (s *Service) allowList(client string) bool {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	return allowIn(&s.logins.lists, now, client, LoginListRate)
}

// allowLoginRequest is allowList for a login or a login pre-approval.
func (s *Service) allowLoginRequest(client string) bool {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	return allowIn(&s.logins.reqs, now, client, LoginRequestRate)
}

// allowNoTicket is allowList for a TOTP request that has no ticket.
func (s *Service) allowNoTicket(client string) bool {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	return allowIn(&s.logins.noTotp, now, client, LoginTOTPNoTicketRate)
}

// addTicket lets the client take one TOTP code for the login.
func (s *Service) addTicket(t loginTicket) {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	if s.logins.tickets == nil {
		s.logins.tickets = make(map[loginTicket]time.Time)
	}
	for k, end := range s.logins.tickets {
		if !now.Before(end) {
			delete(s.logins.tickets, k)
		}
	}
	if len(s.logins.tickets) >= maxLoginTickets {
		return // fail closed: the code is not available
	}
	s.logins.tickets[t] = now.Add(LoginTOTPTime)
}

// hasTicket reports whether a ticket for t is valid now, without using it.
func (s *Service) hasTicket(t loginTicket) bool {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	end, ok := s.logins.tickets[t]
	return ok && now.Before(end)
}

// takeTicket uses the ticket for t, if it is valid: it is gone after.
func (s *Service) takeTicket(t loginTicket) bool {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	end, ok := s.logins.tickets[t]
	delete(s.logins.tickets, t)
	return ok && now.Before(end)
}

// candidateSections returns the names of the [logins.*] sections that
// name client, in the collection's clients or in the clients of an item
// rule, in name order.
func candidateSections(cfg *config.Broker, client string) []string {
	var names []string
	for name, l := range cfg.Logins {
		if slices.Contains(l.Clients, client) {
			names = append(names, name)
			continue
		}
		for _, it := range l.Items {
			if slices.Contains(it.Clients, client) {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

// holds reports whether the collection IDs include collection.
func holds(collections []string, collection string) bool {
	return slices.ContainsFunc(collections, func(c string) bool { return strings.EqualFold(c, collection) })
}

// loginSel is an item that passed the checks of 21.3.
type loginSel struct {
	section string
	clients []string
	rule    config.Rule // with ask = always for an item with a re-prompt
	meta    store.LoginItem
}

// checkLoginItem checks the item meta, which came from the store named
// from, for client and page against cfg (DESIGN.md section 21.3): exactly
// one configured collection, a section whose store is from, the rule of
// the item, and a URI that matches the page. It returns a fixed reason
// text for the journal when a check fails.
func checkLoginItem(cfg *config.Broker, client string, page loginmatch.Page, meta store.LoginItem, from string) (loginSel, string) {
	var sections []string
	for name, l := range cfg.Logins {
		if holds(meta.Collections, l.Collection) {
			sections = append(sections, name)
		}
	}
	switch {
	case len(sections) == 0:
		return loginSel{}, "the item is in no collection of a [logins.*] section"
	case len(sections) > 1:
		return loginSel{}, "the item is in two configured collections"
	}
	for name, other := range cfg.Logins {
		if _, has := other.Items[strings.ToLower(meta.ID)]; has && name != sections[0] {
			return loginSel{}, "another [logins.*] section has an item rule for the item"
		}
	}
	l := cfg.Logins[sections[0]]
	if l.Store != from {
		return loginSel{}, "the item came from another store than its section's"
	}
	clients, rule, ok := l.RuleFor(strings.ToLower(meta.ID))
	if !ok || !slices.Contains(clients, client) {
		return loginSel{}, "the rule of the item does not name the client"
	}
	if rule.Ask != config.AskAlways && rule.Ask != config.AskWindow {
		return loginSel{}, "the rule of the item is not always or window"
	}
	if !slices.ContainsFunc(meta.URIs, func(u store.LoginURI) bool { return loginmatch.Match(page, u.URI, u.Match) }) {
		return loginSel{}, "no URI of the item matches the page"
	}
	if meta.Reprompt {
		rule.Ask = config.AskAlways
	}
	return loginSel{section: sections[0], clients: clients, rule: rule, meta: meta}, ""
}

// loginStores returns the names of the stores of the sections, once each,
// in the order of the sections.
func loginStores(cfg *config.Broker, sections []string) []string {
	var names []string
	for _, s := range sections {
		if n := cfg.Logins[s].Store; !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// fetchLogin gets the login item from the stores of the sections. Its
// password and seed are in rq.values, so they are cleared on every path;
// the caller clears the returned login as soon as it can. On a failure it
// has answered the request, and ok is false.
//
// A store that cannot find the item (bw exits with an error) is skipped
// for the next store; any other error ends the request.
func (rq *request) fetchLogin(ctx context.Context, cfg *config.Broker, sections []string, item string, sub audit.Subject) (store.Login, string, bool) {
	var lastErr error
	for _, name := range loginStores(cfg, sections) {
		ls, isLS := rq.s.stores[name].(store.LoginStore)
		if !isLS {
			continue
		}
		if ctx.Err() != nil {
			rq.recordDenied(sub, audit.CauseCancelled, "", false)
			rq.answer(http.StatusForbidden)
			return store.Login{}, "", false
		}
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		l, err := ls.FetchLogin(fctx, item)
		cancel()
		if err == nil {
			rq.values = append(rq.values, l.Password, l.TOTP)
			return l, name, true
		}
		l.Clear()
		switch {
		case ctx.Err() != nil:
			rq.recordDenied(sub, audit.CauseCancelled, "", false)
			rq.answer(http.StatusForbidden)
			return store.Login{}, "", false
		case errors.Is(err, store.ErrFailed) && !errors.Is(err, store.ErrLoggedOut) && !errors.Is(err, store.ErrLocked):
			lastErr = err
			continue
		case errors.Is(err, store.ErrTrashed), errors.Is(err, store.ErrArchived), errors.Is(err, store.ErrNotLogin),
			errors.Is(err, store.ErrNoValue):
			rq.refuseLogin(sub, "the item is in the trash, archived, not a login, or has no password")
			return store.Login{}, "", false
		}
		rq.s.log.Warn("broker: a store failed; the request is denied",
			slog.String("client", rq.client), slog.String("store", name), slog.String("error", errorText(err)))
		if errors.Is(err, store.ErrRateLimited) {
			rq.s.rateLimited(name)
		}
		rq.recordDenied(sub, audit.CauseError, audit.CodeStoreFailed, false)
		rq.answer(http.StatusServiceUnavailable)
		return store.Login{}, "", false
	}
	if lastErr != nil {
		rq.s.log.Warn("broker: no store has the login item, or it failed; the request is denied",
			slog.String("client", rq.client), slog.String("error", errorText(lastErr)))
	}
	rq.refuseLogin(sub, "no store has the item")
	return store.Login{}, "", false
}

// refuseLogin denies a request for a login that a check refused. The
// journal gets a fixed reason, never the URL or the item name.
func (rq *request) refuseLogin(sub audit.Subject, reason string) {
	rq.s.log.Info("broker: a request for a website login is denied: "+reason,
		slog.String("client", rq.client))
	rq.deny(sub, audit.CauseNotAllowed, "", http.StatusForbidden)
}

// loginInput reads the page and the item of a request: the URL must be an
// https page that loginmatch accepts, and the item an item ID in lower
// case. On a failure the request is denied.
func (rq *request) loginInput(url, item string) (loginmatch.Page, string, bool) {
	page, err := loginmatch.ParsePage(url)
	if err != nil || !itemIDPattern.MatchString(item) {
		rq.releaseBody()
		rq.s.log.Info("broker: a request for a website login is denied: the page URL or the item ID is not valid",
			slog.String("client", rq.client))
		rq.deny(audit.Subject{}, audit.CauseNotAllowed, "", http.StatusForbidden)
		return loginmatch.Page{}, "", false
	}
	return page, strings.ToLower(item), true
}

// loginScope returns the request of the core for a login.
func loginScope(sel loginSel, origin string) *approval.LoginScope {
	return &approval.LoginScope{
		Section: sel.section, Item: strings.ToLower(sel.meta.ID), Name: sel.meta.Name, Username: sel.meta.Username,
		Origin: origin, Clients: sel.clients, Rule: sel.rule,
	}
}

// checkedLogin fetches the item, checks it, and clears its secrets at
// once: the secrets must not sit in memory while the person decides. It
// returns only what the item says about itself. On a failure the request
// is answered.
func (rq *request) checkedLogin(ctx context.Context, page loginmatch.Page, item string) (loginSel, bool) {
	if !rq.s.allowLoginRequest(rq.client) {
		rq.s.log.Info("broker: a request for a website login is denied: the client asks too often; wait a minute",
			slog.String("client", rq.client))
		rq.recordDenied(audit.Subject{}, audit.CauseLimit, "", true)
		rq.answer(http.StatusTooManyRequests)
		return loginSel{}, false
	}
	cfg := rq.v.cfg
	sections := candidateSections(cfg, rq.client)
	rq.failCode = audit.CodeStoreFailed
	l, from, ok := rq.fetchLogin(ctx, cfg, sections, item, audit.Subject{})
	if !ok {
		return loginSel{}, false
	}
	meta := l.LoginItem
	l.Clear()
	if !strings.EqualFold(meta.ID, item) {
		rq.refuseLogin(audit.Subject{}, "the store answered with another item")
		return loginSel{}, false
	}
	sel, reason := checkLoginItem(cfg, rq.client, page, meta, from)
	if reason != "" {
		rq.refuseLogin(audit.Subject{}, reason)
		return loginSel{}, false
	}
	if !slices.Contains(sections, sel.section) {
		rq.refuseLogin(audit.Subject{}, "the section is not one of the client's")
		return loginSel{}, false
	}
	return sel, true
}

// logins answers a request for a login: username and password (DESIGN.md
// section 21.3).
func (rq *request) logins(ctx context.Context, r *http.Request) {
	req, err := transport.ReadJSON[api.LoginRequest](rq.w, r)
	if err != nil {
		rq.deniedBody()
		return
	}
	if len(r.Header.Values(api.GrantTokenHeader)) > 0 {
		// Standing grants for logins are not built (DESIGN.md section 21.7).
		rq.releaseBody()
		rq.refuseLogin(audit.Subject{}, "a grant token is not used for logins")
		return
	}
	page, item, ok := rq.loginInput(req.URL, req.Item)
	if !ok {
		return
	}
	rq.releaseBody()
	sel, ok := rq.checkedLogin(ctx, page, item)
	if !ok {
		return
	}
	origin := page.Origin()
	rq.pre = audit.Subject{Logins: sel.section, Item: item, Origin: origin}
	res, rc, ok := rq.decide(ctx, &approval.Request{
		Client: rq.client, Kind: audit.KindWebLogin, Login: loginScope(sel, origin),
	})
	if !ok {
		return
	}
	res.StartGrants()
	rq.decided = res.Config()
	// The password is fetched again after the tap: it was cleared during
	// the wait, and the item may have changed.
	if !rc.valid() {
		rq.fail(audit.CodeStoreFailed)
		return
	}
	if ctx.Err() != nil {
		rq.cancelled()
		return
	}
	rq.failCode = audit.CodeStoreFailed
	l, from, ok := rq.fetchApproved(ctx, item)
	if !ok {
		return
	}
	defer l.Clear()
	again, reason := checkLoginItem(rq.s.view().cfg, rq.client, page, l.LoginItem, from)
	if reason != "" || again.section != sel.section || l.Username != sel.meta.Username ||
		l.Name != sel.meta.Name || l.Reprompt != sel.meta.Reprompt || !reflect.DeepEqual(again.rule, sel.rule) ||
		!strings.EqualFold(l.ID, item) || !rq.stillAllowedLogin(sel, item) {
		rq.s.log.Warn("broker: the login item changed while the request waited; the request is denied",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client))
		rq.ended = true
		_, _ = rq.s.append(audit.Denied{Subject: rq.sub, Cause: audit.CauseNotAllowed})
		rq.answer(http.StatusForbidden)
		return
	}
	ans := api.LoginAnswer{Username: l.Username, Password: l.Password.Bytes()}
	body, err := ans.Encode()
	defer clear(body)
	if err != nil {
		rq.s.log.Warn("broker: a login value is longer than the broker hands out; the request is denied",
			slog.String("request_id", rq.sub.RequestID))
		rq.fail(audit.CodeStoreFailed)
		return
	}
	if ctx.Err() != nil {
		rq.cancelled()
		return
	}
	if !rq.handOut(rc, audit.SecretSent{Subject: rq.sub}) {
		return
	}
	rq.answered = true
	// One TOTP code may follow this login.
	rq.s.addTicket(loginTicket{client: rq.client, item: item, origin: origin})
	if err := transport.WriteJSONBody(rq.w, http.StatusOK, body); err != nil {
		rq.s.log.Warn("broker: cannot write the answer; the client may not have it",
			slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client))
	}
}

// fetchApproved gets the item of an approved request again. The stores
// are those of the current config's sections. On a failure the request
// has its end entries and its answer.
func (rq *request) fetchApproved(ctx context.Context, item string) (store.Login, string, bool) {
	cfg := rq.s.view().cfg
	for _, name := range loginStores(cfg, candidateSections(cfg, rq.client)) {
		ls, isLS := rq.s.stores[name].(store.LoginStore)
		if !isLS {
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		l, err := ls.FetchLogin(fctx, item)
		cancel()
		if err == nil {
			rq.values = append(rq.values, l.Password, l.TOTP)
			return l, name, true
		}
		l.Clear()
		if ctx.Err() != nil {
			rq.cancelled()
			return store.Login{}, "", false
		}
		if errors.Is(err, store.ErrFailed) && !errors.Is(err, store.ErrLoggedOut) && !errors.Is(err, store.ErrLocked) {
			continue // not in this store
		}
		rq.s.log.Warn("broker: a store failed; the request is denied",
			slog.String("request_id", rq.sub.RequestID), slog.String("store", name), slog.String("error", errorText(err)))
		if errors.Is(err, store.ErrRateLimited) {
			rq.s.rateLimited(name)
		}
		rq.fail(audit.CodeStoreFailed)
		return store.Login{}, "", false
	}
	rq.fail(audit.CodeStoreFailed)
	return store.Login{}, "", false
}

// stillAllowedLogin checks, after the tap, that a reload did not take away
// what the request uses: the client and its pin, and the rule of the item.
func (rq *request) stillAllowedLogin(sel loginSel, item string) bool {
	if !rq.stillAllowed(rq.decided, nil, "", nil) {
		return false // it has answered
	}
	l, ok := rq.s.view().cfg.Logins[sel.section]
	if !ok {
		return false
	}
	clients, rule, ok := l.RuleFor(item)
	if sel.meta.Reprompt {
		rule.Ask = config.AskAlways // as in checkLoginItem
	}
	return ok && slices.Equal(clients, sel.clients) && slices.Contains(clients, rq.client) &&
		reflect.DeepEqual(rule, sel.rule)
}

// listLogins answers a request for the list of logins of a page. It needs
// no tap, so it never holds a password, and it is limited per client.
func (rq *request) listLogins(ctx context.Context, r *http.Request) {
	req, err := transport.ReadJSON[api.ListLoginsRequest](rq.w, r)
	if err != nil {
		return // ReadJSON has answered
	}
	rq.releaseBody()
	// refuse writes the one entry of a refused list, limited per minute so
	// that a client cannot fill the disk with them, then answers.
	refuse := func(cause audit.ListCause, origin string, status int) {
		if rq.s.refusedAllowed(rq.client) {
			if _, err := rq.s.append(audit.LoginList{Client: rq.client, Origin: origin, Cause: cause}); err != nil {
				status = http.StatusServiceUnavailable
			}
		}
		rq.answer(status)
	}
	page, err := loginmatch.ParsePage(req.URL)
	if err != nil {
		rq.s.log.Info("broker: a request for a list of logins is denied: the page URL is not valid",
			slog.String("client", rq.client))
		refuse(audit.ListBadURL, "", http.StatusForbidden)
		return
	}
	if !rq.s.allowList(rq.client) {
		rq.s.log.Info("broker: a request for a list of logins is denied: the client asks too often; wait a minute",
			slog.String("client", rq.client))
		refuse(audit.ListLimited, page.Origin(), http.StatusTooManyRequests)
		return
	}
	cfg := rq.v.cfg
	var entries []api.LoginEntry
	counts := make(map[string]int)
	for _, name := range candidateSections(cfg, rq.client) {
		l := cfg.Logins[name]
		ls, isLS := rq.s.stores[l.Store].(store.LoginStore)
		if !isLS {
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		items, err := ls.ListLogins(fctx, l.Collection)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				rq.answer(http.StatusForbidden)
				return
			}
			rq.s.log.Warn("broker: a store failed; the list of logins is denied",
				slog.String("client", rq.client), slog.String("store", l.Store), slog.String("error", errorText(err)))
			if errors.Is(err, store.ErrRateLimited) {
				rq.s.rateLimited(l.Store)
			}
			refuse(audit.ListStore, page.Origin(), http.StatusServiceUnavailable)
			return
		}
		counts[name] = 0
		for _, it := range items {
			sel, reason := checkLoginItem(cfg, rq.client, page, it, l.Store)
			if reason != "" || sel.section != name {
				continue
			}
			entries = append(entries, api.LoginEntry{Logins: name, ID: strings.ToLower(it.ID), Name: it.Name, Username: it.Username})
			counts[name]++
		}
	}
	if len(entries) > api.MaxLoginEntries {
		refuse(audit.ListStore, page.Origin(), http.StatusServiceUnavailable)
		return
	}
	// The entries come before the answer; no entry, no list. A section
	// with no match gets an entry with a count of 0.
	for _, name := range slices.Sorted(maps.Keys(counts)) {
		if _, err := rq.s.append(audit.LoginList{Client: rq.client, Logins: name, Origin: page.Origin(), Count: counts[name]}); err != nil {
			rq.answer(http.StatusServiceUnavailable)
			return
		}
	}
	rq.answerJSON(api.ListLoginsAnswer{Logins: entries})
}

// loginTOTP answers a request for the current TOTP code of a login. The
// seed never leaves the broker (DESIGN.md section 21.3).
func (rq *request) loginTOTP(ctx context.Context, r *http.Request) {
	req, err := transport.ReadJSON[api.TOTPRequest](rq.w, r)
	if err != nil {
		return
	}
	rq.releaseBody()
	deny := func(cause audit.TOTPCause, status int, sub audit.Subject) {
		ev := audit.LoginTOTP{Client: rq.client, Logins: sub.Logins, Item: sub.Item, Origin: sub.Origin, Cause: cause}
		if _, err := rq.s.append(ev); err != nil {
			status = http.StatusServiceUnavailable
		}
		rq.answer(status)
	}
	page, item, ok := func() (loginmatch.Page, string, bool) {
		p, err := loginmatch.ParsePage(req.URL)
		if err != nil || !itemIDPattern.MatchString(req.Item) {
			return p, "", false
		}
		return p, strings.ToLower(req.Item), true
	}()
	if !ok {
		deny(audit.TOTPBadItem, http.StatusForbidden, audit.Subject{})
		return
	}
	origin := page.Origin()
	ticket := loginTicket{client: rq.client, item: item, origin: origin}
	// Cheap check first: no ticket and no window grant, no fetch.
	if !rq.s.hasTicket(ticket) && !rq.core.LoginGranted(rq.client, item) {
		if !rq.s.allowNoTicket(rq.client) {
			// Limited: no entry, as for other refused requests over the cap.
			rq.s.log.Info("broker: a request for a TOTP code is denied: the client asks too often without a login; wait a minute",
				slog.String("client", rq.client))
			rq.answer(http.StatusTooManyRequests)
			return
		}
		deny(audit.TOTPNoGrant, http.StatusForbidden, audit.Subject{Logins: "", Item: item, Origin: origin})
		return
	}
	cfg := rq.v.cfg
	sections := candidateSections(cfg, rq.client)
	rq.failCode = ""
	l, from, kind := rq.fetchLoginForTOTP(ctx, cfg, sections, item)
	switch kind {
	case totpFetchStore:
		deny(audit.TOTPStoreFail, http.StatusServiceUnavailable, audit.Subject{})
		return
	case totpFetchRefused:
		deny(audit.TOTPBadItem, http.StatusForbidden, audit.Subject{})
		return
	}
	defer l.Clear()
	sel, reason := checkLoginItem(cfg, rq.client, page, l.LoginItem, from)
	sub := audit.Subject{Logins: sel.section, Item: item, Origin: origin}
	if reason != "" || !strings.EqualFold(l.ID, item) {
		rq.s.log.Info("broker: a request for a TOTP code is denied: "+reason, slog.String("client", rq.client))
		deny(audit.TOTPBadItem, http.StatusForbidden, audit.Subject{})
		return
	}
	if len(l.TOTP.Bytes()) == 0 {
		rq.s.log.Info("broker: the login item has no TOTP seed; ask for a code only for an item that has one",
			slog.String("client", rq.client))
		deny(audit.TOTPNoSeed, http.StatusForbidden, sub)
		return
	}
	key, err := totp.Parse(l.TOTP.Bytes())
	if err != nil {
		rq.s.log.Warn("broker: the TOTP seed of a login item is not in a form nodkey knows; see DESIGN.md section 21.5",
			slog.String("client", rq.client))
		deny(audit.TOTPBadSeed, http.StatusForbidden, sub)
		return
	}
	defer key.Clear()
	// A window grant covers codes while the rule is a window rule and the
	// item has no re-prompt; else a ticket of an approved login is needed.
	byGrant := sel.rule.Ask == config.AskWindow && !sel.meta.Reprompt && rq.core.LoginGranted(rq.client, item)
	if !byGrant && !rq.s.takeTicket(ticket) {
		deny(audit.TOTPNoGrant, http.StatusForbidden, sub)
		return
	}
	code, err := key.Code(rq.s.nowTime())
	if err != nil {
		deny(audit.TOTPBadSeed, http.StatusForbidden, sub)
		return
	}
	ev := audit.LoginTOTP{Client: rq.client, Logins: sub.Logins, Item: item, Origin: origin, Allowed: true}
	if _, err := rq.s.append(ev); err != nil {
		rq.answer(http.StatusServiceUnavailable)
		return
	}
	rq.answerJSON(struct {
		Code string `json:"code"`
	}{Code: code})
}

// totpFetch says how fetchLoginForTOTP ended.
type totpFetch int

const (
	totpFetched      totpFetch = iota // the login is returned
	totpFetchRefused                  // no store has the item, or it was cancelled
	totpFetchStore                    // a store failed
)

// fetchLoginForTOTP is fetchLogin for a request that has no audit subject
// of the core: it does not answer; it says how the fetch ended.
func (rq *request) fetchLoginForTOTP(ctx context.Context, cfg *config.Broker, sections []string, item string) (store.Login, string, totpFetch) {
	for _, name := range loginStores(cfg, sections) {
		ls, isLS := rq.s.stores[name].(store.LoginStore)
		if !isLS {
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		l, err := ls.FetchLogin(fctx, item)
		cancel()
		if err == nil {
			rq.values = append(rq.values, l.Password, l.TOTP)
			return l, name, totpFetched
		}
		l.Clear()
		if ctx.Err() == nil && errors.Is(err, store.ErrFailed) && !errors.Is(err, store.ErrLoggedOut) && !errors.Is(err, store.ErrLocked) {
			continue
		}
		rq.s.log.Warn("broker: a store failed or refused the item; the request for a TOTP code is denied",
			slog.String("client", rq.client), slog.String("store", name), slog.String("error", errorText(err)))
		if errors.Is(err, store.ErrRateLimited) {
			rq.s.rateLimited(name)
		}
		if ctx.Err() != nil || errors.Is(err, store.ErrTrashed) || errors.Is(err, store.ErrArchived) ||
			errors.Is(err, store.ErrNotLogin) || errors.Is(err, store.ErrNoValue) {
			return store.Login{}, "", totpFetchRefused
		}
		return store.Login{}, "", totpFetchStore
	}
	return store.Login{}, "", totpFetchRefused
}

// preapproveLogin answers a request for a one-use pre-approval of a login
// (DESIGN.md section 21.3): one login, in the 60 s after the tap. The
// item is checked as for a login, and its secrets are cleared at once.
func (rq *request) preapproveLogin(ctx context.Context, req *api.PreapproveRequest) {
	if req.Login == "" || req.URL == "" || len(req.Secrets) > 0 || req.Key != "" || req.User != "" ||
		len(req.Hosts) > 0 || req.From != "" || req.Until != "" || req.Uses != 1 || req.Windows != nil {
		rq.releaseBody()
		rq.s.log.Info("broker: a request for a login pre-approval is denied: it must give a login, a URL and one use, and nothing else",
			slog.String("client", rq.client))
		rq.deny(audit.Subject{}, audit.CauseNotAllowed, "", http.StatusForbidden)
		return
	}
	cl := approval.Claim{Reason: freeText(req.Reason, maxReasonRunes)}
	page, item, ok := rq.loginInput(req.URL, req.Login)
	if !ok {
		return
	}
	rq.releaseBody()
	sel, ok := rq.checkedLogin(ctx, page, item)
	if !ok {
		return
	}
	origin := page.Origin()
	rq.pre = audit.Subject{Logins: sel.section, Item: item, Origin: origin, Reason: cl.Reason}
	res, _, ok := rq.decide(ctx, &approval.Request{
		Client: rq.client, Kind: audit.KindPreapprove, Uses: 1, Login: loginScope(sel, origin), Claim: cl,
	})
	if !ok {
		return
	}
	rq.startedGrant(ctx, res, false, grantkey.Token{})
}
