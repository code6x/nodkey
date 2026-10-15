package broker

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
	"github.com/code6x/nodkey/internal/transport"
)

// listKeys answers the list of the keys that the client may use. It is not
// a request for a secret or a signature, so it has no audit entry.
func (rq *request) listKeys(r *http.Request) {
	_, err := transport.ReadJSON[api.KeysRequest](rq.w, r)
	rq.releaseBody()
	if err != nil {
		rq.answered = true
		return
	}
	rq.answerJSON(rq.s.keysOf[rq.client])
}

// sign answers a request for the signature of one SSH login: nodkey
// ssh-agent (DESIGN.md section 6).
func (rq *request) sign(ctx context.Context, r *http.Request) {
	req, err := transport.ReadJSON[api.SignRequest](rq.w, r)
	if err != nil {
		rq.deniedBody()
		return
	}
	cl := approval.Claim{Command: sshCommands(req.Commands), Reason: freeText(req.Reason, maxReasonRunes)}
	rq.pre = audit.Subject{Command: cl.Command, Reason: cl.Reason}
	rq.releaseBody()
	// The key is the one with exactly these bytes, among the keys this
	// client may use. Otherwise there is no message.
	key, ok := rq.s.keyFor(rq.client, req.PublicKey)
	if !ok {
		rq.deny(rq.pre, audit.CauseNotAllowed, "", http.StatusForbidden)
		return
	}
	rq.pre.Key = key.Name()
	// The checks of the data to sign and the session-bind come before any
	// message or place in a queue. A Login holds only checked data.
	login, err := key.Check(sshauth.Request{
		Key: req.PublicKey, Data: req.Data, Flags: agent.SignatureFlags(req.Flags), Binds: req.Binds,
	}, rq.s.cfg.KnownHosts)
	if err != nil {
		rq.deny(rq.pre, audit.CauseNotAllowed, "", http.StatusForbidden)
		// The errors of sshauth are fixed texts, without data from the
		// request. An agent can send many such requests, so these lines
		// are limited per minute.
		if rq.s.refusedLines.allow() {
			rq.s.log.Info("broker: refused an SSH login request", slog.String("request_id", rq.sub.RequestID),
				slog.String("client", rq.client), slog.String("key", rq.pre.Key), slog.String("error", errorText(err)))
		}
		return
	}
	// The Login holds only checked data, for a record of a panic in the
	// core.
	rq.pre.Hosts = []string{login.Host()}
	rq.pre.HostKey, rq.pre.RemoteUser = login.HostKeyFingerprint(), login.RemoteUser()
	res, rc, ok := rq.decide(ctx, &approval.Request{
		Client: rq.client, Kind: audit.KindSSHLogin, Key: login.KeyName(), HostKey: login.HostKey(),
		RemoteUser: login.RemoteUser(), Claim: cl,
	})
	if !ok {
		return
	}
	res.StartGrants()
	// A handler stops before a signature when its context has ended.
	if ctx.Err() != nil {
		rq.cancelled()
		return
	}
	sig, ok := rq.signLogin(rc, key, login)
	if !ok {
		return
	}
	if !rq.handOut(rc, audit.Signed{Subject: rq.sub}) {
		return
	}
	rq.answerJSON(api.SignAnswer{Format: sig.Format, Blob: sig.Blob})
}

// keyFor returns the key whose public key is exactly blob, among the keys
// that client may use.
func (s *Service) keyFor(client string, blob []byte) (sshauth.Key, bool) {
	for _, k := range s.keysOf[client].Keys {
		if bytes.Equal(k.PublicKey, blob) {
			return s.keys[k.Name], true
		}
	}
	return sshauth.Key{}, false
}

// signLogin signs login, the Login that this request's Check returned,
// with key. It needs the receipt of the decision.
func (rq *request) signLogin(rc receipt, key sshauth.Key, login sshauth.Login) (*ssh.Signature, bool) {
	if !rc.valid() {
		rq.fail(audit.CodeSignFailed)
		return nil, false
	}
	rq.failCode = audit.CodeSignFailed
	sig, err := key.Sign(login)
	if err != nil {
		rq.s.log.Error("broker: signing failed; the request is denied", slog.String("request_id", rq.sub.RequestID),
			slog.String("error", errorText(err)))
		rq.fail(audit.CodeSignFailed)
		return nil, false
	}
	return sig, true
}

// grant answers a request for SSH grants: nodkey ssh-grant (DESIGN.md
// section 13). The broker never signs for it; an approval only starts the
// grants.
func (rq *request) grant(ctx context.Context, r *http.Request) {
	req, err := transport.ReadJSON[api.GrantRequest](rq.w, r)
	if err != nil {
		rq.deniedBody()
		return
	}
	cl := approval.Claim{Reason: freeText(req.Reason, maxReasonRunes)}
	sub, ok := rq.s.checkGrant(rq.client, req)
	sub.Reason = cl.Reason
	rq.pre = sub
	rq.releaseBody()
	if !ok {
		rq.deny(sub, audit.CauseNotAllowed, "", http.StatusForbidden)
		return
	}
	res, _, ok := rq.decide(ctx, &approval.Request{
		Client: rq.client, Kind: audit.KindSSHGrant, Key: sub.Key, RemoteUser: sub.RemoteUser,
		Hosts: sub.Hosts, For: time.Duration(req.Seconds) * time.Second, Claim: cl,
	})
	if !ok {
		return
	}
	// The grants are all that an approval gives. When the client has hung
	// up, such as after SIGINT, it tells the agent that the request was
	// cancelled: then no grant starts.
	if ctx.Err() != nil {
		rq.cancelled()
		return
	}
	res.StartGrants()
	rq.ended = true
	rq.answerJSON(api.GrantAnswer{Minutes: res.WindowMinutes})
}

// checkGrant checks an SSH grant (DESIGN.md section 13): the key is in the
// config, allowed for client, and has the "window" rule; the remote user
// name is valid; there are 1 to api.MaxGrantHosts hosts, each in the
// broker's known_hosts, and in the key's hosts list when it has one; and
// the grants last at least one minute and at most the key's window. It
// returns the subject for the audit log with the names that passed, and
// whether every check passed.
func (s *Service) checkGrant(client string, req *api.GrantRequest) (audit.Subject, bool) {
	var sub audit.Subject
	ok := true
	k, known := s.cfg.Keys[req.Key]
	if known && slices.Contains(k.Clients, client) {
		sub.Key = k.Name
		window := int64(k.Rule.Window / time.Second)
		if k.Rule.Ask != config.AskWindow || req.Seconds < 60 || req.Seconds > window {
			ok = false
		}
	} else {
		known, ok = false, false
	}
	if sshauth.ValidUser(req.User) {
		sub.RemoteUser = req.User
	} else {
		ok = false
	}
	if len(req.Hosts) == 0 || len(req.Hosts) > api.MaxGrantHosts {
		ok = false
	}
	seen := make(map[string]bool, len(req.Hosts))
	for _, h := range req.Hosts {
		if seen[h] {
			continue // a host that is listed twice counts once
		}
		seen[h] = true
		if len(s.cfg.KnownHosts.KeysFor(h)) == 0 || (known && len(k.Hosts) > 0 && !slices.Contains(k.Hosts, h)) {
			ok = false
			continue
		}
		sub.Hosts = append(sub.Hosts, h)
	}
	return sub, ok
}
