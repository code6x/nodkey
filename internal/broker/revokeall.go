package broker

import (
	"errors"
	"fmt"
	"log/slog"
)

// RevokeAll ends every grant of the core of Run, of every client and kind
// (approval.Core.RevokeAll), and drops every login that a login
// pre-approval keeps (DESIGN.md section 8, "Revoke all"). It is the
// emergency stop: since scheduled and standing grants survive a restart,
// a restart is no stop any more. by says who asked, such as "nodkey
// revoke --all on the broker host"; it is the broker's own text, never
// text of a client. Each scheduled or standing grant gets its grant_ended
// entry (cause revoked), and the approver gets one alert. It returns how
// many grants ended. Before Run, and after the core stopped, it ends
// nothing and returns an error.
func (s *Service) RevokeAll(by string) (int, error) {
	s.mu.Lock()
	core, closed := s.core, s.closed
	s.mu.Unlock()
	if core == nil || closed || s.coreStopped.Load() {
		return 0, errors.New("broker: the service does not run, so it cannot end the grants; start the broker " +
			"(systemctl start nodkey), as root, then run nodkey revoke --all again")
	}
	n := core.RevokeAll()
	s.forgetLogins()
	s.log.Warn("broker: every grant ended, as the person asked", slog.String("by", by), slog.Int("grants_ended", n))
	s.sendAlert(fmt.Sprintf("Every grant ended (%s): %d grant(s). Each later request needs a tap again. "+
		"A client may ask for a new grant with nodkey preapprove.", by, n))
	return n, nil
}
