package approval

import (
	"io"
	"time"
)

// SetRandom replaces the source of random bytes for request IDs and short
// codes, for tests of what happens when IDs repeat or the source fails.
func (c *Core) SetRandom(r io.Reader) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.random = r
}

// Counts returns the open messages and the queued requests of a client.
func (c *Core) Counts(client string) (open, queued int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs := c.clients[client]
	if cs == nil {
		return 0, 0
	}
	return cs.open, len(cs.queue)
}

// Live returns how many request IDs and short codes are in use, and how
// many requests wait for an answer.
func (c *Core) Live() (ids, codes, waiting int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ids), len(c.codes), len(c.waiting)
}

// Uses returns how many uses of the "never ask" rule of the secret name,
// or of the key name if key, by client count for the wall time at.
func (c *Core) Uses(client string, key bool, name string, at time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	rule := c.cfg.Secrets[name].Rule
	if key {
		rule = c.cfg.Keys[name].Rule
	}
	return c.uses[useKey{client, ref{key: key, name: name}}].on(useDay(rule, at))
}

// StandingGrants returns the token hash and the number of old hashes of
// each live standing grant of client, with its windows and uses per window.
func (c *Core) StandingGrants(client string) (hashes [][32]byte, oldHashes []int, windows []int, perWindow []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, g := range c.grants {
		if g.standing() && g.client == client {
			hashes = append(hashes, g.tokenHash)
			oldHashes = append(oldHashes, len(g.oldHashes))
			windows = append(windows, len(g.windows))
			perWindow = append(perWindow, g.perWindow)
		}
	}
	return
}
