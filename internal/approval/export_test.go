package approval

import "io"

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
