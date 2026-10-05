package decision

// CompleteStage releases unused reservations for later stages. A finished
// stage cannot reopen its budget. Future stages keep their own reservations;
// all requests, including borrowers, still count toward the global cap.
func (c *Client) CompleteStage(stage string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.completedStages[stage] {
		return
	}
	c.completedStages[stage] = true
	if limit, ok := c.opts.StageLimits[stage]; ok {
		c.released += max(0, limit-c.stageCalls[stage])
	}
}
