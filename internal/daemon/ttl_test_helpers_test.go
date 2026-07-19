package daemon

// These registry-size helpers are test-only; production behavior is exposed
// through snapshotRules and the journal preflight predicates.
func (r *ttlRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func (r *ttlRegistry) pendingLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, entry := range r.entries {
		if entry.pending() {
			n++
		}
	}
	return n
}
