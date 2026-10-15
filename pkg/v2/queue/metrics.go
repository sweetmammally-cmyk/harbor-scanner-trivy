package queue

import "sync/atomic"

// metrics are the queue's counters (P8-5 adds the rest).
type metrics struct {
	leaseLosses    atomic.Int64
	reaperRequeues atomic.Int64
}

func (m *metrics) leaseLost() {
	m.leaseLosses.Add(1)
}
