package proxy

import (
	"sync"

	"github.com/evalops/asb/internal/core"
)

type BudgetTracker struct {
	mu       sync.Mutex
	limits   core.ProxyBudget
	active   int
	requests int
	bytes    int64
}

func NewBudgetTracker(limits core.ProxyBudget) *BudgetTracker {
	return &BudgetTracker{
		limits: limits,
	}
}

func (b *BudgetTracker) Acquire() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.limits.MaxRequests > 0 && b.requests >= b.limits.MaxRequests {
		return core.ErrResourceBudgetExceeded
	}
	if b.limits.MaxConcurrent > 0 && b.active >= b.limits.MaxConcurrent {
		return core.ErrResourceBudgetExceeded
	}

	b.active++
	b.requests++
	return nil
}

func (b *BudgetTracker) Complete(responseBytes int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.active > 0 {
		b.active--
	}
	b.bytes += responseBytes
	if b.limits.MaxBytes > 0 && b.bytes > b.limits.MaxBytes {
		return core.ErrResourceBudgetExceeded
	}
	return nil
}
