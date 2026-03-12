package proxy_test

import (
	"errors"
	"testing"

	"github.com/haasonsaas/asb/internal/core"
	"github.com/haasonsaas/asb/internal/delivery/proxy"
)

func TestBudgetTracker_EnforcesConcurrencyRequestAndByteBudgets(t *testing.T) {
	t.Parallel()

	tracker := proxy.NewBudgetTracker(core.ProxyBudget{
		MaxConcurrent: 1,
		MaxRequests:   2,
		MaxBytes:      10,
	})

	if err := tracker.Acquire(); err != nil {
		t.Fatalf("Acquire() error = %v, want nil", err)
	}
	if err := tracker.Acquire(); !errors.Is(err, core.ErrResourceBudgetExceeded) {
		t.Fatalf("Acquire() second error = %v, want %v", err, core.ErrResourceBudgetExceeded)
	}
	if err := tracker.Complete(4); err != nil {
		t.Fatalf("Complete() error = %v, want nil", err)
	}

	if err := tracker.Acquire(); err != nil {
		t.Fatalf("Acquire() after completion error = %v, want nil", err)
	}
	if err := tracker.Complete(7); !errors.Is(err, core.ErrResourceBudgetExceeded) {
		t.Fatalf("Complete() byte budget error = %v, want %v", err, core.ErrResourceBudgetExceeded)
	}
	if err := tracker.Acquire(); !errors.Is(err, core.ErrResourceBudgetExceeded) {
		t.Fatalf("Acquire() request budget error = %v, want %v", err, core.ErrResourceBudgetExceeded)
	}
}
