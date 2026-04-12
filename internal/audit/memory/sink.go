package memory

import (
	"context"
	"sync"

	"github.com/evalops/asb/internal/core"
)

type Sink struct {
	mu     sync.RWMutex
	events []*core.AuditEvent
}

func NewSink() *Sink {
	return &Sink{
		events: make([]*core.AuditEvent, 0, 16),
	}
}

func (s *Sink) Append(_ context.Context, evt *core.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *evt
	s.events = append(s.events, &cp)
	return nil
}

func (s *Sink) Events() []*core.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*core.AuditEvent, len(s.events))
	for i, evt := range s.events {
		cp := *evt
		out[i] = &cp
	}
	return out
}
