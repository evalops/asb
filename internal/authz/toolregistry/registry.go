package toolregistry

import (
	"context"
	"fmt"
	"sync"

	"github.com/haasonsaas/asb/internal/core"
)

type Registry struct {
	mu    sync.RWMutex
	tools map[string]core.Tool
}

func New() *Registry {
	return &Registry{
		tools: make(map[string]core.Tool),
	}
}

func (r *Registry) Put(_ context.Context, tool core.Tool) error {
	if tool.TenantID == "" || tool.Tool == "" {
		return fmt.Errorf("%w: tenant_id and tool are required", core.ErrInvalidRequest)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[key(tool.TenantID, tool.Tool)] = tool
	return nil
}

func (r *Registry) Get(_ context.Context, tenantID string, tool string) (*core.Tool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	item, ok := r.tools[key(tenantID, tool)]
	if !ok {
		return nil, fmt.Errorf("%w: tool %q", core.ErrNotFound, tool)
	}

	cp := item
	return &cp, nil
}

func key(tenantID string, tool string) string {
	return tenantID + ":" + tool
}
