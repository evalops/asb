package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/haasonsaas/asb/internal/core"
)

type Engine struct {
	mu       sync.RWMutex
	policies map[string]core.Policy
}

func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]core.Policy),
	}
}

func (e *Engine) Put(policy core.Policy) error {
	if policy.TenantID == "" || policy.Capability == "" {
		return fmt.Errorf("%w: tenant_id and capability are required", core.ErrInvalidRequest)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[key(policy.TenantID, policy.Capability)] = policy
	return nil
}

func (e *Engine) Evaluate(_ context.Context, in *core.DecisionInput) (*core.Decision, error) {
	if in == nil || in.Session == nil || in.Request == nil || in.Tool == nil {
		return nil, fmt.Errorf("%w: incomplete decision input", core.ErrInvalidRequest)
	}

	policy, ok := e.lookup(in.Session.TenantID, in.Request.Capability)
	if !ok {
		return &core.Decision{
			Allowed: false,
			Reason:  "no matching policy",
		}, nil
	}

	if policy.ResourceKind != in.Resource.Kind {
		return denied(policy, "resource kind not allowed"), nil
	}
	if !containsDelivery(policy.AllowedDeliveryModes, in.Request.DeliveryMode) {
		return denied(policy, "delivery mode not allowed by policy"), nil
	}
	if !containsDelivery(in.Tool.AllowedDeliveryModes, in.Request.DeliveryMode) {
		return denied(policy, "delivery mode not allowed by tool"), nil
	}
	if !containsCapability(in.Tool.AllowedCapabilities, in.Request.Capability) {
		return denied(policy, "capability not allowed by tool"), nil
	}
	if !containsAll(in.Tool.TrustTags, policy.RequiredToolTags) {
		return denied(policy, "tool missing required trust tags"), nil
	}
	if ok := evaluateCondition(policy.Condition, in); !ok {
		return denied(policy, "policy condition rejected request"), nil
	}

	return &core.Decision{
		Allowed:      true,
		Reason:       "allowed",
		EffectiveTTL: clampTTL(in.Request.TTL, policy.DefaultTTL, policy.MaxTTL),
		ApprovalMode: policy.ApprovalMode,
		Policy:       policy,
	}, nil
}

func (e *Engine) lookup(tenantID string, capability string) (core.Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	item, ok := e.policies[key(tenantID, capability)]
	return item, ok
}

func key(tenantID string, capability string) string {
	return tenantID + ":" + capability
}

func denied(policy core.Policy, reason string) *core.Decision {
	return &core.Decision{
		Allowed:      false,
		Reason:       reason,
		EffectiveTTL: 0,
		ApprovalMode: policy.ApprovalMode,
		Policy:       policy,
	}
}

func clampTTL(requested time.Duration, fallback time.Duration, max time.Duration) time.Duration {
	if requested <= 0 {
		requested = fallback
	}
	if max > 0 && requested > max {
		return max
	}
	return requested
}

func containsDelivery(have []core.DeliveryMode, want core.DeliveryMode) bool {
	for _, item := range have {
		if item == want {
			return true
		}
	}
	return false
}

func containsCapability(have []string, want string) bool {
	for _, item := range have {
		if item == want {
			return true
		}
		if strings.HasSuffix(item, "*") && strings.HasPrefix(want, strings.TrimSuffix(item, "*")) {
			return true
		}
	}
	return false
}

func containsAll(have []string, required []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, item := range have {
		set[item] = struct{}{}
	}
	for _, item := range required {
		if _, ok := set[item]; !ok {
			return false
		}
	}
	return true
}

func evaluateCondition(expr string, in *core.DecisionInput) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "true" {
		return true
	}

	clauses := strings.Split(expr, "&&")
	for _, rawClause := range clauses {
		clause := strings.TrimSpace(rawClause)
		if clause == "" {
			continue
		}
		if strings.HasPrefix(clause, "session.tool_context.exists(") {
			if !evalExistsClause(clause, in.Session.ToolContext) {
				return false
			}
			continue
		}
		if !evalEqualityClause(clause, in) {
			return false
		}
	}
	return true
}

func evalExistsClause(clause string, items []string) bool {
	const prefix = `session.tool_context.exists(`
	if !strings.HasPrefix(clause, prefix) || !strings.HasSuffix(clause, ")") {
		return false
	}

	body := strings.TrimSuffix(strings.TrimPrefix(clause, prefix), ")")
	parts := strings.SplitN(body, ",", 2)
	if len(parts) != 2 {
		return false
	}

	predicate := strings.TrimSpace(parts[1])
	if !strings.HasPrefix(predicate, "t == ") {
		return false
	}
	expected := strings.Trim(strings.TrimPrefix(predicate, "t == "), `"`)
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func evalEqualityClause(clause string, in *core.DecisionInput) bool {
	parts := strings.SplitN(clause, "==", 2)
	if len(parts) != 2 {
		return false
	}

	lhs := strings.TrimSpace(parts[0])
	rhs := strings.Trim(strings.TrimSpace(parts[1]), `"`)

	switch lhs {
	case "request.tool":
		return in.Request.Tool == rhs
	case "resource.name":
		return in.Resource.Name == rhs
	case "request.origin":
		return in.Resource.Origin == rhs
	case "session.agent_id":
		return in.Session.AgentID == rhs
	default:
		return false
	}
}
