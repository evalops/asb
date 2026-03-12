package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/haasonsaas/asb/internal/authz/policy"
	"github.com/haasonsaas/asb/internal/core"
)

func TestEngine_EvaluateAllowsAndClampsTTL(t *testing.T) {
	t.Parallel()

	engine := policy.NewEngine()
	if err := engine.Put(core.Policy{
		TenantID:             "t_acme",
		Capability:           "repo.read",
		ResourceKind:         core.ResourceKindGitHubRepo,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               10 * time.Minute,
		ApprovalMode:         core.ApprovalModeNone,
		RequiredToolTags:     []string{"trusted", "github"},
		Condition:            `request.tool == "github" && resource.name == "acme/widgets" && session.agent_id == "agent_pr_reviewer"`,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	decision, err := engine.Evaluate(context.Background(), &core.DecisionInput{
		Session: &core.Session{
			TenantID:    "t_acme",
			AgentID:     "agent_pr_reviewer",
			ToolContext: []string{"github"},
		},
		Request: &core.RequestGrantRequest{
			Tool:         "github",
			Capability:   "repo.read",
			ResourceRef:  "github:repo:acme/widgets",
			DeliveryMode: core.DeliveryModeProxy,
			TTL:          20 * time.Minute,
		},
		Tool: &core.Tool{
			Tool:                 "github",
			AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeProxy},
			AllowedCapabilities:  []string{"repo.read"},
			TrustTags:            []string{"trusted", "github"},
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindGitHubRepo,
			Name: "acme/widgets",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("Allowed = false, want true: %s", decision.Reason)
	}
	if decision.EffectiveTTL != 10*time.Minute {
		t.Fatalf("EffectiveTTL = %s, want %s", decision.EffectiveTTL, 10*time.Minute)
	}
	if decision.ApprovalMode != core.ApprovalModeNone {
		t.Fatalf("ApprovalMode = %q, want %q", decision.ApprovalMode, core.ApprovalModeNone)
	}
}

func TestEngine_EvaluateRejectsMissingRequiredToolTag(t *testing.T) {
	t.Parallel()

	engine := policy.NewEngine()
	if err := engine.Put(core.Policy{
		TenantID:             "t_acme",
		Capability:           "browser.login",
		ResourceKind:         core.ResourceKindBrowserOrigin,
		AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
		DefaultTTL:           2 * time.Minute,
		MaxTTL:               5 * time.Minute,
		ApprovalMode:         core.ApprovalModeLiveHuman,
		RequiredToolTags:     []string{"trusted", "browser"},
		Condition:            `request.origin == "https://admin.vendor.example"`,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	decision, err := engine.Evaluate(context.Background(), &core.DecisionInput{
		Session: &core.Session{
			TenantID:    "t_acme",
			AgentID:     "browser_agent",
			ToolContext: []string{"browser"},
		},
		Request: &core.RequestGrantRequest{
			Tool:         "browser",
			Capability:   "browser.login",
			ResourceRef:  "browser_origin:https://admin.vendor.example",
			DeliveryMode: core.DeliveryModeWrappedSecret,
			TTL:          5 * time.Minute,
		},
		Tool: &core.Tool{
			Tool:                 "browser",
			AllowedDeliveryModes: []core.DeliveryMode{core.DeliveryModeWrappedSecret},
			AllowedCapabilities:  []string{"browser.login"},
			TrustTags:            []string{"browser"},
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindBrowserOrigin,
			Name: "https://admin.vendor.example",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Allowed {
		t.Fatalf("Allowed = true, want false")
	}
	if decision.Reason == "" {
		t.Fatal("Reason = empty, want rejection reason")
	}
}
