package browser_test

import (
	"context"
	"testing"
	"time"

	"github.com/haasonsaas/asb/internal/connectors/browser"
	"github.com/haasonsaas/asb/internal/core"
)

func TestConnector_ValidateAndIssueBrowserCredential(t *testing.T) {
	t.Parallel()

	connector := browser.NewConnector(browser.Config{
		Credentials: browser.StaticCredentialStore(map[string]browser.Credential{
			"https://admin.vendor.example": {
				Username: "admin",
				Password: "secret",
			},
		}),
		SelectorMaps: map[string]browser.SelectorMap{
			"https://admin.vendor.example": {
				Username: "#username",
				Password: "#password",
			},
		},
	})

	if err := connector.ValidateResource(context.Background(), core.ValidateResourceRequest{
		TenantID:    "t_acme",
		Capability:  "browser.login",
		ResourceRef: "browser_origin:https://admin.vendor.example",
	}); err != nil {
		t.Fatalf("ValidateResource() error = %v", err)
	}

	issued, err := connector.Issue(context.Background(), core.IssueRequest{
		Session: &core.Session{ID: "sess_browser", TenantID: "t_acme"},
		Grant: &core.Grant{
			ID:           "gr_browser",
			DeliveryMode: core.DeliveryModeWrappedSecret,
			ExpiresAt:    time.Date(2026, 3, 12, 20, 5, 0, 0, time.UTC),
		},
		Resource: core.ResourceDescriptor{
			Kind:   core.ResourceKindBrowserOrigin,
			Name:   "https://admin.vendor.example",
			Origin: "https://admin.vendor.example",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if issued.Kind != core.ArtifactKindWrappedSecret {
		t.Fatalf("Kind = %q, want %q", issued.Kind, core.ArtifactKindWrappedSecret)
	}
	if issued.Metadata["selector_username"] != "#username" || issued.SecretData["password"] != "secret" {
		t.Fatalf("issued artifact = %#v, want selectors and secret data", issued)
	}
}
