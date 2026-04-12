package delegationjwt_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/evalops/asb/internal/authn/delegationjwt"
	"github.com/evalops/asb/internal/core"
)

func TestValidator_ValidateSignedDelegation(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)
	raw := mustSignDelegation(t, privateKey, jwt.MapClaims{
		"iss":                  "app.evalops.example",
		"sub":                  "user:jonathan",
		"tenant_id":            "t_acme",
		"agent_id":             "agent_pr_reviewer",
		"allowed_capabilities": []string{"repo.read", "db.read"},
		"resource_filters": map[string][]string{
			"repo":    []string{"acme/widgets"},
			"db_role": []string{"analytics_ro"},
		},
		"exp": now.Add(10 * time.Minute).Unix(),
	})

	validator, err := delegationjwt.NewValidator(delegationjwt.Config{
		Issuers: map[string]ed25519.PublicKey{
			"app.evalops.example": publicKey,
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}

	delegation, err := validator.Validate(context.Background(), raw, "t_acme", "agent_pr_reviewer")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if delegation.Subject != "user:jonathan" {
		t.Fatalf("Subject = %q, want user:jonathan", delegation.Subject)
	}
	if len(delegation.AllowedCapabilities) != 2 {
		t.Fatalf("AllowedCapabilities len = %d, want 2", len(delegation.AllowedCapabilities))
	}
	if delegation.ResourceFilters["repo"][0] != "acme/widgets" {
		t.Fatalf("repo filter = %#v, want acme/widgets", delegation.ResourceFilters["repo"])
	}
}

func TestValidator_RejectsTenantMismatch(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)
	raw := mustSignDelegation(t, privateKey, jwt.MapClaims{
		"iss":                  "app.evalops.example",
		"sub":                  "user:jonathan",
		"tenant_id":            "t_other",
		"agent_id":             "agent_pr_reviewer",
		"allowed_capabilities": []string{"repo.read"},
		"exp":                  now.Add(10 * time.Minute).Unix(),
	})

	validator, err := delegationjwt.NewValidator(delegationjwt.Config{
		Issuers: map[string]ed25519.PublicKey{
			"app.evalops.example": publicKey,
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewValidator() error = %v", err)
	}

	if _, err := validator.Validate(context.Background(), raw, "t_acme", "agent_pr_reviewer"); err == nil {
		t.Fatal("Validate() error = nil, want non-nil")
	}
}

func mustSignDelegation(t *testing.T, privateKey ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return signed
}

var _ core.DelegationValidator = (*delegationjwt.Validator)(nil)
