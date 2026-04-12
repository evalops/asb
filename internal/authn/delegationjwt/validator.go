package delegationjwt

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/evalops/asb/internal/core"
)

type Config struct {
	Issuers map[string]ed25519.PublicKey
	Now     func() time.Time
}

type Validator struct {
	issuers map[string]ed25519.PublicKey
	now     func() time.Time
}

type claims struct {
	AgentID             string              `json:"agent_id"`
	TenantID            string              `json:"tenant_id"`
	AllowedCapabilities []string            `json:"allowed_capabilities"`
	ResourceFilters     map[string][]string `json:"resource_filters"`
	JTI                 string              `json:"jti"`
	jwt.RegisteredClaims
}

func NewValidator(cfg Config) (*Validator, error) {
	if len(cfg.Issuers) == 0 {
		return nil, fmt.Errorf("%w: at least one issuer key is required", core.ErrInvalidRequest)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Validator{
		issuers: cfg.Issuers,
		now:     cfg.Now,
	}, nil
}

func (v *Validator) Validate(_ context.Context, raw string, tenantID string, agentID string) (*core.Delegation, error) {
	if raw == "" || tenantID == "" || agentID == "" {
		return nil, fmt.Errorf("%w: raw assertion, tenant_id, and agent_id are required", core.ErrInvalidRequest)
	}

	parser := jwt.NewParser()
	unverified := &claims{}
	if _, _, err := parser.ParseUnverified(raw, unverified); err != nil {
		return nil, fmt.Errorf("%w: parse unverified delegation: %v", core.ErrUnauthorized, err)
	}

	publicKey, ok := v.issuers[unverified.Issuer]
	if !ok {
		return nil, fmt.Errorf("%w: untrusted delegation issuer %q", core.ErrUnauthorized, unverified.Issuer)
	}

	verified, err := jwt.ParseWithClaims(raw, &claims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("%w: unexpected signing method %q", core.ErrUnauthorized, token.Method.Alg())
		}
		return publicKey, nil
	}, jwt.WithTimeFunc(v.now))
	if err != nil {
		return nil, fmt.Errorf("%w: verify delegation: %v", core.ErrUnauthorized, err)
	}

	tokenClaims, ok := verified.Claims.(*claims)
	if !ok || !verified.Valid {
		return nil, fmt.Errorf("%w: invalid delegation assertion", core.ErrUnauthorized)
	}
	if tokenClaims.TenantID != tenantID {
		return nil, fmt.Errorf("%w: delegation tenant mismatch", core.ErrForbidden)
	}
	if tokenClaims.AgentID != agentID {
		return nil, fmt.Errorf("%w: delegation agent mismatch", core.ErrForbidden)
	}
	if tokenClaims.ExpiresAt == nil || v.now().After(tokenClaims.ExpiresAt.Time) {
		return nil, fmt.Errorf("%w: delegation expired", core.ErrForbidden)
	}

	return &core.Delegation{
		ID:                  tokenClaims.JTI,
		Issuer:              tokenClaims.Issuer,
		Subject:             tokenClaims.Subject,
		TenantID:            tokenClaims.TenantID,
		AgentID:             tokenClaims.AgentID,
		AllowedCapabilities: append([]string(nil), tokenClaims.AllowedCapabilities...),
		ResourceFilters:     cloneResourceFilters(tokenClaims.ResourceFilters),
		ExpiresAt:           tokenClaims.ExpiresAt.Time,
	}, nil
}

func cloneResourceFilters(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
