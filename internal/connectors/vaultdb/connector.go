package vaultdb

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/evalops/asb/internal/core"
)

type LeaseCredentials struct {
	Username      string
	Password      string
	LeaseID       string
	LeaseDuration time.Duration
	Renewable     bool
}

type Client interface {
	GenerateCredentials(ctx context.Context, role string) (*LeaseCredentials, error)
	RenewLease(ctx context.Context, leaseID string, increment time.Duration) (*LeaseCredentials, error)
	RevokeLease(ctx context.Context, leaseID string) error
}

type Config struct {
	AllowedRoleSuffixes []string
	Client              Client
	RoleDSNs            map[string]string
}

type Connector struct {
	allowedRoleSuffixes []string
	client              Client
	roleDSNs            map[string]string
}

func NewConnector(cfg Config) (*Connector, error) {
	roleDSNs, err := normalizeRoleDSNs(cfg.RoleDSNs)
	if err != nil {
		return nil, err
	}
	allowedRoleSuffixes := normalizeRoleSuffixes(cfg.AllowedRoleSuffixes)
	for role := range roleDSNs {
		if !roleHasAllowedSuffix(role, allowedRoleSuffixes) {
			return nil, fmt.Errorf("%w: db role %q must match one of the allowed suffixes %v", core.ErrInvalidRequest, role, allowedRoleSuffixes)
		}
	}
	return &Connector{
		allowedRoleSuffixes: allowedRoleSuffixes,
		client:              cfg.Client,
		roleDSNs:            roleDSNs,
	}, nil
}

func normalizeRoleDSNs(roleDSNs map[string]string) (map[string]string, error) {
	if len(roleDSNs) == 0 {
		return map[string]string{}, nil
	}

	normalized := make(map[string]string, len(roleDSNs))
	for role, pattern := range roleDSNs {
		renderPattern, err := normalizeDSNTemplate(pattern)
		if err != nil {
			return nil, fmt.Errorf("%w: role %q: %v", core.ErrInvalidRequest, role, err)
		}
		normalized[role] = renderPattern
	}
	return normalized, nil
}

func normalizeRoleSuffixes(suffixes []string) []string {
	if len(suffixes) == 0 {
		return []string{"_ro"}
	}

	normalized := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		trimmed := strings.TrimSpace(suffix)
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	if len(normalized) == 0 {
		return []string{"_ro"}
	}
	return normalized
}

func (c *Connector) Kind() string {
	return "vaultdb"
}

func (c *Connector) ValidateResource(_ context.Context, req core.ValidateResourceRequest) error {
	resource, err := core.ParseResource(req.ResourceRef)
	if err != nil {
		return err
	}
	return c.validateRole(resource.Kind, resource.Name)
}

func (c *Connector) Issue(ctx context.Context, req core.IssueRequest) (*core.IssuedArtifact, error) {
	if c.client == nil {
		return nil, fmt.Errorf("%w: vault client is required", core.ErrInvalidRequest)
	}
	if req.Grant == nil || req.Session == nil {
		return nil, fmt.Errorf("%w: session and grant are required", core.ErrInvalidRequest)
	}
	if req.Grant.DeliveryMode != core.DeliveryModeWrappedSecret {
		return nil, fmt.Errorf("%w: vault db connector only supports wrapped secret delivery", core.ErrInvalidRequest)
	}
	if err := c.validateRole(req.Resource.Kind, req.Resource.Name); err != nil {
		return nil, err
	}

	lease, err := c.client.GenerateCredentials(ctx, req.Resource.Name)
	if err != nil {
		return nil, err
	}
	extendedLease, leaseExpiresAt, err := c.extendLeaseForGrant(ctx, lease, req.Grant.ExpiresAt)
	if err != nil {
		if lease != nil && lease.LeaseID != "" {
			_ = c.client.RevokeLease(ctx, lease.LeaseID)
		}
		return nil, err
	}
	lease = extendedLease
	dsn, err := renderDSN(c.roleDSNs[req.Resource.Name], lease)
	if err != nil {
		return nil, err
	}

	return &core.IssuedArtifact{
		Kind: core.ArtifactKindWrappedSecret,
		Metadata: map[string]string{
			"artifact_id":      "art_" + req.Grant.ID,
			"lease_id":         lease.LeaseID,
			"lease_expires_at": leaseExpiresAt.UTC().Format(time.RFC3339),
			"db_role":          req.Resource.Name,
		},
		SecretData: map[string]string{
			"username": lease.Username,
			"password": lease.Password,
			"dsn":      dsn,
		},
		ExpiresAt: minTime(req.Grant.ExpiresAt, leaseExpiresAt),
	}, nil
}

func (c *Connector) Revoke(ctx context.Context, req core.RevokeRequest) error {
	if c.client == nil || req.Artifact == nil {
		return nil
	}
	leaseID := req.Artifact.Metadata["lease_id"]
	if leaseID == "" {
		return nil
	}
	return c.client.RevokeLease(ctx, leaseID)
}

func (c *Connector) validateRole(kind core.ResourceKind, role string) error {
	if kind != core.ResourceKindDBRole {
		return fmt.Errorf("%w: vault db connector only supports db roles", core.ErrInvalidRequest)
	}
	if !c.allowedRole(role) {
		return fmt.Errorf("%w: db role %q must match one of the allowed suffixes %v", core.ErrForbidden, role, c.allowedRoleSuffixes)
	}
	if _, ok := c.roleDSNs[role]; !ok {
		return fmt.Errorf("%w: no DSN template configured for %q", core.ErrNotFound, role)
	}
	return nil
}

func (c *Connector) allowedRole(role string) bool {
	return roleHasAllowedSuffix(role, c.allowedRoleSuffixes)
}

func roleHasAllowedSuffix(role string, allowedRoleSuffixes []string) bool {
	for _, suffix := range allowedRoleSuffixes {
		if strings.HasSuffix(role, suffix) {
			return true
		}
	}
	return false
}

func normalizeDSNTemplate(pattern string) (string, error) {
	trimmed := strings.TrimSpace(pattern)
	if !strings.Contains(trimmed, "{{username}}") || !strings.Contains(trimmed, "{{password}}") {
		return "", fmt.Errorf("dsn template must include {{username}} and {{password}} placeholders")
	}
	trimmed = strings.ReplaceAll(trimmed, "{{username}}", "{{.username}}")
	trimmed = strings.ReplaceAll(trimmed, "{{password}}", "{{.password}}")
	if _, err := template.New("dsn").Parse(trimmed); err != nil {
		return "", fmt.Errorf("parse dsn template: %v", err)
	}
	return trimmed, nil
}

func renderDSN(renderPattern string, lease *LeaseCredentials) (string, error) {
	tpl, err := template.New("dsn").Parse(renderPattern)
	if err != nil {
		return "", fmt.Errorf("%w: parse dsn template: %v", core.ErrInvalidRequest, err)
	}
	var builder strings.Builder
	if err := tpl.Execute(&builder, map[string]string{
		"username": url.PathEscape(lease.Username),
		"password": url.PathEscape(lease.Password),
	}); err != nil {
		return "", fmt.Errorf("%w: render dsn template: %v", core.ErrInvalidRequest, err)
	}
	return builder.String(), nil
}

func (c *Connector) extendLeaseForGrant(ctx context.Context, lease *LeaseCredentials, grantExpiresAt time.Time) (*LeaseCredentials, time.Time, error) {
	now := time.Now()
	leaseExpiresAt := now.Add(lease.LeaseDuration)
	if grantExpiresAt.IsZero() || !grantExpiresAt.After(leaseExpiresAt) {
		return lease, leaseExpiresAt, nil
	}
	if lease.LeaseID == "" || !lease.Renewable {
		return nil, time.Time{}, fmt.Errorf("%w: vault lease expires before the requested grant ttl and is not renewable", core.ErrForbidden)
	}

	remaining := time.Until(grantExpiresAt)
	renewed, err := c.client.RenewLease(ctx, lease.LeaseID, remaining)
	if err != nil {
		return nil, time.Time{}, err
	}
	merged := mergeLeaseCredentials(lease, renewed)
	leaseExpiresAt = time.Now().Add(merged.LeaseDuration)
	if grantExpiresAt.After(leaseExpiresAt) {
		return nil, time.Time{}, fmt.Errorf("%w: vault lease renewal for %q was capped before the requested grant ttl", core.ErrForbidden, lease.LeaseID)
	}
	return merged, leaseExpiresAt, nil
}

func mergeLeaseCredentials(current *LeaseCredentials, updated *LeaseCredentials) *LeaseCredentials {
	if updated == nil {
		return current
	}
	merged := *current
	if updated.Username != "" {
		merged.Username = updated.Username
	}
	if updated.Password != "" {
		merged.Password = updated.Password
	}
	if updated.LeaseID != "" {
		merged.LeaseID = updated.LeaseID
	}
	if updated.LeaseDuration > 0 {
		merged.LeaseDuration = updated.LeaseDuration
	}
	merged.Renewable = updated.Renewable
	return &merged
}

func minTime(a time.Time, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.Before(a) {
		return b
	}
	return a
}
