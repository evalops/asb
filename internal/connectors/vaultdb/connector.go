package vaultdb

import (
	"context"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/haasonsaas/asb/internal/core"
)

type LeaseCredentials struct {
	Username      string
	Password      string
	LeaseID       string
	LeaseDuration time.Duration
}

type Client interface {
	GenerateCredentials(ctx context.Context, role string) (*LeaseCredentials, error)
	RevokeLease(ctx context.Context, leaseID string) error
}

type Config struct {
	Client   Client
	RoleDSNs map[string]string
}

type Connector struct {
	client   Client
	roleDSNs map[string]string
}

func NewConnector(cfg Config) *Connector {
	return &Connector{
		client:   cfg.Client,
		roleDSNs: cfg.RoleDSNs,
	}
}

func (c *Connector) Kind() string {
	return "vaultdb"
}

func (c *Connector) ValidateResource(_ context.Context, req core.ValidateResourceRequest) error {
	resource, err := core.ParseResource(req.ResourceRef)
	if err != nil {
		return err
	}
	if resource.Kind != core.ResourceKindDBRole {
		return fmt.Errorf("%w: vault db connector only supports db roles", core.ErrInvalidRequest)
	}
	if !strings.HasSuffix(resource.Name, "_ro") {
		return fmt.Errorf("%w: v1 only allows read-only db roles", core.ErrForbidden)
	}
	if _, ok := c.roleDSNs[resource.Name]; !ok {
		return fmt.Errorf("%w: no DSN template configured for %q", core.ErrNotFound, resource.Name)
	}
	return nil
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

	lease, err := c.client.GenerateCredentials(ctx, req.Resource.Name)
	if err != nil {
		return nil, err
	}
	dsn, err := renderDSN(c.roleDSNs[req.Resource.Name], lease)
	if err != nil {
		return nil, err
	}

	return &core.IssuedArtifact{
		Kind: core.ArtifactKindWrappedSecret,
		Metadata: map[string]string{
			"artifact_id": "art_" + req.Grant.ID,
			"lease_id":    lease.LeaseID,
			"db_role":     req.Resource.Name,
		},
		SecretData: map[string]string{
			"username": lease.Username,
			"password": lease.Password,
			"dsn":      dsn,
		},
		ExpiresAt: minTime(req.Grant.ExpiresAt, time.Now().Add(lease.LeaseDuration)),
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

func renderDSN(pattern string, lease *LeaseCredentials) (string, error) {
	pattern = strings.ReplaceAll(pattern, "{{username}}", "{{.username}}")
	pattern = strings.ReplaceAll(pattern, "{{password}}", "{{.password}}")
	tpl, err := template.New("dsn").Parse(pattern)
	if err != nil {
		return "", fmt.Errorf("%w: parse dsn template: %v", core.ErrInvalidRequest, err)
	}
	var builder strings.Builder
	if err := tpl.Execute(&builder, map[string]string{
		"username": lease.Username,
		"password": lease.Password,
	}); err != nil {
		return "", fmt.Errorf("%w: render dsn template: %v", core.ErrInvalidRequest, err)
	}
	return builder.String(), nil
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
