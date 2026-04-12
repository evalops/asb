package browser

import (
	"context"
	"fmt"
	"net/url"

	"github.com/evalops/asb/internal/core"
)

type Credential struct {
	Username string
	Password string
	OTP      string
}

type SelectorMap struct {
	Username string
	Password string
	OTP      string
}

type CredentialStore interface {
	Get(ctx context.Context, origin string) (*Credential, error)
}

type Config struct {
	Credentials  CredentialStore
	SelectorMaps map[string]SelectorMap
}

type Connector struct {
	credentials  CredentialStore
	selectorMaps map[string]SelectorMap
}

func NewConnector(cfg Config) *Connector {
	return &Connector{
		credentials:  cfg.Credentials,
		selectorMaps: cfg.SelectorMaps,
	}
}

func StaticCredentialStore(entries map[string]Credential) CredentialStore {
	return staticCredentialStore(entries)
}

func (c *Connector) Kind() string {
	return "browser"
}

func (c *Connector) ValidateResource(_ context.Context, req core.ValidateResourceRequest) error {
	resource, err := core.ParseResource(req.ResourceRef)
	if err != nil {
		return err
	}
	if resource.Kind != core.ResourceKindBrowserOrigin {
		return fmt.Errorf("%w: browser connector only supports browser origins", core.ErrInvalidRequest)
	}
	if _, err := url.ParseRequestURI(resource.Origin); err != nil {
		return fmt.Errorf("%w: invalid browser origin %q", core.ErrInvalidRequest, resource.Origin)
	}
	if _, ok := c.selectorMaps[resource.Origin]; !ok {
		return fmt.Errorf("%w: no selector map configured for %q", core.ErrNotFound, resource.Origin)
	}
	return nil
}

func (c *Connector) Issue(ctx context.Context, req core.IssueRequest) (*core.IssuedArtifact, error) {
	if req.Session == nil || req.Grant == nil {
		return nil, fmt.Errorf("%w: session and grant are required", core.ErrInvalidRequest)
	}
	if req.Grant.DeliveryMode != core.DeliveryModeWrappedSecret {
		return nil, fmt.Errorf("%w: browser connector only supports wrapped secret delivery", core.ErrInvalidRequest)
	}
	selectorMap, ok := c.selectorMaps[req.Resource.Origin]
	if !ok {
		return nil, fmt.Errorf("%w: no selector map configured for %q", core.ErrNotFound, req.Resource.Origin)
	}
	credential, err := c.credentials.Get(ctx, req.Resource.Origin)
	if err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"artifact_id":       "art_" + req.Grant.ID,
		"origin":            req.Resource.Origin,
		"selector_username": selectorMap.Username,
		"selector_password": selectorMap.Password,
	}
	if selectorMap.OTP != "" {
		metadata["selector_otp"] = selectorMap.OTP
	}

	secretData := map[string]string{
		"username": credential.Username,
		"password": credential.Password,
	}
	if credential.OTP != "" {
		secretData["otp"] = credential.OTP
	}

	return &core.IssuedArtifact{
		Kind:       core.ArtifactKindWrappedSecret,
		Metadata:   metadata,
		SecretData: secretData,
		ExpiresAt:  req.Grant.ExpiresAt,
	}, nil
}

func (c *Connector) Revoke(context.Context, core.RevokeRequest) error {
	return nil
}

type staticCredentialStore map[string]Credential

func (s staticCredentialStore) Get(_ context.Context, origin string) (*Credential, error) {
	value, ok := s[origin]
	if !ok {
		return nil, fmt.Errorf("%w: browser credential for %q", core.ErrNotFound, origin)
	}
	cp := value
	return &cp, nil
}
