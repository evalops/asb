package resolver

import (
	"context"
	"fmt"

	"github.com/haasonsaas/asb/internal/core"
)

type StaticResolver struct {
	github  core.Connector
	vault   core.Connector
	browser core.Connector
}

type Option func(*StaticResolver)

func WithGitHub(connector core.Connector) Option {
	return func(r *StaticResolver) {
		r.github = connector
	}
}

func WithVaultDB(connector core.Connector) Option {
	return func(r *StaticResolver) {
		r.vault = connector
	}
}

func WithBrowser(connector core.Connector) Option {
	return func(r *StaticResolver) {
		r.browser = connector
	}
}

func NewStaticResolver(options ...Option) *StaticResolver {
	resolver := &StaticResolver{}
	for _, option := range options {
		option(resolver)
	}
	return resolver
}

func (r *StaticResolver) Resolve(_ context.Context, _ string, resourceRef string) (core.Connector, error) {
	resource, err := core.ParseResource(resourceRef)
	if err != nil {
		return nil, err
	}

	switch resource.Kind {
	case core.ResourceKindGitHubRepo:
		if r.github == nil {
			return nil, fmt.Errorf("%w: github connector not configured", core.ErrNotFound)
		}
		return r.github, nil
	case core.ResourceKindDBRole:
		if r.vault == nil {
			return nil, fmt.Errorf("%w: vault db connector not configured", core.ErrNotFound)
		}
		return r.vault, nil
	case core.ResourceKindBrowserOrigin:
		if r.browser == nil {
			return nil, fmt.Errorf("%w: browser connector not configured", core.ErrNotFound)
		}
		return r.browser, nil
	default:
		return nil, fmt.Errorf("%w: unsupported resource kind %q", core.ErrInvalidRequest, resource.Kind)
	}
}
