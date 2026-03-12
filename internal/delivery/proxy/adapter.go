package proxy

import (
	"context"
	"fmt"

	"github.com/haasonsaas/asb/internal/core"
)

type Adapter struct{}

func NewAdapter() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Mode() core.DeliveryMode {
	return core.DeliveryModeProxy
}

func (a *Adapter) Deliver(_ context.Context, art *core.IssuedArtifact, _ *core.Session, _ *core.Grant) (*core.Delivery, error) {
	if art == nil || art.Kind != core.ArtifactKindProxyHandle {
		return nil, fmt.Errorf("%w: proxy delivery requires a proxy handle artifact", core.ErrInvalidRequest)
	}
	handle := art.Metadata["handle"]
	if handle == "" {
		return nil, fmt.Errorf("%w: proxy handle metadata is required", core.ErrInvalidRequest)
	}
	return &core.Delivery{
		Kind:   core.DeliveryKindProxyHandle,
		Handle: handle,
	}, nil
}
