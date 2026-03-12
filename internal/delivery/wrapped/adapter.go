package wrapped

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
	return core.DeliveryModeWrappedSecret
}

func (a *Adapter) Deliver(_ context.Context, art *core.IssuedArtifact, _ *core.Session, _ *core.Grant) (*core.Delivery, error) {
	if art == nil || art.Kind != core.ArtifactKindWrappedSecret {
		return nil, fmt.Errorf("%w: wrapped delivery requires a wrapped secret artifact", core.ErrInvalidRequest)
	}
	artifactID := art.Metadata["artifact_id"]
	if artifactID == "" {
		return nil, fmt.Errorf("%w: wrapped delivery requires artifact_id metadata", core.ErrInvalidRequest)
	}
	return &core.Delivery{
		Kind:       core.DeliveryKindWrappedSecret,
		ArtifactID: artifactID,
	}, nil
}
