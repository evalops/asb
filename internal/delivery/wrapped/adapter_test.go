package wrapped_test

import (
	"context"
	"testing"

	"github.com/haasonsaas/asb/internal/core"
	"github.com/haasonsaas/asb/internal/delivery/wrapped"
)

func TestAdapter_DeliverReturnsArtifactReference(t *testing.T) {
	t.Parallel()

	adapter := wrapped.NewAdapter()
	delivery, err := adapter.Deliver(context.Background(), &core.IssuedArtifact{
		Kind: core.ArtifactKindWrappedSecret,
		Metadata: map[string]string{
			"artifact_id": "art_123",
		},
	}, &core.Session{ID: "sess"}, &core.Grant{ID: "gr"})
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if delivery.Kind != core.DeliveryKindWrappedSecret || delivery.ArtifactID != "art_123" {
		t.Fatalf("delivery = %#v, want wrapped artifact ref", delivery)
	}
}
