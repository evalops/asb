package proxy_test

import (
	"context"
	"testing"

	"github.com/evalops/asb/internal/core"
	"github.com/evalops/asb/internal/delivery/proxy"
)

func TestAdapter_DeliverReturnsProxyHandle(t *testing.T) {
	t.Parallel()

	adapter := proxy.NewAdapter()
	delivery, err := adapter.Deliver(context.Background(), &core.IssuedArtifact{
		Kind: core.ArtifactKindProxyHandle,
		Metadata: map[string]string{
			"handle": "ph_123",
		},
	}, &core.Session{ID: "sess"}, &core.Grant{ID: "gr"})
	if err != nil {
		t.Fatalf("Deliver() error = %v", err)
	}
	if delivery.Kind != core.DeliveryKindProxyHandle || delivery.Handle != "ph_123" {
		t.Fatalf("delivery = %#v, want proxy handle", delivery)
	}
}
