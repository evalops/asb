package vaultdb_test

import (
	"context"
	"testing"
	"time"

	"github.com/evalops/asb/internal/connectors/vaultdb"
	"github.com/evalops/asb/internal/core"
)

func TestConnector_IssueAndRevokeDynamicCredentials(t *testing.T) {
	t.Parallel()

	client := &fakeVaultClient{
		lease: &vaultdb.LeaseCredentials{
			Username:      "v-token-user",
			Password:      "secret",
			LeaseID:       "database/creds/analytics_ro/123",
			LeaseDuration: 10 * time.Minute,
		},
	}
	connector := vaultdb.NewConnector(vaultdb.Config{
		Client: client,
		RoleDSNs: map[string]string{
			"analytics_ro": "postgres://{{username}}:{{password}}@db.internal:5432/analytics?sslmode=require",
		},
	})

	issued, err := connector.Issue(context.Background(), core.IssueRequest{
		Session: &core.Session{ID: "sess_db", TenantID: "t_acme"},
		Grant: &core.Grant{
			ID:           "gr_db",
			DeliveryMode: core.DeliveryModeWrappedSecret,
			ExpiresAt:    time.Date(2026, 3, 12, 20, 10, 0, 0, time.UTC),
		},
		Resource: core.ResourceDescriptor{
			Kind: core.ResourceKindDBRole,
			Name: "analytics_ro",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if issued.Kind != core.ArtifactKindWrappedSecret {
		t.Fatalf("Kind = %q, want %q", issued.Kind, core.ArtifactKindWrappedSecret)
	}
	if issued.SecretData["dsn"] == "" || issued.Metadata["lease_id"] == "" {
		t.Fatalf("issued artifact = %#v, want dsn and lease id", issued)
	}

	if err := connector.Revoke(context.Background(), core.RevokeRequest{
		Session: &core.Session{ID: "sess_db", TenantID: "t_acme"},
		Grant:   &core.Grant{ID: "gr_db"},
		Artifact: &core.Artifact{
			ID: "art_db",
			Metadata: map[string]string{
				"lease_id": "database/creds/analytics_ro/123",
			},
		},
		Reason: "run_cancelled",
	}); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if client.revokedLeaseID != "database/creds/analytics_ro/123" {
		t.Fatalf("revoked lease = %q, want expected lease", client.revokedLeaseID)
	}
}

type fakeVaultClient struct {
	lease          *vaultdb.LeaseCredentials
	revokedLeaseID string
}

func (f *fakeVaultClient) GenerateCredentials(context.Context, string) (*vaultdb.LeaseCredentials, error) {
	return f.lease, nil
}

func (f *fakeVaultClient) RevokeLease(_ context.Context, leaseID string) error {
	f.revokedLeaseID = leaseID
	return nil
}
