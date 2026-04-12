package postgres_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/evalops/asb/internal/core"
	"github.com/evalops/asb/internal/store/postgres"
	pgxmock "github.com/pashagolub/pgxmock/v4"
)

func TestRepository_SaveAndLookupArtifactByHandle(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer mock.Close()

	repo := postgres.NewRepository(mock)
	secretJSON, _ := json.Marshal(map[string]string{"token": "secret"})
	metadataJSON, _ := json.Marshal(map[string]string{"operations": "pull_request_files"})
	bindingJSON, _ := json.Marshal(map[string]string{"origin": "https://admin.vendor.example"})
	usedAt := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)
	expiresAt := usedAt.Add(10 * time.Minute)

	mock.ExpectExec("INSERT INTO artifacts").
		WithArgs(
			"art_123", "t_acme", "sess_abc", "gr_123", "ph_456", string(core.ArtifactKindProxyHandle),
			"github", secretJSON, metadataJSON, bindingJSON, false, string(core.ArtifactStateIssued), expiresAt, pgxmock.AnyArg(), pgxmock.AnyArg(),
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	if err := repo.SaveArtifact(context.Background(), &core.Artifact{
		ID:            "art_123",
		TenantID:      "t_acme",
		SessionID:     "sess_abc",
		GrantID:       "gr_123",
		Handle:        "ph_456",
		Kind:          core.ArtifactKindProxyHandle,
		ConnectorKind: "github",
		SecretData:    map[string]string{"token": "secret"},
		Metadata:      map[string]string{"operations": "pull_request_files"},
		RecipientBinding: map[string]string{
			"origin": "https://admin.vendor.example",
		},
		SingleUse: false,
		State:     core.ArtifactStateIssued,
		ExpiresAt: expiresAt,
		CreatedAt: usedAt,
	}); err != nil {
		t.Fatalf("SaveArtifact() error = %v", err)
	}

	mock.ExpectQuery("SELECT id, tenant_id, session_id, grant_id, handle").
		WithArgs("ph_456").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "tenant_id", "session_id", "grant_id", "handle", "kind", "connector_kind", "ciphertext", "metadata_json", "recipient_binding_json", "single_use", "state", "expires_at", "created_at", "used_at",
		}).AddRow(
			"art_123", "t_acme", "sess_abc", "gr_123", "ph_456", string(core.ArtifactKindProxyHandle), "github",
			secretJSON, metadataJSON, bindingJSON, false, string(core.ArtifactStateIssued), expiresAt, usedAt, nil,
		))

	artifact, err := repo.GetArtifactByHandle(context.Background(), "ph_456")
	if err != nil {
		t.Fatalf("GetArtifactByHandle() error = %v", err)
	}
	if artifact.Handle != "ph_456" || artifact.GrantID != "gr_123" {
		t.Fatalf("artifact = %#v, want saved artifact", artifact)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("ExpectationsWereMet() error = %v", err)
	}
}

func TestRepository_UseArtifactMarksSingleUse(t *testing.T) {
	t.Parallel()

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer mock.Close()

	repo := postgres.NewRepository(mock)
	secretJSON, _ := json.Marshal(map[string]string{"username": "admin"})
	metadataJSON, _ := json.Marshal(map[string]string{"origin": "https://admin.vendor.example"})
	bindingJSON, _ := json.Marshal(map[string]string{"origin": "https://admin.vendor.example"})
	now := time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC)
	expiresAt := now.Add(10 * time.Minute)

	mock.ExpectQuery("UPDATE artifacts SET state =").
		WithArgs(string(core.ArtifactStateUsed), now, "art_123").
		WillReturnRows(pgxmock.NewRows([]string{
			"id", "tenant_id", "session_id", "grant_id", "handle", "kind", "connector_kind", "ciphertext", "metadata_json", "recipient_binding_json", "single_use", "state", "expires_at", "created_at", "used_at",
		}).AddRow(
			"art_123", "t_acme", "sess_abc", "gr_123", "", string(core.ArtifactKindWrappedSecret), "browser",
			secretJSON, metadataJSON, bindingJSON, true, string(core.ArtifactStateUsed), expiresAt, now, now,
		))

	artifact, err := repo.UseArtifact(context.Background(), "art_123", now)
	if err != nil {
		t.Fatalf("UseArtifact() error = %v", err)
	}
	if artifact.State != core.ArtifactStateUsed {
		t.Fatalf("artifact state = %q, want %q", artifact.State, core.ArtifactStateUsed)
	}
}
