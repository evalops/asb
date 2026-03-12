package vaultdb_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/haasonsaas/asb/internal/connectors/vaultdb"
)

func TestHTTPClient_GenerateCredentialsAndRevokeLease(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/database/creds/analytics_ro":
			if r.Header.Get("X-Vault-Token") != "vault-token" {
				t.Fatalf("vault token = %q, want vault-token", r.Header.Get("X-Vault-Token"))
			}
			_, _ = w.Write([]byte(`{
				"lease_id":"database/creds/analytics_ro/123",
				"lease_duration":600,
				"data":{"username":"dyn-user","password":"dyn-pass"}
			}`))
		case "/v1/sys/leases/revoke":
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"lease_id":"database/creds/analytics_ro/123"}` {
				t.Fatalf("revoke body = %s, want lease id payload", string(body))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	client := vaultdb.NewHTTPClient(vaultdb.HTTPClientConfig{
		BaseURL: server.URL,
		Token:   "vault-token",
		Client:  server.Client(),
	})
	lease, err := client.GenerateCredentials(context.Background(), "analytics_ro")
	if err != nil {
		t.Fatalf("GenerateCredentials() error = %v", err)
	}
	if lease.Username != "dyn-user" || lease.LeaseID != "database/creds/analytics_ro/123" {
		t.Fatalf("lease = %#v, want parsed vault lease", lease)
	}
	if err := client.RevokeLease(context.Background(), lease.LeaseID); err != nil {
		t.Fatalf("RevokeLease() error = %v", err)
	}
}
