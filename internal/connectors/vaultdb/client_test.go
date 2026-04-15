package vaultdb_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evalops/asb/internal/connectors/vaultdb"
	"github.com/evalops/service-runtime/resilience"
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
				"renewable":true,
				"data":{"username":"dyn-user","password":"dyn-pass"}
			}`))
		case "/v1/sys/leases/renew":
			body, _ := io.ReadAll(r.Body)
			if string(body) != `{"increment":1800,"lease_id":"database/creds/analytics_ro/123"}` {
				t.Fatalf("renew body = %s, want lease renew payload", string(body))
			}
			_, _ = w.Write([]byte(`{
				"lease_id":"database/creds/analytics_ro/123",
				"lease_duration":1800,
				"renewable":true
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
	renewed, err := client.RenewLease(context.Background(), lease.LeaseID, 30*time.Minute)
	if err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}
	if renewed.LeaseDuration != 30*time.Minute {
		t.Fatalf("renewed lease = %#v, want renewed duration", renewed)
	}
	if err := client.RevokeLease(context.Background(), lease.LeaseID); err != nil {
		t.Fatalf("RevokeLease() error = %v", err)
	}
}

func TestHTTPClient_RevokeLeaseRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/leases/revoke" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		attempt := attempts.Add(1)
		if attempt < 3 {
			http.Error(w, "vault warming up", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := vaultdb.NewHTTPClient(vaultdb.HTTPClientConfig{
		BaseURL: server.URL,
		Token:   "vault-token",
		Client:  server.Client(),
		RevokeRetry: resilience.RetryConfig{
			MaxAttempts:  4,
			InitialDelay: time.Millisecond,
			MaxDelay:     time.Millisecond,
		},
	})
	if err := client.RevokeLease(context.Background(), "lease-123"); err != nil {
		t.Fatalf("RevokeLease() error = %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("revoke attempts = %d, want 3", attempts.Load())
	}
}

func TestHTTPClient_RevokeLeaseDoesNotRetryPermanentFailures(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/leases/revoke" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		attempts.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	client := vaultdb.NewHTTPClient(vaultdb.HTTPClientConfig{
		BaseURL: server.URL,
		Token:   "vault-token",
		Client:  server.Client(),
		RevokeRetry: resilience.RetryConfig{
			MaxAttempts:  4,
			InitialDelay: time.Millisecond,
			MaxDelay:     time.Millisecond,
		},
	})
	if err := client.RevokeLease(context.Background(), "lease-123"); err == nil {
		t.Fatal("RevokeLease() error = nil, want permanent error")
	}
	if attempts.Load() != 1 {
		t.Fatalf("revoke attempts = %d, want 1", attempts.Load())
	}
}
