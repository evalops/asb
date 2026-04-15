package bootstrap

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewApprovalNotifierDisabledByDefault(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "")
	t.Setenv("ASB_NOTIFICATIONS_WORKSPACE_ID", "")
	t.Setenv("ASB_NOTIFICATIONS_BEARER_TOKEN", "")
	t.Setenv("ASB_PUBLIC_BASE_URL", "")

	notifier, err := newApprovalNotifier()
	if err != nil {
		t.Fatalf("newApprovalNotifier() error = %v", err)
	}
	if notifier != nil {
		t.Fatalf("newApprovalNotifier() = %#v, want nil", notifier)
	}
}

func TestNewApprovalNotifierRequiresBaseURLWhenConfigured(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "approval-queue")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "slack")

	notifier, err := newApprovalNotifier()
	if err == nil || !strings.Contains(err.Error(), "ASB_NOTIFICATIONS_BASE_URL") {
		t.Fatalf("newApprovalNotifier() error = %v, want base url error", err)
	}
	if notifier != nil {
		t.Fatalf("newApprovalNotifier() = %#v, want nil", notifier)
	}
}

func TestNewApprovalNotifierRequiresValidChannel(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "http://notifications:8080")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "approval-queue")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "sms")

	notifier, err := newApprovalNotifier()
	if err == nil || !strings.Contains(err.Error(), "ASB_NOTIFICATIONS_CHANNEL") {
		t.Fatalf("newApprovalNotifier() error = %v, want channel error", err)
	}
	if notifier != nil {
		t.Fatalf("newApprovalNotifier() = %#v, want nil", notifier)
	}
}

func TestNewApprovalNotifierConfigured(t *testing.T) {
	t.Setenv("ASB_NOTIFICATIONS_BASE_URL", "http://notifications:8080")
	t.Setenv("ASB_NOTIFICATIONS_RECIPIENT_ID", "approval-queue")
	t.Setenv("ASB_NOTIFICATIONS_CHANNEL", "slack")
	t.Setenv("ASB_NOTIFICATIONS_WORKSPACE_ID", "ws_control")
	t.Setenv("ASB_NOTIFICATIONS_BEARER_TOKEN", "secret-token")
	t.Setenv("ASB_PUBLIC_BASE_URL", "https://asb.example.com")

	notifier, err := newApprovalNotifier()
	if err != nil {
		t.Fatalf("newApprovalNotifier() error = %v", err)
	}
	if notifier == nil {
		t.Fatal("newApprovalNotifier() = nil, want configured notifier")
	}
}

func TestNewVerifierReturnsOIDCVerifierWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	publicKeyPath := writeEd25519PublicKeyFile(t, dir, "oidc.pub.pem")

	t.Setenv("ASB_K8S_ISSUER", "")
	t.Setenv("ASB_K8S_PUBLIC_KEY_FILE", "")
	t.Setenv("ASB_OIDC_ISSUER", "https://token.actions.githubusercontent.com")
	t.Setenv("ASB_OIDC_PUBLIC_KEY_FILE", publicKeyPath)
	t.Setenv("ASB_OIDC_AUDIENCE", "asb-control-plane")
	t.Setenv("ASB_OIDC_ALLOWED_SUBJECT_PREFIXES", "repo:evalops/")

	verifier, err := newVerifier(true)
	if err != nil {
		t.Fatalf("newVerifier() error = %v", err)
	}
	if verifier == nil {
		t.Fatal("newVerifier() = nil, want configured verifier")
	}
}

func TestNewVerifierRequiresCompleteOIDCConfiguration(t *testing.T) {
	t.Setenv("ASB_K8S_ISSUER", "")
	t.Setenv("ASB_K8S_PUBLIC_KEY_FILE", "")
	t.Setenv("ASB_OIDC_ISSUER", "https://token.actions.githubusercontent.com")
	t.Setenv("ASB_OIDC_PUBLIC_KEY_FILE", "")

	verifier, err := newVerifier(true)
	if err == nil || !strings.Contains(err.Error(), "ASB_OIDC_ISSUER and ASB_OIDC_PUBLIC_KEY_FILE") {
		t.Fatalf("newVerifier() error = %v, want oidc config error", err)
	}
	if verifier != nil {
		t.Fatalf("newVerifier() = %#v, want nil", verifier)
	}
}

func writeEd25519PublicKeyFile(t *testing.T, dir, name string) string {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: encoded}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
