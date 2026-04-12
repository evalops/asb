package k8s_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/evalops/asb/internal/authn/k8s"
	"github.com/evalops/asb/internal/core"
)

func TestVerifier_VerifyProjectedServiceAccountToken(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	claims := jwt.MapClaims{
		"iss":                                    "https://cluster.example",
		"sub":                                    "system:serviceaccount:agents:runner",
		"aud":                                    []string{"asb-control-plane"},
		"exp":                                    time.Now().Add(5 * time.Minute).Unix(),
		"iat":                                    time.Now().Add(-1 * time.Minute).Unix(),
		"kubernetes.io/serviceaccount/namespace": "agents",
		"kubernetes.io/serviceaccount/name":      "runner",
		"kubernetes.io/pod/uid":                  "pod_123",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier, err := k8s.NewVerifier(k8s.Config{
		Issuer:   "https://cluster.example",
		Audience: "asb-control-plane",
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	identity, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindK8SServiceAccountJWT,
		Token: signed,
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if identity.Type != core.WorkloadIdentityTypeK8SSA {
		t.Fatalf("Type = %q, want %q", identity.Type, core.WorkloadIdentityTypeK8SSA)
	}
	if identity.Namespace != "agents" || identity.ServiceAccount != "runner" {
		t.Fatalf("namespace/service account = %q/%q, want agents/runner", identity.Namespace, identity.ServiceAccount)
	}
}

func TestVerifier_RejectsWrongAudience(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://cluster.example",
		"sub": "system:serviceaccount:agents:runner",
		"aud": []string{"other-audience"},
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	verifier, err := k8s.NewVerifier(k8s.Config{
		Issuer:   "https://cluster.example",
		Audience: "asb-control-plane",
		Keyfunc: func(context.Context, *jwt.Token) (any, error) {
			return publicKey, nil
		},
	})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	if _, err := verifier.Verify(context.Background(), &core.Attestation{
		Kind:  core.AttestationKindK8SServiceAccountJWT,
		Token: signed,
	}); err == nil {
		t.Fatal("Verify() error = nil, want non-nil")
	}
}
