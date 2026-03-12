package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/haasonsaas/asb/internal/core"
)

type Keyfunc func(ctx context.Context, token *jwt.Token) (any, error)

type Config struct {
	Issuer   string
	Audience string
	Keyfunc  Keyfunc
}

type Verifier struct {
	issuer   string
	audience string
	keyfunc  Keyfunc
}

func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" || cfg.Keyfunc == nil {
		return nil, fmt.Errorf("%w: issuer, audience, and keyfunc are required", core.ErrInvalidRequest)
	}
	return &Verifier{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		keyfunc:  cfg.Keyfunc,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, in *core.Attestation) (*core.WorkloadIdentity, error) {
	if in == nil || in.Kind != core.AttestationKindK8SServiceAccountJWT || in.Token == "" {
		return nil, fmt.Errorf("%w: k8s service account attestation is required", core.ErrInvalidRequest)
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(in.Token, claims, func(token *jwt.Token) (any, error) {
		return v.keyfunc(ctx, token)
	}, jwt.WithIssuer(v.issuer), jwt.WithAudience(v.audience))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", core.ErrUnauthorized, err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("%w: invalid service account token", core.ErrUnauthorized)
	}

	subject, _ := claims["sub"].(string)
	if !strings.HasPrefix(subject, "system:serviceaccount:") {
		return nil, fmt.Errorf("%w: unexpected subject %q", core.ErrUnauthorized, subject)
	}

	namespace, _ := claims["kubernetes.io/serviceaccount/namespace"].(string)
	serviceAccount, _ := claims["kubernetes.io/serviceaccount/name"].(string)
	issuer, _ := claims["iss"].(string)

	identity := &core.WorkloadIdentity{
		Type:           core.WorkloadIdentityTypeK8SSA,
		Issuer:         issuer,
		Subject:        subject,
		Audience:       v.audience,
		Namespace:      namespace,
		ServiceAccount: serviceAccount,
		Attributes:     map[string]string{},
	}
	if podUID, ok := claims["kubernetes.io/pod/uid"].(string); ok && podUID != "" {
		identity.Attributes["pod_uid"] = podUID
	}
	return identity, nil
}
