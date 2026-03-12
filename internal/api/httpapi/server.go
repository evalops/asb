package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/haasonsaas/asb/internal/core"
)

type Service interface {
	CreateSession(ctx context.Context, req *core.CreateSessionRequest) (*core.CreateSessionResponse, error)
	RequestGrant(ctx context.Context, req *core.RequestGrantRequest) (*core.RequestGrantResponse, error)
	ApproveGrant(ctx context.Context, req *core.ApproveGrantRequest) (*core.RequestGrantResponse, error)
	DenyGrant(ctx context.Context, req *core.DenyGrantRequest) error
	RevokeGrant(ctx context.Context, req *core.RevokeGrantRequest) error
	RevokeSession(ctx context.Context, req *core.RevokeSessionRequest) error
	ExecuteGitHubProxy(ctx context.Context, req *core.ExecuteGitHubProxyRequest) (*core.ExecuteGitHubProxyResponse, error)
	RegisterBrowserRelay(ctx context.Context, req *core.RegisterBrowserRelayRequest) (*core.RegisterBrowserRelayResponse, error)
	UnwrapArtifact(ctx context.Context, req *core.UnwrapArtifactRequest) (*core.UnwrapArtifactResponse, error)
}

type Server struct {
	service Service
}

func NewServer(service Service) *Server {
	return &Server{service: service}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions":
		s.handleCreateSession(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/grants":
		s.handleRequestGrant(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/approvals/") && strings.HasSuffix(r.URL.Path, ":approve"):
		s.handleApproveGrant(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/approvals/") && strings.HasSuffix(r.URL.Path, ":deny"):
		s.handleDenyGrant(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/grants/") && strings.HasSuffix(r.URL.Path, ":revoke"):
		s.handleRevokeGrant(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, ":revoke"):
		s.handleRevokeSession(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/proxy/github/rest":
		s.handleExecuteGitHubProxy(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/browser/relay-sessions":
		s.handleRegisterBrowserRelay(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/artifacts/") && strings.HasSuffix(r.URL.Path, ":unwrap"):
		s.handleUnwrapArtifact(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := s.service.CreateSession(r.Context(), &core.CreateSessionRequest{
		TenantID:    req.TenantID,
		AgentID:     req.AgentID,
		RunID:       req.RunID,
		ToolContext: req.ToolContext,
		Attestation: &core.Attestation{
			Kind:  core.AttestationKind(req.Attestation.Kind),
			Token: req.Attestation.Token,
		},
		DelegationAssertion: req.DelegationAssertion,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":    resp.SessionID,
		"session_token": resp.SessionToken,
		"expires_at":    resp.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleRequestGrant(w http.ResponseWriter, r *http.Request) {
	var req requestGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	resp, err := s.service.RequestGrant(r.Context(), &core.RequestGrantRequest{
		SessionToken: req.SessionToken,
		Tool:         req.Tool,
		Capability:   req.Capability,
		ResourceRef:  req.ResourceRef,
		DeliveryMode: core.DeliveryMode(req.DeliveryMode),
		TTL:          time.Duration(req.TTLSeconds) * time.Second,
		Reason:       req.Reason,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeGrantResponse(w, resp)
}

func (s *Server) handleApproveGrant(w http.ResponseWriter, r *http.Request) {
	var req approvalDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	approvalID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/approvals/"), ":approve")
	resp, err := s.service.ApproveGrant(r.Context(), &core.ApproveGrantRequest{
		ApprovalID: approvalID,
		Approver:   req.Approver,
		Comment:    req.Comment,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeGrantResponse(w, resp)
}

func (s *Server) handleDenyGrant(w http.ResponseWriter, r *http.Request) {
	var req approvalDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}

	approvalID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/approvals/"), ":deny")
	err := s.service.DenyGrant(r.Context(), &core.DenyGrantRequest{
		ApprovalID: approvalID,
		Approver:   req.Approver,
		Comment:    req.Comment,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "denied"})
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, err)
		return
	}

	grantID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/grants/"), ":revoke")
	if err := s.service.RevokeGrant(r.Context(), &core.RevokeGrantRequest{
		GrantID: grantID,
		Reason:  req.Reason,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "revoked"})
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, err)
		return
	}

	sessionID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), ":revoke")
	if err := s.service.RevokeSession(r.Context(), &core.RevokeSessionRequest{
		SessionID: sessionID,
		Reason:    req.Reason,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "revoked"})
}

func (s *Server) handleExecuteGitHubProxy(w http.ResponseWriter, r *http.Request) {
	var req executeGitHubProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := s.service.ExecuteGitHubProxy(r.Context(), &core.ExecuteGitHubProxyRequest{
		ProxyHandle: req.ProxyHandle,
		Operation:   req.Operation,
		Params:      req.Params,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", resp.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp.Payload)
}

func (s *Server) handleRegisterBrowserRelay(w http.ResponseWriter, r *http.Request) {
	var req registerBrowserRelayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}
	resp, err := s.service.RegisterBrowserRelay(r.Context(), &core.RegisterBrowserRelayRequest{
		SessionToken: req.SessionToken,
		KeyID:        req.KeyID,
		PublicKey:    req.PublicKey,
		Origin:       req.Origin,
		TabID:        req.TabID,
		Selectors:    req.Selectors,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": resp.SessionID,
		"key_id":     resp.KeyID,
		"expires_at": resp.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleUnwrapArtifact(w http.ResponseWriter, r *http.Request) {
	var req unwrapArtifactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, err)
		return
	}
	artifactID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/artifacts/"), ":unwrap")
	resp, err := s.service.UnwrapArtifact(r.Context(), &core.UnwrapArtifactRequest{
		SessionToken: req.SessionToken,
		ArtifactID:   artifactID,
		KeyID:        req.KeyID,
		Origin:       req.Origin,
		TabID:        req.TabID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"artifact_id": resp.ArtifactID,
		"origin":      resp.Origin,
		"auto_submit": resp.AutoSubmit,
		"fields":      resp.Fields,
	})
}

func writeGrantResponse(w http.ResponseWriter, resp *core.RequestGrantResponse) {
	payload := map[string]any{
		"grant_id":    resp.GrantID,
		"state":       string(resp.State),
		"approval_id": resp.ApprovalID,
		"expires_at":  resp.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if resp.Delivery != nil {
		payload["delivery"] = map[string]any{
			"kind":        string(resp.Delivery.Kind),
			"handle":      resp.Delivery.Handle,
			"token":       resp.Delivery.Token,
			"artifact_id": resp.Delivery.ArtifactID,
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntaxErr), errors.As(err, &typeErr), errors.Is(err, io.EOF):
		status = http.StatusBadRequest
	case errors.Is(err, core.ErrInvalidRequest):
		status = http.StatusBadRequest
	case errors.Is(err, core.ErrUnauthorized):
		status = http.StatusUnauthorized
	case errors.Is(err, core.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, core.ErrNotFound):
		status = http.StatusNotFound
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

type createSessionRequest struct {
	TenantID            string   `json:"tenant_id"`
	AgentID             string   `json:"agent_id"`
	RunID               string   `json:"run_id"`
	ToolContext         []string `json:"tool_context"`
	DelegationAssertion string   `json:"delegation_assertion"`
	Attestation         struct {
		Kind  string `json:"kind"`
		Token string `json:"token"`
	} `json:"attestation"`
}

type requestGrantRequest struct {
	SessionToken string `json:"session_token"`
	Tool         string `json:"tool"`
	Capability   string `json:"capability"`
	ResourceRef  string `json:"resource_ref"`
	DeliveryMode string `json:"delivery_mode"`
	TTLSeconds   int    `json:"ttl_seconds"`
	Reason       string `json:"reason"`
}

type approvalDecisionRequest struct {
	Approver string `json:"approver"`
	Comment  string `json:"comment"`
}

type revokeRequest struct {
	Reason string `json:"reason"`
}

type executeGitHubProxyRequest struct {
	ProxyHandle string         `json:"proxy_handle"`
	Operation   string         `json:"operation"`
	Params      map[string]any `json:"params"`
}

type registerBrowserRelayRequest struct {
	SessionToken string            `json:"session_token"`
	KeyID        string            `json:"key_id"`
	PublicKey    string            `json:"public_key"`
	Origin       string            `json:"origin"`
	TabID        string            `json:"tab_id"`
	Selectors    map[string]string `json:"selectors"`
}

type unwrapArtifactRequest struct {
	SessionToken string `json:"session_token"`
	KeyID        string `json:"key_id"`
	Origin       string `json:"origin"`
	TabID        string `json:"tab_id"`
}
