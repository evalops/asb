package vaultdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/haasonsaas/asb/internal/core"
)

type HTTPClientConfig struct {
	BaseURL   string
	Token     string
	Namespace string
	Client    *http.Client
}

type HTTPClient struct {
	baseURL   string
	token     string
	namespace string
	client    *http.Client
}

func NewHTTPClient(cfg HTTPClientConfig) *HTTPClient {
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPClient{
		baseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		token:     cfg.Token,
		namespace: cfg.Namespace,
		client:    client,
	}
}

func (c *HTTPClient) GenerateCredentials(ctx context.Context, role string) (*LeaseCredentials, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/database/creds/"+role, nil)
	if err != nil {
		return nil, err
	}
	c.applyHeaders(request)

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: vault generate credentials returned %d: %s", core.ErrForbidden, response.StatusCode, string(body))
	}

	var payload struct {
		LeaseID       string `json:"lease_id"`
		LeaseDuration int64  `json:"lease_duration"`
		Data          struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return &LeaseCredentials{
		Username:      payload.Data.Username,
		Password:      payload.Data.Password,
		LeaseID:       payload.LeaseID,
		LeaseDuration: time.Duration(payload.LeaseDuration) * time.Second,
	}, nil
}

func (c *HTTPClient) RevokeLease(ctx context.Context, leaseID string) error {
	body, err := json.Marshal(map[string]string{"lease_id": leaseID})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/sys/leases/revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.applyHeaders(request)
	request.Header.Set("Content-Type", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return fmt.Errorf("%w: vault revoke lease returned %d: %s", core.ErrForbidden, response.StatusCode, string(payload))
	}
	return nil
}

func (c *HTTPClient) applyHeaders(request *http.Request) {
	request.Header.Set("X-Vault-Token", c.token)
	if c.namespace != "" {
		request.Header.Set("X-Vault-Namespace", c.namespace)
	}
}
