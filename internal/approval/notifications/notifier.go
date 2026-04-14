package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	"github.com/evalops/asb/internal/core"
	notificationsv1 "github.com/evalops/proto/gen/go/notifications/v1"
	"github.com/evalops/proto/gen/go/notifications/v1/notificationsv1connect"
)

type Config struct {
	BaseURL       string
	BearerToken   string
	WorkspaceID   string
	RecipientID   string
	Channel       notificationsv1.DeliveryChannel
	Priority      notificationsv1.Priority
	PublicBaseURL string
	Client        *http.Client
}

type notificationSender interface {
	Send(context.Context, *connect.Request[notificationsv1.SendRequest]) (*connect.Response[notificationsv1.SendResponse], error)
}

type Notifier struct {
	client        notificationSender
	bearerToken   string
	workspaceID   string
	recipientID   string
	channel       notificationsv1.DeliveryChannel
	priority      notificationsv1.Priority
	publicBaseURL string
}

func NewNotifier(cfg Config) (*Notifier, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("notifications base url is required")
	}
	if strings.TrimSpace(cfg.RecipientID) == "" {
		return nil, fmt.Errorf("notifications recipient id is required")
	}
	if cfg.Channel == notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_UNSPECIFIED {
		return nil, fmt.Errorf("notifications channel is required")
	}
	if cfg.Priority == notificationsv1.Priority_PRIORITY_UNSPECIFIED {
		cfg.Priority = notificationsv1.Priority_PRIORITY_HIGH
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Second}
	}

	return &Notifier{
		client:        notificationsv1connect.NewNotificationServiceClient(cfg.Client, strings.TrimRight(cfg.BaseURL, "/")),
		bearerToken:   strings.TrimSpace(cfg.BearerToken),
		workspaceID:   strings.TrimSpace(cfg.WorkspaceID),
		recipientID:   strings.TrimSpace(cfg.RecipientID),
		channel:       cfg.Channel,
		priority:      cfg.Priority,
		publicBaseURL: strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/"),
	}, nil
}

func NewNotifierWithClient(client notificationSender, cfg Config) (*Notifier, error) {
	if client == nil {
		return nil, fmt.Errorf("notifications client is required")
	}
	if strings.TrimSpace(cfg.RecipientID) == "" {
		return nil, fmt.Errorf("notifications recipient id is required")
	}
	if cfg.Channel == notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_UNSPECIFIED {
		return nil, fmt.Errorf("notifications channel is required")
	}
	if cfg.Priority == notificationsv1.Priority_PRIORITY_UNSPECIFIED {
		cfg.Priority = notificationsv1.Priority_PRIORITY_HIGH
	}

	return &Notifier{
		client:        client,
		bearerToken:   strings.TrimSpace(cfg.BearerToken),
		workspaceID:   strings.TrimSpace(cfg.WorkspaceID),
		recipientID:   strings.TrimSpace(cfg.RecipientID),
		channel:       cfg.Channel,
		priority:      cfg.Priority,
		publicBaseURL: strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/"),
	}, nil
}

func ParseChannel(raw string) (notificationsv1.DeliveryChannel, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "slack":
		return notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_SLACK, nil
	case "email":
		return notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_EMAIL, nil
	case "webhook":
		return notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_WEBHOOK, nil
	case "in_app", "in-app", "inapp":
		return notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_IN_APP, nil
	case "":
		return notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_UNSPECIFIED, fmt.Errorf("notifications channel is required")
	default:
		return notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_UNSPECIFIED, fmt.Errorf("unsupported notifications channel %q", raw)
	}
}

func (n *Notifier) NotifyPending(ctx context.Context, _ *core.ApprovalCallbackConfig, approval *core.Approval, grant *core.Grant) error {
	if approval == nil {
		return fmt.Errorf("approval is required")
	}
	if grant == nil {
		return fmt.Errorf("grant is required")
	}

	workspaceID := n.workspaceID
	if workspaceID == "" {
		workspaceID = approval.TenantID
	}

	metadataJSON, err := json.Marshal(n.buildMetadata(approval, grant, workspaceID))
	if err != nil {
		return fmt.Errorf("marshal approval notification metadata: %w", err)
	}

	req := connect.NewRequest(&notificationsv1.SendRequest{
		WorkspaceId:  workspaceID,
		RecipientId:  n.recipientID,
		Channel:      n.channel,
		Priority:     n.priority,
		Subject:      buildSubject(grant),
		Body:         buildBody(approval, grant),
		MetadataJson: string(metadataJSON),
	})
	if n.bearerToken != "" {
		req.Header().Set("Authorization", "Bearer "+n.bearerToken)
	}

	if _, err := n.client.Send(ctx, req); err != nil {
		return fmt.Errorf("send approval notification %q: %w", approval.ID, err)
	}
	return nil
}

func (n *Notifier) buildMetadata(approval *core.Approval, grant *core.Grant, workspaceID string) map[string]any {
	metadata := map[string]any{
		"approval_id":  approval.ID,
		"grant_id":     grant.ID,
		"tenant_id":    approval.TenantID,
		"workspace_id": workspaceID,
		"requested_by": approval.RequestedBy,
		"tool":         grant.Tool,
		"capability":   grant.Capability,
		"resource_ref": grant.ResourceRef,
		"reason":       approval.Reason,
		"expires_at":   approval.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if n.publicBaseURL != "" {
		metadata["approve_endpoint"] = n.publicBaseURL + "/v1/approvals/" + approval.ID + ":approve"
		metadata["deny_endpoint"] = n.publicBaseURL + "/v1/approvals/" + approval.ID + ":deny"
	}
	return metadata
}

func buildSubject(grant *core.Grant) string {
	return fmt.Sprintf("Approval required: %s on %s", grant.Capability, grant.ResourceRef)
}

func buildBody(approval *core.Approval, grant *core.Grant) string {
	lines := []string{
		fmt.Sprintf("Approval is required for grant %s.", grant.ID),
		fmt.Sprintf("Requested by: %s", approval.RequestedBy),
		fmt.Sprintf("Tool: %s", grant.Tool),
		fmt.Sprintf("Capability: %s", grant.Capability),
		fmt.Sprintf("Resource: %s", grant.ResourceRef),
		fmt.Sprintf("Expires at: %s", approval.ExpiresAt.UTC().Format(time.RFC3339)),
	}
	if approval.Reason != "" {
		lines = append(lines, fmt.Sprintf("Reason: %s", approval.Reason))
	}
	return strings.Join(lines, "\n")
}

var _ core.ApprovalNotifier = (*Notifier)(nil)
