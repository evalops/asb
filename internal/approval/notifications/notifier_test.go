package notifications

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	"github.com/evalops/asb/internal/core"
	notificationsv1 "github.com/evalops/proto/gen/go/notifications/v1"
)

type fakeNotificationSender struct {
	send func(context.Context, *connect.Request[notificationsv1.SendRequest]) (*connect.Response[notificationsv1.SendResponse], error)
}

func (f fakeNotificationSender) Send(ctx context.Context, req *connect.Request[notificationsv1.SendRequest]) (*connect.Response[notificationsv1.SendResponse], error) {
	return f.send(ctx, req)
}

func TestNotifierNotifyPending(t *testing.T) {
	t.Parallel()

	var sent *notificationsv1.SendRequest
	var authHeader string
	notifier, err := NewNotifierWithClient(fakeNotificationSender{
		send: func(_ context.Context, req *connect.Request[notificationsv1.SendRequest]) (*connect.Response[notificationsv1.SendResponse], error) {
			sent = req.Msg
			authHeader = req.Header().Get("Authorization")
			return connect.NewResponse(&notificationsv1.SendResponse{
				Notification: &notificationsv1.Notification{Id: "ntf_123"},
			}), nil
		},
	}, Config{
		BearerToken:   "secret-token",
		RecipientID:   "approval-queue",
		Channel:       notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_SLACK,
		Priority:      notificationsv1.Priority_PRIORITY_URGENT,
		PublicBaseURL: "https://asb.internal",
	})
	if err != nil {
		t.Fatalf("NewNotifierWithClient() error = %v", err)
	}

	approval := &core.Approval{
		ID:          "ap_123",
		TenantID:    "t_acme",
		GrantID:     "gr_123",
		RequestedBy: "agent_browser",
		Reason:      "log into vendor admin",
		ExpiresAt:   time.Date(2026, 4, 14, 1, 0, 0, 0, time.UTC),
	}
	grant := &core.Grant{
		ID:          "gr_123",
		Tool:        "browser",
		Capability:  "browser.login",
		ResourceRef: "browser_origin:https://admin.vendor.example",
	}

	if err := notifier.NotifyPending(context.Background(), nil, approval, grant); err != nil {
		t.Fatalf("NotifyPending() error = %v", err)
	}
	if sent == nil {
		t.Fatal("Send() was not called")
	}
	if sent.GetWorkspaceId() != "t_acme" {
		t.Fatalf("workspace_id = %q, want tenant id fallback", sent.GetWorkspaceId())
	}
	if sent.GetRecipientId() != "approval-queue" {
		t.Fatalf("recipient_id = %q, want approval-queue", sent.GetRecipientId())
	}
	if sent.GetChannel() != notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_SLACK {
		t.Fatalf("channel = %s, want slack", sent.GetChannel())
	}
	if sent.GetPriority() != notificationsv1.Priority_PRIORITY_URGENT {
		t.Fatalf("priority = %s, want urgent", sent.GetPriority())
	}
	if authHeader != "Bearer secret-token" {
		t.Fatalf("authorization = %q, want bearer token", authHeader)
	}
	if sent.GetSubject() == "" || sent.GetBody() == "" || sent.GetMetadataJson() == "" {
		t.Fatalf("send request = %#v, want subject/body/metadata", sent)
	}
	if !containsAll(sent.GetMetadataJson(), "approve_endpoint", "deny_endpoint", "browser.login") {
		t.Fatalf("metadata_json = %q, want approval endpoints and capability", sent.GetMetadataJson())
	}
}

func TestNotifierNotifyPendingPropagatesErrors(t *testing.T) {
	t.Parallel()

	notifier, err := NewNotifierWithClient(fakeNotificationSender{
		send: func(_ context.Context, req *connect.Request[notificationsv1.SendRequest]) (*connect.Response[notificationsv1.SendResponse], error) {
			return nil, errors.New("boom")
		},
	}, Config{
		RecipientID: "approval-queue",
		Channel:     notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_EMAIL,
	})
	if err != nil {
		t.Fatalf("NewNotifierWithClient() error = %v", err)
	}

	err = notifier.NotifyPending(context.Background(), nil, &core.Approval{
		ID:          "ap_123",
		TenantID:    "t_acme",
		RequestedBy: "agent_browser",
		ExpiresAt:   time.Now().UTC(),
	}, &core.Grant{
		ID:          "gr_123",
		Tool:        "browser",
		Capability:  "browser.login",
		ResourceRef: "browser_origin:https://admin.vendor.example",
	})
	if err == nil || !containsAll(err.Error(), "send approval notification", "boom") {
		t.Fatalf("NotifyPending() error = %v, want wrapped send error", err)
	}
}

func TestParseChannel(t *testing.T) {
	t.Parallel()

	cases := map[string]notificationsv1.DeliveryChannel{
		"slack":   notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_SLACK,
		"email":   notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_EMAIL,
		"webhook": notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_WEBHOOK,
		"in_app":  notificationsv1.DeliveryChannel_DELIVERY_CHANNEL_IN_APP,
	}

	for input, want := range cases {
		got, err := ParseChannel(input)
		if err != nil {
			t.Fatalf("ParseChannel(%q) error = %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseChannel(%q) = %s, want %s", input, got, want)
		}
	}

	if _, err := ParseChannel("sms"); err == nil {
		t.Fatal("ParseChannel(sms) error = nil, want non-nil")
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
