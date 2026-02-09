// Copyright (c) 2026 John Earle
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webhook handles incoming Graph API change notifications and
// lifecycle events. When a subscribed mailbox receives a new message,
// Microsoft Graph POSTs a notification to the registered webhook URL.
// This handler fetches the full message and publishes it to the
// analysis pipeline via Redis.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/bcem/ingestion/internal/dedup"
	"github.com/bcem/ingestion/internal/graph"
	"github.com/bcem/ingestion/internal/queue"
	"github.com/bcem/ingestion/internal/subscription"
)

// ChangeNotification represents a single Graph API change notification.
type ChangeNotification struct {
	SubscriptionID                 string `json:"subscriptionId"`
	ChangeType                     string `json:"changeType"`
	Resource                       string `json:"resource"`
	ClientState                    string `json:"clientState"`
	TenantID                       string `json:"tenantId"`
	LifecycleEvent                 string `json:"lifecycleEvent"`
	SubscriptionExpirationDateTime string `json:"subscriptionExpirationDateTime"`
}

// NotificationPayload is the wrapper Graph sends.
type NotificationPayload struct {
	Value []ChangeNotification `json:"value"`
}

// Handler processes Graph API change notifications.
type Handler struct {
	fetcher   *graph.Fetcher
	publisher *queue.Publisher
	filter    *dedup.Filter
	store     *subscription.Store
	manager   *subscription.LifecycleManager
}

// NewHandler creates a change notification handler.
func NewHandler(
	fetcher *graph.Fetcher,
	publisher *queue.Publisher,
	filter *dedup.Filter,
	store *subscription.Store,
	manager *subscription.LifecycleManager,
) *Handler {
	return &Handler{
		fetcher:   fetcher,
		publisher: publisher,
		filter:    filter,
		store:     store,
		manager:   manager,
	}
}

// ServeNotification handles change notification webhook requests.
//
// Graph API validation flow:
//   - When creating a subscription, Graph sends a POST with ?validationToken=<token>
//   - We must respond 200 OK with the token in plain text
//
// Normal notification flow:
//   - Graph POSTs a JSON body with an array of ChangeNotification objects
//   - We respond 202 Accepted immediately
//   - Process notifications in the background
func (h *Handler) ServeNotification(w http.ResponseWriter, r *http.Request) {
	// Handle validation probe
	if token := r.URL.Query().Get("validationToken"); token != "" {
		slog.Info("subscription validation probe received")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(token))
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusOK)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("failed to read notification body", "error", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var payload NotificationPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		slog.Info("notification body not valid JSON, treating as probe",
			"body_len", len(body),
		)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Respond immediately — Graph expects a fast response
	w.WriteHeader(http.StatusAccepted)

	// Process in background
	go h.processNotifications(context.Background(), payload.Value)
}

// ServeLifecycle handles lifecycle notification webhook requests.
func (h *Handler) ServeLifecycle(w http.ResponseWriter, r *http.Request) {
	// Lifecycle notifications also use the validation flow
	if token := r.URL.Query().Get("validationToken"); token != "" {
		slog.Info("lifecycle validation probe received")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(token))
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var payload NotificationPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.WriteHeader(http.StatusAccepted)

	// Extract tenant alias from path
	parts := strings.Split(r.URL.Path, "/")
	tenantAlias := ""
	if len(parts) >= 3 {
		tenantAlias = parts[2] // /lifecycle/{tenant}
	}

	for _, n := range payload.Value {
		if n.LifecycleEvent != "" {
			h.manager.HandleLifecycleEvent(
				context.Background(),
				n.LifecycleEvent,
				n.SubscriptionID,
				tenantAlias,
			)
		}
	}
}

// processNotifications handles each change notification.
func (h *Handler) processNotifications(ctx context.Context, notifications []ChangeNotification) {
	for _, n := range notifications {
		// Skip non-creation events (we only care about new messages)
		if n.ChangeType != "created" {
			slog.Debug("skipping non-created notification",
				"change_type", n.ChangeType,
				"resource", n.Resource,
			)
			continue
		}

		// Parse resource: "/users/{userId}/messages/{messageId}"
		userID, messageID, err := parseResource(n.Resource)
		if err != nil {
			slog.Warn("failed to parse notification resource",
				"resource", n.Resource,
				"error", err,
			)
			continue
		}

		// Validate clientState against stored subscription
		rec, err := h.store.Get(ctx, n.TenantID, userID)
		if err != nil {
			slog.Error("failed to look up subscription for validation",
				"tenant", n.TenantID,
				"user", userID,
				"error", err,
			)
			// Process anyway — don't lose the notification
		} else if rec != nil && n.ClientState != "" && rec.ClientState != n.ClientState {
			slog.Warn("clientState mismatch — possible spoofed notification",
				"expected", rec.ClientState,
				"got", n.ClientState,
			)
			continue
		}

		// Update last notification time
		if rec != nil {
			_ = h.store.TouchNotification(ctx, n.TenantID, userID)
		}

		// Dedup
		isNew, err := h.filter.IsNew(ctx, messageID)
		if err != nil {
			slog.Warn("dedup check failed, proceeding", "error", err)
		} else if !isNew {
			slog.Debug("skipping duplicate message", "message_id", messageID)
			continue
		}

		// Determine tenant alias from subscription record
		tenantAlias := ""
		if rec != nil {
			tenantAlias = rec.TenantAlias
		}

		slog.Info("processing change notification",
			"tenant", tenantAlias,
			"user", userID,
			"message_id", messageID,
		)

		// Fetch full message
		event, err := h.fetcher.FetchMessage(ctx, userID, messageID, n.TenantID, tenantAlias)
		if err != nil {
			slog.Error("fetch message failed",
				"message_id", messageID,
				"error", err,
			)
			continue
		}

		if event == nil {
			continue
		}

		// Publish to Redis
		if err := h.publisher.PublishEmailEvent(ctx, event); err != nil {
			slog.Error("publish failed",
				"message_id", messageID,
				"error", err,
			)
		}
	}
}

// parseResource extracts userID and messageID from a Graph notification resource string.
// Format: "users/{userId}/messages/{messageId}"
func parseResource(resource string) (userID, messageID string, err error) {
	// Remove leading slash if present
	resource = strings.TrimPrefix(resource, "/")

	parts := strings.Split(resource, "/")
	// Expected: ["users", "{userId}", "messages", "{messageId}"]
	// Graph may send capitalised variants: "Users", "Messages"
	if len(parts) != 4 || !strings.EqualFold(parts[0], "users") || !strings.EqualFold(parts[2], "messages") {
		return "", "", fmt.Errorf("unexpected resource format: %s", resource)
	}

	return parts[1], parts[3], nil
}

// Serve starts the webhook HTTP server on the given port.
// It binds the port immediately and signals readiness via the returned channel
// before starting to accept connections.
func Serve(ctx context.Context, port int, handler *Handler) (<-chan struct{}, error) {
	mux := http.NewServeMux()

	// Change notification endpoints — catch-all pattern
	mux.HandleFunc("/webhook/", handler.ServeNotification)

	// Lifecycle notification endpoints
	mux.HandleFunc("/lifecycle/", handler.ServeLifecycle)

	server := &http.Server{
		Handler: mux,
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("bind webhook port %d: %w", port, err)
	}

	ready := make(chan struct{})

	go func() {
		<-ctx.Done()
		slog.Info("webhook server shutting down")
		server.Close()
	}()

	go func() {
		slog.Info("webhook server listening", "port", port)
		close(ready)
		if err := server.Serve(ln); err != http.ErrServerClosed {
			slog.Error("webhook server error", "error", err)
		}
	}()

	return ready, nil
}
