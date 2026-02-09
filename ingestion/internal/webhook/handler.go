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

// Package webhook handles incoming Activity Feed webhook notifications.
// When a webhook address is registered with the Management Activity API,
// Microsoft POSTs an array of ContentBlob references whenever new audit
// content is available. This handler receives those notifications and
// processes them through the same pipeline as the polling path.
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

	"github.com/bcem/ingestion/internal/activityfeed"
	"github.com/bcem/ingestion/internal/config"
	"github.com/bcem/ingestion/internal/dedup"
	"github.com/bcem/ingestion/internal/graph"
	"github.com/bcem/ingestion/internal/queue"
)

// Handler processes Activity Feed webhook notifications.
type Handler struct {
	feedClient *activityfeed.Client
	fetcher    *graph.Fetcher
	publisher  *queue.Publisher
	filter     *dedup.Filter
	authID     string
	tenant     config.TenantConfig
}

// NewHandler creates a webhook handler.
func NewHandler(
	feedClient *activityfeed.Client,
	fetcher *graph.Fetcher,
	publisher *queue.Publisher,
	filter *dedup.Filter,
	authID string,
	tenant config.TenantConfig,
) *Handler {
	return &Handler{
		feedClient: feedClient,
		fetcher:    fetcher,
		publisher:  publisher,
		filter:     filter,
		authID:     authID,
		tenant:     tenant,
	}
}

// ServeHTTP handles webhook requests from the Management Activity API.
//
// Non-POST requests are treated as validation probes — Microsoft sends one when
// the subscription is created to verify the endpoint is reachable and returns 200.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Validation probe: respond 200 OK.
		slog.Info("webhook validation probe received",
			"method", r.Method,
			"tenant", h.tenant.Alias,
		)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validate Webhook-AuthID header (skip for validation probes)
	if h.authID != "" {
		got := r.Header.Get("Webhook-AuthID")
		if got != "" && got != h.authID {
			slog.Warn("webhook auth mismatch",
				"expected", h.authID,
				"got", got,
			)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Read body — may be a validation probe or a real notification.
	// Microsoft sends a validation POST when the subscription is created.
	// We must return 200 OK for validation to succeed.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("failed to read webhook body", "error", err)
		w.WriteHeader(http.StatusOK) // Still return 200 for safety
		return
	}

	// Try to decode as notification (array of content blobs)
	var blobs []activityfeed.ContentBlob
	if err := json.Unmarshal(body, &blobs); err != nil {
		// Not a valid notification — likely a validation probe
		slog.Info("webhook probe/validation received (body not a notification array)",
			"tenant", h.tenant.Alias,
			"body_len", len(body),
		)
		w.WriteHeader(http.StatusOK)
		return
	}

	if len(blobs) == 0 {
		slog.Debug("webhook notification with empty blob array", "tenant", h.tenant.Alias)
		w.WriteHeader(http.StatusOK)
		return
	}

	slog.Info("webhook notification received",
		"blobs", len(blobs),
		"tenant", h.tenant.Alias,
	)

	// Respond immediately — Microsoft expects 200 OK promptly.
	// Process blobs in the background.
	w.WriteHeader(http.StatusOK)

	go h.processBlobs(context.Background(), blobs)
}

// processBlobs fetches and processes content blobs, filtering for email events.
// This mirrors the logic in poller.poll().
func (h *Handler) processBlobs(ctx context.Context, blobs []activityfeed.ContentBlob) {
	for _, blob := range blobs {
		slog.Info("webhook: fetching blob content",
			"content_uri", blob.ContentURI,
			"content_id", blob.ContentID,
			"content_type", blob.ContentType,
		)

		events, err := h.feedClient.FetchBlob(ctx, blob.ContentURI)
		if err != nil {
			slog.Error("webhook: failed to fetch blob",
				"blob_id", blob.ContentID,
				"error", err,
			)
			continue
		}

		slog.Info("webhook: blob fetched",
			"blob_id", blob.ContentID,
			"events", len(events),
		)

		for _, event := range events {
			slog.Info("webhook: inspecting event",
				"event_id", event.ID,
				"operation", event.Operation,
				"workload", event.Workload,
				"user_id", event.UserID,
				"item_id", event.ItemID,
				"subject", event.Subject,
			)

			// Only process Exchange workload events
			if !strings.EqualFold(event.Workload, "Exchange") {
				slog.Info("webhook: skipping non-Exchange workload",
					"workload", event.Workload,
					"operation", event.Operation,
					"event_id", event.ID,
				)
				continue
			}

			if event.ItemID == "" {
				slog.Warn("webhook: audit event has no ItemId, skipping",
					"event_id", event.ID,
				)
				continue
			}

			// Dedup
			isNew, err := h.filter.IsNew(ctx, event.ID)
			if err != nil {
				slog.Warn("webhook: dedup check failed, proceeding",
					"event_id", event.ID, "error", err,
				)
			} else if !isNew {
				slog.Debug("webhook: skipping duplicate event",
					"event_id", event.ID,
				)
				continue
			}

			slog.Info("webhook: processing email event",
				"tenant", h.tenant.Alias,
				"operation", event.Operation,
				"user_id", event.UserID,
				"item_id", event.ItemID,
			)

			emailEvent, err := h.fetcher.FetchMessage(ctx, event.UserID, event.ItemID, h.tenant.TenantID, h.tenant.Alias)
			if err != nil {
				slog.Error("webhook: fetch message failed",
					"event_id", event.ID,
					"error", err,
				)
				continue
			}

			if emailEvent == nil {
				continue
			}

			if err := h.publisher.PublishEmailEvent(ctx, emailEvent); err != nil {
				slog.Error("webhook: publish failed",
					"event_id", event.ID,
					"error", err,
				)
			}
		}
	}
}

// Serve starts the webhook HTTP server on the given port.
// It binds the port immediately and signals readiness via the returned channel
// before starting to accept connections. This ensures the port is open before
// StartSubscription is called (Microsoft validates the endpoint immediately).
func Serve(ctx context.Context, port int, handlers map[string]*Handler) (<-chan struct{}, error) {
	mux := http.NewServeMux()

	// Each tenant gets its own path: /webhook/{alias}
	for alias, handler := range handlers {
		path := fmt.Sprintf("/webhook/%s", alias)
		mux.Handle(path, handler)
		slog.Info("webhook endpoint registered",
			"path", path,
			"tenant", alias,
		)
	}

	// Catch-all /webhook for single-tenant setups
	if len(handlers) == 1 {
		for _, handler := range handlers {
			mux.Handle("/webhook", handler)
		}
	}

	server := &http.Server{
		Handler: mux,
	}

	// Bind port immediately so it's ready for validation probes.
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
		close(ready) // Signal that the port is bound and ready
		if err := server.Serve(ln); err != http.ErrServerClosed {
			slog.Error("webhook server error", "error", err)
		}
	}()

	return ready, nil
}
