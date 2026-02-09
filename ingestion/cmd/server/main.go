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

// BCEM Ingestion Service
//
// This is the entry point for the Go ingestion service. It:
//  1. Loads multi-tenant configuration from config.yaml
//  2. Authenticates with M365 via client credentials per tenant
//  3. Connects to Redis
//  4. Starts an Activity Feed poller per tenant
//  5. Serves a health check endpoint on :PORT
//  6. Handles graceful shutdown on SIGTERM/SIGINT
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/bcem/ingestion/internal/activityfeed"
	"github.com/bcem/ingestion/internal/config"
	"github.com/bcem/ingestion/internal/dedup"
	"github.com/bcem/ingestion/internal/graph"
	"github.com/bcem/ingestion/internal/queue"
	"github.com/bcem/ingestion/internal/webhook"
)

func main() {
	// Structured JSON logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting BCEM ingestion service")

	// --- Load Configuration ---
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("configuration loaded", "tenants", len(cfg.Tenants))

	// --- Connect to Redis ---
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		slog.Error("invalid REDIS_URL", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)

	publisher := queue.NewPublisher(rdb, cfg.EmailsQueue)
	if err := publisher.Ping(context.Background()); err != nil {
		slog.Error("failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to Redis", "url", cfg.RedisURL)

	// --- Dedup Filter ---
	filter := dedup.NewFilter(rdb)
	slog.Info("dedup filter initialised", "ttl", "24h")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Resolve webhook URL ---
	webhookAddr := resolveWebhookURL(cfg.WebhookURL)
	webhookMode := webhookAddr != ""

	if webhookMode {
		slog.Info("running in WEBHOOK mode", "webhook_addr", webhookAddr)
	} else {
		slog.Info("running in POLL mode", "interval", cfg.PollInterval)
	}

	// Track tenant resources for both modes
	type tenantResources struct {
		tenant     config.TenantConfig
		feedClient *activityfeed.Client
		fetcher    *graph.Fetcher
	}
	var tenants []tenantResources

	// Webhook handlers — one per tenant (used in webhook mode)
	webhookHandlers := make(map[string]*webhook.Handler)

	// --- Phase 1: Build clients + handlers (no subscription calls yet) ---
	for _, tenant := range cfg.Tenants {
		tenant := tenant // capture loop variable

		slog.Info("initialising tenant",
			"alias", tenant.Alias,
			"provider", tenant.Provider,
			"tenant_id", tenant.TenantID,
		)

		if tenant.Provider != "m365" {
			slog.Warn("skipping unsupported provider", "alias", tenant.Alias, "provider", tenant.Provider)
			continue
		}

		// OAuth2 clients per tenant
		graphCreds := &clientcredentials.Config{
			ClientID:     tenant.ClientID,
			ClientSecret: tenant.ClientSecret,
			TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant.TenantID),
			Scopes:       []string{"https://graph.microsoft.com/.default"},
		}
		graphHTTP := graphCreds.Client(context.Background())

		feedCreds := &clientcredentials.Config{
			ClientID:     tenant.ClientID,
			ClientSecret: tenant.ClientSecret,
			TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant.TenantID),
			Scopes:       []string{"https://manage.office.com/.default"},
		}
		feedHTTP := feedCreds.Client(context.Background())

		feedClient := activityfeed.NewClient(feedHTTP, tenant.TenantID)
		fetcher := graph.NewFetcher(graphHTTP, "https://graph.microsoft.com/v1.0")

		tenants = append(tenants, tenantResources{tenant, feedClient, fetcher})

		if webhookMode {
			webhookHandlers[tenant.Alias] = webhook.NewHandler(
				feedClient, fetcher, publisher, filter,
				cfg.WebhookAuthID, tenant,
			)
		}
	}

	// --- Phase 2: Start webhook server BEFORE registering subscriptions ---
	// Microsoft immediately validates the endpoint when StartSubscription is called,
	// so the server must be listening before we make that call.
	if webhookMode {
		ready, err := webhook.Serve(ctx, cfg.WebhookPort, webhookHandlers)
		if err != nil {
			slog.Error("failed to start webhook server", "error", err)
			os.Exit(1)
		}
		<-ready // Wait for the port to be bound
		slog.Info("webhook server ready, proceeding to register subscriptions")
	}

	// --- Phase 3: Register subscriptions + start pollers ---
	for _, tr := range tenants {
		// Start Activity Feed subscription
		// In webhook mode: register the webhook address (Microsoft will validate it now)
		// In poll mode: no webhook (empty strings)
		if err := tr.feedClient.StartSubscription(ctx, webhookAddr, cfg.WebhookAuthID); err != nil {
			slog.Error("failed to start activity feed subscription",
				"alias", tr.tenant.Alias,
				"error", err,
			)
			os.Exit(1)
		}

		if webhookMode {
			slog.Info("subscription registered with webhook",
				"alias", tr.tenant.Alias,
				"webhook_addr", webhookAddr,
			)
		} else {
			// Poll mode: start background poller
			tenant := tr.tenant
			feedClient := tr.feedClient
			fetcher := tr.fetcher
			poller := activityfeed.NewPoller(feedClient, cfg.PollInterval, cfg.PollLookback,
				func(ctx context.Context, event activityfeed.AuditEvent) error {
					slog.Info("processing email event",
						"tenant", tenant.Alias,
						"operation", event.Operation,
						"user_id", event.UserID,
						"item_id", event.ItemID,
						"subject", event.Subject,
					)

					if event.ItemID == "" {
						slog.Warn("audit event has no ItemId, skipping fetch",
							"tenant", tenant.Alias,
							"event_id", event.ID,
						)
						return nil
					}

					// Dedup: skip events we've already processed
					isNew, err := filter.IsNew(ctx, event.ID)
					if err != nil {
						slog.Warn("dedup check failed, proceeding anyway",
							"event_id", event.ID, "error", err,
						)
					} else if !isNew {
						slog.Debug("skipping duplicate event",
							"event_id", event.ID, "tenant", tenant.Alias,
						)
						return nil
					}

					emailEvent, err := fetcher.FetchMessage(ctx, event.UserID, event.ItemID, tenant.TenantID, tenant.Alias)
					if err != nil {
						return fmt.Errorf("fetch message: %w", err)
					}

					if emailEvent == nil {
						return nil
					}

					return publisher.PublishEmailEvent(ctx, emailEvent)
				},
			)

			go poller.Run(ctx)
			slog.Info("activity feed poller started",
				"alias", tenant.Alias,
				"interval", cfg.PollInterval,
				"lookback", cfg.PollLookback,
			)
		}
	}

	// --- Health Check Server ---
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := publisher.Ping(r.Context()); err != nil {
			http.Error(w, "redis unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy"}`))
	})

	addr := fmt.Sprintf(":%d", cfg.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// --- Graceful Shutdown ---
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh

		slog.Info("received shutdown signal", "signal", sig)
		cancel() // Stop all pollers

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown error", "error", err)
		}

		rdb.Close()
	}()

	slog.Info("ingestion service listening", "addr", addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	slog.Info("ingestion service stopped")
}

// resolveWebhookURL resolves the webhook URL from config.
//
//   - Empty string → poll mode (no webhook)
//   - "auto" → discover the public URL from a local ngrok container
//   - Any other string → use as-is (production)
func resolveWebhookURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if strings.ToLower(raw) != "auto" {
		return raw
	}

	// Auto-discover from ngrok's local API.
	// The ngrok container exposes its API on http://ngrok:4040 inside Docker.
	ngrokAPI := os.Getenv("NGROK_API_URL")
	if ngrokAPI == "" {
		ngrokAPI = "http://ngrok:4040"
	}

	slog.Info("discovering webhook URL from ngrok", "api", ngrokAPI)

	// Retry a few times — ngrok may not be ready yet
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		resp, err := http.Get(ngrokAPI + "/api/tunnels")
		if err != nil {
			lastErr = err
			slog.Debug("ngrok not ready, retrying",
				"attempt", attempt+1,
				"error", err,
			)
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()

		var result struct {
			Tunnels []struct {
				PublicURL string `json:"public_url"`
				Proto     string `json:"proto"`
			} `json:"tunnels"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			lastErr = err
			slog.Warn("failed to decode ngrok response", "error", err)
			time.Sleep(2 * time.Second)
			continue
		}

		// Prefer HTTPS tunnel
		for _, t := range result.Tunnels {
			if t.Proto == "https" {
				slog.Info("ngrok tunnel discovered", "url", t.PublicURL)
				return t.PublicURL + "/webhook"
			}
		}

		// Fall back to any tunnel
		if len(result.Tunnels) > 0 {
			url := result.Tunnels[0].PublicURL
			slog.Info("ngrok tunnel discovered", "url", url)
			return url + "/webhook"
		}

		lastErr = fmt.Errorf("no tunnels found")
		time.Sleep(2 * time.Second)
	}

	slog.Error("failed to discover ngrok tunnel, falling back to poll mode",
		"error", lastErr,
	)
	return ""
}
