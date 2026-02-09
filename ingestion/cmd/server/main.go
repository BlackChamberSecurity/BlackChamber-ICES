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

// BlackChamber ICES — Ingestion Service
//
// Entry point for the Go ingestion service. It:
//  1. Loads multi-tenant configuration from config.yaml
//  2. Connects to PostgreSQL and Redis
//  3. Discovers mailbox users per tenant (hybrid: auto + config overrides)
//  4. Creates Graph API subscriptions for each mailbox
//  5. Runs a subscription renewal loop and periodic delta sync
//  6. Serves webhook endpoints for Graph change notifications
//  7. Handles graceful shutdown on SIGTERM/SIGINT
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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/bcem/ingestion/internal/config"
	"github.com/bcem/ingestion/internal/dedup"
	"github.com/bcem/ingestion/internal/delta"
	"github.com/bcem/ingestion/internal/discovery"
	"github.com/bcem/ingestion/internal/graph"
	"github.com/bcem/ingestion/internal/queue"
	"github.com/bcem/ingestion/internal/subscription"
	"github.com/bcem/ingestion/internal/webhook"
)

const graphBaseURL = "https://graph.microsoft.com/v1.0"

func main() {
	// Structured JSON logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("starting BlackChamber ICES ingestion service")

	// --- Load Configuration ---
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("configuration loaded",
		"tenants", len(cfg.Tenants),
		"renewal_buffer", cfg.SubscriptionRenewalBuffer,
		"delta_interval", cfg.DeltaSyncInterval,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Connect to PostgreSQL ---
	pgPool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to create Postgres pool", "error", err)
		os.Exit(1)
	}
	defer pgPool.Close()

	if err := pgPool.Ping(ctx); err != nil {
		slog.Error("failed to connect to PostgreSQL", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to PostgreSQL")

	// --- Connect to Redis ---
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		slog.Error("invalid REDIS_URL", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)

	publisher := queue.NewPublisher(rdb, cfg.EmailsQueue)
	if err := publisher.Ping(ctx); err != nil {
		slog.Error("failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to Redis")

	// --- Dedup Filter ---
	filter := dedup.NewFilter(rdb)

	// --- Subscription Store (Postgres) ---
	store, err := subscription.NewStore(ctx, pgPool)
	if err != nil {
		slog.Error("failed to initialise subscription store", "error", err)
		os.Exit(1)
	}

	// --- Build OAuth2 clients per tenant ---
	graphClients := make(map[string]*http.Client)
	for _, tenant := range cfg.Tenants {
		if tenant.Provider != "m365" {
			continue
		}

		creds := &clientcredentials.Config{
			ClientID:     tenant.ClientID,
			ClientSecret: tenant.ClientSecret,
			TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant.TenantID),
			Scopes:       []string{"https://graph.microsoft.com/.default"},
		}
		graphClients[tenant.Alias] = creds.Client(ctx)
	}

	// --- Graph Fetcher ---
	// Pass all per-tenant clients so the fetcher uses the correct
	// OAuth token for each tenant's notification.
	fetcher := graph.NewFetcher(graphClients, graphBaseURL)

	// --- User Discovery ---
	disc := discovery.NewDiscovery(graphBaseURL)

	// --- Resolve webhook URL ---
	webhookURL := resolveWebhookURL(cfg.WebhookURL)
	if webhookURL == "" {
		slog.Error("WEBHOOK_URL is required — Graph API subscriptions need a public webhook endpoint")
		os.Exit(1)
	}
	slog.Info("webhook URL resolved", "url", webhookURL)

	// --- Lifecycle Manager ---
	mgr := subscription.NewManager(subscription.ManagerConfig{
		Store:        store,
		Discovery:    disc,
		GraphClients: graphClients,
		Tenants:      cfg.Tenants,
		WebhookURL:   webhookURL,
		RenewBuffer:  cfg.SubscriptionRenewalBuffer,
		GraphBaseURL: graphBaseURL,
	})

	// --- Delta Syncer ---
	syncer := delta.NewSyncer(delta.SyncerConfig{
		GraphClients: graphClients,
		GraphBaseURL: graphBaseURL,
		Fetcher:      fetcher,
		Publisher:    publisher,
		Dedup:        filter,
		Store:        store,
		SyncInterval: cfg.DeltaSyncInterval,
	})

	// Wire gap detection: lifecycle manager triggers delta sync
	mgr.OnGapDetected = func(ctx context.Context, tenantID, userID string) {
		// Find the right client
		for _, t := range cfg.Tenants {
			if t.TenantID == tenantID {
				if client, ok := graphClients[t.Alias]; ok {
					if err := syncer.SyncMailbox(ctx, client, tenantID, t.Alias, userID); err != nil {
						slog.Error("gap delta sync failed",
							"tenant", t.Alias,
							"user", userID,
							"error", err,
						)
					}
				}
				break
			}
		}
	}

	// --- Phase 1: Start webhook server BEFORE registering subscriptions ---
	// Graph validates the endpoint immediately when creating a subscription.
	handler := webhook.NewHandler(fetcher, publisher, filter, store, mgr)
	ready, err := webhook.Serve(ctx, cfg.WebhookPort, handler)
	if err != nil {
		slog.Error("failed to start webhook server", "error", err)
		os.Exit(1)
	}
	<-ready
	slog.Info("webhook server ready, proceeding to register subscriptions")

	// --- Phase 2: Start lifecycle manager (discovers users + creates subscriptions) ---
	if err := mgr.Start(ctx); err != nil {
		slog.Error("failed to start lifecycle manager", "error", err)
		os.Exit(1)
	}

	// --- Phase 3: Load delta links and start periodic delta sync ---
	// Load existing delta links from Postgres into the syncer's cache
	for _, tenant := range cfg.Tenants {
		records, err := store.ListByTenant(ctx, tenant.TenantID)
		if err != nil {
			slog.Error("failed to load subscriptions for delta links",
				"tenant", tenant.Alias,
				"error", err,
			)
			continue
		}
		for _, rec := range records {
			if rec.DeltaLink != "" {
				syncer.SetDeltaLink(rec.TenantID, rec.UserID, rec.DeltaLink)
			}
		}
	}

	// Build tenant info for periodic sync
	var syncTenants []struct {
		TenantID    string
		TenantAlias string
		Users       []string
		Client      *http.Client
	}
	for _, tenant := range cfg.Tenants {
		client, ok := graphClients[tenant.Alias]
		if !ok {
			continue
		}
		records, _ := store.ListByTenant(ctx, tenant.TenantID)
		var users []string
		for _, r := range records {
			users = append(users, r.UserID)
		}
		syncTenants = append(syncTenants, struct {
			TenantID    string
			TenantAlias string
			Users       []string
			Client      *http.Client
		}{
			TenantID:    tenant.TenantID,
			TenantAlias: tenant.Alias,
			Users:       users,
			Client:      client,
		})
	}
	syncer.StartPeriodicSync(ctx, syncTenants)

	// --- Health Check Server ---
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// Check Redis
		if err := publisher.Ping(r.Context()); err != nil {
			http.Error(w, "redis unhealthy", http.StatusServiceUnavailable)
			return
		}
		// Check Postgres
		if err := pgPool.Ping(r.Context()); err != nil {
			http.Error(w, "postgres unhealthy", http.StatusServiceUnavailable)
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
		cancel() // Stop all background goroutines

		mgr.Stop()
		syncer.Stop()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown error", "error", err)
		}

		rdb.Close()
		pgPool.Close()
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
//   - Empty string → error (webhook is required)
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
	ngrokAPI := os.Getenv("NGROK_API_URL")
	if ngrokAPI == "" {
		ngrokAPI = "http://ngrok:4040"
	}

	slog.Info("discovering webhook URL from ngrok", "api", ngrokAPI)

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
			time.Sleep(2 * time.Second)
			continue
		}

		for _, t := range result.Tunnels {
			if t.Proto == "https" {
				slog.Info("ngrok tunnel discovered", "url", t.PublicURL)
				return t.PublicURL
			}
		}

		if len(result.Tunnels) > 0 {
			url := result.Tunnels[0].PublicURL
			slog.Info("ngrok tunnel discovered", "url", url)
			return url
		}

		lastErr = fmt.Errorf("no tunnels found")
		time.Sleep(2 * time.Second)
	}

	slog.Error("failed to discover ngrok tunnel", "error", lastErr)
	return ""
}
