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

// BlackChamber ICES — Historical Backfill Command
//
// Standalone CLI tool that ingests historical emails from Microsoft 365
// mailboxes within a configurable date range. Intended for seeding data
// on new deployments.
//
// Usage:
//
//	go run ./cmd/backfill/ --tenant <alias> [--users user1@org.com,user2@org.com] [--since 168h]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/bcem/ingestion/internal/backfill"
	"github.com/bcem/ingestion/internal/config"
	"github.com/bcem/ingestion/internal/dedup"
	"github.com/bcem/ingestion/internal/discovery"
	"github.com/bcem/ingestion/internal/graph"
	"github.com/bcem/ingestion/internal/queue"
)

const graphBaseURL = "https://graph.microsoft.com/v1.0"

func main() {
	// Structured JSON logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// --- CLI Flags ---
	tenantFlag := flag.String("tenant", "", "Tenant alias to backfill (required)")
	usersFlag := flag.String("users", "", "Comma-separated list of user emails (optional; empty = all discovered users)")
	sinceFlag := flag.String("since", "168h", "Lookback duration (e.g. 168h for 1 week, 720h for 30 days)")
	flag.Parse()

	if *tenantFlag == "" {
		fmt.Fprintf(os.Stderr, "Error: --tenant is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	sinceDuration, err := time.ParseDuration(*sinceFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid --since duration %q: %v\n", *sinceFlag, err)
		os.Exit(1)
	}

	slog.Info("starting historical backfill",
		"tenant", *tenantFlag,
		"since", sinceDuration,
	)

	// --- Load Configuration ---
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Find the requested tenant
	var tenant *config.TenantConfig
	for i := range cfg.Tenants {
		if cfg.Tenants[i].Alias == *tenantFlag {
			tenant = &cfg.Tenants[i]
			break
		}
	}
	if tenant == nil {
		slog.Error("tenant not found in configuration", "alias", *tenantFlag)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Connect to Redis ---
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		slog.Error("invalid REDIS_URL", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()

	publisher := queue.NewPublisher(rdb, cfg.EmailsQueue)
	if err := publisher.Ping(ctx); err != nil {
		slog.Error("failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to Redis")

	// --- Dedup Filter ---
	filter := dedup.NewFilter(rdb)

	// --- Build OAuth2 client for the tenant ---
	creds := &clientcredentials.Config{
		ClientID:     tenant.ClientID,
		ClientSecret: tenant.ClientSecret,
		TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant.TenantID),
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}
	httpClient := creds.Client(ctx)

	graphClients := map[string]*http.Client{tenant.Alias: httpClient}
	fetcher := graph.NewFetcher(graphClients, graphBaseURL)

	// --- Resolve users ---
	var users []string
	if *usersFlag != "" {
		for _, u := range strings.Split(*usersFlag, ",") {
			u = strings.TrimSpace(u)
			if u != "" {
				users = append(users, u)
			}
		}
	} else {
		// Auto-discover users for this tenant
		disc := discovery.NewDiscovery(graphBaseURL)
		discovered, err := disc.DiscoverUsers(ctx, httpClient, tenant.Alias, tenant.IncludeUsers, tenant.ExcludeUsers)
		if err != nil {
			slog.Error("user discovery failed", "error", err)
			os.Exit(1)
		}
		for _, u := range discovered {
			// Use UPN or mail as the identifier
			id := u.UserPrincipalName
			if id == "" {
				id = u.Mail
			}
			users = append(users, id)
		}
	}

	if len(users) == 0 {
		slog.Error("no users to backfill")
		os.Exit(1)
	}

	slog.Info("resolved users for backfill", "count", len(users), "users", users)

	// --- Run Backfill ---
	runner := backfill.NewRunner(backfill.RunnerConfig{
		GraphBaseURL: graphBaseURL,
		Fetcher:      fetcher,
		Publisher:    publisher,
		Dedup:        filter,
	})

	result, err := runner.Run(ctx, httpClient, backfill.BackfillRequest{
		TenantID:    tenant.TenantID,
		TenantAlias: tenant.Alias,
		Users:       users,
		Since:       sinceDuration,
	})
	if err != nil {
		slog.Error("backfill failed", "error", err)
		os.Exit(1)
	}

	// --- Summary ---
	slog.Info("backfill complete",
		"tenant", result.TenantAlias,
		"total_new", result.TotalNew,
		"total_skipped", result.TotalSkipped,
		"elapsed", result.Elapsed,
	)

	for _, ur := range result.UserResults {
		slog.Info("user result",
			"user", ur.UserID,
			"fetched", ur.Fetched,
			"skipped", ur.Skipped,
			"errors", ur.Errors,
		)
	}
}
