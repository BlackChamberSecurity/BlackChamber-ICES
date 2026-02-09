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

// Package backfill provides historical email ingestion by listing messages
// within a date range from the Graph API and publishing them through the
// existing analysis pipeline.
package backfill

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/bcem/ingestion/internal/dedup"
	"github.com/bcem/ingestion/internal/graph"
	"github.com/bcem/ingestion/internal/queue"
)

// BackfillRequest defines the scope of a historical ingestion run.
type BackfillRequest struct {
	TenantID    string
	TenantAlias string
	Users       []string      // user IDs / UPNs to backfill
	Since       time.Duration // lookback window (e.g. 168h = 1 week)
}

// BackfillResult summarises a completed backfill run.
type BackfillResult struct {
	TenantAlias  string
	UserResults  []UserResult
	TotalNew     int
	TotalSkipped int
	Elapsed      time.Duration
}

// UserResult tracks per-user backfill progress.
type UserResult struct {
	UserID  string
	Fetched int
	Skipped int
	Errors  int
}

// messagesResponse represents a page of the /messages list response.
type messagesResponse struct {
	Value    []messageStub `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

// messageStub is a minimal message from the list endpoint.
type messageStub struct {
	ID string `json:"id"`
}

// Runner performs historical email backfill.
type Runner struct {
	graphBaseURL string
	fetcher      *graph.Fetcher
	publisher    *queue.Publisher
	dedup        *dedup.Filter
	pageDelay    time.Duration // delay between pages to avoid throttling
}

// RunnerConfig holds dependencies for the backfill runner.
type RunnerConfig struct {
	GraphBaseURL string
	Fetcher      *graph.Fetcher
	Publisher    *queue.Publisher
	Dedup        *dedup.Filter
	PageDelay    time.Duration
}

// NewRunner creates a backfill runner.
func NewRunner(cfg RunnerConfig) *Runner {
	delay := cfg.PageDelay
	if delay == 0 {
		delay = 500 * time.Millisecond
	}
	return &Runner{
		graphBaseURL: cfg.GraphBaseURL,
		fetcher:      cfg.Fetcher,
		publisher:    cfg.Publisher,
		dedup:        cfg.Dedup,
		pageDelay:    delay,
	}
}

// Run performs the backfill for all specified users.
func (r *Runner) Run(ctx context.Context, httpClient *http.Client, req BackfillRequest) (*BackfillResult, error) {
	start := time.Now()
	sinceTime := time.Now().UTC().Add(-req.Since).Format(time.RFC3339)

	slog.Info("starting historical backfill",
		"tenant", req.TenantAlias,
		"users", len(req.Users),
		"since", sinceTime,
	)

	result := &BackfillResult{
		TenantAlias: req.TenantAlias,
	}

	for _, userID := range req.Users {
		ur, err := r.backfillUser(ctx, httpClient, req.TenantID, req.TenantAlias, userID, sinceTime)
		if err != nil {
			slog.Error("backfill failed for user",
				"tenant", req.TenantAlias,
				"user", userID,
				"error", err,
			)
			// Continue with other users
			ur = UserResult{UserID: userID, Errors: 1}
		}

		result.UserResults = append(result.UserResults, ur)
		result.TotalNew += ur.Fetched
		result.TotalSkipped += ur.Skipped
	}

	result.Elapsed = time.Since(start)

	slog.Info("historical backfill complete",
		"tenant", req.TenantAlias,
		"total_new", result.TotalNew,
		"total_skipped", result.TotalSkipped,
		"elapsed", result.Elapsed,
	)

	return result, nil
}

// backfillUser lists and processes historical messages for a single user.
func (r *Runner) backfillUser(ctx context.Context, httpClient *http.Client, tenantID, tenantAlias, userID, sinceTime string) (UserResult, error) {
	ur := UserResult{UserID: userID}

	slog.Info("backfilling user mailbox",
		"tenant", tenantAlias,
		"user", userID,
		"since", sinceTime,
	)

	// Build initial URL with date filter
	params := url.Values{}
	params.Set("$filter", fmt.Sprintf("receivedDateTime ge %s", sinceTime))
	params.Set("$select", "id")
	params.Set("$orderby", "receivedDateTime desc")
	params.Set("$top", "50")

	listURL := fmt.Sprintf("%s/users/%s/messages?%s", r.graphBaseURL, userID, params.Encode())

	pageCount := 0
	for nextURL := listURL; nextURL != ""; {
		// Rate limit between pages
		if pageCount > 0 {
			select {
			case <-ctx.Done():
				return ur, ctx.Err()
			case <-time.After(r.pageDelay):
			}
		}

		page, err := r.fetchPage(ctx, httpClient, nextURL)
		if err != nil {
			return ur, fmt.Errorf("fetch page %d: %w", pageCount, err)
		}
		pageCount++

		slog.Debug("backfill page fetched",
			"user", userID,
			"page", pageCount,
			"messages", len(page.Value),
		)

		// Process each message
		for _, msg := range page.Value {
			// Dedup check — use "backfill:" prefix to share namespace with delta sync
			if r.dedup != nil {
				isNew, err := r.dedup.IsNew(ctx, "backfill:"+msg.ID)
				if err != nil {
					slog.Warn("dedup check failed", "error", err)
				} else if !isNew {
					ur.Skipped++
					continue
				}
			}

			// Fetch full message via existing fetcher
			event, err := r.fetcher.FetchMessage(ctx, userID, msg.ID, tenantID, tenantAlias)
			if err != nil {
				slog.Warn("backfill: fetch message failed",
					"message_id", msg.ID,
					"error", err,
				)
				ur.Errors++
				continue
			}

			if event == nil {
				ur.Skipped++
				continue
			}

			// Publish to analysis pipeline
			if err := r.publisher.PublishEmailEvent(ctx, event); err != nil {
				slog.Warn("backfill: publish failed",
					"message_id", msg.ID,
					"error", err,
				)
				ur.Errors++
				continue
			}

			ur.Fetched++
		}

		nextURL = page.NextLink
	}

	slog.Info("user backfill complete",
		"tenant", tenantAlias,
		"user", userID,
		"fetched", ur.Fetched,
		"skipped", ur.Skipped,
		"errors", ur.Errors,
		"pages", pageCount,
	)

	return ur, nil
}

// fetchPage retrieves a single page of messages from the list endpoint.
func (r *Runner) fetchPage(ctx context.Context, client *http.Client, pageURL string) (*messagesResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", "odata.maxpagesize=50")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch messages page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.Error("messages list error", "status", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("messages list returned HTTP %d", resp.StatusCode)
	}

	var page messagesResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decode messages response: %w", err)
	}

	return &page, nil
}
