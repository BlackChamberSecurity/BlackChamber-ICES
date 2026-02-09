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

// Package delta provides gap-recovery synchronisation using the Graph API
// delta query endpoint (/users/{id}/messages/delta). It processes changes
// since the last known delta token and publishes new messages to the
// analysis pipeline.
package delta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bcem/ingestion/internal/dedup"
	"github.com/bcem/ingestion/internal/graph"
	"github.com/bcem/ingestion/internal/models"
	"github.com/bcem/ingestion/internal/queue"
)

// DeltaStore is the interface the syncer needs to persist delta tokens.
// Implemented by subscription.Store.
type DeltaStore interface {
	SaveDeltaLink(ctx context.Context, tenantID, userID, deltaLink string) error
}

// deltaResponse represents a page of the /messages/delta response.
type deltaResponse struct {
	Value     []deltaMessage `json:"value"`
	NextLink  string         `json:"@odata.nextLink"`
	DeltaLink string         `json:"@odata.deltaLink"`
}

// deltaMessage is a minimal message from the delta query.
type deltaMessage struct {
	ID      string `json:"id"`
	Removed *struct {
		Reason string `json:"reason"`
	} `json:"@removed"`
}

// Syncer provides catch-up synchronisation via delta queries.
type Syncer struct {
	graphClients map[string]*http.Client // keyed by tenant alias
	graphBaseURL string
	fetcher      *graph.Fetcher
	publisher    *queue.Publisher
	dedup        *dedup.Filter
	store        DeltaStore

	// deltaLinks is a cache of tenant:user -> deltaLink, loaded from Postgres.
	deltaLinks map[string]string
	mu         sync.RWMutex

	syncInterval time.Duration
	cancel       context.CancelFunc
	wg           sync.WaitGroup
}

// SyncerConfig holds the configuration for the delta syncer.
type SyncerConfig struct {
	GraphClients map[string]*http.Client
	GraphBaseURL string
	Fetcher      *graph.Fetcher
	Publisher    *queue.Publisher
	Dedup        *dedup.Filter
	Store        DeltaStore
	SyncInterval time.Duration
}

// NewSyncer creates a delta syncer.
func NewSyncer(cfg SyncerConfig) *Syncer {
	return &Syncer{
		graphClients: cfg.GraphClients,
		graphBaseURL: cfg.GraphBaseURL,
		fetcher:      cfg.Fetcher,
		publisher:    cfg.Publisher,
		dedup:        cfg.Dedup,
		store:        cfg.Store,
		deltaLinks:   make(map[string]string),
		syncInterval: cfg.SyncInterval,
	}
}

// SetDeltaLink caches a known delta link (loaded from Postgres on startup).
func (s *Syncer) SetDeltaLink(tenantID, userID, link string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deltaLinks[tenantID+":"+userID] = link
}

// SyncMailbox performs a delta sync for a single mailbox.
// If no delta token exists, does a full initial sync (only collecting the
// delta token — we don't process historical messages on first sync to
// avoid overwhelming the pipeline).
func (s *Syncer) SyncMailbox(ctx context.Context, httpClient *http.Client, tenantID, tenantAlias, userID string) error {
	key := tenantID + ":" + userID

	s.mu.RLock()
	deltaLink := s.deltaLinks[key]
	s.mu.RUnlock()

	if deltaLink == "" {
		// Initial sync — collect the delta token without processing messages
		return s.initialSync(ctx, httpClient, tenantID, tenantAlias, userID)
	}

	return s.incrementalSync(ctx, httpClient, tenantID, tenantAlias, userID, deltaLink)
}

// initialSync pages through /messages/delta to obtain the initial delta token.
// We don't process messages from the initial sync to avoid re-processing
// the entire mailbox history. Only the delta token is saved.
func (s *Syncer) initialSync(ctx context.Context, client *http.Client, tenantID, tenantAlias, userID string) error {
	slog.Info("starting initial delta sync (collecting token)",
		"tenant", tenantAlias,
		"user", userID,
	)

	params := url.Values{}
	params.Set("$select", "id")
	initialURL := fmt.Sprintf("%s/users/%s/messages/delta?%s", s.graphBaseURL, userID, params.Encode())
	pageCount := 0

	for nextURL := initialURL; nextURL != ""; {
		page, err := s.fetchDeltaPage(ctx, client, nextURL)
		if err != nil {
			return fmt.Errorf("initial delta sync page %d: %w", pageCount, err)
		}
		pageCount++

		if page.DeltaLink != "" {
			// We have the token — save it and we're done
			return s.saveDeltaLink(ctx, tenantID, userID, page.DeltaLink)
		}

		nextURL = page.NextLink
	}

	return fmt.Errorf("initial delta sync completed without receiving deltaLink")
}

// incrementalSync processes changes since the last delta token.
func (s *Syncer) incrementalSync(ctx context.Context, client *http.Client, tenantID, tenantAlias, userID string, deltaLink string) error {
	slog.Info("starting incremental delta sync",
		"tenant", tenantAlias,
		"user", userID,
	)

	url := deltaLink
	totalNew := 0

	for url != "" {
		page, err := s.fetchDeltaPage(ctx, client, url)
		if err != nil {
			// 410 Gone = delta token expired, need full re-sync
			if isGone(err) {
				slog.Warn("delta token expired (410 Gone), performing full re-sync",
					"tenant", tenantAlias,
					"user", userID,
				)
				// Clear the cached token and do initial sync
				s.mu.Lock()
				delete(s.deltaLinks, tenantID+":"+userID)
				s.mu.Unlock()
				return s.initialSync(ctx, client, tenantID, tenantAlias, userID)
			}
			return fmt.Errorf("incremental delta sync: %w", err)
		}

		// Process new messages (skip removed/updated)
		for _, msg := range page.Value {
			if msg.Removed != nil {
				continue // Skip deletions
			}

			// Dedup check
			isNew, err := s.dedup.IsNew(ctx, "delta:"+msg.ID)
			if err != nil {
				slog.Warn("dedup check failed during delta sync", "error", err)
			} else if !isNew {
				continue
			}

			// Fetch full message
			event, err := s.fetcher.FetchMessage(ctx, userID, msg.ID, tenantID, tenantAlias)
			if err != nil {
				slog.Error("delta sync: fetch message failed",
					"message_id", msg.ID,
					"error", err,
				)
				continue
			}

			if event == nil {
				continue
			}

			if err := s.publisher.PublishEmailEvent(ctx, event); err != nil {
				slog.Error("delta sync: publish failed",
					"message_id", msg.ID,
					"error", err,
				)
				continue
			}

			totalNew++
		}

		if page.DeltaLink != "" {
			if err := s.saveDeltaLink(ctx, tenantID, userID, page.DeltaLink); err != nil {
				return err
			}
			url = "" // Done
		} else {
			url = page.NextLink
		}
	}

	slog.Info("incremental delta sync complete",
		"tenant", tenantAlias,
		"user", userID,
		"new_messages", totalNew,
	)

	return nil
}

// fetchDeltaPage fetches a single page from the delta endpoint.
func (s *Syncer) fetchDeltaPage(ctx context.Context, client *http.Client, url string) (*deltaResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build delta request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", "odata.maxpagesize=100")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch delta page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusGone {
		return nil, &goneError{}
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		slog.Error("delta query error", "status", resp.StatusCode, "body", string(body))
		return nil, fmt.Errorf("delta query returned HTTP %d", resp.StatusCode)
	}

	var page deltaResponse
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("decode delta response: %w", err)
	}

	return &page, nil
}

// saveDeltaLink persists and caches a delta token.
func (s *Syncer) saveDeltaLink(ctx context.Context, tenantID, userID, link string) error {
	s.mu.Lock()
	s.deltaLinks[tenantID+":"+userID] = link
	s.mu.Unlock()

	if err := s.store.SaveDeltaLink(ctx, tenantID, userID, link); err != nil {
		return fmt.Errorf("persist delta link: %w", err)
	}

	slog.Debug("delta link saved", "tenant", tenantID, "user", userID)
	return nil
}

// StartPeriodicSync runs delta sync for all known subscriptions at the
// configured interval as a safety net.
func (s *Syncer) StartPeriodicSync(ctx context.Context, tenants []struct {
	TenantID    string
	TenantAlias string
	Users       []string
	Client      *http.Client
}) {
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()

		ticker := time.NewTicker(s.syncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				for _, t := range tenants {
					for _, userID := range t.Users {
						if err := s.SyncMailbox(loopCtx, t.Client, t.TenantID, t.TenantAlias, userID); err != nil {
							slog.Error("periodic delta sync failed",
								"tenant", t.TenantAlias,
								"user", userID,
								"error", err,
							)
						}
					}
				}
			}
		}
	}()

	slog.Info("periodic delta sync started", "interval", s.syncInterval)
}

// Stop shuts down the periodic sync loop.
func (s *Syncer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

// goneError represents a 410 Gone response (expired delta token).
type goneError struct{}

func (e *goneError) Error() string { return "delta token expired (410 Gone)" }

func isGone(err error) bool {
	_, ok := err.(*goneError)
	return ok
}

// Ensure models import is used (fetcher returns *models.EmailEvent)
var _ *models.EmailEvent
