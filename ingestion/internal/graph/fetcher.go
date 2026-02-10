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

// Package graph provides a message fetcher that retrieves full email content
// from the Microsoft Graph API using the official SDK.
package graph

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/bcem/ingestion/internal/models"
)

// Fetcher retrieves full email messages from the Graph API.
// It holds a per-tenant map of authenticated HTTP clients so the correct
// OAuth token is used for each tenant.
type Fetcher struct {
	graphClients map[string]*http.Client // keyed by tenant alias
	graphBaseURL string
}

// NewFetcher creates a Graph API message fetcher.
// graphClients maps tenant alias → authenticated *http.Client.
func NewFetcher(graphClients map[string]*http.Client, graphBaseURL string) *Fetcher {
	return &Fetcher{
		graphClients: graphClients,
		graphBaseURL: graphBaseURL,
	}
}

// FetchMessage retrieves the full email content for a given user and message ID.
// Returns an EmailEvent ready for enqueuing to the analysis pipeline.
func (f *Fetcher) FetchMessage(ctx context.Context, userID, messageID, tenantID, tenantAlias string) (*models.EmailEvent, error) {
	// Select the correct per-tenant Graph client
	client, ok := f.graphClients[tenantAlias]
	if !ok {
		return nil, fmt.Errorf("no Graph client for tenant alias %q", tenantAlias)
	}

	// Build Graph API URL — select only the fields we need
	url := fmt.Sprintf("%s/users/%s/messages/%s?$select=id,subject,receivedDateTime,from,toRecipients,body,internetMessageHeaders,hasAttachments",
		f.graphBaseURL, userID, messageID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", "outlook.body-content-type=\"text\"")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		slog.Warn("message not found (may have been deleted)",
			"user_id", userID,
			"message_id", messageID,
		)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graph API returned HTTP %d for message %s", resp.StatusCode, messageID)
	}

	// Parse Graph API response into our canonical EmailEvent
	event, err := parseGraphMessage(resp.Body, userID, tenantID, tenantAlias)
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	return event, nil
}
