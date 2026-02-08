// Copyright (c) 2026 John Earle
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://github.com/yourusername/bcem/blob/main/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package activityfeed implements a client for the Office 365 Management
// Activity API. This provides tenant-wide audit events via a single
// Audit.Exchange subscription — no per-user subscriptions needed.
//
// API docs: https://learn.microsoft.com/en-us/office/office-365-management-api/
package activityfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the root of the Management Activity API.
	DefaultBaseURL = "https://manage.office.com/api/v1.0"
	// ContentType for Exchange audit events.
	ContentTypeExchange = "Audit.Exchange"
)

// Client talks to the Office 365 Management Activity API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	tenantID   string
}

// NewClient creates an Activity Feed client. The httpClient must already
// handle authentication (e.g. via azidentity token credential).
func NewClient(httpClient *http.Client, tenantID string) *Client {
	return &Client{
		httpClient: httpClient,
		baseURL:    DefaultBaseURL,
		tenantID:   tenantID,
	}
}

// ContentBlob represents a blob reference returned by the list content endpoint.
type ContentBlob struct {
	ContentURI        string `json:"contentUri"`
	ContentID         string `json:"contentId"`
	ContentType       string `json:"contentType"`
	ContentCreated    string `json:"contentCreated"`
	ContentExpiration string `json:"contentExpiration"`
}

// AuditEvent represents a single audit event within a content blob.
// We only parse the fields relevant to email ingestion.
type AuditEvent struct {
	ID           string `json:"Id"`
	Operation    string `json:"Operation"`
	CreationTime string `json:"CreationTime"`
	UserID       string `json:"UserId"`
	Workload     string `json:"Workload"`

	// Exchange-specific fields
	MessageID     string `json:"InternetMessageId"`
	ItemID        string `json:"ItemId,omitempty"`
	Subject       string `json:"Subject,omitempty"`
	SenderAddress string `json:"SenderAddress,omitempty"`
}

// StartSubscription activates the Audit.Exchange content type.
// This is idempotent — calling it when already active is a no-op.
func (c *Client) StartSubscription(ctx context.Context) error {
	u := fmt.Sprintf("%s/%s/activity/feed/subscriptions/start?contentType=%s",
		c.baseURL, c.tenantID, ContentTypeExchange)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("start subscription: %w", err)
	}
	defer resp.Body.Close()

	// 200 = already active, 200 = just started — both are fine
	// 400 with AF20024 = subscription already enabled — also fine
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// AF20024 means "The subscription is already enabled" — treat as success
		if resp.StatusCode == http.StatusBadRequest && strings.Contains(bodyStr, "AF20024") {
			slog.Info("activity feed subscription already active", "content_type", ContentTypeExchange)
			return nil
		}

		return fmt.Errorf("start subscription failed (HTTP %d): %s", resp.StatusCode, bodyStr)
	}

	slog.Info("activity feed subscription active", "content_type", ContentTypeExchange)
	return nil
}

// ListContent returns available content blobs for the given time window.
// The Management API makes blobs available in ~60-90 minutes.
func (c *Client) ListContent(ctx context.Context, startTime, endTime time.Time) ([]ContentBlob, error) {
	u := fmt.Sprintf("%s/%s/activity/feed/subscriptions/content?contentType=%s&startTime=%s&endTime=%s",
		c.baseURL, c.tenantID, ContentTypeExchange,
		url.QueryEscape(startTime.UTC().Format(time.RFC3339)),
		url.QueryEscape(endTime.UTC().Format(time.RFC3339)),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list content: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list content failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var blobs []ContentBlob
	if err := json.NewDecoder(resp.Body).Decode(&blobs); err != nil {
		return nil, fmt.Errorf("decode content list: %w", err)
	}

	// Handle pagination via NextPageUri header
	nextPage := resp.Header.Get("NextPageUri")
	for nextPage != "" {
		moreBlobs, next, err := c.fetchPage(ctx, nextPage)
		if err != nil {
			return blobs, fmt.Errorf("fetch next page: %w", err)
		}
		blobs = append(blobs, moreBlobs...)
		nextPage = next
	}

	return blobs, nil
}

// FetchBlob downloads and parses a content blob into audit events.
func (c *Client) FetchBlob(ctx context.Context, blobURL string) ([]AuditEvent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch blob: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetch blob failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var events []AuditEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, fmt.Errorf("decode blob: %w", err)
	}

	return events, nil
}

func (c *Client) fetchPage(ctx context.Context, pageURL string) ([]ContentBlob, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	var blobs []ContentBlob
	if err := json.NewDecoder(resp.Body).Decode(&blobs); err != nil {
		return nil, "", err
	}

	return blobs, resp.Header.Get("NextPageUri"), nil
}
