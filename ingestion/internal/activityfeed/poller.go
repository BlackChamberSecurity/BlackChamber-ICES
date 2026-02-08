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

// Package activityfeed — poller runs a background loop that periodically
// checks the Activity Feed for new Exchange audit events and dispatches
// email events for analysis.
package activityfeed

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

// EmailEventCallback is called for each email event extracted from the feed.
type EmailEventCallback func(ctx context.Context, event AuditEvent) error

// Poller periodically checks the Activity Feed for new Audit.Exchange events.
type Poller struct {
	client   *Client
	interval time.Duration
	lookback time.Duration
	onEvent  EmailEventCallback
}

// NewPoller creates a poller that checks for new content at the given interval.
// lookback defines how far back each poll window extends (should be > interval
// to prevent gaps; the Activity Feed deduplicates on its side).
func NewPoller(client *Client, interval, lookback time.Duration, onEvent EmailEventCallback) *Poller {
	return &Poller{
		client:   client,
		interval: interval,
		lookback: lookback,
		onEvent:  onEvent,
	}
}

// emailOperations are the audit event operations that indicate a new email.
var emailOperations = map[string]bool{
	"MessageReceived":  true,
	"MessageDelivered": true,
}

// Run starts the polling loop. It blocks until the context is cancelled.
func (p *Poller) Run(ctx context.Context) {
	slog.Info("activity feed poller starting",
		"interval", p.interval,
		"lookback", p.lookback,
	)

	// Do an initial poll immediately
	p.poll(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("activity feed poller stopping")
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

// poll fetches and processes new content blobs.
func (p *Poller) poll(ctx context.Context) {
	endTime := time.Now().UTC()
	startTime := endTime.Add(-p.lookback)

	slog.Debug("polling activity feed",
		"start", startTime.Format(time.RFC3339),
		"end", endTime.Format(time.RFC3339),
	)

	blobs, err := p.client.ListContent(ctx, startTime, endTime)
	if err != nil {
		slog.Error("failed to list content", "error", err)
		return
	}

	if len(blobs) == 0 {
		slog.Debug("no new content blobs")
		return
	}

	slog.Info("found content blobs", "count", len(blobs))

	for _, blob := range blobs {
		events, err := p.client.FetchBlob(ctx, blob.ContentURI)
		if err != nil {
			slog.Error("failed to fetch blob", "blob_id", blob.ContentID, "error", err)
			continue
		}

		for _, event := range events {
			// Only process email-related operations
			if !emailOperations[event.Operation] {
				continue
			}

			// Only process Exchange workload events
			if !strings.EqualFold(event.Workload, "Exchange") {
				continue
			}

			if err := p.onEvent(ctx, event); err != nil {
				slog.Error("failed to process event",
					"event_id", event.ID,
					"operation", event.Operation,
					"error", err,
				)
			}
		}
	}
}
