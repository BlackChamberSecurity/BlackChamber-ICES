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

// Package dedup provides event deduplication using a Redis SET with TTL.
// This prevents the same email event from being processed multiple times
// when the Activity Feed poller's lookback windows overlap.
package dedup

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// DefaultTTL is how long we remember a seen event ID.
	// Activity Feed content blobs expire after 7 days, so 24h is safe.
	DefaultTTL = 24 * time.Hour

	// keyPrefix namespaces dedup keys in Redis.
	keyPrefix = "ices:seen:"
)

// Filter tracks which event IDs have already been processed.
type Filter struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewFilter creates a dedup filter backed by Redis.
func NewFilter(rdb *redis.Client) *Filter {
	return &Filter{
		rdb: rdb,
		ttl: DefaultTTL,
	}
}

// IsNew returns true if the event ID has NOT been seen before.
// If true, the event is marked as seen atomically (SETNX).
func (f *Filter) IsNew(ctx context.Context, eventID string) (bool, error) {
	key := fmt.Sprintf("%s%s", keyPrefix, eventID)

	// SET NX = set only if key does not exist. Returns true if the key was set.
	set, err := f.rdb.SetNX(ctx, key, 1, f.ttl).Result()
	if err != nil {
		return false, fmt.Errorf("dedup SETNX: %w", err)
	}

	return set, nil
}
