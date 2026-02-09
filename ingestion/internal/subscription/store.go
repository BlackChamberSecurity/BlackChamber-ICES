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

// Package subscription provides a Postgres-backed store for Graph API
// subscription state and a lifecycle manager that handles creation,
// renewal, and recovery of per-mailbox subscriptions.
package subscription

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Record represents a single Graph API subscription persisted in Postgres.
type Record struct {
	ID               int64
	SubscriptionID   string
	UserID           string
	TenantID         string
	TenantAlias      string
	ClientState      string
	ExpiresAt        time.Time
	DeltaLink        string
	LastNotification *time.Time
	LastDeltaSync    *time.Time
	Status           string // "active", "expired", "removed"
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Store provides CRUD operations for subscription records in Postgres.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a subscription store backed by the given Postgres pool.
// It ensures the subscriptions table exists on creation.
func NewStore(ctx context.Context, pool *pgxpool.Pool) (*Store, error) {
	s := &Store{pool: pool}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("ensure subscription schema: %w", err)
	}
	slog.Info("subscription store initialised")
	return s, nil
}

func (s *Store) ensureSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS subscriptions (
			id                BIGSERIAL PRIMARY KEY,
			subscription_id   TEXT NOT NULL UNIQUE,
			user_id           TEXT NOT NULL,
			tenant_id         TEXT NOT NULL,
			tenant_alias      TEXT DEFAULT '',
			client_state      TEXT NOT NULL,
			expires_at        TIMESTAMPTZ NOT NULL,
			delta_link        TEXT DEFAULT '',
			last_notification TIMESTAMPTZ,
			last_delta_sync   TIMESTAMPTZ,
			status            TEXT DEFAULT 'active',
			created_at        TIMESTAMPTZ DEFAULT NOW(),
			updated_at        TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(tenant_id, user_id)
		);
		CREATE INDEX IF NOT EXISTS idx_subs_tenant ON subscriptions(tenant_id);
		CREATE INDEX IF NOT EXISTS idx_subs_expires ON subscriptions(expires_at);
		CREATE INDEX IF NOT EXISTS idx_subs_status ON subscriptions(status);
	`)
	return err
}

// Upsert inserts or updates a subscription record keyed on (tenant_id, user_id).
func (s *Store) Upsert(ctx context.Context, r Record) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO subscriptions
			(subscription_id, user_id, tenant_id, tenant_alias, client_state, expires_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET
			subscription_id = EXCLUDED.subscription_id,
			client_state    = EXCLUDED.client_state,
			expires_at      = EXCLUDED.expires_at,
			status          = EXCLUDED.status,
			updated_at      = NOW()
	`, r.SubscriptionID, r.UserID, r.TenantID, r.TenantAlias, r.ClientState, r.ExpiresAt, r.Status)
	return err
}

// Get retrieves a single subscription for a tenant + user.
func (s *Store) Get(ctx context.Context, tenantID, userID string) (*Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, subscription_id, user_id, tenant_id, tenant_alias,
		       client_state, expires_at, delta_link, last_notification,
		       last_delta_sync, status, created_at, updated_at
		FROM subscriptions
		WHERE tenant_id = $1 AND user_id = $2
	`, tenantID, userID)
	return scanRecord(row)
}

// GetBySubscriptionID retrieves a subscription by its Graph API subscription ID.
// Used by lifecycle event handlers that only receive a subscription ID.
func (s *Store) GetBySubscriptionID(ctx context.Context, subscriptionID string) (*Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, subscription_id, user_id, tenant_id, tenant_alias,
		       client_state, expires_at, delta_link, last_notification,
		       last_delta_sync, status, created_at, updated_at
		FROM subscriptions
		WHERE subscription_id = $1
	`, subscriptionID)
	return scanRecord(row)
}

// ListByTenant returns all subscriptions for a tenant.
func (s *Store) ListByTenant(ctx context.Context, tenantID string) ([]Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, subscription_id, user_id, tenant_id, tenant_alias,
		       client_state, expires_at, delta_link, last_notification,
		       last_delta_sync, status, created_at, updated_at
		FROM subscriptions
		WHERE tenant_id = $1
		ORDER BY user_id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRecords(rows)
}

// ListExpiringSoon returns active subscriptions expiring within the given buffer.
func (s *Store) ListExpiringSoon(ctx context.Context, buffer time.Duration) ([]Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, subscription_id, user_id, tenant_id, tenant_alias,
		       client_state, expires_at, delta_link, last_notification,
		       last_delta_sync, status, created_at, updated_at
		FROM subscriptions
		WHERE status = 'active' AND expires_at < NOW() + $1::interval
		ORDER BY expires_at
	`, fmt.Sprintf("%d seconds", int(buffer.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectRecords(rows)
}

// SaveDeltaLink persists the delta token for a mailbox.
func (s *Store) SaveDeltaLink(ctx context.Context, tenantID, userID, deltaLink string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET delta_link = $1, last_delta_sync = NOW(), updated_at = NOW()
		WHERE tenant_id = $2 AND user_id = $3
	`, deltaLink, tenantID, userID)
	return err
}

// UpdateExpiry updates the expiration time after a successful renewal.
func (s *Store) UpdateExpiry(ctx context.Context, subscriptionID string, newExpiry time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET expires_at = $1, updated_at = NOW()
		WHERE subscription_id = $2
	`, newExpiry, subscriptionID)
	return err
}

// MarkStatus sets the status of a subscription (active, expired, removed).
func (s *Store) MarkStatus(ctx context.Context, subscriptionID, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET status = $1, updated_at = NOW()
		WHERE subscription_id = $2
	`, status, subscriptionID)
	return err
}

// TouchNotification updates last_notification to NOW().
func (s *Store) TouchNotification(ctx context.Context, tenantID, userID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE subscriptions
		SET last_notification = NOW(), updated_at = NOW()
		WHERE tenant_id = $1 AND user_id = $2
	`, tenantID, userID)
	return err
}

// Delete removes a subscription record.
func (s *Store) Delete(ctx context.Context, tenantID, userID string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM subscriptions WHERE tenant_id = $1 AND user_id = $2
	`, tenantID, userID)
	return err
}

// scanRecord scans a single row into a Record.
func scanRecord(row pgx.Row) (*Record, error) {
	var r Record
	err := row.Scan(
		&r.ID, &r.SubscriptionID, &r.UserID, &r.TenantID, &r.TenantAlias,
		&r.ClientState, &r.ExpiresAt, &r.DeltaLink, &r.LastNotification,
		&r.LastDeltaSync, &r.Status, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// collectRecords scans multiple rows into a slice of Records.
func collectRecords(rows pgx.Rows) ([]Record, error) {
	var records []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(
			&r.ID, &r.SubscriptionID, &r.UserID, &r.TenantID, &r.TenantAlias,
			&r.ClientState, &r.ExpiresAt, &r.DeltaLink, &r.LastNotification,
			&r.LastDeltaSync, &r.Status, &r.CreatedAt, &r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
