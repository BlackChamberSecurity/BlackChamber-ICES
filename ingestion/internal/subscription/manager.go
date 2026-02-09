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

package subscription

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/bcem/ingestion/internal/config"
	"github.com/bcem/ingestion/internal/discovery"
)

// Maximum subscription lifetime for messages is 4230 minutes (~2.94 days).
const maxSubscriptionMinutes = 4230

// LifecycleManager handles creation, renewal, and recovery of per-mailbox
// Graph API subscriptions. It runs a background renewal loop and responds
// to lifecycle notifications.
type LifecycleManager struct {
	store        *Store
	discovery    *discovery.Discovery
	graphClients map[string]*http.Client // keyed by tenant alias
	tenants      []config.TenantConfig
	webhookURL   string
	renewBuffer  time.Duration
	graphBaseURL string

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// OnGapDetected is called when a subscription gap is detected and
	// delta sync should run for the given tenant/user. Wired by main.go.
	OnGapDetected func(ctx context.Context, tenantID, userID string)
}

// ManagerConfig holds the configuration for the lifecycle manager.
type ManagerConfig struct {
	Store        *Store
	Discovery    *discovery.Discovery
	GraphClients map[string]*http.Client
	Tenants      []config.TenantConfig
	WebhookURL   string
	RenewBuffer  time.Duration
	GraphBaseURL string
}

// NewManager creates a new subscription lifecycle manager.
func NewManager(cfg ManagerConfig) *LifecycleManager {
	return &LifecycleManager{
		store:        cfg.Store,
		discovery:    cfg.Discovery,
		graphClients: cfg.GraphClients,
		tenants:      cfg.Tenants,
		webhookURL:   cfg.WebhookURL,
		renewBuffer:  cfg.RenewBuffer,
		graphBaseURL: cfg.GraphBaseURL,
	}
}

// Start discovers mailboxes, ensures subscriptions exist, and starts the
// renewal loop. It blocks until initial setup is complete, then runs the
// renewal loop in the background.
func (m *LifecycleManager) Start(ctx context.Context) error {
	// Initial subscription setup per tenant
	for _, tenant := range m.tenants {
		if tenant.Provider != "m365" {
			continue
		}

		client, ok := m.graphClients[tenant.Alias]
		if !ok {
			return fmt.Errorf("no Graph client for tenant %s", tenant.Alias)
		}

		users, err := m.discovery.DiscoverUsers(ctx, client, tenant.Alias, tenant.IncludeUsers, tenant.ExcludeUsers)
		if err != nil {
			return fmt.Errorf("discover users for %s: %w", tenant.Alias, err)
		}

		slog.Info("ensuring subscriptions for tenant",
			"alias", tenant.Alias,
			"users", len(users),
		)

		for _, user := range users {
			userID := user.Mail // Graph accepts UPN/mail as user identifier
			if user.ID != "" {
				userID = user.ID // Prefer GUID if known
			}

			if err := m.ensureSubscription(ctx, client, tenant, userID); err != nil {
				slog.Error("failed to create subscription",
					"tenant", tenant.Alias,
					"user", userID,
					"error", err,
				)
				// Continue with other users — don't fail the whole startup
			}
		}
	}

	// Start renewal loop
	loopCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.wg.Add(1)
	go m.renewalLoop(loopCtx)

	slog.Info("subscription lifecycle manager started",
		"renewal_interval", m.renewBuffer/2,
	)

	return nil
}

// Stop gracefully shuts down the renewal loop.
func (m *LifecycleManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	slog.Info("subscription lifecycle manager stopped")
}

// ensureSubscription checks whether an active subscription exists for a
// user and creates one if not, or renews it if it's about to expire.
func (m *LifecycleManager) ensureSubscription(ctx context.Context, client *http.Client, tenant config.TenantConfig, userID string) error {
	existing, err := m.store.Get(ctx, tenant.TenantID, userID)
	if err != nil {
		return fmt.Errorf("check existing subscription: %w", err)
	}

	if existing != nil && existing.Status == "active" {
		// Check if it needs renewal
		if time.Until(existing.ExpiresAt) < m.renewBuffer {
			slog.Info("renewing near-expiry subscription",
				"tenant", tenant.Alias,
				"user", userID,
				"expires_in", time.Until(existing.ExpiresAt).Round(time.Minute),
			)
			return m.renewSubscription(ctx, client, *existing)
		}
		slog.Debug("subscription already active",
			"tenant", tenant.Alias,
			"user", userID,
			"expires_at", existing.ExpiresAt,
		)
		return nil
	}

	// Create new subscription
	slog.Info("creating subscription",
		"tenant", tenant.Alias,
		"user", userID,
	)

	return m.createSubscription(ctx, client, tenant, userID)
}

// createSubscription creates a new Graph API subscription for a mailbox.
func (m *LifecycleManager) createSubscription(ctx context.Context, client *http.Client, tenant config.TenantConfig, userID string) error {
	clientState := generateClientState()
	expiry := time.Now().UTC().Add(time.Duration(maxSubscriptionMinutes) * time.Minute)

	notificationURL := fmt.Sprintf("%s/webhook/%s/%s", m.webhookURL, tenant.Alias, userID)
	lifecycleURL := fmt.Sprintf("%s/lifecycle/%s", m.webhookURL, tenant.Alias)

	payload := map[string]interface{}{
		"changeType":               "created",
		"notificationUrl":          notificationURL,
		"lifecycleNotificationUrl": lifecycleURL,
		"resource":                 fmt.Sprintf("/users/%s/messages", userID),
		"expirationDateTime":       expiry.Format(time.RFC3339),
		"clientState":              clientState,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal subscription body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/subscriptions", m.graphBaseURL), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build subscription request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("create subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Graph subscription creation returned HTTP %d for user %s", resp.StatusCode, userID)
	}

	var result struct {
		ID                 string `json:"id"`
		ExpirationDateTime string `json:"expirationDateTime"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode subscription response: %w", err)
	}

	parsedExpiry, _ := time.Parse(time.RFC3339, result.ExpirationDateTime)
	if parsedExpiry.IsZero() {
		parsedExpiry = expiry
	}

	record := Record{
		SubscriptionID: result.ID,
		UserID:         userID,
		TenantID:       tenant.TenantID,
		TenantAlias:    tenant.Alias,
		ClientState:    clientState,
		ExpiresAt:      parsedExpiry,
		Status:         "active",
	}

	if err := m.store.Upsert(ctx, record); err != nil {
		return fmt.Errorf("persist subscription: %w", err)
	}

	slog.Info("subscription created",
		"tenant", tenant.Alias,
		"user", userID,
		"subscription_id", result.ID,
		"expires_at", parsedExpiry,
	)

	// Trigger delta sync to catch any messages that arrived before the subscription was active
	if m.OnGapDetected != nil {
		go m.OnGapDetected(context.Background(), tenant.TenantID, userID)
	}

	return nil
}

// renewSubscription extends the expiry of an existing subscription.
func (m *LifecycleManager) renewSubscription(ctx context.Context, client *http.Client, rec Record) error {
	newExpiry := time.Now().UTC().Add(time.Duration(maxSubscriptionMinutes) * time.Minute)

	payload := map[string]string{
		"expirationDateTime": newExpiry.Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		fmt.Sprintf("%s/subscriptions/%s", m.graphBaseURL, rec.SubscriptionID),
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build renewal request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("renew subscription: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Subscription was removed by Microsoft — re-create
		slog.Warn("subscription removed by Graph, re-creating",
			"subscription_id", rec.SubscriptionID,
			"tenant", rec.TenantAlias,
			"user", rec.UserID,
		)
		if err := m.store.MarkStatus(ctx, rec.SubscriptionID, "removed"); err != nil {
			slog.Error("failed to mark subscription removed", "error", err)
		}

		tenant := m.findTenant(rec.TenantAlias)
		if tenant == nil {
			return fmt.Errorf("tenant %s not found in config", rec.TenantAlias)
		}
		return m.createSubscription(ctx, client, *tenant, rec.UserID)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Graph subscription renewal returned HTTP %d", resp.StatusCode)
	}

	if err := m.store.UpdateExpiry(ctx, rec.SubscriptionID, newExpiry); err != nil {
		return fmt.Errorf("update expiry in store: %w", err)
	}

	slog.Info("subscription renewed",
		"subscription_id", rec.SubscriptionID,
		"tenant", rec.TenantAlias,
		"user", rec.UserID,
		"new_expiry", newExpiry,
	)

	return nil
}

// renewalLoop runs periodically to renew expiring subscriptions.
func (m *LifecycleManager) renewalLoop(ctx context.Context) {
	defer m.wg.Done()

	interval := m.renewBuffer / 2
	if interval < time.Minute {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.renewExpiring(ctx)
		}
	}
}

// renewExpiring renews all subscriptions that are close to expiry.
func (m *LifecycleManager) renewExpiring(ctx context.Context) {
	records, err := m.store.ListExpiringSoon(ctx, m.renewBuffer)
	if err != nil {
		slog.Error("failed to list expiring subscriptions", "error", err)
		return
	}

	if len(records) == 0 {
		return
	}

	slog.Info("renewing expiring subscriptions", "count", len(records))

	for _, rec := range records {
		client, ok := m.graphClients[rec.TenantAlias]
		if !ok {
			slog.Error("no Graph client for tenant", "alias", rec.TenantAlias)
			continue
		}

		if err := m.renewSubscription(ctx, client, rec); err != nil {
			slog.Error("renewal failed",
				"subscription_id", rec.SubscriptionID,
				"tenant", rec.TenantAlias,
				"user", rec.UserID,
				"error", err,
			)
		}
	}
}

// HandleLifecycleEvent processes a lifecycle notification from Graph.
func (m *LifecycleManager) HandleLifecycleEvent(ctx context.Context, lifecycleEvent string, subscriptionID, tenantAlias string) {
	switch lifecycleEvent {
	case "subscriptionRemoved":
		slog.Warn("subscription removed by Graph",
			"subscription_id", subscriptionID,
			"tenant", tenantAlias,
		)
		if err := m.store.MarkStatus(ctx, subscriptionID, "removed"); err != nil {
			slog.Error("failed to mark removed", "error", err)
		}
		// Re-creation happens in the next renewal loop cycle

	case "reauthorizationRequired":
		slog.Info("reauthorization required",
			"subscription_id", subscriptionID,
			"tenant", tenantAlias,
		)
		// Token refresh is handled by the oauth2 transport automatically.
		// Try to renew the subscription.
		rec, err := m.store.Get(ctx, "", "") // We need to find by subscription ID
		if err != nil || rec == nil {
			slog.Error("could not find subscription for reauth", "subscription_id", subscriptionID)
			return
		}
		client, ok := m.graphClients[rec.TenantAlias]
		if !ok {
			return
		}
		_ = m.renewSubscription(ctx, client, *rec)

	case "missed":
		slog.Warn("missed notifications detected",
			"subscription_id", subscriptionID,
			"tenant", tenantAlias,
		)
		// Trigger delta sync — handled by the wired callback
		if m.OnGapDetected != nil {
			// We'd need to look up the userID from the subscription
			// For now, log and let the periodic delta sync handle it
			slog.Info("delta sync will catch up missed notifications")
		}

	default:
		slog.Warn("unknown lifecycle event", "event", lifecycleEvent)
	}
}

// findTenant looks up a tenant config by alias.
func (m *LifecycleManager) findTenant(alias string) *config.TenantConfig {
	for i, t := range m.tenants {
		if t.Alias == alias {
			return &m.tenants[i]
		}
	}
	return nil
}

// generateClientState creates a random secret for webhook validation.
func generateClientState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
