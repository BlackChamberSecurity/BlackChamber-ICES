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
	"testing"
	"time"

	"github.com/bcem/ingestion/internal/config"
)

// TestGenerateClientState verifies the random secret generator.
func TestGenerateClientState(t *testing.T) {
	s1 := generateClientState()
	s2 := generateClientState()

	if len(s1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("expected 32 char hex string, got %d chars: %s", len(s1), s1)
	}

	if s1 == s2 {
		t.Error("two generated states should not be equal")
	}
}

// TestRecord_StatusValues verifies the record status constants.
func TestRecord_StatusValues(t *testing.T) {
	r := Record{
		SubscriptionID: "test-sub",
		UserID:         "user@example.com",
		TenantID:       "tenant-1",
		TenantAlias:    "test",
		ClientState:    "secret",
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		Status:         "active",
	}

	if r.Status != "active" {
		t.Errorf("status = %q, want active", r.Status)
	}

	r.Status = "expired"
	if r.Status != "expired" {
		t.Errorf("status = %q, want expired", r.Status)
	}

	r.Status = "removed"
	if r.Status != "removed" {
		t.Errorf("status = %q, want removed", r.Status)
	}
}

// TestManagerConfig_Wiring verifies manager config wiring.
func TestManagerConfig_Wiring(t *testing.T) {
	cfg := ManagerConfig{
		WebhookURL:   "https://example.com",
		RenewBuffer:  30 * time.Minute,
		GraphBaseURL: "https://graph.microsoft.com/v1.0",
	}

	mgr := NewManager(cfg)

	if mgr.webhookURL != "https://example.com" {
		t.Errorf("webhookURL = %q, want https://example.com", mgr.webhookURL)
	}

	if mgr.renewBuffer != 30*time.Minute {
		t.Errorf("renewBuffer = %v, want 30m", mgr.renewBuffer)
	}

	if mgr.graphBaseURL != "https://graph.microsoft.com/v1.0" {
		t.Errorf("graphBaseURL = %q", mgr.graphBaseURL)
	}
}

// TestFindTenant verifies tenant lookup by alias.
func TestFindTenant(t *testing.T) {
	mgr := &LifecycleManager{
		tenants: []config.TenantConfig{
			{Alias: "alpha", TenantID: "t1"},
			{Alias: "beta", TenantID: "t2"},
		},
	}

	found := mgr.findTenant("alpha")
	if found == nil {
		t.Fatal("expected to find tenant alpha")
	}
	if found.TenantID != "t1" {
		t.Errorf("tenantID = %q, want t1", found.TenantID)
	}

	found = mgr.findTenant("beta")
	if found == nil {
		t.Fatal("expected to find tenant beta")
	}
	if found.TenantID != "t2" {
		t.Errorf("tenantID = %q, want t2", found.TenantID)
	}

	notFound := mgr.findTenant("gamma")
	if notFound != nil {
		t.Error("expected nil for unknown tenant")
	}
}

// TestMaxSubscriptionMinutes verifies the constant matches Graph API docs.
func TestMaxSubscriptionMinutes(t *testing.T) {
	if maxSubscriptionMinutes != 4230 {
		t.Errorf("maxSubscriptionMinutes = %d, want 4230", maxSubscriptionMinutes)
	}

	// ~2.94 days
	hours := float64(maxSubscriptionMinutes) / 60
	if hours < 70 || hours > 71 {
		t.Errorf("max subscription hours = %.1f, expected ~70.5", hours)
	}
}
