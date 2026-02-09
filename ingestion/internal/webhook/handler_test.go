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

package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseResource verifies the resource path parser.
func TestParseResource(t *testing.T) {
	tests := []struct {
		resource  string
		wantUser  string
		wantMsg   string
		wantError bool
	}{
		{
			resource: "users/abc123/messages/msg456",
			wantUser: "abc123",
			wantMsg:  "msg456",
		},
		{
			resource: "/users/abc123/messages/msg456",
			wantUser: "abc123",
			wantMsg:  "msg456",
		},
		{
			resource:  "users/abc123/mailFolders/inbox",
			wantError: true,
		},
		{
			resource:  "invalid",
			wantError: true,
		},
		{
			resource:  "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.resource, func(t *testing.T) {
			userID, msgID, err := parseResource(tt.resource)
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error for resource %q, got none", tt.resource)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if userID != tt.wantUser {
				t.Errorf("userID = %q, want %q", userID, tt.wantUser)
			}
			if msgID != tt.wantMsg {
				t.Errorf("messageID = %q, want %q", msgID, tt.wantMsg)
			}
		})
	}
}

// TestServeNotification_ValidationToken verifies the validation probe flow.
func TestServeNotification_ValidationToken(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodPost, "/webhook/tenant/user?validationToken=test-token-123", nil)
	rr := httptest.NewRecorder()

	h.ServeNotification(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if body != "test-token-123" {
		t.Errorf("body = %q, want %q", body, "test-token-123")
	}

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

// TestServeLifecycle_ValidationToken verifies lifecycle endpoint validation probes.
func TestServeLifecycle_ValidationToken(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodPost, "/lifecycle/tenant?validationToken=lifecycle-token", nil)
	rr := httptest.NewRecorder()

	h.ServeLifecycle(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if body := rr.Body.String(); body != "lifecycle-token" {
		t.Errorf("body = %q, want %q", body, "lifecycle-token")
	}
}

// TestServeNotification_AcceptsNotifications verifies that notification payloads
// are accepted with 202 and processed.
func TestServeNotification_AcceptsNotifications(t *testing.T) {
	h := &Handler{} // nil deps — processNotifications will handle gracefully

	payload := NotificationPayload{
		Value: []ChangeNotification{
			{
				SubscriptionID: "sub-1",
				ChangeType:     "created",
				Resource:       "users/user1/messages/msg1",
				ClientState:    "secret",
				TenantID:       "tenant-1",
			},
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/webhook/tenant/user", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.ServeNotification(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
}

// TestServeNotification_NonPostReturnsOK verifies GET requests return 200.
func TestServeNotification_NonPostReturnsOK(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodGet, "/webhook/tenant/user", nil)
	rr := httptest.NewRecorder()

	h.ServeNotification(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestServeNotification_InvalidJSON verifies graceful handling of bad payloads.
func TestServeNotification_InvalidJSON(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodPost, "/webhook/tenant/user", strings.NewReader("not json"))
	rr := httptest.NewRecorder()

	h.ServeNotification(rr, req)

	// Should still return 202 — don't tell Graph to retry
	if rr.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
}
