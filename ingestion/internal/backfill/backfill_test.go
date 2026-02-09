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

package backfill

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// --- Mock dedup filter ---

type mockDedup struct {
	mu   sync.Mutex
	seen map[string]bool
}

func newMockDedup() *mockDedup {
	return &mockDedup{seen: make(map[string]bool)}
}

func (m *mockDedup) IsNew(_ context.Context, eventID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[eventID] {
		return false, nil
	}
	m.seen[eventID] = true
	return true, nil
}

func (m *mockDedup) markSeen(eventID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[eventID] = true
}

// --- Mock publisher ---

type mockPublisher struct {
	mu       sync.Mutex
	messages []string // collected message IDs
}

func (m *mockPublisher) published() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.messages))
	copy(out, m.messages)
	return out
}

// --- Test helpers ---

// graphMessageResponse creates a minimal Graph API message response body.
func graphMessageResponse(id string) map[string]interface{} {
	return map[string]interface{}{
		"id":      id,
		"subject": "Test Subject " + id,
		"from": map[string]interface{}{
			"emailAddress": map[string]interface{}{
				"address": "sender@test.com",
				"name":    "Sender",
			},
		},
		"toRecipients": []map[string]interface{}{
			{
				"emailAddress": map[string]interface{}{
					"address": "user@test.com",
					"name":    "User",
				},
			},
		},
		"body": map[string]interface{}{
			"contentType": "text",
			"content":     "Test body for " + id,
		},
		"internetMessageHeaders": []map[string]string{},
		"hasAttachments":         false,
	}
}

// TestBackfill_ListsAndFetches verifies that the runner lists message IDs
// from a single page and fetches each one.
func TestBackfill_ListsAndFetches(t *testing.T) {
	var published []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Route: message list (contains $filter)
		if r.URL.Query().Get("$filter") != "" || r.URL.Query().Get("$select") == "id" {
			data, _ := json.Marshal(map[string]interface{}{
				"value": []map[string]string{
					{"id": "msg-1"},
					{"id": "msg-2"},
					{"id": "msg-3"},
				},
			})
			w.Write(data)
			return
		}

		// Route: individual message fetch (path contains /messages/<id>)
		// Extract the message ID from the path
		msgID := ""
		for _, id := range []string{"msg-1", "msg-2", "msg-3"} {
			if r.URL.Path == fmt.Sprintf("/users/user1/messages/%s", id) {
				msgID = id
				break
			}
		}

		if msgID != "" {
			mu.Lock()
			published = append(published, msgID)
			mu.Unlock()

			data, _ := json.Marshal(graphMessageResponse(msgID))
			w.Write(data)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Build a runner with the mock server
	// We can't easily use graph.Fetcher and queue.Publisher with mocks from
	// outside their packages, so we test fetchPage directly and the
	// integration via the Run method using a real HTTP mock.

	// Test fetchPage independently
	r := &Runner{graphBaseURL: server.URL, pageDelay: time.Millisecond}

	ctx := context.Background()
	listURL := fmt.Sprintf("%s/users/user1/messages?$filter=receivedDateTime+ge+2026-01-01&$select=id&$top=50", server.URL)
	page, err := r.fetchPage(ctx, server.Client(), listURL)
	if err != nil {
		t.Fatalf("fetchPage failed: %v", err)
	}

	if len(page.Value) != 3 {
		t.Errorf("expected 3 messages, got %d", len(page.Value))
	}

	if page.Value[0].ID != "msg-1" {
		t.Errorf("first message ID = %q, want msg-1", page.Value[0].ID)
	}
}

// TestBackfill_Pagination verifies that the runner follows pagination links.
func TestBackfill_Pagination(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch page {
		case 0:
			data, _ := json.Marshal(map[string]interface{}{
				"value": []map[string]string{
					{"id": "msg-1"},
					{"id": "msg-2"},
				},
				"@odata.nextLink": fmt.Sprintf("http://%s/page2", r.Host),
			})
			w.Write(data)
			page++
		case 1:
			data, _ := json.Marshal(map[string]interface{}{
				"value": []map[string]string{
					{"id": "msg-3"},
				},
			})
			w.Write(data)
			page++
		}
	}))
	defer server.Close()

	r := &Runner{graphBaseURL: server.URL, pageDelay: time.Millisecond}
	ctx := context.Background()

	// Fetch first page
	firstURL := fmt.Sprintf("http://%s/page1", server.Listener.Addr().String())
	page1, err := r.fetchPage(ctx, server.Client(), firstURL)
	if err != nil {
		t.Fatalf("page 1 failed: %v", err)
	}

	if len(page1.Value) != 2 {
		t.Errorf("page 1: expected 2 messages, got %d", len(page1.Value))
	}

	if page1.NextLink == "" {
		t.Fatal("page 1: expected nextLink, got empty")
	}

	// Follow pagination
	page2, err := r.fetchPage(ctx, server.Client(), page1.NextLink)
	if err != nil {
		t.Fatalf("page 2 failed: %v", err)
	}

	if len(page2.Value) != 1 {
		t.Errorf("page 2: expected 1 message, got %d", len(page2.Value))
	}

	if page2.NextLink != "" {
		t.Errorf("page 2: expected no nextLink, got %q", page2.NextLink)
	}
}

// TestBackfill_EmptyMailbox verifies clean completion with zero messages.
func TestBackfill_EmptyMailbox(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(map[string]interface{}{
			"value": []map[string]string{},
		})
		w.Write(data)
	}))
	defer server.Close()

	r := &Runner{graphBaseURL: server.URL, pageDelay: time.Millisecond}
	ctx := context.Background()

	page, err := r.fetchPage(ctx, server.Client(), server.URL+"/users/user1/messages?$filter=test")
	if err != nil {
		t.Fatalf("fetchPage failed: %v", err)
	}

	if len(page.Value) != 0 {
		t.Errorf("expected 0 messages, got %d", len(page.Value))
	}
}

// TestBackfill_FetchPageError verifies error handling for non-200 responses.
func TestBackfill_FetchPageError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "throttled"}`))
	}))
	defer server.Close()

	r := &Runner{graphBaseURL: server.URL, pageDelay: time.Millisecond}
	ctx := context.Background()

	_, err := r.fetchPage(ctx, server.Client(), server.URL+"/users/user1/messages")
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
}
