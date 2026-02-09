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

package delta

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// mockDeltaStore implements DeltaStore for testing.
type mockDeltaStore struct {
	mu    sync.Mutex
	links map[string]string
}

func newMockStore() *mockDeltaStore {
	return &mockDeltaStore{links: make(map[string]string)}
}

func (m *mockDeltaStore) SaveDeltaLink(_ context.Context, tenantID, userID, link string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links[tenantID+":"+userID] = link
	return nil
}

func (m *mockDeltaStore) getLink(tenantID, userID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.links[tenantID+":"+userID]
}

// TestSyncer_SetDeltaLink verifies caching delta links.
func TestSyncer_SetDeltaLink(t *testing.T) {
	s := &Syncer{deltaLinks: make(map[string]string)}

	s.SetDeltaLink("t1", "user1", "delta://token1")

	s.mu.RLock()
	link := s.deltaLinks["t1:user1"]
	s.mu.RUnlock()

	if link != "delta://token1" {
		t.Errorf("link = %q, want delta://token1", link)
	}
}

// TestSyncer_InitialSync verifies that initial sync collects the delta token
// without processing messages.
func TestSyncer_InitialSync(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch page {
		case 0:
			data, _ := json.Marshal(map[string]interface{}{
				"value": []map[string]string{
					{"id": "msg1"},
					{"id": "msg2"},
				},
				"@odata.nextLink": "http://" + r.Host + "/page2",
			})
			w.Write(data)
			page++
		case 1:
			data, _ := json.Marshal(map[string]interface{}{
				"value":            []map[string]string{},
				"@odata.deltaLink": "delta://final-token",
			})
			w.Write(data)
			page++
		}
	}))
	defer server.Close()

	store := newMockStore()
	s := &Syncer{
		graphBaseURL: server.URL,
		store:        store,
		deltaLinks:   make(map[string]string),
	}

	err := s.initialSync(context.Background(), server.Client(), "t1", "test", "user1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that the token was saved
	saved := store.getLink("t1", "user1")
	if saved != "delta://final-token" {
		t.Errorf("saved link = %q, want delta://final-token", saved)
	}

	// Check the cache
	s.mu.RLock()
	cached := s.deltaLinks["t1:user1"]
	s.mu.RUnlock()
	if cached != "delta://final-token" {
		t.Errorf("cached link = %q, want delta://final-token", cached)
	}
}

// TestSyncer_FetchDeltaPage_Gone verifies 410 Gone handling.
func TestSyncer_FetchDeltaPage_Gone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer server.Close()

	s := &Syncer{}

	_, err := s.fetchDeltaPage(context.Background(), server.Client(), server.URL+"/delta")
	if err == nil {
		t.Fatal("expected error for 410 Gone")
	}

	if !isGone(err) {
		t.Errorf("expected goneError, got %T: %v", err, err)
	}
}

// TestSyncer_FetchDeltaPage_Success verifies successful page fetch.
func TestSyncer_FetchDeltaPage_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(map[string]interface{}{
			"value": []map[string]string{
				{"id": "msg-a"},
				{"id": "msg-b"},
			},
			"@odata.deltaLink": "delta://new-token",
		})
		w.Write(data)
	}))
	defer server.Close()

	s := &Syncer{}

	page, err := s.fetchDeltaPage(context.Background(), server.Client(), server.URL+"/delta")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(page.Value) != 2 {
		t.Errorf("expected 2 messages, got %d", len(page.Value))
	}

	if page.DeltaLink != "delta://new-token" {
		t.Errorf("deltaLink = %q, want delta://new-token", page.DeltaLink)
	}
}

// TestSyncer_Stop verifies graceful shutdown.
func TestSyncer_Stop(t *testing.T) {
	s := &Syncer{
		syncInterval: 1 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
	}()

	// Should not block
	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2 seconds")
	}
}

// TestGoneError verifies the goneError type.
func TestGoneError(t *testing.T) {
	err := &goneError{}
	if err.Error() != "delta token expired (410 Gone)" {
		t.Errorf("unexpected error string: %s", err.Error())
	}

	if !isGone(err) {
		t.Error("isGone should return true for goneError")
	}

	if isGone(context.Canceled) {
		t.Error("isGone should return false for non-goneError")
	}
}
