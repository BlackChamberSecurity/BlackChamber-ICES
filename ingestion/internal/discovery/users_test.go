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

package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDiscoverUsers_ExplicitMode verifies that when include_users is set,
// no Graph API call is made and only those users are returned.
func TestDiscoverUsers_ExplicitMode(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := NewDiscovery(server.URL)

	users, err := d.DiscoverUsers(
		context.Background(),
		server.Client(),
		"test-tenant",
		[]string{"alice@example.com", "bob@example.com"},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if called {
		t.Error("Graph API should NOT be called in explicit mode")
	}

	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	if users[0].Mail != "alice@example.com" {
		t.Errorf("expected alice, got %s", users[0].Mail)
	}
}

// TestDiscoverUsers_ExplicitWithExclusions verifies exclusions work in explicit mode.
func TestDiscoverUsers_ExplicitWithExclusions(t *testing.T) {
	d := NewDiscovery("http://unused")

	users, err := d.DiscoverUsers(
		context.Background(),
		http.DefaultClient,
		"test-tenant",
		[]string{"alice@example.com", "noreply@example.com", "bob@example.com"},
		[]string{"noreply@example.com"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(users) != 2 {
		t.Fatalf("expected 2 users after exclusion, got %d", len(users))
	}

	for _, u := range users {
		if u.Mail == "noreply@example.com" {
			t.Error("excluded user should not appear in results")
		}
	}
}

// TestDiscoverUsers_ExclusionCaseInsensitive verifies case-insensitive exclusion.
func TestDiscoverUsers_ExclusionCaseInsensitive(t *testing.T) {
	d := NewDiscovery("http://unused")

	users, err := d.DiscoverUsers(
		context.Background(),
		http.DefaultClient,
		"test",
		[]string{"Alice@Example.COM"},
		[]string{"alice@example.com"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("case-insensitive exclusion should have removed the user, got %d", len(users))
	}
}

// TestDiscoverUsers_AutoDiscover verifies Graph API auto-discovery with pagination.
func TestDiscoverUsers_AutoDiscover(t *testing.T) {
	page := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		type resp struct {
			Value    []UserInfo `json:"value"`
			NextLink string     `json:"@odata.nextLink"`
		}

		switch page {
		case 0:
			data, _ := json.Marshal(resp{
				Value: []UserInfo{
					{ID: "1", Mail: "alice@example.com", DisplayName: "Alice"},
					{ID: "2", Mail: "bob@example.com", DisplayName: "Bob"},
				},
				NextLink: r.URL.Scheme + "://" + r.Host + "/page2",
			})
			// Fix NextLink for test server
			resp2 := resp{}
			json.Unmarshal(data, &resp2)
			resp2.NextLink = "http://" + r.Host + "/page2"
			data2, _ := json.Marshal(resp2)
			w.Write(data2)
			page++
		case 1:
			data, _ := json.Marshal(resp{
				Value: []UserInfo{
					{ID: "3", Mail: "carol@example.com", DisplayName: "Carol"},
					{ID: "4", Mail: "", DisplayName: "Service Account"}, // no mailbox
				},
			})
			w.Write(data)
			page++
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	d := NewDiscovery(server.URL)

	users, err := d.DiscoverUsers(
		context.Background(),
		server.Client(),
		"test-tenant",
		nil, // auto-discover
		[]string{"bob@example.com"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have alice and carol (bob excluded, service account has no mail)
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	names := map[string]bool{}
	for _, u := range users {
		names[u.DisplayName] = true
	}

	if !names["Alice"] || !names["Carol"] {
		t.Errorf("expected Alice and Carol, got %v", names)
	}
}

// TestDiscoverUsers_AutoDiscover_HTTPError verifies error handling for API failures.
func TestDiscoverUsers_AutoDiscover_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	d := NewDiscovery(server.URL)

	_, err := d.DiscoverUsers(
		context.Background(),
		server.Client(),
		"test-tenant",
		nil,
		nil,
	)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

// TestDiscoverUsers_EmptyIncludeEmptyAutoDiscover verifies empty results
// when no users are explicitly provided and auto-discovery returns nothing.
func TestDiscoverUsers_EmptyAutoDiscover(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"value": []}`))
	}))
	defer server.Close()

	d := NewDiscovery(server.URL)

	users, err := d.DiscoverUsers(
		context.Background(),
		server.Client(),
		"test-tenant",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}
