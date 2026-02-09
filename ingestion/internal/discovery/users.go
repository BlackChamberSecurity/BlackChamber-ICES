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

// Package discovery provides hybrid mailbox discovery — auto-discovers
// licensed users from the Graph API and applies config-driven overrides.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// UserInfo represents a discovered mailbox user.
type UserInfo struct {
	ID                string `json:"id"`
	Mail              string `json:"mail"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// Discovery discovers mailbox users for a tenant using the Graph API,
// with config-driven include/exclude overrides.
type Discovery struct {
	graphBaseURL string
}

// NewDiscovery creates a mailbox discovery instance.
func NewDiscovery(graphBaseURL string) *Discovery {
	return &Discovery{graphBaseURL: graphBaseURL}
}

// graphUsersResponse represents the paged Graph API /users response.
type graphUsersResponse struct {
	Value    []UserInfo `json:"value"`
	NextLink string     `json:"@odata.nextLink"`
}

// DiscoverUsers returns the list of mailbox users to subscribe to.
//
// Hybrid strategy:
//   - If includeUsers is non-empty, returns only those users (no Graph API call).
//   - Otherwise, auto-discovers all licensed users with mailboxes via Graph API.
//   - In both cases, excludeUsers are removed from the final set.
func (d *Discovery) DiscoverUsers(
	ctx context.Context,
	httpClient *http.Client,
	tenantAlias string,
	includeUsers []string,
	excludeUsers []string,
) ([]UserInfo, error) {
	excludeSet := make(map[string]bool, len(excludeUsers))
	for _, u := range excludeUsers {
		excludeSet[strings.ToLower(u)] = true
	}

	var users []UserInfo

	if len(includeUsers) > 0 {
		// Explicit mode: use the provided list
		slog.Info("using explicit user list",
			"tenant", tenantAlias,
			"count", len(includeUsers),
		)
		for _, mail := range includeUsers {
			if excludeSet[strings.ToLower(mail)] {
				continue
			}
			users = append(users, UserInfo{
				Mail:              mail,
				UserPrincipalName: mail,
				// ID will be resolved when creating the subscription
				// (Graph accepts userPrincipalName in place of GUID)
			})
		}
		return users, nil
	}

	// Auto-discover: query Graph API for licensed users with mailboxes
	slog.Info("auto-discovering mailbox users", "tenant", tenantAlias)

	params := url.Values{}
	params.Set("$filter", "assignedLicenses/$count ne 0")
	params.Set("$count", "true")
	params.Set("$select", "id,mail,displayName,userPrincipalName")
	params.Set("$top", "100")

	discoveryURL := fmt.Sprintf("%s/users?%s", d.graphBaseURL, params.Encode())

	for nextURL := discoveryURL; nextURL != ""; {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build users request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("ConsistencyLevel", "eventual") // Required for $count

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch users: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Graph /users returned HTTP %d", resp.StatusCode)
		}

		var page graphUsersResponse
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			return nil, fmt.Errorf("decode users response: %w", err)
		}

		for _, u := range page.Value {
			// Skip users without a mailbox
			if u.Mail == "" {
				continue
			}
			// Apply exclusions
			if excludeSet[strings.ToLower(u.Mail)] {
				slog.Debug("excluding user", "mail", u.Mail, "tenant", tenantAlias)
				continue
			}
			users = append(users, u)
		}

		nextURL = page.NextLink
	}

	slog.Info("mailbox discovery complete",
		"tenant", tenantAlias,
		"discovered", len(users),
	)

	return users, nil
}
