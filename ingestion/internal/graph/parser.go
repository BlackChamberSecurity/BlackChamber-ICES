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

package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/bcem/ingestion/internal/models"
)

// graphMessage represents the relevant fields from a Graph API message response.
type graphMessage struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	From    struct {
		EmailAddress struct {
			Address string `json:"address"`
			Name    string `json:"name"`
		} `json:"emailAddress"`
	} `json:"from"`
	ToRecipients []struct {
		EmailAddress struct {
			Address string `json:"address"`
			Name    string `json:"name"`
		} `json:"emailAddress"`
	} `json:"toRecipients"`
	Body struct {
		ContentType string `json:"contentType"`
		Content     string `json:"content"`
	} `json:"body"`
	InternetMessageHeaders []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"internetMessageHeaders"`
	HasAttachments bool `json:"hasAttachments"`
}

// parseGraphMessage converts a Graph API message response into an EmailEvent.
func parseGraphMessage(body io.Reader, userID, tenantID, tenantAlias string) (*models.EmailEvent, error) {
	var msg graphMessage
	if err := json.NewDecoder(body).Decode(&msg); err != nil {
		return nil, fmt.Errorf("decode graph message: %w", err)
	}

	headers := make(map[string]string, len(msg.InternetMessageHeaders))
	for _, h := range msg.InternetMessageHeaders {
		headers[h.Name] = h.Value
	}

	// Build recipients list from Graph API format
	to := make([]models.EmailAddress, 0, len(msg.ToRecipients))
	for _, r := range msg.ToRecipients {
		to = append(to, models.EmailAddress{
			Address: r.EmailAddress.Address,
			Name:    r.EmailAddress.Name,
		})
	}

	event := &models.EmailEvent{
		MessageID:   msg.ID,
		UserID:      userID,
		TenantID:    tenantID,
		TenantAlias: tenantAlias,
		ReceivedAt:  time.Now().UTC().Format(time.RFC3339),
		From: models.EmailAddress{
			Address: msg.From.EmailAddress.Address,
			Name:    msg.From.EmailAddress.Name,
		},
		To:      to,
		Subject: msg.Subject,
		Body: models.EmailBody{
			ContentType: msg.Body.ContentType,
			Content:     msg.Body.Content,
		},
		Headers:     headers,
		Attachments: []models.Attachment{},
	}

	return event, nil
}
