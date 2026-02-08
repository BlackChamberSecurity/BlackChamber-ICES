// Copyright (c) 2026 John Earle
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://github.com/yourusername/bcem/blob/main/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package models defines shared data types used across the ingestion service.
package models

// EmailEvent is the canonical email representation sent to the analysis queue.
// Must match the Python EmailEvent dataclass in analysis/models.py.
type EmailEvent struct {
	MessageID   string            `json:"message_id"`
	UserID      string            `json:"user_id"`
	TenantID    string            `json:"tenant_id"`
	TenantAlias string            `json:"tenant_alias"`
	Sender      string            `json:"sender"`
	Subject     string            `json:"subject"`
	Body        EmailBody         `json:"body"`
	Headers     map[string]string `json:"headers"`
	Attachments []Attachment      `json:"attachments"`
}

// EmailBody holds the email content.
type EmailBody struct {
	ContentType string `json:"content_type"`
	Content     string `json:"content"`
}

// Attachment represents an email attachment.
type Attachment struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Size        int    `json:"size"`
}
