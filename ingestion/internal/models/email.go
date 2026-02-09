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

// Package models defines the data structures shared across the ingestion service.
package models

// EmailAddress represents a sender or recipient with an address and optional name.
type EmailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

// EmailBody represents the message body content.
type EmailBody struct {
	ContentType string `json:"content_type"`
	Content     string `json:"content"`
}

// Attachment represents a file attached to an email.
type Attachment struct {
	Name         string `json:"name"`
	ContentType  string `json:"content_type"`
	Size         int    `json:"size"`
	ContentBytes string `json:"content_bytes,omitempty"`
}

// EmailEvent represents a fully parsed email ready for the analysis pipeline.
//
// This struct's JSON serialisation MUST match the shared/schemas/email_event.json
// contract. The Python analysis service deserialises this JSON via
// EmailEvent.from_dict().
type EmailEvent struct {
	MessageID   string            `json:"message_id"`
	UserID      string            `json:"user_id"`
	TenantID    string            `json:"tenant_id"`
	TenantAlias string            `json:"tenant_alias"`
	ReceivedAt  string            `json:"received_at,omitempty"`
	From        EmailAddress      `json:"from"`
	To          []EmailAddress    `json:"to"`
	Subject     string            `json:"subject"`
	Body        EmailBody         `json:"body"`
	Headers     map[string]string `json:"headers,omitempty"`
	Attachments []Attachment      `json:"attachments"`
}
