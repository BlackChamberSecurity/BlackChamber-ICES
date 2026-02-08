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

// Package queue publishes email events to Redis as Celery-compatible tasks.
// This is the bridge between Go ingestion and Python analysis workers.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/bcem/ingestion/internal/models"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Publisher sends email events to Redis in Celery task format.
type Publisher struct {
	rdb       *redis.Client
	queueName string
}

// NewPublisher creates a new Redis publisher targeting the specified queue.
func NewPublisher(rdb *redis.Client, queueName string) *Publisher {
	return &Publisher{
		rdb:       rdb,
		queueName: queueName,
	}
}

// celeryTask represents a Celery-compatible task message.
// Celery reads tasks from Redis using this exact JSON structure.
type celeryTask struct {
	ID      string        `json:"id"`
	Task    string        `json:"task"`
	Args    []interface{} `json:"args"`
	Kwargs  interface{}   `json:"kwargs"`
	Retries int           `json:"retries"`
	ETA     *string       `json:"eta"`
}

// celeryMessage wraps a task for Redis transport.
type celeryMessage struct {
	Body            string                 `json:"body"`
	ContentEncoding string                 `json:"content-encoding"`
	ContentType     string                 `json:"content-type"`
	Headers         map[string]interface{} `json:"headers"`
	Properties      map[string]interface{} `json:"properties"`
}

// PublishEmailEvent serialises an email event and publishes it as a Celery task
// to Redis. The Python analysis worker picks it up via `celery worker -Q emails`.
func (p *Publisher) PublishEmailEvent(ctx context.Context, event *models.EmailEvent) error {
	// Serialise the email event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal email event: %w", err)
	}

	taskID := uuid.New().String()

	// Build Celery task body
	task := celeryTask{
		ID:     taskID,
		Task:   "analysis.tasks.analyze_email",
		Args:   []interface{}{string(eventJSON)},
		Kwargs: map[string]interface{}{},
	}

	taskBody, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("marshal celery task: %w", err)
	}

	// Wrap in Celery message envelope
	msg := celeryMessage{
		Body:            string(taskBody),
		ContentEncoding: "utf-8",
		ContentType:     "application/json",
		Headers: map[string]interface{}{
			"lang":    "py",
			"task":    "analysis.tasks.analyze_email",
			"id":      taskID,
			"retries": 0,
		},
		Properties: map[string]interface{}{
			"correlation_id": taskID,
			"delivery_mode":  2,
			"delivery_tag":   taskID,
			"body_encoding":  "utf-8",
			"exchange":       p.queueName,
			"routing_key":    p.queueName,
			"delivery_info": map[string]string{
				"exchange":    p.queueName,
				"routing_key": p.queueName,
			},
		},
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal celery message: %w", err)
	}

	// Push to Redis — Celery uses LPUSH to the queue
	if err := p.rdb.LPush(ctx, p.queueName, string(msgJSON)).Err(); err != nil {
		return fmt.Errorf("redis LPUSH: %w", err)
	}

	slog.Info("published email event to queue",
		"task_id", taskID,
		"message_id", event.MessageID,
		"tenant", event.TenantAlias,
		"queue", p.queueName,
	)

	return nil
}

// Ping checks the Redis connection.
func (p *Publisher) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return p.rdb.Ping(ctx).Err()
}
