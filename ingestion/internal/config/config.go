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

// Package config loads configuration from config.yaml and environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TenantConfig holds credentials for a single tenant.
type TenantConfig struct {
	Alias        string `yaml:"alias"`
	Provider     string `yaml:"provider"` // "m365" or "google" (future)
	TenantID     string `yaml:"tenant_id"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// Config holds all configuration for the ingestion service.
type Config struct {
	Tenants []TenantConfig

	// Activity Feed
	PollInterval time.Duration
	PollLookback time.Duration

	// Redis
	RedisURL    string
	EmailsQueue string

	// Server (health check only)
	Port int
}

// rawConfig mirrors the YAML structure for unmarshalling.
type rawConfig struct {
	Tenants []struct {
		Alias        string `yaml:"alias"`
		Provider     string `yaml:"provider"`
		TenantID     string `yaml:"tenant_id"`
		ClientID     string `yaml:"client_id"`
		ClientSecret string `yaml:"client_secret"`
	} `yaml:"tenants"`
	Redis struct {
		URL    string `yaml:"url"`
		Queues struct {
			Emails string `yaml:"emails"`
		} `yaml:"queues"`
	} `yaml:"redis"`
}

// Load reads configuration from config.yaml (with env var expansion) and
// environment variables for non-YAML settings.
func Load() (*Config, error) {
	configPath := envOrDefault("CONFIG_PATH", "/app/config/config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", configPath, err)
	}

	// Expand ${VAR} references in the YAML
	expanded := os.ExpandEnv(string(data))

	var raw rawConfig
	if err := yaml.Unmarshal([]byte(expanded), &raw); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	cfg := &Config{
		PollInterval: envOrDefaultDuration("POLL_INTERVAL", 60*time.Second),
		PollLookback: envOrDefaultDuration("POLL_LOOKBACK", 3*time.Hour),
		RedisURL:     firstNonEmpty(raw.Redis.URL, envOrDefault("REDIS_URL", "redis://localhost:6379/0")),
		EmailsQueue:  firstNonEmpty(raw.Redis.Queues.Emails, envOrDefault("EMAILS_QUEUE", "emails")),
		Port:         envOrDefaultInt("PORT", 8080),
	}

	// Build tenant configs
	for _, t := range raw.Tenants {
		tc := TenantConfig{
			Alias:        t.Alias,
			Provider:     t.Provider,
			TenantID:     t.TenantID,
			ClientID:     t.ClientID,
			ClientSecret: t.ClientSecret,
		}

		// Validate required fields
		if tc.TenantID == "" || tc.ClientID == "" || tc.ClientSecret == "" {
			// Skip tenants with empty credentials (commented out in YAML)
			continue
		}

		if tc.Alias == "" {
			tc.Alias = tc.TenantID[:8] // Use first 8 chars of tenant ID as fallback
		}

		if tc.Provider == "" {
			tc.Provider = "m365"
		}

		cfg.Tenants = append(cfg.Tenants, tc)
	}

	if len(cfg.Tenants) == 0 {
		return nil, fmt.Errorf("no tenants configured — check config.yaml and environment variables")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envOrDefaultDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
