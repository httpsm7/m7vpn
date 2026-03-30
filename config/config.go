// config/config.go — App configuration load/save
// Made by Milkyway Intelligence | Author: Sharlix

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AppConfig holds all global m7vpn settings
type AppConfig struct {
	Version       string `json:"version"`
	CountriesFile string `json:"countries_file"`
	LogLevel      string `json:"log_level"`
	AutoReconnect bool   `json:"auto_reconnect"`
	DNSLeak       bool   `json:"dns_leak_protection"`
	DefaultProto  string `json:"default_protocol"`
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *AppConfig {
	home, _ := os.UserHomeDir()
	return &AppConfig{
		Version:       "1.0.0",
		CountriesFile: filepath.Join(home, ".m7vpn", "countries.json"),
		LogLevel:      "info",
		AutoReconnect: true,
		DNSLeak:       true,
		DefaultProto:  "wg",
	}
}

// Load reads ~/.m7vpn/config.json; returns error if missing/malformed
func Load() (*AppConfig, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	cfg := &AppConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("invalid config.json: %w", err)
	}
	if cfg.CountriesFile == "" {
		home, _ := os.UserHomeDir()
		cfg.CountriesFile = filepath.Join(home, ".m7vpn", "countries.json")
	}
	return cfg, nil
}

// Save writes the config to disk
func (c *AppConfig) Save() error {
	if err := os.MkdirAll(filepath.Dir(configPath()), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0600)
}

// EnsureDefaults creates the ~/.m7vpn directory tree and default files
func EnsureDefaults() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".m7vpn")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Create config.json if absent
	if _, err := os.Stat(configPath()); os.IsNotExist(err) {
		if err := DefaultConfig().Save(); err != nil {
			return err
		}
	}

	// Create countries.json if absent
	countriesPath := filepath.Join(dir, "countries.json")
	if _, err := os.Stat(countriesPath); os.IsNotExist(err) {
		if err := os.WriteFile(countriesPath, []byte(DefaultCountriesJSON()), 0600); err != nil {
			return err
		}
	}
	return nil
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".m7vpn", "config.json")
}
