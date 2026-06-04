// Package config handles loading, validating, and accessing indago configuration.
// Config lives at ~/.config/indago/config.yaml and is created with sane defaults
// on first run. Format changed from JSON to YAML in v0.1.0.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Keys     map[string]string  `yaml:"keys"`
	Profiles map[string]Profile `yaml:"profiles"`
	Output   OutputConfig       `yaml:"output"`
	Pivot    PivotConfig        `yaml:"pivot"`
	Disabled []string           `yaml:"disabled"`
}

type Profile struct {
	Modules     []string `yaml:"modules"`
	Description string   `yaml:"description"`
}

type OutputConfig struct {
	Format string `yaml:"format"`
	Color  bool   `yaml:"color"`
	Dir    string `yaml:"dir"`
}

type PivotConfig struct {
	Enabled     bool `yaml:"enabled"`
	MaxDepth    int  `yaml:"max_depth"`
	PassiveOnly bool `yaml:"passive_only"`
}

func defaultConfig() *Config {
	return &Config{
		Keys: make(map[string]string),
		Profiles: map[string]Profile{
			"person": {
				Description: "Person-centric OSINT: name, email, phone, username",
				Modules:     []string{"identity", "social", "breach"},
			},
			"domain": {
				Description: "Domain/infrastructure OSINT: DNS, certs, network, history",
				Modules:     []string{"network", "geo"},
			},
			"email": {
				Description: "Email-focused: breach lookup, social account enumeration",
				Modules:     []string{"identity", "breach", "social"},
			},
			"username": {
				Description: "Username enumeration across social and paste sites",
				Modules:     []string{"social"},
			},
			"ip": {
				Description: "IP reputation, geolocation, and threat intelligence",
				Modules:     []string{"network", "geo"},
			},
			"full": {
				Description: "All modules — comprehensive scan (slower)",
				Modules:     []string{"identity", "social", "breach", "network", "geo"},
			},
		},
		Output: OutputConfig{Format: "stdout", Color: true, Dir: "."},
		Pivot:  PivotConfig{Enabled: true, MaxDepth: 2, PassiveOnly: false},
		Disabled: []string{},
	}
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", "indago", "config.yaml"), nil
}

func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := defaultConfig()
		_ = Save(cfg, path)
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	cfg := defaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

func Save(cfg *Config, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (c *Config) Key(source string) (string, bool) {
	k, ok := c.Keys[source]
	return k, ok && k != ""
}

func (c *Config) HasKey(source string) bool {
	_, ok := c.Key(source)
	return ok
}

func (c *Config) IsDisabled(source string) bool {
	for _, d := range c.Disabled {
		if d == source {
			return true
		}
	}
	return false
}

func (c *Config) GetProfile(name string) (Profile, error) {
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q — run indago profiles to see options", name)
	}
	return p, nil
}
