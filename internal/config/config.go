// Package config reads/writes <data_dir>/config.json (same keys as the Python v5 build).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/FaheemRafiq/threatscan/internal/helpers"
)

type Config struct {
	ScanRoots          []string `json:"scan_roots"`
	Exclude            []string `json:"exclude"`
	JSAll              bool     `json:"js_all"`
	Deep               bool     `json:"deep"`
	QuickInterval      int      `json:"quick_interval"`
	FullInterval       int      `json:"full_interval"`
	IOCUpdateInterval  int      `json:"ioc_update_interval"`
	Realtime           bool     `json:"realtime"`
	Action             string   `json:"action"`
	AutoKill           bool     `json:"auto_kill"`
	AutoClean          bool     `json:"auto_clean"`
	Prompt             bool     `json:"prompt"`
	PromptTimeout      int      `json:"prompt_timeout"`
	NotifyDesktop      bool     `json:"notify_desktop"`
	NotifySweeps       bool     `json:"notify_sweeps"` // desktop note when a full sweep starts and finishes
	NotifyMinSeverity  string   `json:"notify_min_severity"`
	WebhookURL         string   `json:"webhook_url"`
	WebhookMinSeverity string   `json:"webhook_min_severity"`
	BlockC2            bool     `json:"block_c2"` // keep the C2 firewall/hosts block installed (needs admin once)
	IOCUpdate          bool     `json:"ioc_update"`
	IOCUpdateURL       string   `json:"ioc_update_url"`
	ReportKeep         int      `json:"report_keep"`
	Journal            bool     `json:"journal"`              // record every finding, action and decision in journal.jsonl
	JournalMinSeverity string   `json:"journal_min_severity"` // lowest finding severity recorded
	// program self-update (Go build)
	AutoUpdate     bool   `json:"auto_update"`
	UpdateChannel  string `json:"update_channel"`
	UpdateInterval int    `json:"update_interval"`
	UpdateAPIURL   string `json:"update_api_url"`
}

func Default() *Config {
	return &Config{
		ScanRoots: []string{}, Exclude: []string{}, JSAll: true,
		QuickInterval: 5, FullInterval: 6 * 3600, IOCUpdateInterval: 24 * 3600,
		Realtime: true, Action: "quarantine", AutoKill: true, AutoClean: true,
		Prompt: true, PromptTimeout: 180, NotifyDesktop: true, NotifySweeps: true, NotifyMinSeverity: "HIGH",
		WebhookMinSeverity: "HIGH", BlockC2: true, IOCUpdate: true, ReportKeep: 60,
		Journal: true, JournalMinSeverity: "WARNING",
		AutoUpdate: true, UpdateChannel: "stable", UpdateInterval: 6 * 3600,
	}
}

func Load(dataDir string) *Config {
	c := Default()
	if b, err := os.ReadFile(filepath.Join(dataDir, "config.json")); err == nil {
		_ = json.Unmarshal(b, c) // missing keys keep defaults
	}
	return c
}

func (c *Config) Save(dataDir string) (string, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dataDir, "config.json")
	b, _ := json.MarshalIndent(c, "", "  ")
	return p, os.WriteFile(p, b, 0o600)
}

// Roots returns the configured scan roots, or auto-discovered project dirs.
func (c *Config) Roots(common func() []string) []string {
	var src []string
	if len(c.ScanRoots) > 0 {
		for _, r := range c.ScanRoots {
			src = append(src, helpers.Expand(r))
		}
	} else {
		src = common()
	}
	var out []string
	for _, r := range src {
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			out = append(out, r)
		}
	}
	return out
}
