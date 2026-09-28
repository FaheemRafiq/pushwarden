// Package iocs loads and validates the indicator database (threatscan/iocs.json).
package iocs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	iocsdata "github.com/FaheemRafiq/threatscan/threatscan"
)

// Raw mirrors iocs.json.  Unknown keys are ignored so newer files load in older binaries.
type Raw struct {
	Version              string              `json:"version"`
	LiteralSignatures    []string            `json:"literal_signatures"`
	XorKeys              []string            `json:"xor_keys"`
	MarkerRegexes        []string            `json:"marker_regexes"`
	HistoryPayloadRegex  string              `json:"history_payload_regex"`
	BlockchainRPCHosts   []string            `json:"blockchain_rpc_hosts"`
	Wallets              []string            `json:"wallets"`
	MaliciousIPs         []string            `json:"malicious_ips"`
	MaliciousHosts       []string            `json:"malicious_hosts"`
	C2URLPaths           []string            `json:"c2_url_paths"`
	TelegramIndicators   []string            `json:"telegram_indicators"`
	FakeFontSHA256       []string            `json:"fake_font_sha256"`
	FakeFontNames        []string            `json:"fake_font_names"`
	ConfigFiles          []string            `json:"config_files"`
	EntryFiles           []string            `json:"entry_files"`
	PropagationScripts   []string            `json:"propagation_scripts"`
	GitignoreIOCs        []string            `json:"gitignore_iocs"`
	CompromisedNPM       map[string][]string `json:"compromised_npm"`
	CompromisedGo        []string            `json:"compromised_go"`
	CompromisedPackagist []string            `json:"compromised_packagist"`
	// Packages compromised only in some versions or branches (e.g. dev-main); absent
	// from CompromisedPackagist so older builds do not flag every version.
	CompromisedPackagistVersions map[string][]string `json:"compromised_packagist_versions"`
	// SHA-256 of any known-malicious file (configs, loaders, package tarballs).
	MaliciousFileSHA256     []string `json:"malicious_file_sha256"`
	RatDirNames             []string `json:"rat_dir_names"`
	RatServiceNames         []string `json:"rat_service_names"`
	RatEnvKeys              []string `json:"rat_env_keys"`
	RatFiles                []string `json:"rat_files"`
	ProcessRegexes          []string `json:"process_regexes"`
	ProcessKillRegexes      []string `json:"process_kill_regexes"`
	ShellRegexes            []string `json:"shell_regexes"`
	ScheduledTaskKeywords   []string `json:"scheduled_task_keywords"`
	ScheduledTaskCritical   []string `json:"scheduled_task_critical"`
	CIEvasionHostnames      []string `json:"ci_evasion_hostnames"`
	TasksJSONLoaderKeywords []string `json:"tasks_json_loader_keywords"`
}

type IOCs struct {
	Raw
	Source         string
	Marker         *regexp.Regexp
	Process        []*regexp.Regexp
	ProcessKill    []*regexp.Regexp
	Shell          []*regexp.Regexp
	FontHashes     map[string]bool
	FileHashes     map[string]bool
	TronWallets    []string
	LoaderExt      *regexp.Regexp
	configSet      map[string]bool
	entrySet       map[string]bool
	fontNameSet    map[string]bool
	propagationSet map[string]bool
}

var (
	ipRe  = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	hexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// compileCI compiles a Python-style pattern case-insensitively with RE2.
func compileCI(p string) (*regexp.Regexp, error) {
	if len(p) > 500 {
		return nil, errors.New("regex too long")
	}
	return regexp.Compile("(?i)" + p)
}

func Parse(b []byte, source string) (*IOCs, error) {
	if len(b) > 2*1024*1024 {
		return nil, errors.New("indicator file too large")
	}
	var r Raw
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if r.Version == "" || len(r.LiteralSignatures) == 0 || len(r.MarkerRegexes) == 0 || len(r.ConfigFiles) == 0 {
		return nil, errors.New("missing required keys")
	}
	i := &IOCs{Raw: r, Source: source}
	parts := make([]string, 0, len(r.MarkerRegexes))
	for _, p := range r.MarkerRegexes {
		if _, err := compileCI(p); err != nil {
			return nil, fmt.Errorf("marker regex %q: %w", p, err)
		}
		parts = append(parts, "(?:"+p+")")
	}
	i.Marker = regexp.MustCompile("(?i)" + strings.Join(parts, "|"))
	for _, set := range []struct {
		src []string
		dst *[]*regexp.Regexp
	}{{r.ProcessRegexes, &i.Process}, {r.ProcessKillRegexes, &i.ProcessKill}, {r.ShellRegexes, &i.Shell}} {
		for _, p := range set.src {
			re, err := compileCI(p)
			if err != nil {
				return nil, fmt.Errorf("regex %q: %w", p, err)
			}
			*set.dst = append(*set.dst, re)
		}
	}
	if _, err := regexp.Compile(r.HistoryPayloadRegex); err != nil {
		return nil, fmt.Errorf("history regex: %w", err)
	}
	for _, ip := range r.MaliciousIPs {
		if !ipRe.MatchString(ip) {
			return nil, fmt.Errorf("bad ip %q", ip)
		}
	}
	i.FontHashes = map[string]bool{}
	for _, h := range r.FakeFontSHA256 {
		if !hexRe.MatchString(h) {
			return nil, fmt.Errorf("bad sha256 %q", h)
		}
		i.FontHashes[h] = true
	}
	i.FileHashes = map[string]bool{}
	for _, h := range r.MaliciousFileSHA256 {
		if !hexRe.MatchString(h) {
			return nil, fmt.Errorf("bad sha256 %q", h)
		}
		i.FileHashes[h] = true
	}
	for _, w := range r.Wallets {
		if strings.HasPrefix(w, "T") {
			i.TronWallets = append(i.TronWallets, w)
		}
	}
	i.LoaderExt = regexp.MustCompile(`(?i)\bnode\s+\S+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|dict)\b`)
	i.configSet, i.entrySet, i.fontNameSet, i.propagationSet = set(r.ConfigFiles), set(r.EntryFiles), set(r.FakeFontNames), set(r.PropagationScripts)
	return i, nil
}

func set(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func (i *IOCs) IsConfig(name string) bool      { return i.configSet[name] }
func (i *IOCs) IsEntry(name string) bool       { return i.entrySet[name] }
func (i *IOCs) IsFontName(name string) bool    { return i.fontNameSet[name] }
func (i *IOCs) IsPropagation(name string) bool { return i.propagationSet[name] }

// HasMarker: any campaign marker, XOR key or literal signature.
func (i *IOCs) HasMarker(content string) bool {
	if i.Marker.MatchString(content) {
		return true
	}
	for _, k := range i.XorKeys {
		if strings.Contains(content, k) {
			return true
		}
	}
	for _, s := range i.LiteralSignatures {
		if strings.Contains(content, s) {
			return true
		}
	}
	return false
}

// UserPath is where `update-iocs` stores a newer indicator file.
func UserPath(dataDir string) string { return filepath.Join(dataDir, "iocs.json") }

// Load returns the newer of the bundled and user-downloaded indicator files.
func Load(dataDir string) (*IOCs, error) {
	b, err := Parse(iocsdata.Bundled, "bundled")
	if err != nil {
		return nil, fmt.Errorf("bundled indicator file invalid: %w", err)
	}
	if dataDir == "" {
		return b, nil
	}
	if blob, err := os.ReadFile(UserPath(dataDir)); err == nil {
		if u, err := Parse(blob, UserPath(dataDir)); err == nil && u.Version >= b.Version {
			return u, nil
		}
	}
	return b, nil
}
