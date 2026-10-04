// Package report writes JSON reports (same shape as the Python v5 build).
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
)

type Report struct {
	Version   string              `json:"version"`
	IOCs      string              `json:"iocs"`
	Generated string              `json:"generated"`
	Stats     *findings.Stats     `json:"stats"`
	Findings  []*findings.Finding `json:"findings"`
}

func New(version, iocVersion string, s *findings.Stats, fs []*findings.Finding) *Report {
	if fs == nil {
		fs = []*findings.Finding{}
	}
	return &Report{Version: version, IOCs: iocVersion, Generated: time.Now().Format("2006-01-02T15:04:05"), Stats: s, Findings: fs}
}

func (r *Report) WriteFile(path string) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// Save writes reports/<ts>-<tag>.json and reports/latest.json, pruning to keep files.
func Save(dataDir string, r *Report, keep int, tag string) (string, error) {
	d := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(d, time.Now().Format("20060102-150405")+"-"+tag+".json")
	if err := r.WriteFile(p); err != nil {
		return "", err
	}
	_ = r.WriteFile(filepath.Join(d, "latest.json"))
	var old []string
	ents, _ := os.ReadDir(d)
	for _, e := range ents {
		if e.Name() != "latest.json" && filepath.Ext(e.Name()) == ".json" {
			old = append(old, filepath.Join(d, e.Name()))
		}
	}
	sort.Strings(old)
	if keep > 0 && len(old) > keep {
		for _, x := range old[:len(old)-keep] {
			_ = os.Remove(x)
		}
	}
	return p, nil
}

func Latest(dataDir string) (*Report, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "reports", "latest.json"))
	if err != nil {
		return nil, err
	}
	var r Report
	return &r, json.Unmarshal(b, &r)
}
