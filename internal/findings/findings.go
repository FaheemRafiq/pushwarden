// Package findings holds the result types shared by scanners, the guard and the CLI.
package findings

import (
	"encoding/json"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Warning
	High
	Critical
)

var sevNames = []string{"INFO", "WARNING", "HIGH", "CRITICAL"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(sevNames) {
		return "INFO"
	}
	return sevNames[s]
}

func ParseSeverity(name string) Severity {
	for i, n := range sevNames {
		if strings.EqualFold(n, name) {
			return Severity(i)
		}
	}
	return High
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var n string
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = ParseSeverity(n)
	return nil
}

// Meta carries machine-readable context (pid, evidence, response hints).
type Meta struct {
	PID              int      `json:"pid,omitempty"`
	Kill             bool     `json:"kill,omitempty"`
	Cmd              string   `json:"cmd,omitempty"`
	IP               string   `json:"ip,omitempty"`
	Cleanable        bool     `json:"cleanable,omitempty"`
	Quarantine       bool     `json:"quarantine,omitempty"`
	Evidence         []string `json:"evidence,omitempty"`
	SystemdUnit      string   `json:"systemd_unit,omitempty"`
	LaunchdPlist     string   `json:"launchd_plist,omitempty"`
	Schtask          string   `json:"schtask,omitempty"`
	CronLine         string   `json:"cron_line,omitempty"`
	Cut              int      `json:"cut,omitempty"`
	MidFileInjection bool     `json:"mid_file_injection,omitempty"`
}

type Finding struct {
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Path        string   `json:"path,omitempty"`
	Details     string   `json:"details"`
	Remediation string   `json:"remediation"`
	Action      string   `json:"action"`
	Meta        Meta     `json:"meta"`
}

// Key is the stable identity the guard uses to avoid re-alerting.
func (f *Finding) Key() string { return f.Category + "|" + f.Title + "|" + f.Path }

type Stats struct {
	ReposScanned  int      `json:"repos_scanned"`
	ReposInfected int      `json:"repos_infected"`
	FilesChecked  int      `json:"files_checked"`
	TotalFindings int      `json:"total_findings"`
	Critical      int      `json:"critical"`
	High          int      `json:"high"`
	Warning       int      `json:"warning"`
	Info          int      `json:"info"`
	ScanDuration  float64  `json:"scan_duration"`
	PlatformName  string   `json:"platform_name"`
	ScanDirs      []string `json:"scan_dirs"`
	StartTime     string   `json:"start_time"`
	Hostname      string   `json:"hostname"`
}

func (s *Stats) Count(fs []*Finding) {
	s.TotalFindings = len(fs)
	s.Critical, s.High, s.Warning, s.Info = 0, 0, 0, 0
	for _, f := range fs {
		switch f.Severity {
		case Critical:
			s.Critical++
		case High:
			s.High++
		case Warning:
			s.Warning++
		default:
			s.Info++
		}
	}
}

func Worst(fs []*Finding) Severity {
	w := Info
	for _, f := range fs {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

func AnyAtLeast(fs []*Finding, s Severity) bool {
	for _, f := range fs {
		if f.Severity >= s {
			return true
		}
	}
	return false
}

// Dedup keeps the first finding per Key.
func Dedup(fs []*Finding) []*Finding {
	seen := map[string]bool{}
	out := fs[:0:0]
	for _, f := range fs {
		if !seen[f.Key()] {
			seen[f.Key()] = true
			out = append(out, f)
		}
	}
	return out
}
