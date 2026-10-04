package feedback

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/journal"
)

// Digest is what the opt-in daily report contains. By construction it has no
// absolute paths, no command lines and no file contents: counts, durations,
// category names, error titles, and the notes users wrote themselves.
type Digest struct {
	MachineID     string         `json:"machine_id"`
	Host          string         `json:"host,omitempty"` // only with feedback_identify
	Version       string         `json:"version"`
	OS            string         `json:"os"`
	IOCs          string         `json:"iocs"`
	From          string         `json:"from"`
	To            string         `json:"to"`
	Events        int            `json:"events"`
	BySeverity    map[string]int `json:"findings_by_severity"`
	ByCategory    map[string]int `json:"findings_by_category"` // distinct findings, not sightings
	Actions       map[string]int `json:"actions"`
	FailedActions []string       `json:"failed_actions,omitempty"` // "kill malicious_process", "clean gitignore_tampering"
	Decisions     map[string]int `json:"decisions"`
	FalsePositive []Mark         `json:"false_positives,omitempty"`
	Sweeps        int            `json:"sweeps"`
	SweepAvgSec   int            `json:"sweep_avg_seconds"`
	SweepMaxSec   int            `json:"sweep_max_seconds"`
	Errors        []string       `json:"errors,omitempty"`
	GuardStarts   int            `json:"guard_starts"`
	Updates       []string       `json:"updates,omitempty"`
}

// Mark is one false-positive report from the user.
type Mark struct {
	File string `json:"file"` // base name only
	Note string `json:"note,omitempty"`
}

// MachineID returns a random, stable identifier for this install. It is not
// derived from the hardware, the user or the host name.
func MachineID(dataDir string) string {
	p := filepath.Join(dataDir, "machine-id")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		return strings.TrimSpace(string(b))
	}
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "unknown"
	}
	id := hex.EncodeToString(raw)
	_ = os.WriteFile(p, []byte(id+"\n"), 0o600)
	return id
}

func num(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// BuildDigest summarises events. Nothing path-like is copied from them.
func BuildDigest(evs []journal.Event, machineID, version, goos, iocs string, from, to time.Time) Digest {
	d := Digest{MachineID: machineID, Version: version, OS: goos, IOCs: iocs, From: from.Format(time.RFC3339), To: to.Format(time.RFC3339),
		Events: len(evs), BySeverity: map[string]int{}, ByCategory: map[string]int{}, Actions: map[string]int{}, Decisions: map[string]int{}}
	seen := map[string]bool{}
	total := 0
	for _, e := range evs {
		switch e.Kind {
		case journal.KindFinding:
			d.BySeverity[e.Sev]++
			k := e.Category + "|" + e.Key
			if e.Category == "malicious_process" || e.Category == "c2_connection" {
				k = e.Category + "|" + e.Matched
			}
			if !seen[k] {
				seen[k] = true
				d.ByCategory[e.Category]++
			}
			if strings.Contains(e.Action, "failed") {
				d.FailedActions = append(d.FailedActions, "respond "+e.Category)
			}
		case journal.KindAction:
			d.Actions[e.Action]++
			if e.OK != nil && !*e.OK {
				d.FailedActions = append(d.FailedActions, e.Action+" "+e.Threat)
			}
		case journal.KindDecision:
			d.Decisions[e.Action]++
		case journal.KindFeedback:
			d.FalsePositive = append(d.FalsePositive, Mark{File: filepath.Base(e.Path), Note: e.Note})
		case journal.KindSweep:
			if e.Data["phase"] == "end" {
				s := num(e.Data["seconds"])
				d.Sweeps++
				total += s
				if s > d.SweepMaxSec {
					d.SweepMaxSec = s
				}
			}
		case journal.KindError:
			d.Errors = append(d.Errors, e.Title)
		case journal.KindGuard:
			if e.Title == "guard started" {
				d.GuardStarts++
			}
		case journal.KindUpdate:
			if strings.HasPrefix(e.Title, "program update") {
				d.Updates = append(d.Updates, e.Title)
			}
		}
	}
	if d.Sweeps > 0 {
		d.SweepAvgSec = total / d.Sweeps
	}
	sort.Strings(d.FailedActions)
	return d
}

// Text is the short human summary sent as the webhook message.
func (d Digest) Text() string {
	var b strings.Builder
	who := d.MachineID
	if d.Host != "" {
		who = d.Host
	}
	fmt.Fprintf(&b, "PushWarden daily digest: %s, v%s on %s, indicators %s\n", who, d.Version, d.OS, d.IOCs)
	fmt.Fprintf(&b, "findings: %d critical, %d high, %d warning sightings; %d sweeps (avg %ds, max %ds)\n",
		d.BySeverity["CRITICAL"], d.BySeverity["HIGH"], d.BySeverity["WARNING"], d.Sweeps, d.SweepAvgSec, d.SweepMaxSec)
	if len(d.ByCategory) > 0 {
		var cats []string
		for c, n := range d.ByCategory {
			cats = append(cats, fmt.Sprintf("%s=%d", c, n))
		}
		sort.Strings(cats)
		b.WriteString("distinct: " + strings.Join(cats, ", ") + "\n")
	}
	if len(d.Actions) > 0 {
		var as []string
		for a, n := range d.Actions {
			as = append(as, fmt.Sprintf("%s=%d", a, n))
		}
		sort.Strings(as)
		b.WriteString("actions: " + strings.Join(as, ", ") + "\n")
	}
	if len(d.FailedActions) > 0 {
		b.WriteString("FAILED: " + strings.Join(d.FailedActions, "; ") + "\n")
	}
	for _, m := range d.FalsePositive {
		b.WriteString("false positive reported: " + m.File + " " + m.Note + "\n")
	}
	if len(d.Errors) > 0 {
		b.WriteString("errors: " + strings.Join(d.Errors, "; ") + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// Post sends the digest as JSON. The body also carries `text` and `content`
// so a Slack or Discord webhook URL works as the receiver.
func Post(url string, d Digest) error {
	body, _ := json.Marshal(map[string]any{"text": "```" + d.Text() + "```", "content": "```" + d.Text() + "```", "digest": d})
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pushwarden")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
