// Package notify raises desktop notifications, writes alerts.log and posts webhooks.
package notify

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/findings"
	h "github.com/FaheemRafiq/threatscan/internal/helpers"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/ncruces/zenity"
)

type Notifier struct {
	P       *platform.Info
	Cfg     *config.Config
	LogPath string
}

func New(p *platform.Info, c *config.Config, dataDir string) *Notifier {
	_ = os.MkdirAll(dataDir, 0o700)
	return &Notifier{P: p, Cfg: c, LogPath: filepath.Join(dataDir, "alerts.log")}
}

// Alert is one line of alerts.log: the finding plus the reasons as they were
// worded at the time.
type Alert struct {
	TS       string `json:"ts"`
	Context  string `json:"context"`
	Why      string `json:"why"`
	Response string `json:"response,omitempty"`
	*findings.Finding
}

func (n *Notifier) Alert(fs []*findings.Finding, context string) {
	if len(fs) == 0 {
		return
	}
	n.log(fs, context)
	top := findings.Worst(fs)
	title, body := BuildAlert(fs)
	if n.Cfg.NotifyDesktop && top >= findings.ParseSeverity(n.Cfg.NotifyMinSeverity) {
		n.Desktop(title, body)
	}
	if n.Cfg.WebhookURL != "" && top >= findings.ParseSeverity(n.Cfg.WebhookMinSeverity) {
		n.Webhook(title, body, fs, context)
	}
}

// line is the one-line summary of a finding used in notifications.
func line(f *findings.Finding) string {
	name := f.Severity.String()
	if f.Severity >= findings.Critical {
		name = prompt.ThreatName(f)
	}
	where := f.Title
	if f.Path != "" {
		where = filepath.Base(f.Path)
	}
	l := name + ": " + where
	if f.Action != "" {
		l += " - " + f.Action
	}
	return l
}

// reason is the sentence a notification shows under a finding: the response
// reason once something was done, otherwise why it was flagged.
func reason(f *findings.Finding) string {
	if f.Action != "" {
		return findings.WhyAction(f)
	}
	return findings.Why(f)
}

// BuildAlert composes the notification title and body. With one finding the
// body is its summary plus the reason (two lines, which is what macOS shows);
// with several it lists up to five.
func BuildAlert(fs []*findings.Finding) (title, body string) {
	top := findings.Worst(fs)
	title = "ThreatScan: " + top.String() + " - review recommended"
	allActed := true
	for _, f := range fs {
		if f.Severity >= findings.Critical && (f.Action == "" || strings.HasPrefix(f.Action, "kept")) {
			allActed = false
		}
	}
	if top >= findings.Critical {
		if allActed {
			title = "Threats found - actions taken"
		} else {
			title = "Threats found - action needed"
		}
	}
	if len(fs) == 1 {
		return title, line(fs[0]) + "\n" + h.Trunc(reason(fs[0]), 110)
	}
	var lines []string
	for i, f := range fs {
		if i == 5 {
			lines = append(lines, fmt.Sprintf("... and %d more (threatscan alerts)", len(fs)-5))
			break
		}
		lines = append(lines, line(f))
	}
	return title, strings.Join(lines, "\n")
}

func (n *Notifier) log(fs []*findings.Finding, context string) {
	fh, err := os.OpenFile(n.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	ts := time.Now().Format("2006-01-02T15:04:05")
	for _, f := range fs {
		resp := ""
		if f.Action != "" {
			resp = findings.WhyAction(f)
		}
		b, _ := json.Marshal(Alert{TS: ts, Context: context, Why: findings.Why(f), Response: resp, Finding: f})
		fh.Write(append(b, '\n'))
	}
}

// ReadAlerts returns the last n alerts from alerts.log (all when n <= 0).
// Malformed lines are skipped.
func ReadAlerts(path string, n int) ([]Alert, error) {
	fh, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer fh.Close()
	var out []Alert
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var a Alert
		if json.Unmarshal(sc.Bytes(), &a) != nil || a.Finding == nil {
			continue
		}
		if a.Why == "" { // written before reasons were recorded
			a.Why = findings.Why(a.Finding)
		}
		out = append(out, a)
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, sc.Err()
}

// Desktop uses the OS notification centre. On macOS the helper app created by
// `threatscan install` posts it, so a click opens the alert details; without
// the app (or on failure) zenity's osascript path is used.
func (n *Notifier) Desktop(title, body string) {
	if n.P != nil && n.P.IsMac() {
		if app := MacAppPath(n.P.InstallDir()); exists(app) {
			sub, text := macArgs(title, body)
			args := []string{"-a", app, "--args", title, sub}
			if text != "" {
				args = append(args, text)
			}
			if rc, _, _ := n.P.RunRC(15*time.Second, "open", args...); rc == 0 {
				return
			}
		}
	}
	_ = zenity.Notify(body, zenity.Title(title), zenity.WarningIcon)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

type webhookReason struct {
	Title    string `json:"title"`
	Path     string `json:"path,omitempty"`
	Severity string `json:"severity"`
	Why      string `json:"why"`
	Response string `json:"response,omitempty"`
}

func (n *Notifier) Webhook(title, body string, fs []*findings.Finding, context string) {
	var reasons []webhookReason
	var whyLines []string
	for i, f := range fs {
		r := webhookReason{Title: f.Title, Path: f.Path, Severity: f.Severity.String(), Why: findings.Why(f)}
		if f.Action != "" {
			r.Response = findings.WhyAction(f)
		}
		reasons = append(reasons, r)
		if i < 5 {
			whyLines = append(whyLines, "why: "+reason(f))
		}
	}
	text := body + "\n" + strings.Join(whyLines, "\n")
	payload := map[string]any{
		"text":    fmt.Sprintf("*%s* on `%s` (%s)\n```%s```", title, n.P.Hostname, n.P.DisplayName(), text),
		"content": fmt.Sprintf("**%s** on `%s`\n```%s```", title, n.P.Hostname, text),
		"host":    n.P.Hostname, "platform": n.P.DisplayName(), "context": context, "findings": fs, "reasons": reasons,
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", n.Cfg.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "threatscan")
	cl := &http.Client{Timeout: 15 * time.Second}
	if resp, err := cl.Do(req); err == nil {
		resp.Body.Close()
	}
}
