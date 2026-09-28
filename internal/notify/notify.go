// Package notify raises desktop notifications, writes alerts.log and posts webhooks.
package notify

import (
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

func (n *Notifier) Alert(fs []*findings.Finding, context string) {
	if len(fs) == 0 {
		return
	}
	n.log(fs, context)
	top := findings.Worst(fs)
	title := "ThreatScan: " + top.String() + " - review recommended"
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
	var lines []string
	for i, f := range fs {
		if i == 5 {
			lines = append(lines, fmt.Sprintf("... and %d more (threatscan history)", len(fs)-5))
			break
		}
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
		lines = append(lines, l)
	}
	body := strings.Join(lines, "\n")
	if n.Cfg.NotifyDesktop && top >= findings.ParseSeverity(n.Cfg.NotifyMinSeverity) {
		n.Desktop(title, body)
	}
	if n.Cfg.WebhookURL != "" && top >= findings.ParseSeverity(n.Cfg.WebhookMinSeverity) {
		n.Webhook(title, body, fs, context)
	}
}

func (n *Notifier) log(fs []*findings.Finding, context string) {
	fh, err := os.OpenFile(n.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	ts := time.Now().Format("2006-01-02T15:04:05")
	for _, f := range fs {
		b, _ := json.Marshal(struct {
			TS      string `json:"ts"`
			Context string `json:"context"`
			*findings.Finding
		}{ts, context, f})
		fh.Write(append(b, '\n'))
	}
}

// Desktop uses the OS notification centre (libnotify / Notification Center / toast).
func (n *Notifier) Desktop(title, body string) {
	_ = zenity.Notify(body, zenity.Title(title), zenity.WarningIcon)
}

func (n *Notifier) Webhook(title, body string, fs []*findings.Finding, context string) {
	payload := map[string]any{
		"text":    fmt.Sprintf("*%s* on `%s` (%s)\n```%s```", title, n.P.Hostname, n.P.DisplayName(), body),
		"content": fmt.Sprintf("**%s** on `%s`\n```%s```", title, n.P.Hostname, body),
		"host":    n.P.Hostname, "platform": n.P.DisplayName(), "context": context, "findings": fs,
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
