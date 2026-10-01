package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/feedback"
	"github.com/FaheemRafiq/threatscan/internal/guard"
	"github.com/FaheemRafiq/threatscan/internal/journal"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/service"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func init() {
	register("feedback", "bundle this machine's activity for analysis, or report a false positive", cmdFeedback)
	guardHooks.Periodic = append(guardHooks.Periodic, guard.PeriodicTask{
		Name: "feedback-digest",
		Interval: func(cfg *config.Config) time.Duration {
			if cfg.FeedbackURL == "" {
				return 0 // opt-in only
			}
			return time.Hour // cheap check; posts at most once a day
		},
		Run: func(g *guard.Guard) { postDigest(g.DataDir, g.Cfg, g.I.Version, g.P.OS, g.P.Hostname, g.Log) },
	})
}

func lastDigest(dataDir string) time.Time {
	b, err := os.ReadFile(filepath.Join(dataDir, "feedback-last"))
	if err != nil {
		return time.Time{}
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return time.Unix(n, 0)
}

// buildDigest summarises the journal since `from`.
func buildDigest(dataDir string, cfg *config.Config, iocVersion, goos, host string, from time.Time) feedback.Digest {
	evs := journal.Read(dataDir, journal.Filter{Since: from, Archives: true})
	d := feedback.BuildDigest(evs, feedback.MachineID(dataDir), version, goos, iocVersion, from, time.Now())
	if cfg.FeedbackIdentify {
		d.Host = host
	}
	return d
}

// postDigest sends the daily digest when feedback_url is set and a day has
// passed since the last one.
func postDigest(dataDir string, cfg *config.Config, iocVersion, goos, host string, log func(string)) {
	last := lastDigest(dataDir)
	if cfg.FeedbackURL == "" || time.Since(last) < 24*time.Hour {
		return
	}
	from := last
	if from.IsZero() || time.Since(from) > 7*24*time.Hour {
		from = time.Now().Add(-24 * time.Hour)
	}
	d := buildDigest(dataDir, cfg, iocVersion, goos, host, from)
	if err := feedback.Post(cfg.FeedbackURL, d); err != nil {
		log("feedback digest not sent: " + err.Error())
		return
	}
	_ = os.WriteFile(filepath.Join(dataDir, "feedback-last"), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
	log(fmt.Sprintf("feedback digest sent (%d events, no paths or command lines)", d.Events))
}

func cmdFeedback(args []string) int {
	fs := newFlags("feedback", "[--days N] [--out FILE] [--no-redact] | --false-positive PATH [--note TEXT] | --digest")
	days := fs.Int("days", 14, "how many days of activity to include")
	out := fs.String("out", "", "write the bundle to `FILE` (default: ./threatscan-feedback-DATE.zip)")
	noRedact := fs.Bool("no-redact", false, "keep paths, user and host names (secrets are still masked)")
	fp := fs.String("false-positive", "", "record that the finding on `PATH` was wrong")
	note := fs.String("note", "", "with --false-positive: what the file really is")
	digest := fs.Bool("digest", false, "print the daily digest that feedback_url would receive")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	jr := openJournal(c)
	switch {
	case *fp != "":
		p, _ := filepath.Abs(*fp)
		jr.Write(journal.Event{Ctx: "cli", Kind: journal.KindFeedback, Title: "marked as a false positive", Path: p, Note: *note})
		u.OK("Recorded. It is included in the next feedback bundle" + map[bool]string{true: " and daily digest", false: ""}[c.Cfg.FeedbackURL != ""] + ".")
		u.Info("To also restore the file and stop flagging it:  threatscan history --allow " + p)
		return 0
	case *digest:
		d := buildDigest(c.DataDir, c.Cfg, c.I.Version, c.P.OS, c.P.Hostname, time.Now().Add(-24*time.Hour))
		b, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(b))
		if c.Cfg.FeedbackURL == "" {
			u.Info("Not sent anywhere: feedback_url is not set.")
		}
		return 0
	}
	path := *out
	if path == "" {
		path = "threatscan-feedback-" + time.Now().Format("20060102-1504") + ".zip"
	}
	red := &feedback.Redactor{Home: c.P.Home, Host: c.P.Hostname}
	if cu, err := user.Current(); err == nil {
		red.User = cu.Username
	}
	if *noRedact {
		red = &feedback.Redactor{} // paths stay; token shapes are still masked
	}
	cfgJSON, _ := json.MarshalIndent(c.Cfg, "", "  ")
	b, err := feedback.WriteBundle(path, c.DataDir, feedbackSummary(c), string(cfgJSON), time.Now().Add(-time.Duration(*days)*24*time.Hour), red)
	if err != nil {
		u.Err("Could not write the bundle: " + err.Error())
		return 2
	}
	abs, _ := filepath.Abs(b.Path)
	u.OK("Feedback bundle written: " + abs)
	u.P("      %d events from the last %d days; files: %s", b.Events, *days, strings.Join(b.Files, ", "))
	if *noRedact {
		u.Warn("Not redacted: paths, user and host names are included.")
	} else {
		u.P("      Redacted: home folder shown as ~, user and host names removed, token-shaped strings masked.")
	}
	u.Info("Nothing was uploaded. Look inside with `unzip -l`, then send the file to whoever maintains ThreatScan for you.")
	return 0
}

// feedbackSummary is the status text placed in the bundle.
func feedbackSummary(c *ctx) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ThreatScan %s on %s/%s (%s)\n", version, runtime.GOOS, runtime.GOARCH, c.P.DisplayName())
	fmt.Fprintf(&b, "indicators: %s (%s)\n", c.I.Version, c.I.Source)
	hb, age, alive := guard.ReadHeartbeat(c.DataDir)
	switch {
	case hb == nil:
		b.WriteString("guard: no heartbeat\n")
	default:
		fmt.Fprintf(&b, "guard: alive=%v phase=%s age=%ds version=%s real-time=%s repos=%d\n", alive, hb.Phase, int(age.Seconds()), hb.Version, hb.Realtime, hb.Repos)
	}
	fmt.Fprintf(&b, "service: %s\n", service.New(c.P, c.DataDir).Status())
	fmt.Fprintf(&b, "firewall: %s\n", (&protect.NetBlocker{P: c.P}).Describe())
	fmt.Fprintf(&b, "policy: action=%s auto_kill=%v prompt=%v deep=%v realtime=%v\n", c.Cfg.Action, c.Cfg.AutoKill, c.Cfg.Prompt, c.Cfg.Deep, c.Cfg.Realtime)
	fmt.Fprintf(&b, "roots: %d\n", len(c.Cfg.Roots(c.P.CommonProjectDirs)))
	return b.String()
}
