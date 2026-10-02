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
	"sync/atomic"
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
	}, guard.PeriodicTask{
		Name: "event-upload",
		Interval: func(cfg *config.Config) time.Duration {
			if cfg.UploadURL == "" {
				return 0 // opt-in only
			}
			return time.Minute // a cheap check; Due decides whether anything is sent
		},
		Run: func(g *guard.Guard) {
			up, log := newUploader(g.DataDir, g.Cfg, g.P.Home, g.P.Hostname, g.P.OS), g.Log
			if !up.Due(time.Now()) {
				return
			}
			// Off the guard's loop: a slow or unreachable server must never
			// delay protection. One upload at a time.
			if !uploading.CompareAndSwap(false, true) {
				return
			}
			go func() {
				defer uploading.Store(false)
				defer func() { _ = recover() }()
				uploadEvents(up, log)
			}()
		},
	})
}

var uploading atomic.Bool

// redactorFor builds the redactor for this machine's home, user and host.
func redactorFor(home, host string) *feedback.Redactor {
	red := &feedback.Redactor{Home: home, Host: host}
	if cu, err := user.Current(); err == nil {
		red.User = cu.Username
	}
	return red
}

// newUploader configures the central-table uploader. Events are always
// redacted on this path; there is no switch to turn that off.
func newUploader(dataDir string, cfg *config.Config, home, host, goos string) *feedback.Uploader {
	return &feedback.Uploader{DataDir: dataDir, URL: cfg.UploadURL, Key: cfg.UploadKey, MachineID: feedback.MachineID(dataDir),
		OS: goos, Red: redactorFor(home, host)}
}

// uploadEvents runs one upload for the guard and logs the outcome: one line
// when uploads start failing, one when they work again, none per retry.
// Failures go to the guard log only: a journal entry per failure would itself
// be uploaded later.
func uploadEvents(up *feedback.Uploader, log func(string)) {
	r := up.Run()
	switch {
	case r.Err != nil && r.Failures == 1:
		log(fmt.Sprintf("event upload failed, %d events are kept and waiting; retrying after 1, 2, 4, 8 minutes, then every 10: %v", r.Waiting, r.Err))
	case r.Err != nil:
	case r.Recovered:
		log(fmt.Sprintf("event upload: back online, %d redacted events sent, %d waiting", r.Sent, r.Waiting))
	case r.Sent > 0:
		log(fmt.Sprintf("event upload: %d redacted events sent, %d waiting", r.Sent, r.Waiting))
	}
}

// uploadSummary is the `status` line for the central upload.
func uploadSummary(up *feedback.Uploader) string {
	if up.URL == "" {
		return "off"
	}
	s := up.Status()
	out := fmt.Sprintf("on, %d uploaded, %d waiting", s.Uploaded, s.Waiting)
	switch {
	case s.Failures > 0:
		out += fmt.Sprintf("; server not reached since %s (%s), retrying", s.FailingSince.Local().Format("2006-01-02 15:04"), s.LastError)
	case !s.LastSuccess.IsZero():
		out += " (last upload " + s.LastSuccess.Local().Format("2006-01-02 15:04") + ")"
	default:
		out += " (no upload yet)"
	}
	return out + ". See: threatscan feedback --preview"
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
	fs := newFlags("feedback", "[--days N] [--out FILE] [--no-redact] | --false-positive PATH [--note TEXT] | --digest | --preview | --upload")
	days := fs.Int("days", 14, "how many days of activity to include")
	out := fs.String("out", "", "write the bundle to `FILE` (default: ./threatscan-feedback-DATE.zip)")
	noRedact := fs.Bool("no-redact", false, "keep paths, user and host names (secrets are still masked)")
	fp := fs.String("false-positive", "", "record that the finding on `PATH` was wrong")
	note := fs.String("note", "", "with --false-positive: what the file really is")
	digest := fs.Bool("digest", false, "print the daily digest that feedback_url would receive")
	preview := fs.Bool("preview", false, "show the next redacted events that upload_url would receive, without sending")
	upload := fs.Bool("upload", false, "send the waiting events to upload_url now")
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
	case *preview:
		rows, total := newUploader(c.DataDir, c.Cfg, c.P.Home, c.P.Hostname, c.P.OS).Pending(5)
		if rows == nil {
			rows = []feedback.Row{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false) // show <redacted> as it reads in the table
		_ = enc.Encode(rows)
		u.Info(fmt.Sprintf("%d events are waiting; these are the next %d exactly as they would be stored. Nothing was sent.", total, len(rows)))
		if c.Cfg.UploadURL == "" {
			u.Info("upload_url is not set, so nothing is ever uploaded from this machine.")
		}
		return 0
	case *upload:
		if c.Cfg.UploadURL == "" {
			u.Err("upload_url is not set. See: threatscan help feedback")
			return 2
		}
		up := newUploader(c.DataDir, c.Cfg, c.P.Home, c.P.Hostname, c.P.OS)
		up.MaxEvents, up.Timeout = 1<<30, 10*time.Minute // the whole backlog in one go
		r := up.Run()
		if r.Err != nil {
			u.Err(fmt.Sprintf("%d events sent, %d still waiting on this machine: %v", r.Sent, r.Waiting, r.Err))
			u.Info("Nothing is lost: the guard retries by itself, or run this again when the server is reachable.")
			return 1
		}
		u.OK(fmt.Sprintf("%d redacted events uploaded, %d waiting", r.Sent, r.Waiting))
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
	red := redactorFor(c.P.Home, c.P.Hostname)
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
