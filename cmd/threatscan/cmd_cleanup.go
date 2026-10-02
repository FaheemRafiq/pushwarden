package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/guard"
	"github.com/FaheemRafiq/threatscan/internal/housekeep"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func init() {
	register("cleanup", "show what ThreatScan occupies on disk and remove what is past its limits", cmdCleanup)
	guardHooks.Periodic = append(guardHooks.Periodic, guard.PeriodicTask{
		Name:     "housekeeping",
		Interval: func(*config.Config) time.Duration { return 24 * time.Hour },
		Run: func(g *guard.Guard) {
			// not while an upload is reading the journal: both count its events
			if !uploading.CompareAndSwap(false, true) {
				return
			}
			defer uploading.Store(false)
			up := newUploader(g.DataDir, g.Cfg, g.P.Home, g.P.Hostname, g.P.OS)
			if r := housekeep.Run(housekeep.Options{DataDir: g.DataDir, Cfg: g.Cfg, Journal: g.J, Unsent: up.Unsent}); len(r.Lines) > 0 {
				g.Log("housekeeping: " + r.String())
			}
		},
	})
}

// diskSummary is the `status` line: the total and the stores that matter.
func diskSummary(c *ctx) string {
	items := housekeep.Usage(c.DataDir, c.Cfg)
	var parts []string
	for _, it := range items {
		if it.Bytes >= 1<<20 {
			parts = append(parts, it.Name+" "+housekeep.MB(it.Bytes))
		}
	}
	out := housekeep.MB(housekeep.Total(items))
	if len(parts) > 0 {
		out += " (" + strings.Join(parts, ", ") + ")"
	}
	return out + ". Limits and cleanup: threatscan cleanup"
}

func cmdCleanup(args []string) int {
	fs := newFlags("cleanup", "[--dry-run]")
	dry := fs.Bool("dry-run", false, "show what would be removed; remove nothing")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	up := newUploader(c.DataDir, c.Cfg, c.P.Home, c.P.Hostname, c.P.OS)
	r := housekeep.Run(housekeep.Options{DataDir: c.DataDir, Cfg: c.Cfg, Dry: *dry, Journal: openJournal(c), Unsent: up.Unsent})

	u.Section("DISK USE  " + c.DataDir)
	items := housekeep.Usage(c.DataDir, c.Cfg)
	u.P("  %-12s %10s   %s", "store", "size", "limit")
	for _, it := range items {
		u.P("  %-12s %10s   %s", it.Name, housekeep.MB(it.Bytes), it.Limit)
	}
	u.P("  %-12s %10s", "total", housekeep.MB(housekeep.Total(items)))
	u.P("")
	verb := "Removed"
	if *dry {
		verb = "Would remove"
	}
	if len(r.Lines) == 0 {
		u.OK("Nothing is past its limit. The guard checks this once a day.")
		return 0
	}
	for _, l := range r.Lines {
		line := fmt.Sprintf("%s %d %s (%s)", verb, l.Count, l.What, housekeep.MB(l.Bytes))
		if l.Note != "" {
			line += ": " + l.Note
		}
		u.Info(line)
	}
	if *dry {
		u.Info(fmt.Sprintf("Dry run: nothing was removed. `threatscan cleanup` frees %s.", housekeep.MB(r.Bytes())))
	} else {
		u.OK(housekeep.MB(r.Bytes()) + " freed.")
	}
	u.Info("Limits are settings: journal_keep_mb, journal_keep_days, quarantine_keep_days, quarantine_keep_mb, clone_keep_days, clone_keep_mb (0 = no limit).")
	return 0
}
