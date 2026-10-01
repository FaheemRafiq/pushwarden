package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/guard"
	"github.com/FaheemRafiq/threatscan/internal/journal"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/service"
	"github.com/FaheemRafiq/threatscan/internal/ui"
	"github.com/FaheemRafiq/threatscan/internal/update"
)

func init() {
	update.Version = version
	register("update", "update ThreatScan to the latest release", cmdUpdate)
	register("update-iocs", "download the latest indicator file", cmdUpdateIOCs)

	guardHooks.UpdateIOCs = update.UpdateIOCs
	guardHooks.Periodic = append(guardHooks.Periodic,
		// cheap: reads update-state.json; announces an update once it is running
		guard.PeriodicTask{Name: "update-confirm", Interval: func(*config.Config) time.Duration { return time.Minute }, Run: confirmUpdate},
		guard.PeriodicTask{Name: "self-update", Interval: func(cfg *config.Config) time.Duration {
			if !cfg.AutoUpdate || isDevBuild() {
				return 0
			}
			return time.Duration(cfg.UpdateInterval) * time.Second
		}, Run: selfUpdate})
	guardPreStart = rollbackIfFailed
}

func isDevBuild() bool { return strings.HasSuffix(version, "-dev") }

func guardUpdater(g *guard.Guard) *update.Updater {
	u := update.New(g.DataDir, platform.Exe(), g.Cfg)
	u.Current, u.Log = g.Version, g.Log
	return u
}

func lastHeartbeat(dataDir string) (string, time.Time) {
	hb, _, _ := guard.ReadHeartbeat(dataDir)
	if hb == nil {
		return "", time.Time{}
	}
	return hb.Version, time.Unix(0, int64(hb.TS*1e9))
}

// rollbackIfFailed restores the previous binary when a fresh update keeps
// failing to start (see update.Updater.OnGuardStart).
func rollbackIfFailed(c *ctx, g *guard.Guard) bool {
	u := guardUpdater(g)
	rolled, err := u.OnGuardStart(lastHeartbeat(c.DataDir))
	if err != nil {
		g.Log("update: rollback failed: " + err.Error())
	}
	if !rolled {
		return false
	}
	g.J.Write(journal.Event{Ctx: "update", Kind: journal.KindError, Title: "program update rolled back: the new version did not start"})
	if err := service.New(c.P, c.DataDir).RestartFromGuard(u.Exe); err != nil {
		g.Log("update: restart after rollback failed: " + err.Error())
	}
	return true
}

func confirmUpdate(g *guard.Guard) {
	hbVersion, _ := lastHeartbeat(g.DataDir)
	if v := guardUpdater(g).Confirm(hbVersion); v != "" {
		g.Log("update: running " + v)
		g.J.Write(journal.Event{Ctx: "update", Kind: journal.KindUpdate, Title: "program update confirmed: running " + v})
		g.Notifier.Desktop("ThreatScan", "ThreatScan updated to v"+v)
	}
}

func selfUpdate(g *guard.Guard) {
	m := service.New(g.P, g.DataDir)
	if exe := platform.Exe(); exe != m.Exe() {
		g.Log("update: skipped, guard runs from " + exe + " rather than the install dir " + m.Exe())
		return
	}
	u := guardUpdater(g)
	rel, err := u.Check()
	if err != nil {
		g.Log("update: check failed: " + err.Error())
		return
	}
	if rel == nil {
		return
	}
	if err := u.Apply(rel); err != nil {
		g.Log("update: " + rel.Tag + " refused: " + err.Error())
		g.J.Write(journal.Event{Ctx: "update", Kind: journal.KindError, Title: "program update " + rel.Tag + " refused", Note: err.Error()})
		return
	}
	g.J.Write(journal.Event{Ctx: "update", Kind: journal.KindUpdate, Title: "program update " + rel.Tag + " installed; restarting",
		Data: map[string]any{"from": g.Version, "to": rel.Version()}})
	if err := m.RestartFromGuard(u.Exe); err != nil {
		g.Log("update: installed " + rel.Tag + " but could not restart: " + err.Error())
		return
	}
	g.Stop()
}

func cmdUpdate(args []string) int {
	fs := newFlags("update", "[--check]")
	check := fs.Bool("check", false, "only report whether a newer release exists")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	up := update.New(c.DataDir, platform.Exe(), c.Cfg)
	up.Log = func(string) {}
	rel, err := up.Check()
	if err != nil {
		u.Err("Update check failed: " + err.Error())
		return 1
	}
	if rel == nil {
		u.OK("ThreatScan " + version + " is up to date")
		return 0
	}
	if *check {
		u.Info(fmt.Sprintf("ThreatScan %s is available (you have %s). Install:  threatscan update", rel.Version(), version))
		return 0
	}
	u.Info("Downloading and verifying ThreatScan " + rel.Version() + "...")
	if err := up.Apply(rel); err != nil {
		u.Err("Update refused: " + err.Error())
		return 1
	}
	u.OK("Installed ThreatScan " + rel.Version() + " at " + up.Exe)
	m := service.New(c.P, c.DataDir)
	if up.Exe == m.Exe() {
		if ok, msg := m.Restart(); ok {
			u.OK("Background guard restarted on the new version")
		} else {
			u.Info("Background guard: " + msg)
		}
	}
	return 0
}

func cmdUpdateIOCs(args []string) int {
	fs := newFlags("update-iocs", "[--url URL]")
	url := fs.String("url", "", "download from `URL` instead of the project repository")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	cfg := *c.Cfg
	if *url != "" {
		cfg.IOCUpdateURL = *url
	}
	if ok, msg := update.UpdateIOCs(c.DataDir, c.I.Version, &cfg); ok {
		u.OK(msg)
	} else {
		u.Info(msg)
	}
	return 0
}
