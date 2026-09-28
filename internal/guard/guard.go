// Package guard is the background protection loop.
//
// Cadences (config.json): behaviour pass every quick_interval seconds
// (processes + sockets + tracked files whose mtime changed), full sweep every
// full_interval, indicator refresh every ioc_update_interval.  State lives in
// <data_dir>/guard/: heartbeat.json and seen.json (same as v5).
package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/findings"
	h "github.com/FaheemRafiq/threatscan/internal/helpers"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/notify"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/report"
	"github.com/FaheemRafiq/threatscan/internal/scan"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

type F = findings.Finding

// Hooks let later phases plug in without changing the loop.
type Hooks struct {
	// StartRealtime starts file watching over roots and calls onEvents with batches.
	StartRealtime func(roots []string, skip func(string) bool, onEvents func([]string), log func(string)) (backend string, stop func())
	// UpdateIOCs refreshes the indicator file; returns (updated, message).
	UpdateIOCs func(dataDir, current string, cfg *config.Config) (bool, string)
	// Periodic runs extra work on its own cadence (program self-update).
	Periodic []PeriodicTask
}

type PeriodicTask struct {
	Name     string
	Interval func(cfg *config.Config) time.Duration
	Run      func(g *Guard)
}

type Guard struct {
	P        *platform.Info
	DataDir  string
	Cfg      *config.Config
	I        *iocs.IOCs
	Version  string
	Once     bool
	DryRun   bool
	Hooks    Hooks
	UI       *ui.UI
	Notifier *notify.Notifier
	Prot     *protect.Protector

	stateDir  string
	logPath   string
	mu        sync.Mutex
	seen      map[string]float64
	mtimes    map[string]time.Time
	repos     []string
	tracked   []string
	lastFull  time.Time
	backend   string
	stopWatch func()
	dialogs   chan *F
	dialogWG  sync.WaitGroup
	stop      chan struct{}
	stopOnce  sync.Once
}

func New(p *platform.Info, dataDir, version string, once, dry, verbose bool) (*Guard, error) {
	i, err := iocs.Load(dataDir)
	if err != nil {
		return nil, err
	}
	cfg := config.Load(dataDir)
	u := ui.New(true, !verbose)
	g := &Guard{P: p, DataDir: dataDir, Cfg: cfg, I: i, Version: version, Once: once, DryRun: dry, UI: u,
		Notifier: notify.New(p, cfg, dataDir), Prot: protect.New(p, i, dataDir, u, dry),
		stateDir: filepath.Join(dataDir, "guard"), logPath: filepath.Join(dataDir, "guard.log"),
		seen: map[string]float64{}, mtimes: map[string]time.Time{}, dialogs: make(chan *F, 64), stop: make(chan struct{})}
	_ = os.MkdirAll(g.stateDir, 0o700)
	if b, err := os.ReadFile(filepath.Join(g.stateDir, "seen.json")); err == nil {
		_ = json.Unmarshal(b, &g.seen)
	}
	return g, nil
}

// ── utils ────────────────────────────────────────────────────────────────────

func (g *Guard) Log(msg string) {
	line := time.Now().Format("2006-01-02 15:04:05") + " " + msg
	if f, err := os.OpenFile(g.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		f.WriteString(line + "\n")
		f.Close()
	}
	if !g.UI.Quiet {
		fmt.Println(line)
	}
}

func saveJSON(path string, v any) {
	b, _ := json.Marshal(v)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}

type Heartbeat struct {
	TS       float64        `json:"ts"`
	PID      int            `json:"pid"`
	Phase    string         `json:"phase"`
	Version  string         `json:"version"`
	IOCs     string         `json:"iocs"`
	LastFull float64        `json:"last_full"`
	Repos    int            `json:"repos"`
	Realtime string         `json:"realtime"`
	Action   string         `json:"action"`
	Stats    map[string]int `json:"last_full_stats,omitempty"`
}

func (g *Guard) heartbeat(phase string, stats map[string]int) {
	rt := g.backend
	if rt == "" {
		rt = "off"
	}
	lf := 0.0
	if !g.lastFull.IsZero() {
		lf = float64(g.lastFull.Unix())
	}
	saveJSON(filepath.Join(g.stateDir, "heartbeat.json"), Heartbeat{TS: float64(time.Now().UnixNano()) / 1e9, PID: os.Getpid(),
		Phase: phase, Version: g.Version, IOCs: g.I.Version, LastFull: lf, Repos: len(g.repos), Realtime: rt,
		Action: g.Cfg.Action, Stats: stats})
}

// ReadHeartbeat is used by `threatscan status` and the updater.
func ReadHeartbeat(dataDir string) (*Heartbeat, time.Duration, bool) {
	b, err := os.ReadFile(filepath.Join(dataDir, "guard", "heartbeat.json"))
	if err != nil {
		return nil, 0, false
	}
	var hb Heartbeat
	if json.Unmarshal(b, &hb) != nil {
		return nil, 0, false
	}
	age := time.Since(time.Unix(0, int64(hb.TS*1e9)))
	return &hb, age, age < 10*time.Minute
}

func (g *Guard) roots() []string { return g.Cfg.Roots(g.P.CommonProjectDirs) }

// ── discovery ────────────────────────────────────────────────────────────────

var fontDirs = []string{"public/fonts", "public/font", "static/fonts", "assets/fonts", "src/assets/fonts", "fonts"}

func (g *Guard) trackedFor(repos []string) []string {
	var out []string
	for _, r := range repos {
		for _, n := range append(append(append([]string{}, g.I.ConfigFiles...), g.I.EntryFiles...), g.I.PropagationScripts...) {
			out = append(out, filepath.Join(r, filepath.FromSlash(n)))
		}
		out = append(out, filepath.Join(r, ".vscode", "tasks.json"), filepath.Join(r, ".vscode", "settings.json"))
		for _, d := range fontDirs {
			for _, n := range g.I.FakeFontNames {
				out = append(out, filepath.Join(r, filepath.FromSlash(d), n))
			}
		}
	}
	return out
}

func (g *Guard) setTargets(repos []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.repos = repos
	g.tracked = g.trackedFor(repos)
	for _, p := range g.tracked {
		if st, err := os.Stat(p); err == nil {
			g.mtimes[p] = st.ModTime()
		} else {
			delete(g.mtimes, p)
		}
	}
}

// ── response + alerting ──────────────────────────────────────────────────────

func (g *Guard) decide(f *F, action string) prompt.Verdict {
	if !g.Cfg.Prompt {
		return prompt.Unavailable
	}
	g.Log("asking user about " + f.Path + " (" + action + ")")
	v := prompt.Ask(f, action, time.Duration(g.Cfg.PromptTimeout)*time.Second)
	g.Log(fmt.Sprintf("user decision for %s: %s", f.Path, v))
	return v
}

func (g *Guard) afterQuarantine(f *F) {
	v := prompt.AskQuarantined(f, time.Duration(g.Cfg.PromptTimeout)*time.Second)
	g.Log(fmt.Sprintf("post-quarantine decision for %s: %s", f.Path, v))
	switch v {
	case prompt.Delete:
		g.Log(fmt.Sprintf("removed %d quarantined cop(ies) of %s", g.Prot.Purge(f.Path), f.Path))
	case prompt.Keep:
		if g.Prot.Restore(f.Path) {
			g.Prot.Remember(f.Path, f.Title, prompt.Keep)
			g.Log("restored and allowed " + f.Path)
		}
	}
	// timeout / unavailable: stays in quarantine (threatscan history to review)
}

func (g *Guard) startDialogWorker() {
	g.dialogWG.Add(1)
	go func() {
		defer g.dialogWG.Done()
		for f := range g.dialogs {
			func() {
				defer func() {
					if r := recover(); r != nil {
						g.Log(fmt.Sprintf("dialog error: %v", r))
					}
				}()
				g.afterQuarantine(f)
			}()
		}
	}()
}

// Handle applies the configured policy, alerts and records.
func (g *Guard) Handle(fs []*F, context string) {
	if len(fs) == 0 {
		return
	}
	policy := strings.ToLower(g.Cfg.Action)
	var acted []*F
	switch policy {
	case "ask":
		acted = g.Prot.Respond(fs, g.Cfg.AutoKill, g.Cfg.AutoClean, g.decide)
	case "delete":
		acted = g.Prot.Respond(fs, g.Cfg.AutoKill, true, func(*F, string) prompt.Verdict { return prompt.Delete })
	case "report":
		acted = g.Prot.Respond(fs, g.Cfg.AutoKill, false, nil)
	default: // quarantine: act first (reversible), then let the user decide
		policy = "quarantine"
		acted = g.Prot.Respond(fs, g.Cfg.AutoKill, true, nil)
	}
	now := float64(time.Now().Unix())
	var fresh []*F
	g.mu.Lock()
	for _, f := range fs {
		if strings.HasPrefix(f.Action, "kept") {
			g.seen[f.Key()] = now
			continue
		}
		// Alert again on the same finding at most once per 6 hours; always alert actions.
		if f.Action != "" || now-g.seen[f.Key()] > 6*3600 {
			fresh = append(fresh, f)
			g.seen[f.Key()] = now
		}
	}
	for k, t := range g.seen {
		if now-t > 7*86400 {
			delete(g.seen, k)
		}
	}
	saveJSON(filepath.Join(g.stateDir, "seen.json"), g.seen)
	g.mu.Unlock()
	for _, f := range fs {
		msg := fmt.Sprintf("[%s] %s %s", f.Severity, f.Title, f.Path)
		if f.Action != "" {
			msg += " -> " + f.Action
		}
		g.Log(msg)
	}
	if findings.AnyAtLeast(fresh, findings.High) {
		var alert []*F
		for _, f := range fresh {
			if f.Severity >= findings.Warning {
				alert = append(alert, f)
			}
		}
		g.Notifier.Alert(alert, context)
	}
	if len(acted) > 0 {
		g.Log(fmt.Sprintf("responded to %d finding(s)", len(acted)))
	}
	if policy == "quarantine" && g.Cfg.Prompt && !g.DryRun {
		for _, f := range acted {
			if f.Path != "" && f.Category != "malicious_process" && f.Category != "c2_connection" &&
				(f.Meta.Quarantine || f.Meta.Cleanable || f.Meta.MidFileInjection) {
				select {
				case g.dialogs <- f:
				default:
					g.Log("dialog queue full; " + f.Path + " stays in quarantine")
				}
			}
		}
	}
}

// ── real-time events (called by internal/realtime) ───────────────────────────

func (g *Guard) interesting(p string) bool {
	if h.IsUnder(p, []string{g.DataDir}) || h.IsUnder(p, g.Cfg.Exclude) {
		return false
	}
	name, parent := filepath.Base(p), filepath.Base(filepath.Dir(p))
	if (name == "tasks.json" || name == "settings.json") && parent == ".vscode" {
		return true
	}
	if g.I.IsPropagation(name) || g.I.IsFontName(name) {
		return true
	}
	ext := strings.ToLower(filepath.Ext(p))
	_, asset := h.AssetMagic[ext]
	return h.ScriptExt[ext] || asset || h.TextAssetExt[ext]
}

func (g *Guard) SkipDir(name string) bool {
	if g.Cfg.Deep && (name == "node_modules" || name == "vendor") {
		return false
	}
	return h.SkipDir(name)
}

// OnEvents scans files reported by the watcher.
func (g *Guard) OnEvents(paths []string) {
	r := scan.NewRepo(g.P.Home, g.UI, g.I)
	r.Deep, r.Exclude = g.Cfg.Deep, g.Cfg.Exclude
	var fs []*F
	n := 0
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() > 8<<20 || !g.interesting(p) {
			continue
		}
		n++
		fs = append(fs, r.ScanFile(p)...)
		g.mu.Lock()
		g.mtimes[p] = st.ModTime()
		g.mu.Unlock()
	}
	if len(fs) > 0 {
		g.Log(fmt.Sprintf("realtime: %d file(s) scanned, %d finding(s)", n, len(fs)))
	}
	g.Handle(fs, "realtime")
}

// ── passes ───────────────────────────────────────────────────────────────────

func (g *Guard) QuickPass() {
	g.heartbeat("quick", nil)
	s := &scan.System{P: g.P, UI: g.UI, I: g.I}
	fs := s.Quick()
	g.mu.Lock()
	tracked := append([]string{}, g.tracked...)
	g.mu.Unlock()
	var changed []string
	for _, p := range tracked {
		st, err := os.Stat(p)
		g.mu.Lock()
		if err != nil {
			delete(g.mtimes, p)
		} else if !g.mtimes[p].Equal(st.ModTime()) {
			g.mtimes[p] = st.ModTime()
			changed = append(changed, p)
		}
		g.mu.Unlock()
	}
	if len(changed) > 0 {
		r := scan.NewRepo(g.P.Home, g.UI, g.I)
		r.Deep, r.Exclude = g.Cfg.Deep, g.Cfg.Exclude
		for _, p := range changed {
			fs = append(fs, r.ScanFile(p)...)
		}
		g.Log(fmt.Sprintf("quick pass: %d changed file(s) rescanned", len(changed)))
	}
	g.Handle(fs, "guard-quick")
}

func (g *Guard) FullPass() {
	g.heartbeat("full", nil)
	start := time.Now()
	var all []*F
	var repos []string
	total, infected, files := 0, 0, 0
	roots := g.roots()
	for _, root := range roots {
		r := scan.NewRepo(root, g.UI, g.I)
		r.JSAll, r.Deep, r.Exclude = g.Cfg.JSAll, g.Cfg.Deep, g.Cfg.Exclude
		rp, pj := r.Discover()
		fs, t, inf := r.ScanAll(rp, pj)
		all = append(all, fs...)
		repos = append(append(repos, rp...), pj...)
		total, infected, files = total+t, infected+inf, files+r.FilesChecked
	}
	g.setTargets(repos)
	s := &scan.System{P: g.P, UI: g.UI, I: g.I}
	all = append(all, s.ScanAll(infected > 0)...)
	g.Handle(all, "guard-full")
	st := &findings.Stats{ReposScanned: total, ReposInfected: infected, FilesChecked: files,
		ScanDuration: time.Since(start).Seconds(), PlatformName: g.P.DisplayName(), ScanDirs: append([]string{}, roots...),
		StartTime: start.Format("2006-01-02 15:04:05"), Hostname: g.P.Hostname}
	st.Count(all)
	_, _ = report.Save(g.DataDir, report.New(g.Version, g.I.Version, st, all), g.Cfg.ReportKeep, "guard")
	g.lastFull = time.Now()
	g.Log(fmt.Sprintf("full pass: %d repos, %d infected, %d critical, %d high in %.1fs",
		total, infected, st.Critical, st.High, st.ScanDuration))
	g.heartbeat("idle", map[string]int{"repos": total, "infected": infected, "critical": st.Critical, "high": st.High})
}

func (g *Guard) lastIOCCheck() time.Time {
	b, err := os.ReadFile(filepath.Join(g.DataDir, "ioc-last-check"))
	if err != nil {
		return time.Time{}
	}
	var sec float64
	fmt.Sscan(strings.TrimSpace(string(b)), &sec)
	return time.Unix(int64(sec), 0)
}

func (g *Guard) maybeUpdateIOCs() {
	if !g.Cfg.IOCUpdate || g.Hooks.UpdateIOCs == nil {
		return
	}
	if time.Since(g.lastIOCCheck()) < time.Duration(g.Cfg.IOCUpdateInterval)*time.Second {
		return
	}
	updated, msg := g.Hooks.UpdateIOCs(g.DataDir, g.I.Version, g.Cfg)
	g.Log("ioc update: " + msg)
	if updated {
		if i, err := iocs.Load(g.DataDir); err == nil {
			g.I = i
			g.Prot.I = i
		}
	}
}

func (g *Guard) startRealtime() {
	if !g.Cfg.Realtime || g.Hooks.StartRealtime == nil || g.stopWatch != nil {
		return
	}
	roots := g.roots()
	if len(roots) == 0 {
		return
	}
	g.backend, g.stopWatch = g.Hooks.StartRealtime(roots, g.SkipDir, g.OnEvents, g.Log)
}

// Stop ends Run (used by signals and tests).
func (g *Guard) Stop() { g.stopOnce.Do(func() { close(g.stop) }) }

func (g *Guard) safely(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			g.Log(fmt.Sprintf("%s error: %v\n%s", name, r, debug.Stack()))
		}
	}()
	fn()
}

// Run is the main loop.
func (g *Guard) Run() int {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		select {
		case <-sig:
			g.Stop()
		case <-g.stop:
		}
	}()
	g.Log(fmt.Sprintf("guard v%s starting (iocs %s, action=%s, auto_kill=%v, prompt=%v, deep=%v, dry_run=%v)",
		g.Version, g.I.Version, g.Cfg.Action, g.Cfg.AutoKill, g.Cfg.Prompt, g.Cfg.Deep, g.DryRun))
	g.startDialogWorker()
	defer func() {
		close(g.dialogs)
		g.dialogWG.Wait()
	}()
	g.safely("ioc update", g.maybeUpdateIOCs)
	g.safely("full pass", g.FullPass)
	if g.Once {
		return 0
	}
	g.safely("realtime start", g.startRealtime)
	quick := time.Duration(g.Cfg.QuickInterval) * time.Second
	minQuick := 2 * time.Second
	if g.P.IsWindows() {
		minQuick = 15 * time.Second
	}
	if quick < minQuick {
		quick = minQuick
	}
	last := map[string]time.Time{}
	tick := time.NewTicker(quick)
	defer tick.Stop()
	for {
		select {
		case <-g.stop:
			if g.stopWatch != nil {
				g.stopWatch()
			}
			g.Log("guard stopped")
			return 0
		case <-tick.C:
			if time.Since(g.lastFull) >= time.Duration(g.Cfg.FullInterval)*time.Second {
				g.safely("ioc update", g.maybeUpdateIOCs)
				g.safely("full pass", g.FullPass)
			} else {
				g.safely("quick pass", g.QuickPass)
			}
			for _, t := range g.Hooks.Periodic {
				if iv := t.Interval(g.Cfg); iv > 0 && time.Since(last[t.Name]) >= iv {
					last[t.Name] = time.Now()
					g.safely(t.Name, func() { t.Run(g) })
				}
			}
		}
	}
}
