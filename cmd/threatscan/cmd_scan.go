package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/notify"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/report"
	"github.com/FaheemRafiq/threatscan/internal/scan"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func init() {
	register("scan", "one-off scan of repos and this computer", cmdScan)
	register("check-staged", "pre-commit hook helper: scan staged files", cmdCheckStaged)
	register("version", "print the version", func([]string) int { fmt.Println("ThreatScan " + version); return 0 })
}

type scanOpts struct {
	dirs                                 []string
	home, verbose, noSystem, noRepos, ci bool
	configsOnly, deep, fix, dryRun, gui  bool
	noPrompt, notify, noReport           bool
	json                                 string
}

func cmdScan(args []string) int {
	var o scanOpts
	fs := newFlags("scan", "[options] [directories]")
	fs.BoolVar(&o.home, "home", false, "also scan common project dirs under your home folder")
	fs.BoolVar(&o.verbose, "verbose", false, "show every repo, including clean ones")
	fs.BoolVar(&o.noSystem, "no-system", false, "skip host checks")
	fs.BoolVar(&o.noRepos, "no-repos", false, "skip repository checks")
	fs.BoolVar(&o.ci, "ci", false, "CI mode: no colour, compact, never prompt")
	fs.BoolVar(&o.configsOnly, "configs-only", false, "only check known config/entry files (v4 scope)")
	jsAll := fs.Bool("js-all", false, "accepted for v4 compatibility (now the default)")
	fs.BoolVar(&o.deep, "deep", false, "also descend into node_modules / vendor")
	fs.BoolVar(&o.fix, "fix", false, "act on CRITICAL findings without asking (quarantine/strip, reversible)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "show what --fix would do")
	fs.BoolVar(&o.gui, "gui", false, "ask about each malicious file with a native dialog")
	fs.BoolVar(&o.noPrompt, "no-prompt", false, "report only; never ask, never change files")
	fs.BoolVar(&o.notify, "notify", false, "send a desktop/webhook alert on HIGH+")
	fs.BoolVar(&o.noReport, "no-report", false, "do not save a report under ~/.threatscan/reports")
	fs.StringVar(&o.json, "json", "", "write a JSON report to `FILE`")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	_ = jsAll
	o.dirs = pos
	return runScan(mustCtx(), o)
}

func runScan(c *ctx, o scanOpts) int {
	u := ui.New(o.ci, false)
	start := time.Now()
	dirs, err := absDirs(o.dirs)
	if err != nil {
		u.Err(err.Error())
		return 2
	}
	if o.home {
		for _, r := range c.Cfg.Roots(c.P.CommonProjectDirs) {
			dup := false
			for _, d := range dirs {
				dup = dup || d == r
			}
			if !dup {
				dirs = append(dirs, r)
			}
		}
	}
	if len(dirs) == 0 && !o.noRepos {
		wd, _ := os.Getwd()
		dirs = []string{wd}
	}
	if !o.ci {
		u.Banner(version, c.I.Version)
		u.P("  %s", u.C("BOLD", "System"))
		for _, kv := range [][2]string{{"Platform", c.P.DisplayName()}, {"Hostname", c.P.Hostname}, {"Arch", c.P.Arch},
			{"Scan dirs", strings.Join(dirs, ", ")}, {"Started", start.Format("2006-01-02 15:04:05")}} {
			u.P("    %-22s %s", u.C("BOLD_CYAN", kv[0]+":"), kv[1])
		}
	}
	var all []*findings.Finding
	total, infected, files := 0, 0, 0
	if !o.noRepos {
		u.Section("REPOSITORY SCAN")
		for _, d := range dirs {
			r := scan.NewRepo(d, u, c.I)
			r.JSAll, r.Deep, r.Verbose, r.Exclude = !o.configsOnly, o.deep, o.verbose, c.Cfg.Exclude
			fs, t, inf := r.ScanAll(nil, nil)
			all = append(all, fs...)
			total, infected, files = total+t, infected+inf, files+r.FilesChecked
		}
		if total > 0 && infected == 0 {
			u.OK(fmt.Sprintf("%d repositories scanned, none infected", total))
		}
	}
	if !o.noSystem {
		u.Section("SYSTEM SCAN")
		s := &scan.System{P: c.P, UI: u, I: c.I}
		sys := s.ScanAll(infected > 0)
		for _, f := range sys {
			if f.Severity >= findings.Warning || o.verbose {
				u.Finding(f)
			}
		}
		if !findings.AnyAtLeast(sys, findings.High) {
			u.OK("No malicious processes, C2 connections, or RAT persistence found")
		}
		all = append(all, sys...)
	}

	strong := false
	for _, f := range all {
		strong = strong || protect.NeedsDecision(f)
	}
	interactive := !o.ci && !o.noPrompt && !o.fix && (o.gui || isTTY())
	if o.fix || o.dryRun || (interactive && strong) {
		title := "RESPONSE"
		if o.dryRun {
			title += " (dry run)"
		}
		u.Section(title)
		pr := protect.New(c.P, c.I, c.DataDir, u, o.dryRun)
		var decide protect.DecideFn
		switch {
		case o.fix || o.dryRun:
		case o.gui:
			decide = func(f *findings.Finding, w string) prompt.Verdict {
				return prompt.Ask(f, w, time.Duration(c.Cfg.PromptTimeout)*time.Second)
			}
		default:
			decide = prompt.AskTerminal
		}
		acted := pr.Respond(all, c.Cfg.AutoKill, o.fix || o.dryRun, decide)
		for _, f := range all {
			if f.Action != "" {
				u.Finding(f)
			}
		}
		if len(acted) == 0 {
			u.Info("Nothing was changed.")
		} else {
			u.Info("Protection history: threatscan history   (undo: threatscan history --restore <path>)")
		}
	}

	st := &findings.Stats{ReposScanned: total, ReposInfected: infected, FilesChecked: files,
		ScanDuration: time.Since(start).Seconds(), PlatformName: c.P.DisplayName(), ScanDirs: dirs,
		StartTime: start.Format("2006-01-02 15:04:05"), Hostname: c.P.Hostname}
	if st.ScanDirs == nil {
		st.ScanDirs = []string{}
	}
	st.Count(all)
	u.Summary(st)
	if !o.ci {
		u.Remediation(all)
	}
	rep := report.New(version, c.I.Version, st, all)
	if o.json != "" {
		if err := rep.WriteFile(o.json); err != nil {
			u.Err("Could not write JSON: " + err.Error())
			return 2
		}
		u.Info("JSON report written to " + o.json)
	}
	if !o.noReport {
		_, _ = report.Save(c.DataDir, rep, c.Cfg.ReportKeep, "scan")
	}
	if o.notify && findings.AnyAtLeast(all, findings.High) {
		var alert []*findings.Finding
		for _, f := range all {
			if f.Severity >= findings.Warning {
				alert = append(alert, f)
			}
		}
		notify.New(c.P, c.Cfg, c.DataDir).Alert(alert, "scan")
	}
	switch {
	case st.Critical+st.High > 0:
		return 1
	case o.noSystem && total == 0:
		u.Err("Nothing was scanned: no git repositories or projects found.")
		return 2
	}
	return 0
}

func cmdCheckStaged(args []string) int {
	c := mustCtx()
	u := ui.New(true, false)
	out, err := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM").Output()
	if err != nil {
		return 0
	}
	wd, _ := os.Getwd()
	r := scan.NewRepo(wd, u, c.I)
	var bad []*findings.Finding
	for _, name := range strings.Split(string(out), "\n") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		for _, f := range r.ScanFile(name) {
			if f.Severity >= findings.High {
				bad = append(bad, f)
			}
		}
	}
	for _, f := range bad {
		u.Finding(f)
	}
	if len(bad) > 0 {
		u.Err("Commit blocked: PolinRider indicators in staged files.")
		return 1
	}
	return 0
}
