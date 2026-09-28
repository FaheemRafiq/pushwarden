package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/FaheemRafiq/threatscan/internal/helpers"
	"github.com/FaheemRafiq/threatscan/internal/notify"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/service"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func init() {
	register("install", "install the background guard (starts at sign-in) and harden editors", cmdInstall)
	register("uninstall", "remove the background guard", cmdUninstall)
	prev := statusServiceRows
	statusServiceRows = func(c *ctx) [][2]string {
		m := service.New(c.P, c.DataDir)
		bin := "not installed (" + m.Exe() + ")"
		if _, err := os.Stat(m.Exe()); err == nil {
			bin = m.Exe()
			if self := platform.Exe(); self != "" && self != m.Exe() {
				bin += "  (this command runs " + self + ")"
			}
		}
		add := [][2]string{{"Service", m.Status()}, {"Binary", bin}}
		rows := prev(c)
		for i, r := range rows {
			if r[0] == "Guard" {
				return append(append(append([][2]string{}, rows[:i+1]...), add...), rows[i+1:]...)
			}
		}
		return append(add, rows...)
	}
}

func cmdInstall(args []string) int {
	fs := newFlags("install", "[options]")
	var roots stringList
	fs.Var(&roots, "roots", "project `DIR` to watch (repeatable; default: auto-discover)")
	webhook := fs.String("webhook", "", "`URL` that receives JSON alerts (Slack/Discord/Teams/custom)")
	noKill := fs.Bool("no-kill", false, "never kill processes automatically")
	noClean := fs.Bool("no-clean", false, "when no dialog can be shown, leave files in place instead of quarantining")
	noPrompt := fs.Bool("no-prompt", false, "never show dialogs; rely on auto-clean (quarantine) only")
	deep := fs.Bool("deep", false, "guard also scans node_modules / vendor (slow)")
	noHarden := fs.Bool("no-harden", false, "skip editor hardening")
	npm := fs.Bool("npm-ignore-scripts", false, "also set ignore-scripts=true in ~/.npmrc")
	blockC2 := fs.Bool("block-c2", false, "also add firewall + hosts blocks (needs admin)")
	fullInterval := fs.Int("full-interval", 0, "seconds between full sweeps (default 21600)")
	dry := fs.Bool("dry-run", false, "show what would be done; change nothing")
	unattended := fs.Bool("unattended", false, "for installers: no questions, first scan in the background")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	roots = append(roots, pos...) // allow: install --roots a b
	c := mustCtx()
	u := ui.New(false, false)
	u.Banner(version, c.I.Version)

	changed := false
	if len(roots) > 0 {
		c.Cfg.ScanRoots = nil
		for _, r := range roots {
			c.Cfg.ScanRoots = append(c.Cfg.ScanRoots, helpers.Expand(r))
		}
		changed = true
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "webhook" {
			c.Cfg.WebhookURL, changed = *webhook, true
		}
	})
	if *noKill {
		c.Cfg.AutoKill, changed = false, true
	}
	if *noClean {
		c.Cfg.AutoClean, changed = false, true
	}
	if *noPrompt {
		c.Cfg.Prompt, changed = false, true
	}
	if *deep {
		c.Cfg.Deep, changed = true, true
	}
	if *fullInterval > 0 {
		c.Cfg.FullInterval, changed = *fullInterval, true
	}
	if *dry {
		u.Info("[dry-run] config would be saved to " + c.DataDir + string(os.PathSeparator) + "config.json")
	} else if p, err := c.Cfg.Save(c.DataDir); err != nil {
		u.Err("Could not save config: " + err.Error())
	} else {
		u.Info("Config: " + p + map[bool]string{true: " (updated)", false: ""}[changed])
	}
	rs := c.Cfg.Roots(c.P.CommonProjectDirs)
	sweep := strings.Join(rs, ", ")
	if sweep == "" {
		sweep = "(no project dirs found; set with --roots)"
	}
	u.Info("Guard will sweep: " + sweep)

	if !*noHarden {
		u.Section("HARDENING")
		doHarden(c.P, u, *npm, *dry)
	}

	u.Section("BACKGROUND GUARD")
	m := service.New(c.P, c.DataDir)
	m.Version = version
	ok := true
	if *dry {
		for _, l := range strings.Split(strings.TrimRight(m.Preview(), "\n"), "\n") {
			fmt.Println("    " + l)
		}
		if msg := m.LinkCLI(true); msg != "" {
			u.Info(msg)
		}
	} else {
		var msg string
		ok, msg = m.Install()
		for _, l := range strings.Split(msg, "\n") {
			if ok {
				u.OK(l)
			} else {
				u.Err(l)
			}
		}
		if !ok {
			u.Warn("You can still run the guard in a terminal:  threatscan guard")
		}
		if msg := m.LinkCLI(false); msg != "" {
			u.Info(msg)
		}
	}

	if *blockC2 {
		u.Section("NETWORK BLOCKING")
		if platform.IsAdmin() && !*dry {
			nb := &protect.NetBlocker{P: c.P, I: c.I, UI: u}
			nb.BlockIPs()
			nb.SinkholeHosts()
		} else if *dry {
			u.Info("[dry-run] would block C2 IPs and sinkhole C2 hostnames")
		} else {
			u.Warn("Not running as root/Administrator; skip. Later:  sudo threatscan protect --block-c2")
		}
	}

	u.Section("FIRST SCAN")
	switch {
	case *unattended && !*dry:
		exe := m.Exe()
		if _, err := os.Stat(exe); err != nil {
			exe = platform.Exe()
		}
		cmd := exec.Command(exe, "scan", "--home", "--fix", "--notify")
		platform.Detach(cmd)
		if err := cmd.Start(); err != nil {
			u.Warn("Could not start the first scan: " + err.Error())
		} else {
			u.Info(fmt.Sprintf("First scan running in the background (pid %d); results: threatscan status", cmd.Process.Pid))
			_ = cmd.Process.Release()
		}
		if ok {
			notify.New(c.P, c.Cfg, c.DataDir).Desktop("ThreatScan", "ThreatScan is protecting this computer")
		}
	default:
		u.Info("Running the first full scan now (this may take a minute)...")
		// dry run: report only, so nothing is written (no report, no protection history)
		runScan(c, scanOpts{home: true, deep: c.Cfg.Deep, gui: !isTTY(), noPrompt: *dry, noReport: *dry, notify: !*dry})
	}
	u.Info("Status any time:  threatscan status      Logs: " + m.Log)
	if ok {
		return 0
	}
	return 1
}

func cmdUninstall(args []string) int {
	fs := newFlags("uninstall", "[--unblock] [--purge]")
	unblock := fs.Bool("unblock", false, "also remove firewall/hosts blocks")
	purge := fs.Bool("purge", false, "also delete ~/.threatscan (config, reports, quarantine)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	m := service.New(c.P, c.DataDir)
	ok, msg := m.Uninstall()
	if ok {
		u.OK(msg)
	} else {
		u.Err(msg)
	}
	m.UnlinkCLI()
	if *unblock {
		nb := &protect.NetBlocker{P: c.P, I: c.I, UI: u}
		nb.UnblockIPs()
		nb.UnsinkholeHosts()
	}
	if *purge {
		if err := os.RemoveAll(c.DataDir); err != nil {
			u.Err("Could not remove " + c.DataDir + ": " + err.Error())
		} else {
			u.OK("Removed " + c.DataDir + " (config, reports, quarantine)")
		}
	} else {
		u.Info("Kept " + c.DataDir + " (quarantine, reports). Remove with --purge.")
	}
	if ok {
		return 0
	}
	return 1
}
