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
	_ = fs.Bool("block-c2", true, "kept for compatibility: C2 blocking is on by default")
	noBlock := fs.Bool("no-block-c2", false, "do not ask for administrator rights to block the C2 servers")
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
	if *noBlock {
		c.Cfg.BlockC2, changed = false, true
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

	// Interactive installs scan first, in the foreground, so the guard that
	// starts next finds a fresh report and skips a duplicate sweep.
	if !*unattended && !*dry {
		u.Section("FIRST SCAN")
		u.Info("Running the first full scan now (this may take a few minutes)...")
		runScan(c, scanOpts{home: true, deep: c.Cfg.Deep, gui: !isTTY(), notify: true})
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
	if c.P.IsMac() {
		// notifications posted by this applet open `threatscan alerts --gui` when clicked
		if msg, err := notify.InstallMacNotifier(c.P, c.P.InstallDir(), m.Exe(), *dry); err != nil {
			u.Warn("Notification helper not built (" + err.Error() + "); clicking a notification will not show details")
		} else {
			u.OK("Notification helper: " + msg)
		}
	}

	if c.Cfg.BlockC2 && !protect.ElevationDisabled() {
		u.Section("NETWORK BLOCKING")
		installBlock(u, c, m.Exe(), *dry, *unattended)
	} else if c.Cfg.BlockC2 {
		u.Info("C2 blocking left to the package installer (" + protect.NoBlockEnv + " is set)")
	}

	switch {
	case *unattended && !*dry && ok:
		// the guard's start-up sweep is the first scan; a second process would
		// race it and double every quarantine and alert
		u.Section("FIRST SCAN")
		u.Info("The guard is running the first full scan now; results: threatscan status")
		notify.New(c.P, c.Cfg, c.DataDir).Desktop("ThreatScan", "ThreatScan is protecting this computer")
	case *unattended && !*dry:
		u.Section("FIRST SCAN")
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
	case *dry:
		u.Section("FIRST SCAN")
		u.Info("[dry-run] report-only scan; nothing is written")
		runScan(c, scanOpts{home: true, deep: c.Cfg.Deep, gui: !isTTY(), noPrompt: true, noReport: true})
	}
	u.Info("Status any time:  threatscan status      Logs: " + m.Log)
	if ok {
		return 0
	}
	return 1
}

// installBlock makes the C2 firewall/hosts block persistent, asking the OS for
// administrator rights when needed. It never changes the install exit code.
func installBlock(u *ui.UI, c *ctx, exe string, dry, unattended bool) {
	nb := &protect.NetBlocker{P: c.P, UI: u}
	if strings.HasPrefix(nb.Describe(), "active (persistent") && !dry {
		u.OK("Firewall: " + nb.Describe())
		return
	}
	switch {
	case dry:
		for _, l := range strings.Split(nb.PreviewInstall(), "\n") {
			u.Info("[dry-run] " + l)
		}
		return
	case platform.IsAdmin():
		ok, msg := nb.InstallPersistent()
		say(u, ok, msg)
		return
	}
	if _, err := os.Stat(exe); err != nil {
		exe = platform.Exe()
	}
	u.Info("The PolinRider command servers are blocked system-wide at the firewall; this needs administrator rights once.")
	if !unattended && isTTY() {
		fmt.Print("  Block them now? [Y/n] ")
		var ans string
		fmt.Scanln(&ans)
		if a := strings.ToLower(strings.TrimSpace(ans)); a == "n" || a == "no" {
			u.Info("Skipped. Later:  threatscan protect --install     Opt out for good:  threatscan config --set block_c2=false")
			return
		}
	}
	rc, how := protect.Elevate(c.P, exe, []string{"protect", "--install"}, unattended || !isTTY())
	if rc == 0 {
		u.OK("Firewall: " + nb.Describe())
		return
	}
	u.Warn("C2 blocking not enabled (" + how + ")")
	if c.P.IsWindows() {
		u.Info("Later, from an elevated terminal:  threatscan protect --install")
	} else {
		u.Info("Later:  sudo threatscan protect --install")
	}
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
	if c.P.IsMac() {
		notify.RemoveMacNotifier(c.P.InstallDir())
	}
	if *unblock {
		if platform.IsAdmin() {
			nb := &protect.NetBlocker{P: c.P, I: c.I, UI: u}
			nb.UninstallPersistent()
		} else if rc, how := protect.Elevate(c.P, platform.Exe(), []string{"protect", "--uninstall"}, !isTTY()); rc != 0 {
			u.Warn("Could not remove the C2 block (" + how + "). Run:  sudo threatscan protect --uninstall")
		} else {
			u.OK("C2 block removed")
		}
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
