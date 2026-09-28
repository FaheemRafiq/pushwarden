package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/harden"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/report"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func init() {
	register("status", "protection status, hardening and the latest report", cmdStatus)
	register("history", "protection history: restore, allow or remove quarantined files", cmdHistory)
	register("restore", "put a quarantined file back (alias for history --restore)", cmdRestore)
	register("harden", "apply preventive editor/npm settings", cmdHarden)
	register("protect", "block C2 IPs and hostnames (needs admin)", cmdProtect)
	register("config", "show or change settings", cmdConfig)
}

func cmdHistory(args []string) int {
	fs := newFlags("history", "[--restore PATH | --allow PATH | --remove PATH]")
	restore := fs.String("restore", "", "put the original back (it is still malicious)")
	allow := fs.String("allow", "", "restore and stop flagging this exact file content")
	remove := fs.String("remove", "", "delete the quarantined copies permanently")
	limit := fs.Int("limit", 50, "number of entries to show")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	pr := protect.New(c.P, c.I, c.DataDir, u, false)
	switch {
	case *restore != "":
		if pr.Restore(*restore) {
			u.OK("Restored " + *restore + ". It is malicious as far as the scanner knows: re-scan before use.")
			return 0
		}
		u.Err("No quarantine entry for " + *restore)
		return 1
	case *allow != "":
		if !pr.Restore(*allow) {
			u.Err("No quarantine entry for " + *allow)
			return 1
		}
		pr.Remember(*allow, "allowed by user", prompt.Keep)
		u.OK("Restored and allowed " + *allow + " (this exact content will not be flagged again for 30 days)")
		return 0
	case *remove != "":
		n := pr.Purge(*remove)
		if n == 0 {
			u.Err("No quarantined copy of " + *remove)
			return 1
		}
		u.OK(fmt.Sprintf("Removed %d quarantined cop%s of %s", n, map[bool]string{true: "y", false: "ies"}[n == 1], *remove))
		return 0
	}
	es := pr.Entries()
	if len(es) == 0 {
		u.Info("Protection history is empty.")
		return 0
	}
	fmt.Printf("  %-19s %-11s %-38s %s\n", "when", "action", "threat", "path")
	if len(es) > *limit {
		es = es[len(es)-*limit:]
	}
	for _, e := range es {
		label := e.Threat
		if label == "" {
			label = e.Title
		}
		target := e.Original
		switch {
		case target == "" && e.PID > 0:
			target = "pid " + strconv.Itoa(e.PID)
		case target == "" && e.Name != "":
			target = e.Name
		case target == "":
			target = e.Line
		}
		extra := ""
		if e.RemovedBytes > 0 {
			extra = fmt.Sprintf("  (%d bytes stripped)", e.RemovedBytes)
		}
		if e.DryRun {
			extra += "  [dry-run]"
		}
		if len(label) > 38 {
			label = label[:38]
		}
		fmt.Printf("  %-19s %-11s %-38s %s%s\n", e.TS, e.Type, label, target, extra)
	}
	fmt.Println("\n  threatscan history --restore <path> | --allow <path> | --remove <path>")
	return 0
}

func cmdRestore(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return cmdHistory(nil)
	}
	return cmdHistory([]string{"--restore", args[0]})
}

func cmdHarden(args []string) int {
	fs := newFlags("harden", "[options]")
	npm := fs.Bool("npm-ignore-scripts", false, "also set ignore-scripts=true in ~/.npmrc")
	undoNPM := fs.Bool("undo-npm", false, "remove ignore-scripts=true from ~/.npmrc")
	dry := fs.Bool("dry-run", false, "show what would change")
	var hooks stringList
	fs.Var(&hooks, "pre-commit", "install a pre-commit hook in `REPO` (repeatable)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	if *undoNPM {
		if harden.UndoNPM(c.P.Home) {
			u.OK("npm ignore-scripts removed")
		} else {
			u.Info("npm ignore-scripts was not set")
		}
		return 0
	}
	doHarden(c.P, u, *npm, *dry)
	for _, r := range hooks {
		ok, msg := harden.PreCommit(r, *dry)
		if ok {
			u.OK(r + ": " + msg)
		} else {
			u.Warn(r + ": " + msg)
		}
	}
	return 0
}

func doHarden(p *platform.Info, u *ui.UI, npm, dry bool) {
	eds := p.EditorSettings()
	if len(eds) == 0 {
		u.Info("No VS Code-family editor found (VS Code, Cursor, VSCodium, Windsurf).")
	}
	labels := make([]string, 0, len(eds))
	for l := range eds {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		changed, notes, err := harden.Editor(eds[l], dry)
		switch {
		case err != nil:
			u.Warn(l + ": " + err.Error())
		case changed:
			verb := "updated"
			if dry {
				verb = "would update"
			}
			u.OK(l + ": " + verb + " " + eds[l])
			for _, n := range notes {
				u.Info("   " + n)
			}
		default:
			u.OK(l + ": already hardened")
		}
	}
	if npm {
		changed, msg := harden.NPM(p.Home, dry)
		if changed {
			u.OK("npm: " + msg)
		} else {
			u.Info("npm: " + msg)
		}
	} else {
		u.Info("npm: ignore-scripts not changed (opt in with --npm-ignore-scripts)")
	}
}

func cmdProtect(args []string) int {
	fs := newFlags("protect", "[--block-c2 | --unblock | --status]")
	_ = fs.Bool("block-c2", true, "block C2 IPs at the firewall and sinkhole C2 hostnames (default)")
	unblock := fs.Bool("unblock", false, "remove the firewall rules and hosts entries")
	status := fs.Bool("status", false, "show whether blocking is active")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	nb := &protect.NetBlocker{P: c.P, I: c.I, UI: u}
	switch {
	case *status:
		u.Info("Firewall: " + nb.Status())
		return 0
	case *unblock:
		nb.UnblockIPs()
		nb.UnsinkholeHosts()
		return 0
	}
	if !platform.IsAdmin() {
		u.Err("Network blocking needs root/Administrator.  Linux/macOS: sudo threatscan protect   Windows: run an elevated terminal.")
		return 2
	}
	ok1, ok2 := nb.BlockIPs(), nb.SinkholeHosts()
	if ok1 || ok2 {
		return 0
	}
	return 1
}

func cmdConfig(args []string) int {
	fs := newFlags("config", "[--set key=value ...]")
	var sets stringList
	fs.Var(&sets, "set", "set `key=value` (repeatable; lists are comma-separated)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	sets = append(sets, pos...) // allow: config --set a=1 b=2
	c := mustCtx()
	u := ui.New(false, false)
	if len(sets) > 0 {
		v := reflect.ValueOf(c.Cfg).Elem()
		t := v.Type()
		for _, kv := range sets {
			k, val, ok := strings.Cut(kv, "=")
			if !ok {
				u.Err("expected key=value, got " + kv)
				return 2
			}
			found := false
			for i := 0; i < t.NumField(); i++ {
				if strings.Split(t.Field(i).Tag.Get("json"), ",")[0] != k {
					continue
				}
				found = true
				fv := v.Field(i)
				switch fv.Kind() {
				case reflect.Bool:
					fv.SetBool(val == "1" || strings.EqualFold(val, "true") || val == "yes" || val == "on")
				case reflect.Int:
					n, err := strconv.Atoi(val)
					if err != nil {
						u.Err(k + ": not a number")
						return 2
					}
					fv.SetInt(int64(n))
				case reflect.Slice:
					var parts []string
					for _, p := range strings.Split(val, ",") {
						if p != "" {
							parts = append(parts, p)
						}
					}
					fv.Set(reflect.ValueOf(append([]string{}, parts...)))
				default:
					fv.SetString(val)
				}
			}
			if !found {
				u.Err("unknown key " + k)
				return 2
			}
		}
		if _, err := c.Cfg.Save(c.DataDir); err != nil {
			u.Err(err.Error())
			return 2
		}
		u.OK("config saved")
	}
	b, _ := json.MarshalIndent(c.Cfg, "", "  ")
	fmt.Println(string(b))
	return 0
}

func cmdStatus(args []string) int {
	c := mustCtx()
	u := ui.New(false, false)
	u.Banner(version, c.I.Version)
	rows := [][2]string{
		{"Indicators", c.I.Version + " (" + c.I.Source + ")"},
		{"Action / auto-kill / prompt", fmt.Sprintf("%s / %v / %v", c.Cfg.Action, c.Cfg.AutoKill, c.Cfg.Prompt)},
		{"Webhook", map[bool]string{true: "configured", false: "none"}[c.Cfg.WebhookURL != ""]},
		{"Firewall", (&protect.NetBlocker{P: c.P, I: c.I}).Status()},
		{"Data dir", c.DataDir},
	}
	rows = append(statusServiceRows(c), rows...)
	for _, r := range rows {
		fmt.Printf("  %-36s %s\n", u.C("BOLD_CYAN", r[0]+":"), r[1])
	}
	if rep, err := report.Latest(c.DataDir); err == nil && rep.Stats != nil {
		s := rep.Stats
		fmt.Printf("\n  Latest report (%s): %d repos, %d critical, %d high, %d warning\n", rep.Generated, s.ReposScanned, s.Critical, s.High, s.Warning)
		for _, f := range rep.Findings {
			if f.Severity >= findings.High {
				fmt.Printf("    [%s] %s  %s  %s\n", f.Severity, f.Title, f.Path, f.Action)
			}
		}
	}
	fmt.Println("\n  Editor hardening:")
	eds := c.P.EditorSettings()
	labels := make([]string, 0, len(eds))
	for l := range eds {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		v := harden.EditorStatus(eds[l])
		mark := "!! "
		if v == "off" {
			mark = "OK "
		}
		fmt.Printf("    %s%-18s task.allowAutomaticTasks = %s\n", mark, l, v)
	}
	return 0
}

// statusServiceRows is extended in P2/P4 (guard heartbeat, login service).
var statusServiceRows = func(c *ctx) [][2]string {
	return [][2]string{{"Guard", "not available in this build"}}
}
