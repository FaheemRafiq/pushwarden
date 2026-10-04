package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
	"github.com/FaheemRafiq/pushwarden/internal/harden"
	"github.com/FaheemRafiq/pushwarden/internal/iocs"
	"github.com/FaheemRafiq/pushwarden/internal/journal"
	"github.com/FaheemRafiq/pushwarden/internal/platform"
	"github.com/FaheemRafiq/pushwarden/internal/prompt"
	"github.com/FaheemRafiq/pushwarden/internal/protect"
	"github.com/FaheemRafiq/pushwarden/internal/report"
	"github.com/FaheemRafiq/pushwarden/internal/ui"
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
	fs := newFlags("history", "[filters] [--all] [--details] | --restore PATH | --allow PATH [--note TEXT] | --remove PATH")
	restore := fs.String("restore", "", "put the original back (it is still malicious)")
	allow := fs.String("allow", "", "restore and stop flagging this exact file content")
	remove := fs.String("remove", "", "delete the quarantined copies permanently")
	limit := fs.Int("limit", 50, "number of entries to show")
	details := fs.Bool("details", false, "show the evidence behind each entry")
	asJSON := fs.Bool("json", false, "print the raw entries as JSON")
	all := fs.Bool("all", false, "every recorded event in time order, nothing collapsed")
	sev := fs.String("severity", "", "only findings at this `LEVEL` or above (warning, high, critical)")
	var kinds stringList
	fs.Var(&kinds, "kind", "only this `KIND`: finding, action, decision, sweep, guard, update, error, feedback (repeatable)")
	since := fs.String("since", "", "only events newer than `WHEN`: 30m, 24h, 7d, 2w or a date")
	pathSub := fs.String("path", "", "only events whose path, title or command contains `TEXT`")
	archive := fs.Bool("archive", false, "also read the rotated journal archives")
	notUp := fs.Bool("not-uploaded", false, "only events still waiting to be uploaded to upload_url (implies --all --archive)")
	note := fs.String("note", "", "with --allow: why this is a false positive (recorded as feedback)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	pr := protect.New(c.P, c.I, c.DataDir, u, false)
	jr := openJournal(c)
	pr.AttachJournal(jr, "cli")
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
		jr.Write(journal.Event{Ctx: "cli", Kind: journal.KindFeedback, Title: "marked as a false positive", Path: *allow, Note: *note})
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
	if journal.Exists(c.DataDir) {
		f := journal.Filter{Kinds: kinds, PathSubstr: *pathSub, Archives: *archive || *notUp}
		if *sev != "" {
			f.MinSeverity = findings.ParseSeverity(strings.ToUpper(*sev))
			if len(f.Kinds) == 0 {
				f.Kinds = []string{journal.KindFinding}
			}
		}
		t, err := parseSince(*since, time.Now())
		if err != nil {
			u.Err(err.Error())
			return 2
		}
		f.Since = t
		evs := journal.Read(c.DataDir, f)
		if c.Cfg.UploadURL != "" {
			// each event carries whether it is stored at upload_url
			newUploader(c.DataDir, c.Cfg, c.P.Home, c.P.Hostname, c.P.OS).Mark(evs)
		}
		if *notUp {
			if c.Cfg.UploadURL == "" {
				u.Err("upload_url is not set, so nothing is uploaded from this machine. See: pushwarden help feedback")
				return 2
			}
			kept := evs[:0]
			for _, e := range evs {
				if e.Uploaded != nil && !*e.Uploaded {
					kept = append(kept, e)
				}
			}
			evs, *all = kept, true
		}
		switch {
		case *asJSON:
			b, _ := json.MarshalIndent(tail(evs, *limit), "", "  ")
			fmt.Println(string(b))
		case len(evs) == 0:
			u.Info("Nothing recorded for this selection.")
		case *all || len(kinds) > 0:
			fmt.Print(formatJournalAll(evs, *limit, *details))
		default:
			fmt.Print(formatJournal(evs, *limit, *details))
		}
		return 0
	}
	// no journal on this machine (disabled, or nothing recorded yet): the action history
	es := pr.Entries()
	if len(es) > *limit {
		es = es[len(es)-*limit:]
	}
	if *asJSON {
		b, _ := json.MarshalIndent(es, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	if len(es) == 0 {
		u.Info("Protection history is empty.")
		return 0
	}
	fmt.Print(formatHistory(es, *details))
	return 0
}

// formatHistory renders history entries: one row each plus the reason for the
// response; --details adds the evidence and, for kills, the command line.
func formatHistory(es []protect.Entry, details bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %-19s %-11s %-38s %s\n", "when", "action", "threat", "path")
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
		if e.OK != nil && !*e.OK {
			extra += "  [failed]"
		}
		if e.DryRun {
			extra += "  [dry-run]"
		}
		if len(label) > 38 {
			label = label[:38]
		}
		fmt.Fprintf(&b, "  %-19s %-11s %-38s %s%s\n", e.TS, e.Type, label, target, extra)
		why := e.Reason
		if why == "" && len(e.Evidence) > 0 {
			why = e.Evidence[0]
		}
		if why != "" {
			fmt.Fprintf(&b, "      why: %s\n", why)
		}
		if details {
			if e.Title != "" && e.Title != label {
				fmt.Fprintf(&b, "      finding: %s\n", e.Title)
			}
			for _, ev := range e.Evidence {
				fmt.Fprintf(&b, "      - %s\n", ev)
			}
			if e.Cmd != "" {
				fmt.Fprintf(&b, "      cmd: %s\n", e.Cmd)
			}
			if e.Copy != "" {
				fmt.Fprintf(&b, "      copy: %s\n", e.Copy)
			}
		}
	}
	b.WriteString("\n  pushwarden history --details | --restore <path> | --allow <path> | --remove <path>\n")
	return b.String()
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
	fs := newFlags("protect", "[--install | --refresh | --uninstall | --status | --block-c2 | --unblock] [--dry-run]")
	install := fs.Bool("install", false, "block now and keep it blocked: boot-time job + daily refresh (default when no other option is given)")
	refresh := fs.Bool("refresh", false, "re-apply the block from the root-owned indicators and fetch newer ones (what the job runs)")
	uninstall := fs.Bool("uninstall", false, "remove the job, the firewall rules and the hosts entries")
	once := fs.Bool("block-c2", false, "one-shot block for this boot only (no job)")
	unblock := fs.Bool("unblock", false, "remove the firewall rules and hosts entries (keeps the job, if any)")
	status := fs.Bool("status", false, "show whether blocking is active and persistent")
	dry := fs.Bool("dry-run", false, "show what --install would do")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	u := ui.New(false, false)
	p := platform.New()
	// The privileged paths never read the user's data dir: a user-writable
	// iocs.json or config must not drive a hosts-file edit as root.
	nb := &protect.NetBlocker{P: p, UI: u}
	nb.I, _ = iocs.Load("")
	switch {
	case *status:
		u.Info("Firewall: " + nb.Describe())
		return 0
	case *dry:
		for _, l := range strings.Split(nb.PreviewInstall(), "\n") {
			u.Info("[dry-run] " + l)
		}
		return 0
	case *refresh:
		if !platform.IsAdmin() {
			u.Err("protect --refresh needs root/Administrator (it is what the scheduled job runs)")
			return 2
		}
		ok, msg := nb.Refresh()
		say(u, ok, msg)
		return rcOf(ok)
	case *uninstall:
		if !platform.IsAdmin() {
			return elevateOrHint(u, p, []string{"protect", "--uninstall"})
		}
		ok, msg := nb.UninstallPersistent()
		say(u, ok, msg)
		return rcOf(ok)
	case *unblock:
		if !platform.IsAdmin() {
			return elevateOrHint(u, p, []string{"protect", "--unblock"})
		}
		nb.UnblockIPs()
		nb.UnsinkholeHosts()
		return 0
	case *once:
		if !platform.IsAdmin() {
			return elevateOrHint(u, p, []string{"protect", "--block-c2"})
		}
		ok1, ok2 := nb.BlockIPs(), nb.SinkholeHosts()
		return rcOf(ok1 || ok2)
	}
	_ = install
	if !platform.IsAdmin() {
		return elevateOrHint(u, p, []string{"protect", "--install"})
	}
	ok, msg := nb.InstallPersistent()
	say(u, ok, msg)
	return rcOf(ok)
}

func say(u *ui.UI, ok bool, msg string) {
	if ok {
		u.OK(msg)
	} else {
		u.Err(msg)
	}
}

func rcOf(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

// elevateOrHint asks the OS for administrator rights and re-runs this program
// with args; when that is impossible it prints the command to run by hand.
func elevateOrHint(u *ui.UI, p *platform.Info, args []string) int {
	exe := platform.Exe()
	u.Info("Asking for administrator rights to " + strings.Join(args, " ") + "...")
	rc, how := protect.Elevate(p, exe, args, !isTTY())
	if rc == 0 {
		u.OK("done (via " + how + ")")
		nb := &protect.NetBlocker{P: p}
		u.Info("Firewall: " + nb.Describe())
		return 0
	}
	u.Warn(how)
	switch {
	case p.IsWindows():
		u.Info("Run in an elevated terminal:  pushwarden " + strings.Join(args, " "))
	default:
		u.Info("Run:  sudo pushwarden " + strings.Join(args, " "))
	}
	return 2
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
	h := readHealth(c)
	cs := h.checks()
	for _, l := range append(statusHeader(u, h, cs), statusChecks(u, cs)...) {
		fmt.Println(l)
	}
	fmt.Println("\n  " + u.C("BOLD", "DETAILS"))
	rows := [][2]string{
		{"Indicators", c.I.Version + " (" + c.I.Source + ")"},
		{"Action / auto-kill / prompt", fmt.Sprintf("%s / %v / %v", c.Cfg.Action, c.Cfg.AutoKill, c.Cfg.Prompt)},
		{"Webhook", map[bool]string{true: "configured", false: "none"}[c.Cfg.WebhookURL != ""]},
		{"Event upload", uploadSummary(newUploader(c.DataDir, c.Cfg, c.P.Home, c.P.Hostname, c.P.OS))},
		{"Firewall", (&protect.NetBlocker{P: c.P, I: c.I}).Describe()},
		{"Data dir", c.DataDir},
		{"Disk use", diskSummary(c)},
	}
	rows = append(statusServiceRows(c), rows...)
	for _, r := range rows {
		fmt.Printf("    %s %s\n", u.C("BOLD_CYAN", fmt.Sprintf("%-28s", r[0]+":")), r[1])
	}
	if rep, err := report.Latest(c.DataDir); err == nil && rep.Stats != nil {
		s := rep.Stats
		fmt.Printf("\n  %s (%s): %d repos, %d critical, %d high, %d warning\n", u.C("BOLD", "LATEST SWEEP"), rep.Generated, s.ReposScanned, s.Critical, s.High, s.Warning)
		for _, f := range rep.Findings {
			if f.Severity >= findings.High {
				fmt.Printf("    [%s] %s  %s  %s\n", f.Severity, f.Title, f.Path, f.Action)
			}
		}
	}
	fmt.Println("\n  " + u.C("BOLD", "EDITOR HARDENING"))
	for _, l := range sortedKeys(h.editors) {
		mark := u.C("BOLD_RED", "!!")
		if h.editors[l] == "off" {
			mark = u.C("BOLD_GREEN", "OK")
		}
		fmt.Printf("    %s  %-18s task.allowAutomaticTasks = %s\n", mark, l, h.editors[l])
	}
	fmt.Println()
	return 0
}

// statusServiceRows is extended in P2/P4 (guard heartbeat, login service).
var statusServiceRows = func(c *ctx) [][2]string {
	return [][2]string{{"Guard", "not available in this build"}}
}
