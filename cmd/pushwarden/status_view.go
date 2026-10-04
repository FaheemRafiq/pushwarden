package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/guard"
	"github.com/FaheemRafiq/pushwarden/internal/harden"
	"github.com/FaheemRafiq/pushwarden/internal/protect"
	"github.com/FaheemRafiq/pushwarden/internal/report"
	"github.com/FaheemRafiq/pushwarden/internal/service"
	"github.com/FaheemRafiq/pushwarden/internal/ui"
)

// health is what the protection score is worked out from.
type health struct {
	guardAlive   bool
	guardVersion string
	realtime     string            // watcher backend; "off" or "" = none
	service      string            // service.Manager.Status()
	firewall     string            // protect.NetBlocker.Describe()
	editors      map[string]string // editor -> task.allowAutomaticTasks
	iocVersion   string            // "2026.09.28.2"
	lastFull     time.Time         // zero = never
	repos        int
	haveReport   bool
	critical     int // in the latest full sweep
	high         int
	now          time.Time
}

// check is one line of the protection list: what is covered, how well, and
// what to run when it is not.
type check struct {
	name        string
	points, max int
	note        string
	fix         string
}

// checks scores every layer of protection. The weights add up to 100.
func (h health) checks() []check {
	var out []check
	add := func(name string, points, max int, note, fix string) {
		if points == max {
			fix = ""
		}
		out = append(out, check{name, points, max, note, fix})
	}

	if h.guardAlive {
		add("Background guard", 25, 25, "alive, v"+h.guardVersion, "")
	} else {
		add("Background guard", 0, 25, "not running", "pushwarden install")
	}

	switch {
	case !h.guardAlive:
		add("Real-time file protection", 0, 15, "needs the guard", "pushwarden install")
	case h.realtime == "" || h.realtime == "off":
		add("Real-time file protection", 0, 15, "off: files are only checked by the scheduled sweeps", "pushwarden install")
	case h.realtime == "polling":
		add("Real-time file protection", 8, 15, "polling: a new file is noticed with a delay", "pushwarden install")
	default:
		add("Real-time file protection", 15, 15, "every file is checked as it is written ("+h.realtime+")", "")
	}

	switch h.service {
	case "active", "running", "scheduled task registered", "startup launcher":
		add("Starts when you sign in", 10, 10, h.service, "")
	default:
		add("Starts when you sign in", 0, 10, h.service, "pushwarden install")
	}

	switch {
	case strings.HasPrefix(h.firewall, "active (persistent") && !strings.Contains(h.firewall, " - "):
		add("Malware servers blocked", 10, 10, "in the firewall, kept across restarts", "")
	case strings.HasPrefix(h.firewall, "active"):
		add("Malware servers blocked", 5, 10, "blocked now, but not reliably kept", "pushwarden protect --install")
	default:
		add("Malware servers blocked", 0, 10, "not blocked", "pushwarden protect --install")
	}

	hardened := 0
	for _, v := range h.editors {
		if v == "off" {
			hardened++
		}
	}
	switch {
	case len(h.editors) == 0:
		add("Editors cannot auto-run tasks", 10, 10, "no VS Code-family editor found", "")
	case hardened == len(h.editors):
		add("Editors cannot auto-run tasks", 10, 10, plural(hardened, "editor", "editors")+" hardened", "")
	default:
		add("Editors cannot auto-run tasks", 10*hardened/len(h.editors), 10,
			fmt.Sprintf("%d of %d editors hardened", hardened, len(h.editors)), "pushwarden harden")
	}

	if age, ok := iocAge(h.iocVersion, h.now); ok && age > 30*24*time.Hour {
		add("Indicators up to date", 2, 5, fmt.Sprintf("%s, %d days old", h.iocVersion, int(age.Hours()/24)), "pushwarden update-iocs")
	} else {
		add("Indicators up to date", 5, 5, h.iocVersion, "")
	}

	switch {
	case h.lastFull.IsZero():
		add("Recent full sweep", 0, 5, "never", "pushwarden scan --home")
	case h.now.Sub(h.lastFull) > 24*time.Hour:
		add("Recent full sweep", 0, 5, "last one "+h.lastFull.Format("2006-01-02 15:04"), "pushwarden scan --home")
	default:
		add("Recent full sweep", 5, 5, h.lastFull.Format("2006-01-02 15:04")+", "+plural(h.repos, "repository", "repositories"), "")
	}

	switch {
	case !h.haveReport:
		add("Nothing critical or high found", 0, 20, "no sweep has finished yet", "pushwarden scan --home")
	case h.critical+h.high > 0:
		add("Nothing critical or high found", 0, 20, fmt.Sprintf("the latest sweep found %d critical and %d high", h.critical, h.high), "pushwarden scan --home --fix")
	default:
		add("Nothing critical or high found", 20, 20, "the latest sweep found none", "")
	}
	return out
}

// iocAge reads the date an indicator version ("2026.09.28.2") starts with.
func iocAge(version string, now time.Time) (time.Duration, bool) {
	if len(version) < 10 {
		return 0, false
	}
	t, err := time.Parse("2006.01.02", version[:10])
	if err != nil {
		return 0, false
	}
	return now.Sub(t), true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// verdict sums the checks into a score, a word for it, the colour that word
// and the logo are shown in, and a sentence on what it means.
func (h health) verdict(cs []check) (score int, level, colour, meaning string) {
	for _, c := range cs {
		score += c.points
	}
	switch {
	case h.haveReport && h.critical+h.high > 0:
		return score, "THREATS FOUND", "BOLD_RED",
			"The latest sweep found malware indicators on this computer. See them with `pushwarden history`."
	case score >= 90:
		return score, "PROTECTED", "BOLD_GREEN",
			"Files are checked as they are written, the malware's servers are blocked and editors cannot auto-run tasks."
	case score >= 65:
		return score, "PARTLY PROTECTED", "BOLD_YELLOW",
			"The main protection is working, but some layers are missing. The list below says which, and how to add them."
	}
	return score, "AT RISK", "BOLD_RED",
		"This computer is not being watched for the malware. Run `pushwarden install` to turn the protection on."
}

// logo is the shield shown beside the status on a terminal.
var logo = []string{
	`    ▄▄████████▄▄    `,
	`  ████████████████  `,
	`  ███▀▀▀▀▀▀▀▀▀▀███  `,
	`  ███  █▀▀▀▀█  ███  `,
	`  ███  █▄▄▄▄▀  ███  `,
	`  ███  █       ███  `,
	`   ███ ▀      ███   `,
	`    ▀███▄▄▄▄███▀    `,
	`       ▀▀██▀▀       `,
}

// wrapText breaks s into lines of at most w columns.
func wrapText(s string, w int) []string {
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = word
		case len(cur)+1+len(word) > w:
			lines, cur = append(lines, cur), word
		default:
			cur += " " + word
		}
	}
	return append(lines, cur)
}

// statusHeader is the top of `status`: the logo, the verdict with its score
// bar and what it means. Without a colour terminal it is plain text.
func statusHeader(u *ui.UI, h health, cs []check) []string {
	score, level, colour, meaning := h.verdict(cs)
	if !u.Color() {
		return []string{
			"",
			"  PushWarden " + version + " - PolinRider / Contagious Interview protection",
			"",
			fmt.Sprintf("  Protection:  %s  %d/100  %s", level, score, u.Bar(float64(score)/100, colour)),
			"  " + meaning,
		}
	}
	right := []string{
		u.C("BOLD", "PushWarden "+version),
		u.C("DIM", "PolinRider / Contagious Interview protection"),
		"",
		fmt.Sprintf("%s  %s  %s", u.C(colour, level), u.Bar(float64(score)/100, colour), u.C("BOLD", fmt.Sprintf("%d/100", score))),
	}
	right = append(right, wrapText(meaning, 58)...)
	right = append(right, "")
	if h.guardAlive {
		right = append(right, u.C("BOLD_GREEN", "● ")+"watching "+plural(h.repos, "repository", "repositories"))
	} else {
		right = append(right, u.C("BOLD_RED", "● ")+"the guard is not running")
	}
	out := []string{""}
	for i := 0; i < max(len(logo), len(right)); i++ {
		l, r := strings.Repeat(" ", len([]rune(logo[0]))), ""
		if i < len(logo) {
			l = u.C(colour, logo[i])
		}
		if i < len(right) {
			r = right[i]
		}
		out = append(out, strings.TrimRight("  "+l+"   "+r, " "))
	}
	return out
}

// statusChecks is the protection list: one line per layer, with the command
// that adds a missing one.
func statusChecks(u *ui.UI, cs []check) []string {
	out := []string{"", "  " + u.C("BOLD", "PROTECTION")}
	w := 0
	for _, c := range cs {
		w = max(w, len(c.name))
	}
	for _, c := range cs {
		mark := u.C("BOLD_GREEN", "OK")
		switch {
		case c.points == 0:
			mark = u.C("BOLD_RED", "!!")
		case c.points < c.max:
			mark = u.C("BOLD_YELLOW", " !")
		}
		out = append(out, fmt.Sprintf("    %s  %-*s  %s", mark, w, c.name, u.C("DIM", c.note)))
		if c.fix != "" {
			out = append(out, fmt.Sprintf("        %-*s  %s %s", w, "", u.C("CYAN", "fix:"), c.fix))
		}
	}
	return out
}

// readHealth gathers the state the score is worked out from.
func readHealth(c *ctx) health {
	h := health{now: time.Now(), iocVersion: c.I.Version, editors: map[string]string{}}
	hb, _, alive := guard.ReadHeartbeat(c.DataDir)
	h.guardAlive = alive
	if hb != nil {
		h.guardVersion, h.realtime, h.repos = hb.Version, hb.Realtime, hb.Repos
		if hb.LastFull > 0 {
			h.lastFull = time.Unix(int64(hb.LastFull), 0)
		}
	}
	h.service = service.New(c.P, c.DataDir).Status()
	h.firewall = (&protect.NetBlocker{P: c.P, I: c.I}).Describe()
	for label, path := range c.P.EditorSettings() {
		h.editors[label] = harden.EditorStatus(path)
	}
	if rep, err := report.Latest(c.DataDir); err == nil && rep.Stats != nil {
		h.haveReport, h.critical, h.high = true, rep.Stats.Critical, rep.Stats.High
	}
	return h
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
