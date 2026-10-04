// Package ui prints scan output to the terminal.
package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
)

type UI struct {
	CI, Quiet, color bool
	barLive          bool // a progress bar occupies the current line
}

func New(ci, quiet bool) *UI {
	u := &UI{CI: ci, Quiet: quiet}
	st, err := os.Stdout.Stat()
	u.color = !ci && os.Getenv("NO_COLOR") == "" && err == nil && st.Mode()&os.ModeCharDevice != 0
	return u
}

var colors = map[string]string{"BOLD": "\033[1m", "DIM": "\033[2m", "RED": "\033[0;31m", "BOLD_RED": "\033[1;31m",
	"BOLD_GREEN": "\033[1;32m", "YELLOW": "\033[0;33m", "BOLD_YELLOW": "\033[1;33m", "CYAN": "\033[0;36m", "BOLD_CYAN": "\033[1;36m"}

// Color reports whether output is styled: a terminal, not CI, no NO_COLOR.
func (u *UI) Color() bool { return u.color }

func (u *UI) C(color, s string) string {
	if !u.color {
		return s
	}
	return colors[color] + s + "\033[0m"
}

func (u *UI) P(format string, a ...any) {
	if u.Quiet {
		return
	}
	if u.barLive { // clear the bar before printing a line, redraw on the next Step
		fmt.Print("\r\033[K")
		u.barLive = false
	}
	fmt.Printf(format+"\n", a...)
}

// One progress bar for the whole program: the scan, the update download, the
// status score and the guided screens all draw these cells at this width.
const (
	BarFull  = "█"
	BarEmpty = "░"
	BarWidth = 24
)

// BarCells returns the filled and the empty part of a bar for frac (0 to 1).
func BarCells(frac float64, width int) (full, empty string) {
	n := int(frac*float64(width) + 0.5)
	n = max(min(n, width), 0)
	return strings.Repeat(BarFull, n), strings.Repeat(BarEmpty, width-n)
}

// PlainBar is the bar for output without colour: [#####-----].
func PlainBar(frac float64, width int) string {
	full, empty := BarCells(frac, width)
	return "[" + strings.Repeat("#", len([]rune(full))) + strings.Repeat("-", len([]rune(empty))) + "]"
}

// Bar is the bar in colour (the filled part in the given colour), or the
// plain form when colour is off.
func (u *UI) Bar(frac float64, colour string) string {
	if !u.color {
		return PlainBar(frac, BarWidth)
	}
	full, empty := BarCells(frac, BarWidth)
	if empty == "" {
		return u.C(colour, full)
	}
	return u.C(colour, full) + u.C("DIM", empty)
}

// Meter draws the bar in place on a terminal: bar, count, percent, label.
// frac >= 1 ends the line. Without a terminal it prints nothing.
func (u *UI) Meter(frac float64, count, label string) {
	if u.Quiet || !u.color {
		return
	}
	if len(label) > 50 {
		label = "..." + label[len(label)-47:]
	}
	fmt.Printf("\r\033[K  %s  %s  %s  %s", u.Bar(frac, "BOLD_CYAN"), u.C("BOLD", count), u.C("DIM", fmt.Sprintf("%3.0f%%", frac*100)), u.C("DIM", label))
	u.barLive = true
	if frac >= 1 {
		fmt.Println()
		u.barLive = false
	}
}

// Step reports progress through a list: an in-place bar on a terminal, a
// numbered line otherwise. done == total ends the bar.
func (u *UI) Step(done, total int, label string) {
	if u.Quiet || total <= 0 {
		return
	}
	if !u.color { // CI, pipes, NO_COLOR
		if !u.CI || done == total {
			u.P("  > [%d/%d] %s", done, total, label)
		}
		return
	}
	u.Meter(float64(done)/float64(total), fmt.Sprintf("%d/%d", done, total), label)
}

// Live reports whether a progress bar is being drawn (callers skip their
// own per-item progress lines then).
func (u *UI) Live() bool { return u.barLive }

func (u *UI) Banner(version, iocVersion string) {
	line := strings.Repeat("=", 70)
	u.P("\n%s", u.C("BOLD_CYAN", line))
	u.P("%s", u.C("BOLD_CYAN", "  PushWarden v"+version+" - PolinRider / Contagious Interview protection"))
	u.P("%s", u.C("BOLD_CYAN", "  Cross-platform | Indicators "+iocVersion))
	u.P("%s\n", u.C("BOLD_CYAN", line))
}

func (u *UI) Section(t string) {
	u.P("\n%s\n%s\n%s", u.C("BOLD", strings.Repeat("-", 70)), u.C("BOLD", "  "+t), u.C("BOLD", strings.Repeat("-", 70)))
}

var badge = map[findings.Severity][2]string{findings.Critical: {"CRITICAL", "BOLD_RED"}, findings.High: {"HIGH", "RED"},
	findings.Warning: {"WARNING", "BOLD_YELLOW"}, findings.Info: {"INFO", "CYAN"}}

func (u *UI) Finding(f *findings.Finding) {
	b := badge[f.Severity]
	u.P("  [%s] %s", u.C(b[1], b[0]), u.C("BOLD", f.Title))
	if f.Path != "" {
		u.P("      Path: %s", f.Path)
	}
	for _, l := range strings.Split(strings.TrimSpace(f.Details), "\n") {
		if strings.TrimSpace(l) != "" {
			u.P("      %s", u.C("DIM", l))
		}
	}
	if f.Severity >= findings.Warning {
		u.P("      %s", u.C("CYAN", "Why: "+findings.Why(f)))
	}
	if f.Action != "" {
		u.P("      %s", u.C("BOLD_GREEN", "Action: "+f.Action))
		u.P("      %s", u.C("CYAN", findings.WhyAction(f)))
	}
}

func (u *UI) Progress(m string) {
	if !u.CI {
		u.P("  > %s", u.C("DIM", m))
	}
}
func (u *UI) OK(m string)   { u.P("  + %s", u.C("BOLD_GREEN", m)) }
func (u *UI) Info(m string) { u.P("  i %s", u.C("CYAN", m)) }
func (u *UI) Warn(m string) { u.P("  ! %s", u.C("YELLOW", m)) }
func (u *UI) Err(m string)  { u.P("  x %s", u.C("BOLD_RED", m)) }

func (u *UI) Summary(s *findings.Stats) {
	u.P("\n%s\n%s\n%s", u.C("BOLD", strings.Repeat("=", 70)), u.C("BOLD", "  SCAN SUMMARY"), u.C("BOLD", strings.Repeat("=", 70)))
	row := func(k string, v any, c string) { u.P("  %-30s %s", u.C("BOLD_CYAN", k+":"), u.C(c, fmt.Sprint(v))) }
	row("Platform", s.PlatformName, "")
	row("Duration", fmt.Sprintf("%.1fs", s.ScanDuration), "")
	row("Repos scanned", s.ReposScanned, "")
	row("Repos infected", s.ReposInfected, map[bool]string{true: "BOLD_RED", false: "BOLD_GREEN"}[s.ReposInfected > 0])
	row("Files checked", s.FilesChecked, "")
	u.P("")
	row("CRITICAL", s.Critical, map[bool]string{true: "BOLD_RED", false: "DIM"}[s.Critical > 0])
	row("HIGH", s.High, map[bool]string{true: "RED", false: "DIM"}[s.High > 0])
	row("WARNING", s.Warning, map[bool]string{true: "BOLD_YELLOW", false: "DIM"}[s.Warning > 0])
	row("INFO", s.Info, "DIM")
	u.P("")
	status, c := "CLEAN", "BOLD_GREEN"
	if s.Critical+s.High > 0 {
		status, c = "INFECTIONS DETECTED", "BOLD_RED"
	} else if s.Warning > 0 {
		status, c = "REVIEW WARNINGS", "BOLD_YELLOW"
	}
	row("Status", status, c)
	u.P("%s", u.C("BOLD", strings.Repeat("=", 70)))
}

func (u *UI) Remediation(fs []*findings.Finding) {
	if !findings.AnyAtLeast(fs, findings.Warning) {
		return
	}
	u.P("\n%s\n  %s", u.C("BOLD", "  REMEDIATION (by priority)"), strings.Repeat("-", 66))
	for _, lvl := range []struct {
		s     findings.Severity
		title string
	}{{findings.Critical, "CRITICAL - act now"}, {findings.High, "HIGH - rotate credentials & audit"}, {findings.Warning, "WARNING - review"}} {
		seen := map[string]bool{}
		var lines []string
		for _, f := range fs {
			if f.Severity == lvl.s && f.Remediation != "" && !seen[f.Remediation] {
				seen[f.Remediation] = true
				lines = append(lines, f.Remediation)
			}
		}
		if len(lines) == 0 {
			continue
		}
		u.P("\n  %s", lvl.title)
		for _, r := range lines {
			for _, l := range strings.Split(strings.TrimSpace(r), "\n") {
				u.P("    %s", l)
			}
		}
	}
	u.P("\n  After ANY critical/high finding, regardless of what else you do:")
	for _, l := range []string{
		"1. Rotate: GitHub PATs, SSH keys, npm tokens, cloud/deploy tokens (Vercel/Netlify/AWS).",
		"2. Revoke OAuth apps & GitHub App installs you don't recognise.",
		"3. Enable hardware-backed 2FA on GitHub and npm.",
		"4. Run: pushwarden harden   (turns off VS Code automatic tasks).",
		"5. Report: https://opensourcemalware.com",
	} {
		u.P("    %s", l)
	}
	u.P("")
}
