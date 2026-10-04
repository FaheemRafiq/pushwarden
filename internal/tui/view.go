package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
	"github.com/FaheemRafiq/pushwarden/internal/github"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
)

// The 16 base colours follow the terminal's own theme, light or dark.
var (
	stTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	stBold  = lipgloss.NewStyle().Bold(true)
	stDim   = lipgloss.NewStyle().Faint(true)
	stGood  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2"))
	stBad   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	stWarn  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
)

func (m *model) size() (w, h int) {
	w, h = m.w, m.h
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	return
}

// bodyHeight is how many lines a scrolling list gets.
func (m *model) bodyHeight() int {
	_, h := m.size()
	return max(h-9, 3)
}

func (m *model) View() string {
	w, _ := m.size()
	head := "  " + stTitle.Render("PushWarden") + "  GitHub clean"
	if m.login != "" {
		head += stDim.Render("   signed in as " + m.login)
	}
	lines := []string{head, ""}
	var body []string
	var keys string
	switch m.scr {
	case scrToken:
		body, keys = m.viewToken()
	case scrRepos:
		body, keys = m.viewRepos()
	case scrRun:
		body, keys = m.viewRun()
	case scrReport:
		body, keys = m.viewReport()
	case scrConfirm:
		body, keys = m.viewConfirm()
	}
	lines = append(lines, body...)
	lines = append(lines, "")
	for _, k := range wrapKeys(keys, w-4) {
		lines = append(lines, "  "+stDim.Render(k))
	}
	// Prose is wrapped; lists keep one line per item and are cut off.
	prose := m.scr == scrToken || m.scr == scrConfirm
	var out []string
	for _, l := range lines {
		if prose && ansi.StringWidth(l) > w {
			out = append(out, strings.Split(strings.ReplaceAll(ansi.Wordwrap(l, w-2, ""), "\n", "\n  "), "\n")...)
			continue
		}
		out = append(out, ansi.Truncate(l, w, ""))
	}
	return strings.Join(out, "\n")
}

// wrapKeys breaks the key help between entries so it fits w columns.
func wrapKeys(keys string, w int) []string {
	var lines []string
	cur := ""
	for _, k := range strings.Split(keys, " · ") {
		switch {
		case cur == "":
			cur = k
		case ansi.StringWidth(cur)+3+ansi.StringWidth(k) > w:
			lines, cur = append(lines, cur), k
		default:
			cur += " · " + k
		}
	}
	return append(lines, cur)
}

func (m *model) waiting() string { return "  " + m.spin.View() + " " + m.busy + "..." }

func (m *model) viewToken() ([]string, string) {
	b := []string{"  " + stBold.Render("Sign in to GitHub"), ""}
	if m.busy != "" {
		return append(b, m.waiting()), "ctrl+c quit"
	}
	if m.err != "" {
		b = append(b, "  "+stBad.Render("x "+m.err), "")
	}
	b = append(b,
		"  PushWarden needs a GitHub token to read and fix your repositories.",
		"  It is used for this run only and is never written to disk.",
		"",
		"  How to create one:",
		"    1. Open https://github.com/settings/personal-access-tokens/new",
		"    2. Repository access: the repositories to clean, or all of them",
		"    3. Repository permissions > Contents: Read and write",
		"    4. Generate the token, copy it, paste it here and press Enter",
		"",
		m.input.View())
	return b, "enter sign in · esc quit"
}

func repoTag(r github.Repo) string {
	var t []string
	if r.Private {
		t = append(t, "private")
	}
	if r.Fork {
		t = append(t, "fork")
	}
	if r.Archived {
		t = append(t, "archived")
	}
	return strings.Join(t, ", ")
}

// window returns the slice [top, end) of n items that keeps item cur in view.
func window(n, cur, height int) (top, end int) {
	if cur >= height {
		top = cur - height + 1
	}
	return top, min(top+height, n)
}

func (m *model) viewRepos() ([]string, string) {
	if m.busy != "" {
		return []string{m.waiting()}, "q quit"
	}
	if m.err != "" {
		return []string{"  " + stBad.Render("x "+m.err)}, "enter try again · q quit"
	}
	vis := m.visible()
	b := []string{fmt.Sprintf("  %s   %d of %d selected", stBold.Render("Choose the repositories to check"), len(m.chosen()), len(m.all))}
	if repos, branches := m.be.verified(); branches > 0 {
		b = append(b, "  "+stDim.Render(fmt.Sprintf("Earlier runs verified %d branches in %d repositories; only what changed since is checked again.", branches, repos)))
	}
	if m.filtering || m.filter.Value() != "" {
		b = append(b, m.filter.View())
	}
	b = append(b, "")
	nameW := 0
	for _, r := range vis {
		nameW = max(nameW, len(r.FullName))
	}
	top, end := window(len(vis), m.cur, m.bodyHeight())
	for i := top; i < end; i++ {
		r := vis[i]
		mark, box := "  ", "[ ]"
		if m.picked[r.FullName] {
			box = "[x]"
		}
		line := fmt.Sprintf("%s %-*s  %s", box, nameW, r.FullName, stDim.Render(repoTag(r)))
		if i == m.cur {
			mark, line = stTitle.Render("> "), stBold.Render(fmt.Sprintf("%s %-*s", box, nameW, r.FullName))+"  "+stDim.Render(repoTag(r))
		}
		b = append(b, "  "+mark+line)
	}
	switch {
	case len(m.all) == 0:
		b = append(b, "  This token cannot push to any repository.")
	case len(vis) == 0:
		b = append(b, "  "+stDim.Render("Nothing matches."))
	case end < len(vis):
		b = append(b, "  "+stDim.Render(fmt.Sprintf("  ... %d more below", len(vis)-end)))
	}
	if m.filtering {
		return b, "type to filter · enter keep · esc clear"
	}
	onOff := func(on bool) string {
		if on {
			return "hide"
		}
		return "show"
	}
	return b, fmt.Sprintf("up/down move · space select · a all · n none · / filter · f %s forks · r %s archived · enter check · q quit",
		onOff(m.forks), onOff(m.archived))
}

// rowText is the one-line state of a repository during a pass.
func (m *model) rowText(r row, current bool) (mark, text string) {
	switch {
	case r.res != nil:
		return resultText(*r.res)
	case current:
		t := plural(len(r.branches), "branch", "branches") + " done"
		if m.logLine != "" {
			t += stDim.Render("   > " + m.logLine)
		}
		return m.spin.View(), t
	}
	return stDim.Render("."), stDim.Render("waiting")
}

func resultText(res remediate.Result) (mark, text string) {
	if res.Error != "" {
		return stBad.Render("x"), stBad.Render(res.Error)
	}
	clean, infected, pushed, failed, manual := res.Counts()
	var parts []string
	mark = stGood.Render("+")
	if clean > 0 {
		parts = append(parts, fmt.Sprintf("%d clean", clean))
	}
	if pushed > 0 {
		parts = append(parts, stGood.Render(fmt.Sprintf("%d fixed", pushed)))
	}
	if manual > 0 {
		parts, mark = append(parts, stWarn.Render(fmt.Sprintf("%d need review", manual))), stWarn.Render("!")
	}
	if infected > 0 {
		parts, mark = append(parts, stBad.Render(fmt.Sprintf("%d INFECTED", infected))), stBad.Render("!")
	}
	if failed > 0 {
		parts, mark = append(parts, stBad.Render(fmt.Sprintf("%d failed", failed))), stBad.Render("x")
	}
	return mark, strings.Join(parts, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (m *model) viewRun() ([]string, string) {
	what := "Checking " + plural(len(m.rows), "repository", "repositories") + ". Nothing is changed."
	if m.apply {
		what = "Fixing and pushing " + plural(m.todoBranches, "branch", "branches") + " in " + plural(len(m.rows), "repository", "repositories") + "."
	}
	b := []string{fmt.Sprintf("  %s   %s", stBold.Render(what), stTitle.Render(fmt.Sprintf("[%d/%d]", min(m.at+1, len(m.rows)), len(m.rows)))), ""}
	nameW := 0
	for _, r := range m.rows {
		nameW = max(nameW, len(r.repo.FullName))
	}
	top, end := window(len(m.rows), min(m.at+2, len(m.rows)-1), m.bodyHeight())
	for i := top; i < end; i++ {
		r := m.rows[i]
		mark, text := m.rowText(r, i == m.at && r.started)
		b = append(b, fmt.Sprintf("  %s %-*s  %s", mark, nameW, r.repo.FullName, text))
	}
	if m.stopping {
		b = append(b, "", "  "+stWarn.Render("Stopping. What is finished stays saved; the next run continues from here."))
		return b, "ctrl+c quit now"
	}
	return b, "q stop (progress is saved)"
}

// reportLines is the whole report; the screen scrolls over it.
func (m *model) reportLines() []string {
	s := m.sum
	var l []string
	add := func(format string, a ...any) { l = append(l, fmt.Sprintf(format, a...)) }
	title := "Check finished"
	if m.apply {
		title = "Fix finished"
	}
	add("  %s", stBold.Render(title))
	add("")
	add("  %-27s %d", "Repositories:", s.Repos)
	add("  %-27s %d", "Branches clean:", s.Clean)
	fixed := fmt.Sprint(s.Pushed)
	if s.PushedEarlier > 0 {
		fixed += fmt.Sprintf(" (%d in earlier runs)", s.PushedEarlier)
	}
	if m.apply {
		add("  %-27s %s", "Branches fixed and pushed:", stGood.Render(fixed))
	} else {
		add("  %-27s %s", "Branches infected:", stBad.Render(fmt.Sprint(s.Infected)))
		if s.Pushed > 0 {
			add("  %-27s %s", "Branches fixed and pushed:", fixed)
		}
	}
	if s.Failed+s.Errors > 0 {
		add("  %-27s %s", "Failed:", stBad.Render(fmt.Sprint(s.Failed+s.Errors)))
	}
	if s.Manual > 0 {
		add("  %-27s %s", "Need manual review:", stWarn.Render(fmt.Sprint(s.Manual)))
	}

	for _, res := range m.results {
		if res.Error != "" {
			add("")
			add("  %s", stBad.Render("x "+res.Repo+": "+res.Error))
			continue
		}
		for _, b := range res.Branches {
			name := res.Repo + " @ " + b.Name
			switch {
			case b.Status == remediate.StatusInfected:
				add("")
				add("  %s  %s", stBad.Render("! "+name), fmt.Sprintf("INFECTED, %s would be fixed", plural(len(b.Fixed), "file", "files")))
			case b.Status == remediate.StatusPushed && !b.Resumed:
				add("")
				add("  %s  %s", stGood.Render("+ "+name), fmt.Sprintf("fixed %s, pushed %s", plural(len(b.Fixed), "file", "files"), b.Commit))
			case b.Status == remediate.StatusPushFailed:
				add("")
				add("  %s  %s", stBad.Render("x "+name), "fixed here, but GitHub refused the push: "+b.Error)
			case b.Status == remediate.StatusManual:
				add("")
				add("  %s  %s", stWarn.Render("! "+name), "needs review: findings PushWarden does not fix automatically")
				for _, f := range b.Findings {
					if f.Severity >= findings.High {
						add("      ! %s  %s", f.Title, stDim.Render(f.Path))
					}
				}
				continue
			case b.Status == remediate.StatusError:
				add("")
				add("  %s  %s", stBad.Render("x "+name), b.Error)
				continue
			default:
				continue
			}
			for _, f := range b.Fixed {
				add("      - %s", f)
			}
		}
		if len(res.History) > 0 {
			add("")
		}
		for _, f := range res.History {
			add("  %s %s: %s", stWarn.Render("history"), res.Repo, f.Title)
		}
	}

	add("")
	switch {
	case !m.apply && m.todoBranches > 0:
		add("  %s", stBold.Render(fmt.Sprintf("Press Enter to fix and push %s in %s.",
			plural(m.todoBranches, "branch", "branches"), plural(len(m.todo), "repository", "repositories"))))
		add("  Nothing has been changed so far.")
	case !m.apply && s.Failed+s.Errors+s.Manual == 0:
		add("  %s", stGood.Render("No PolinRider files were found in these repositories."))
	case m.apply && s.PushedNow() > 0:
		add("  %s", stGood.Render("The fixes are pushed. Now:"))
		add("    1. Rotate this token and every secret those repositories or their CI could read.")
		add("    2. Review GitHub > Settings > Applications and Deploy keys.")
		add("    3. Ask collaborators to git pull.")
		add("  The original files are in quarantine: pushwarden history")
	}
	if s.Failed+s.Errors > 0 {
		add("  Protected branches: allow the push temporarily or open a PR from a clean branch.")
		add("  Archived repositories must be unarchived first.")
	}
	return l
}

func (m *model) viewReport() ([]string, string) {
	lines := m.reportLines()
	_, h := m.size()
	room := max(h-4, 3)
	m.scroll = max(min(m.scroll, len(lines)-room), 0)
	end := min(m.scroll+room, len(lines))
	keys := "enter fix and push · q quit without changing anything"
	if m.final {
		keys = "enter quit"
	}
	if len(lines) > room {
		keys = "up/down scroll · " + keys
	}
	return lines[m.scroll:end], keys
}

func (m *model) viewConfirm() ([]string, string) {
	return []string{
		"  " + stBold.Render(fmt.Sprintf("Fix and push %s in %s?",
			plural(m.todoBranches, "branch", "branches"), plural(len(m.todo), "repository", "repositories"))),
		"",
		"  Each infected branch gets one normal commit, \"security: remove PolinRider malware\",",
		"  and that commit is pushed to GitHub. History is not rewritten and nothing is force-pushed.",
		"  The original files are kept in quarantine on this computer.",
	}, "y fix and push · n go back"
}
