package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
	"github.com/FaheemRafiq/pushwarden/internal/ghclean"
	"github.com/FaheemRafiq/pushwarden/internal/github"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
	"github.com/FaheemRafiq/pushwarden/internal/ui"
)

// The 16 base colours follow the terminal's own theme, light or dark.
var (
	stTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	stBold  = lipgloss.NewStyle().Bold(true)
	stDim   = lipgloss.NewStyle().Faint(true)
	stGood  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2"))
	stBad   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))
	stWarn  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	stBadge = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("6")).Padding(0, 1)
	stKey   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
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
	return max(h-13, 3)
}

// steps are the stages shown under the title; step tells which one a screen is.
var steps = []string{"Sign in", "Choose", "Check", "Review", "Fix"}

func (m *model) step() int {
	switch {
	case m.scr == scrToken:
		return 0
	case m.scr == scrRepos:
		return 1
	case m.scr == scrRun && !m.apply:
		return 2
	case m.scr == scrRun:
		return 4
	case m.scr == scrReport && m.apply:
		return len(steps) // all done
	}
	return 3
}

// header is the title bar, the stage line and a rule.
func (m *model) header(w int) []string {
	left := "  " + stBadge.Render("PushWarden") + "  " + stBold.Render("GitHub clean")
	right := ""
	if m.login != "" {
		right = stDim.Render("account ") + stBold.Render(m.login)
		if m.me.Source != "" {
			right += stDim.Render(" · " + m.me.Source)
		}
		right += "  "
	}
	if gap := w - ansi.StringWidth(left) - ansi.StringWidth(right); gap >= 2 {
		left += strings.Repeat(" ", gap) + right
	}
	cur := m.step()
	var st []string
	for i, name := range steps {
		label := fmt.Sprintf("%d %s", i+1, name)
		switch {
		case i < cur:
			st = append(st, stGood.Render(label))
		case i == cur:
			st = append(st, stKey.Underline(true).Render(label))
		default:
			st = append(st, stDim.Render(label))
		}
	}
	return []string{left, "  " + strings.Join(st, stDim.Render("  »  ")), rule(w), ""}
}

func rule(w int) string { return stDim.Render(strings.Repeat("─", max(w, 1))) }

// styleKeys shows "space select" with the key standing out from what it does.
func styleKeys(line string) string {
	var out []string
	for _, k := range strings.Split(line, " · ") {
		key, what, _ := strings.Cut(k, " ")
		out = append(out, strings.TrimSpace(stKey.Render(key)+" "+stDim.Render(what)))
	}
	return strings.Join(out, stDim.Render(" · "))
}

func (m *model) View() string {
	w, _ := m.size()
	lines := m.header(w)
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
	lines = append(lines, "", rule(w))
	for _, k := range wrapKeys(keys, w-4) {
		lines = append(lines, "  "+styleKeys(k))
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
	if !m.pasting {
		b = append(b, "  Which account's repositories do you want to check?", "")
		nameW := len("Use another token")
		for _, a := range m.accounts {
			nameW = max(nameW, len(accountName(a)))
		}
		for i := 0; i <= len(m.accounts); i++ {
			name, note := "Use another token", "paste it on the next screen"
			if i < len(m.accounts) {
				name, note = accountName(m.accounts[i]), m.accounts[i].Source
				if m.login != "" && m.accounts[i].Login == m.login {
					note += ", current"
				}
			}
			line := fmt.Sprintf("  %-*s  %s", nameW, name, stDim.Render(note))
			if i == m.acct {
				line = stTitle.Render("> ") + stBold.Render(fmt.Sprintf("%-*s", nameW, name)) + "  " + stDim.Render(note)
			}
			b = append(b, "  "+line)
		}
		b = append(b, "", "  "+stDim.Render("Another account? Log it in with `gh auth login`, or choose Use another token."))
		return b, "up/down move · enter choose · q quit"
	}
	back := "esc quit"
	if len(m.accounts) > 0 {
		back = "esc back to the accounts"
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
	return b, "enter sign in · " + back
}

// accountName is how an account is listed before and after GitHub named it.
func accountName(a ghclean.Account) string {
	if a.Login != "" {
		return a.Login
	}
	return "token from " + a.Source
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

// tilde shortens a path under the home folder to ~/...
func tilde(p string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home+string(os.PathSeparator)) {
		return "~" + p[len(home):]
	}
	return p
}

// when shows a stored timestamp as a short local date and time.
func when(ts string) string {
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t.Local().Format("2 Jan 15:04")
	}
	if len(ts) >= 16 {
		return strings.Replace(ts[:16], "T", " ", 1)
	}
	return ts
}

// earlier is what earlier runs found for a repository, for the list.
func (m *model) earlier(r github.Repo) string {
	h, ok := m.history[strings.ToLower(r.FullName)]
	if !ok {
		return stDim.Render("not checked yet")
	}
	state := stGood.Render("clean")
	switch {
	case h.Manual > 0:
		state = stWarn.Render("needs review")
	case h.Pushed > 0:
		state = stGood.Render("fixed")
	}
	return state + stDim.Render(" · "+plural(h.Clean+h.Pushed+h.Manual, "branch", "branches")+" · "+when(h.Last))
}

func (m *model) viewRepos() ([]string, string) {
	if m.busy != "" {
		return []string{m.waiting()}, "q quit"
	}
	if m.err != "" && !m.adding {
		return []string{"  " + stBad.Render("x "+m.err)}, "enter try again · s switch account · q quit"
	}
	ssh := m.me.SSHHost != ""
	vis := m.visible()
	chosen := len(m.chosen())
	count := stDim.Render(fmt.Sprintf("%d of %d selected", chosen, len(m.all)))
	if chosen > 0 {
		count = stKey.Render(fmt.Sprintf("%d of %d selected", chosen, len(m.all)))
	}
	b := []string{"  " + stBold.Render("Choose the repositories to check") + "   " + count}
	known := 0
	for _, r := range m.all {
		if _, ok := m.history[strings.ToLower(r.FullName)]; ok {
			known++
		}
	}
	if known > 0 {
		b = append(b, "  "+stDim.Render(fmt.Sprintf("%d verified by earlier runs, %d not checked yet.", known, len(m.all)-known)))
	}
	if ssh {
		b = append(b, "  "+stWarn.Render("SSH cannot list private repositories that are not on this computer."),
			"  "+stDim.Render("Press + to add one by name, or switch to a token account for the complete list."))
	}
	if m.hint != "" {
		b = append(b, "  "+stWarn.Render(m.hint))
	}
	if m.filtering || m.filter.Value() != "" {
		b = append(b, m.filter.View())
	}
	if m.adding {
		if m.err != "" {
			b = append(b, "  "+stBad.Render("x "+m.err))
		}
		b = append(b, m.add.View())
	}
	b = append(b, "")
	nameW, tagW := 0, 0
	tags := make([]string, len(vis))
	for i, r := range vis {
		nameW = max(nameW, len(r.FullName))
		tags[i] = repoTag(r)
		where := m.from[strings.ToLower(r.FullName)]
		if where == "" && m.local[strings.ToLower(r.FullName)] != "" {
			where = ghclean.FromLocal
		}
		if where != "" {
			tags[i] = strings.TrimSuffix(where+", "+tags[i], ", ")
		}
		tagW = max(tagW, len(tags[i]))
	}
	top, end := window(len(vis), m.cur, m.bodyHeight())
	for i := top; i < end; i++ {
		r := vis[i]
		mark, box := "  ", stDim.Render("[ ]")
		if m.picked[r.FullName] {
			box = stGood.Render("[x]")
		}
		name := fmt.Sprintf("%-*s", nameW, r.FullName)
		if i == m.cur {
			mark, name = stKey.Render("> "), stBold.Render(name)
		}
		b = append(b, fmt.Sprintf("  %s%s %s  %s  %s", mark, box, name, stDim.Render(fmt.Sprintf("%-*s", tagW, tags[i])), m.earlier(r)))
	}
	switch {
	case len(m.all) == 0 && ssh:
		b = append(b, "  No repository of this account was found on this computer or among its public ones.")
	case len(m.all) == 0:
		b = append(b, "  This token cannot push to any repository.")
	case len(vis) == 0:
		b = append(b, "  "+stDim.Render("Nothing matches."))
	case len(vis) > end-top:
		b = append(b, "  "+stDim.Render(fmt.Sprintf("  showing %d-%d of %d", top+1, end, len(vis))))
	}
	if m.cur < len(vis) {
		if dir := m.local[strings.ToLower(vis[m.cur].FullName)]; dir != "" {
			b = append(b, "", "  "+stDim.Render("On this computer: ")+tilde(dir))
		}
	}
	if m.filtering {
		return b, "type to filter · enter keep · esc clear"
	}
	if m.adding {
		return b, "enter add · esc cancel"
	}
	plus := ""
	if ssh {
		plus = "+ add a repository · "
	}
	onOff := func(on bool) string {
		if on {
			return "hide"
		}
		return "show"
	}
	return b, fmt.Sprintf("up/down move · space select · a all · n none · l local clones · u not checked yet · / filter · f %s forks · r %s archived · %ss switch account · enter check · q quit",
		onOff(m.forks), onOff(m.archived), plus)
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

// clock shows a duration as m:ss.
func clock(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

func (m *model) viewRun() ([]string, string) {
	what := "Checking " + plural(len(m.rows), "repository", "repositories") + ". Nothing is changed."
	if m.apply {
		what = "Fixing and pushing " + plural(m.todoBranches, "branch", "branches") + " in " + plural(len(m.rows), "repository", "repositories") + "."
	}
	done, clean, infected, fixed, review, failed := 0, 0, 0, 0, 0, 0
	for _, r := range m.rows {
		if r.res != nil {
			done++
			if r.res.Error != "" {
				failed++
			}
		}
		for _, br := range r.branches {
			switch br.Status {
			case remediate.StatusClean:
				clean++
			case remediate.StatusInfected:
				infected++
			case remediate.StatusPushed:
				fixed++
			case remediate.StatusManual:
				review++
			default:
				failed++
			}
		}
	}
	frac := 0.0
	if len(m.rows) > 0 {
		frac = float64(done) / float64(len(m.rows))
	}
	full, empty := ui.BarCells(frac, ui.BarWidth) // the same bar as the rest of the program
	tally := []string{stGood.Render(fmt.Sprintf("%d clean", clean))}
	if m.apply {
		tally = append(tally, stGood.Render(fmt.Sprintf("%d fixed", fixed)))
	} else {
		tally = append(tally, countStyle(infected, stBad).Render(fmt.Sprintf("%d infected", infected)))
	}
	tally = append(tally, countStyle(review, stWarn).Render(fmt.Sprintf("%d need review", review)), countStyle(failed, stBad).Render(fmt.Sprintf("%d failed", failed)))
	b := []string{
		"  " + stBold.Render(what),
		"",
		fmt.Sprintf("  %s  %s  %s  %s", stKey.Render(full)+stDim.Render(empty), stBold.Render(fmt.Sprintf("%d/%d", done, len(m.rows))),
			stDim.Render(fmt.Sprintf("%3.0f%%", frac*100)), stDim.Render(clock(time.Since(m.started)))),
		"  " + stDim.Render("Branches so far: ") + strings.Join(tally, stDim.Render(" · ")),
		"",
	}
	nameW := 0
	for _, r := range m.rows {
		nameW = max(nameW, len(r.repo.FullName))
	}
	top, end := window(len(m.rows), min(m.at+2, len(m.rows)-1), max(m.bodyHeight()-3, 3))
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

// countStyle dims a zero so the counts that matter stand out.
func countStyle(n int, st lipgloss.Style) lipgloss.Style {
	if n == 0 {
		return stDim
	}
	return st
}

// tiles is the row of result counts on a report; "" when it does not fit.
func tiles(w int, items ...tile) []string {
	var boxes []string
	for _, t := range items {
		st := countStyle(t.n, t.st)
		boxes = append(boxes, lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(st.GetForeground()).
			Padding(0, 2).Align(lipgloss.Center).Render(st.Render(fmt.Sprint(t.n))+"\n"+t.label))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top, boxes...)
	if lipgloss.Width(row)+2 > w {
		return nil
	}
	var out []string
	for _, l := range strings.Split(row, "\n") {
		out = append(out, "  "+l)
	}
	return out
}

type tile struct {
	label string
	n     int
	st    lipgloss.Style
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
	w, _ := m.size()
	third := tile{"infected", s.Infected, stBad}
	if m.apply {
		third = tile{"fixed", s.Pushed, stGood}
	}
	row := tiles(w, tile{"repositories", s.Repos, stBold}, tile{"clean", s.Clean, stGood}, third,
		tile{"need review", s.Manual, stWarn}, tile{"failed", s.Failed + s.Errors, stBad})
	if row != nil {
		l = append(l, row...)
		if s.PushedEarlier > 0 {
			add("  %s", stDim.Render(fmt.Sprintf("%d of the fixed branches were fixed in earlier runs.", s.PushedEarlier)))
		}
	} else { // too narrow for the tiles
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
	room := max(h-8, 3)
	m.scroll = max(min(m.scroll, len(lines)-room), 0)
	end := min(m.scroll+room, len(lines))
	keys := "enter fix and push · b back to the list · q quit without changing anything"
	if m.final {
		keys = "b back to the list · s switch account · enter quit"
	}
	if len(lines) > room {
		keys = "up/down scroll · " + keys
	}
	return lines[m.scroll:end], keys
}

func (m *model) viewConfirm() ([]string, string) {
	w, _ := m.size()
	text := stBold.Render(fmt.Sprintf("Fix and push %s in %s?",
		plural(m.todoBranches, "branch", "branches"), plural(len(m.todo), "repository", "repositories"))) + "\n\n" +
		"Each infected branch gets one normal commit, \"security: remove PolinRider malware\", " +
		"and that commit is pushed to GitHub as " + stBold.Render(m.login) + ".\n" +
		"History is not rewritten and nothing is force-pushed.\n" +
		"The original files are kept in quarantine on this computer."
	box := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("3")).
		Padding(1, 2).Width(max(min(w-8, 84), 20)).Render(text)
	var b []string
	for _, l := range strings.Split(box, "\n") {
		b = append(b, "  "+l)
	}
	return b, "y fix and push · n go back"
}
