// Package tui is the terminal UI for github-clean: sign in, choose
// repositories, check them, review what was found, fix and push. It only
// shows; the work is done by package ghclean, as for the command line.
package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/FaheemRafiq/pushwarden/internal/ghclean"
	"github.com/FaheemRafiq/pushwarden/internal/github"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
)

// Run shows the UI until the user leaves it. sess carries everything but the
// token, which the UI finds or asks for. The exit code follows github-clean:
// 0 = clean or all fixed, 1 = infected branches remain or failures.
func Run(sess *ghclean.Session) (int, error) {
	m := newModel(live(sess))
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	m.cancel()
	if m.interrupted {
		fmt.Println("Stopped. Progress is saved: open PushWarden again to continue where it stopped.")
	}
	return m.code, err
}

// backend is what the screens need done; tests replace it.
type backend struct {
	findToken func() (token, source string)
	viewer    func(ctx context.Context, token string) (string, error)
	listRepos func(ctx context.Context, token string) ([]github.Repo, error)
	run       func(ctx context.Context, token string, repos []github.Repo, apply bool, emit func(ghclean.Event)) []remediate.Result
	// verified is what earlier runs already checked.
	verified func() (repos, branches int)
}

func live(sess *ghclean.Session) backend {
	return backend{
		findToken: ghclean.FindToken,
		viewer: func(ctx context.Context, token string) (string, error) {
			return github.New(token, sess.API).Viewer(ctx)
		},
		listRepos: func(ctx context.Context, token string) ([]github.Repo, error) {
			// forks and archived repositories are fetched too: the screen hides them until asked
			repos, _, err := ghclean.ListRepos(ctx, github.New(token, sess.API), ghclean.Filter{Forks: true, Archived: true})
			return repos, err
		},
		run: func(ctx context.Context, token string, repos []github.Repo, apply bool, emit func(ghclean.Event)) []remediate.Result {
			sess.Token = token
			return sess.Run(ctx, repos, apply, emit)
		},
		verified: func() (int, int) { return ghclean.ProgressTotals(sess.State) },
	}
}

type screen int

const (
	scrToken   screen = iota // sign in
	scrRepos                 // choose repositories
	scrRun                   // a pass is running
	scrReport                // what a pass found or did
	scrConfirm               // really fix and push?
)

type (
	tokenMsg  struct{ token, source string }
	viewerMsg struct {
		login string
		err   error
	}
	reposMsg struct {
		repos []github.Repo
		err   error
	}
	eventMsg    struct{ e ghclean.Event }
	passDoneMsg struct{ results []remediate.Result }
)

// row is one repository on the run screen.
type row struct {
	repo     github.Repo
	started  bool
	branches []remediate.Branch // results so far
	res      *remediate.Result  // set when the repository is finished
}

type model struct {
	be     backend
	ctx    context.Context
	cancel context.CancelFunc
	w, h   int
	scr    screen
	spin   spinner.Model
	busy   string // what is being waited for; "" = waiting for the user
	err    string

	// sign in
	input                textinput.Model
	token, login, source string

	// choose repositories
	all             []github.Repo
	forks, archived bool // show them
	filter          textinput.Model
	filtering       bool
	picked          map[string]bool // by full name
	cur             int             // cursor in visible()

	// a pass
	apply     bool
	passRepos []github.Repo
	rows      []row
	at        int // the repository being worked on
	logLine   string
	events    chan tea.Msg
	stopping  bool

	// report
	sum          ghclean.Summary
	results      []remediate.Result
	todo         []github.Repo // repositories with infected branches
	todoBranches int
	final        bool // nothing more to do after this report
	scroll       int

	interrupted bool
	code        int
}

func newModel(be backend) *model {
	ctx, cancel := context.WithCancel(context.Background())
	in := textinput.New()
	in.Placeholder = "paste the token here"
	in.EchoMode = textinput.EchoPassword
	in.EchoCharacter = '*'
	in.Prompt = "  Token: "
	fl := textinput.New()
	fl.Prompt = "  Filter: "
	sp := spinner.New()
	sp.Spinner = spinner.Line
	return &model{be: be, ctx: ctx, cancel: cancel, spin: sp, input: in, filter: fl,
		picked: map[string]bool{}, busy: "Looking for a GitHub login"}
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.spin.Tick, func() tea.Msg {
		t, s := m.be.findToken()
		return tokenMsg{t, s}
	})
}

func (m *model) signIn() tea.Cmd {
	m.busy, m.err = "Signing in to GitHub", ""
	ctx, token, viewer := m.ctx, m.token, m.be.viewer
	return func() tea.Msg {
		login, err := viewer(ctx, token)
		return viewerMsg{login, err}
	}
}

func (m *model) loadRepos() tea.Cmd {
	m.busy, m.err = "Listing the repositories you can push to", ""
	ctx, token, list := m.ctx, m.token, m.be.listRepos
	return func() tea.Msg {
		repos, err := list(ctx, token)
		return reposMsg{repos, err}
	}
}

func waitFor(ch chan tea.Msg) tea.Cmd { return func() tea.Msg { return <-ch } }

// startPass runs a dry (apply=false) or fixing pass over repos; its events
// arrive one by one as messages, the last being passDoneMsg.
func (m *model) startPass(apply bool, repos []github.Repo) tea.Cmd {
	m.scr, m.apply, m.passRepos, m.at, m.logLine = scrRun, apply, repos, 0, ""
	m.rows = make([]row, len(repos))
	for i, r := range repos {
		m.rows[i].repo = r
	}
	ch := make(chan tea.Msg, 64)
	m.events = ch
	ctx, token, run := m.ctx, m.token, m.be.run
	go func() {
		res := run(ctx, token, repos, apply, func(e ghclean.Event) { ch <- eventMsg{e} })
		ch <- passDoneMsg{res}
	}()
	return waitFor(ch)
}

// shown reports whether the fork/archived switches let r through.
func (m *model) shown(r github.Repo) bool {
	return (!r.Fork || m.forks) && (!r.Archived || m.archived)
}

// visible is the repository list as filtered on screen.
func (m *model) visible() []github.Repo {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	var out []github.Repo
	for _, r := range m.all {
		if m.shown(r) && strings.Contains(strings.ToLower(r.FullName), q) {
			out = append(out, r)
		}
	}
	return out
}

// chosen is what a check will run on: the ticked repositories, whatever the
// text filter currently shows.
func (m *model) chosen() []github.Repo {
	var out []github.Repo
	for _, r := range m.all {
		if m.picked[r.FullName] && m.shown(r) {
			out = append(out, r)
		}
	}
	return out
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case spinner.TickMsg:
		var c tea.Cmd
		m.spin, c = m.spin.Update(msg)
		return m, c
	case tokenMsg:
		if msg.token == "" {
			m.busy = ""
			return m, m.input.Focus()
		}
		m.token, m.source = msg.token, msg.source
		return m, m.signIn()
	case viewerMsg:
		if msg.err != nil {
			// a found or pasted token that GitHub refuses: ask for another one
			m.err = msg.err.Error()
			if m.source != "" {
				m.err = "The token from " + m.source + " did not work: " + m.err
			}
			m.busy, m.token, m.source = "", "", ""
			m.input.SetValue("")
			return m, m.input.Focus()
		}
		m.login, m.scr = msg.login, scrRepos
		return m, m.loadRepos()
	case reposMsg:
		m.busy = ""
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		m.all = msg.repos
		for _, r := range m.all {
			m.picked[r.FullName] = m.shown(r)
		}
		return m, nil
	case eventMsg:
		m.event(msg.e)
		return m, waitFor(m.events)
	case passDoneMsg:
		if m.stopping {
			m.interrupted = true
			return m, tea.Quit
		}
		m.report(msg.results)
		return m, nil
	case tea.KeyMsg:
		return m.key(msg)
	}
	// cursor blink and the like
	var c tea.Cmd
	switch {
	case m.scr == scrToken:
		m.input, c = m.input.Update(msg)
	case m.filtering:
		m.filter, c = m.filter.Update(msg)
	}
	return m, c
}

func (m *model) event(e ghclean.Event) {
	switch e := e.(type) {
	case ghclean.RepoStarted:
		if e.Index < len(m.rows) {
			m.at = e.Index
			m.rows[m.at].started = true
		}
	case ghclean.Log:
		m.logLine = e.Msg
	case ghclean.BranchDone:
		m.rows[m.at].branches = append(m.rows[m.at].branches, e.Branch)
	case ghclean.RepoDone:
		m.rows[m.at].res = &e.Result
	}
}

// report turns a finished pass into the report screen.
func (m *model) report(results []remediate.Result) {
	m.scr, m.results, m.scroll = scrReport, results, 0
	m.sum = ghclean.Summarize(results, m.apply)
	m.code = m.sum.ExitCode()
	m.todo, m.todoBranches = nil, 0
	if !m.apply {
		m.todo, m.todoBranches = ghclean.Infected(m.passRepos, results)
	}
	m.final = m.apply || m.todoBranches == 0
}

func (m *model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.Type == tea.KeyCtrlC {
		return m.leave()
	}
	switch m.scr {
	case scrToken:
		if m.busy != "" {
			return m, nil
		}
		switch k.Type {
		case tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			if t := strings.TrimSpace(m.input.Value()); t != "" {
				m.token, m.source = t, ""
				m.input.Blur()
				return m, m.signIn()
			}
			return m, nil
		}
		var c tea.Cmd
		m.input, c = m.input.Update(k)
		return m, c
	case scrRepos:
		return m.keyRepos(k)
	case scrRun:
		if k.String() == "q" {
			return m.leave()
		}
	case scrReport:
		switch k.String() {
		case "up", "k":
			m.scroll = max(m.scroll-1, 0)
		case "down", "j":
			m.scroll++ // clamped when drawn
		case "pgup":
			m.scroll = max(m.scroll-m.bodyHeight(), 0)
		case "pgdown", " ":
			m.scroll += m.bodyHeight()
		case "enter":
			if m.final {
				return m, tea.Quit
			}
			m.scr = scrConfirm
		case "q", "esc":
			return m, tea.Quit
		}
	case scrConfirm:
		switch k.String() {
		case "y", "Y":
			return m, m.startPass(true, m.todo)
		case "n", "N", "esc", "q":
			m.scr = scrReport
		}
	}
	return m, nil
}

func (m *model) keyRepos(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.busy != "" {
		if k.String() == "q" {
			return m, tea.Quit
		}
		return m, nil
	}
	if m.err != "" { // the listing failed
		switch k.String() {
		case "enter":
			return m, m.loadRepos()
		case "q", "esc":
			return m, tea.Quit
		}
		return m, nil
	}
	if m.filtering {
		switch k.Type {
		case tea.KeyEsc:
			m.filter.SetValue("")
			fallthrough
		case tea.KeyEnter:
			m.filtering = false
			m.filter.Blur()
			m.cur = 0
			return m, nil
		}
		var c tea.Cmd
		m.filter, c = m.filter.Update(k)
		m.cur = 0
		return m, c
	}
	vis := m.visible()
	switch k.String() {
	case "up", "k":
		m.cur = max(m.cur-1, 0)
	case "down", "j":
		m.cur = min(m.cur+1, max(len(vis)-1, 0))
	case "pgup":
		m.cur = max(m.cur-m.bodyHeight(), 0)
	case "pgdown":
		m.cur = min(m.cur+m.bodyHeight(), max(len(vis)-1, 0))
	case " ":
		if m.cur < len(vis) {
			n := vis[m.cur].FullName
			m.picked[n] = !m.picked[n]
		}
	case "a", "n":
		for _, r := range vis {
			m.picked[r.FullName] = k.String() == "a"
		}
	case "f":
		m.forks, m.cur = !m.forks, 0
	case "r":
		m.archived, m.cur = !m.archived, 0
	case "/":
		m.filtering = true
		return m, m.filter.Focus()
	case "esc":
		m.filter.SetValue("")
		m.cur = 0
	case "enter":
		if repos := m.chosen(); len(repos) > 0 {
			return m, m.startPass(false, repos)
		}
	case "q":
		return m, tea.Quit
	}
	return m, nil
}

// leave handles Ctrl+C (and q while a pass runs). A running pass is stopped
// cleanly first: git is interrupted, what is finished stays remembered, and
// the program ends when the pass has wound down. A second press ends it now.
func (m *model) leave() (tea.Model, tea.Cmd) {
	if m.scr == scrRun && !m.stopping {
		m.stopping = true
		m.cancel()
		return m, nil
	}
	m.interrupted = m.scr == scrRun
	return m, tea.Quit
}
