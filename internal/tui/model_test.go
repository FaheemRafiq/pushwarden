package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/FaheemRafiq/pushwarden/internal/ghclean"
	"github.com/FaheemRafiq/pushwarden/internal/github"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
)

// fake is a backend with two pushable repositories and a fork; a dry pass
// finds `infected` branches in me/app, an apply pass pushes them.
type fake struct {
	token    string // the only token GitHub accepts
	infected bool
	passes   []string // "dry me/app me/lib", "apply me/app"
}

func (f *fake) backend() backend {
	return backend{
		findToken: func() (string, string) { return "", "" },
		viewer: func(_ context.Context, token string) (string, error) {
			if token != f.token {
				return "", errors.New("GitHub rejected the token")
			}
			return "me", nil
		},
		listRepos: func(context.Context, string) ([]github.Repo, error) {
			return []github.Repo{{FullName: "me/app"}, {FullName: "me/lib"}, {FullName: "me/forked", Fork: true}}, nil
		},
		run: func(ctx context.Context, _ string, repos []github.Repo, apply bool, emit func(ghclean.Event)) []remediate.Result {
			mode := "dry"
			if apply {
				mode = "apply"
			}
			var results []remediate.Result
			for i, r := range repos {
				mode += " " + r.FullName
				emit(ghclean.RepoStarted{Index: i, Total: len(repos), Repo: r})
				emit(ghclean.Log{Msg: "cloning " + r.FullName})
				b := remediate.Branch{Name: "main", Status: remediate.StatusClean}
				if f.infected && r.FullName == "me/app" {
					b.Status, b.Fixed = remediate.StatusInfected, []string{"postcss.config.mjs: stripped"}
					if apply {
						b.Status, b.Commit = remediate.StatusPushed, "abc1234"
					}
				}
				emit(ghclean.BranchDone{Repo: r.FullName, Branch: b})
				res := remediate.Result{Repo: r.FullName, Branches: []remediate.Branch{b}}
				emit(ghclean.RepoDone{Result: res})
				results = append(results, res)
			}
			f.passes = append(f.passes, mode)
			return results
		},
		verified: func() (int, int) { return 0, 0 },
	}
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// send delivers msg and then everything the model's commands produce, until
// the model waits for the user again. It reports whether the model quit.
func send(t *testing.T, m *model, msg tea.Msg) (quit bool) {
	t.Helper()
	for range 100 {
		_, cmd := m.Update(msg)
		_ = m.View() // every state must draw
		if cmd == nil {
			return false
		}
		if m.busy == "" && (m.scr == scrToken || m.filtering) {
			return false // a text field's cursor blink, not work
		}
		msg = cmd()
		if _, ok := msg.(tea.QuitMsg); ok {
			return true
		}
	}
	t.Fatal("the model never settled")
	return false
}

// signedIn brings a model to the repository list.
func signedIn(t *testing.T, f *fake) *model {
	t.Helper()
	f.token = "good"
	m := newModel(f.backend())
	send(t, m, tokenMsg{})
	if m.scr != scrToken || m.busy != "" || !strings.Contains(m.View(), "How to create one") {
		t.Fatalf("without a login the token is asked for:\n%s", m.View())
	}
	send(t, m, key("bad"))
	send(t, m, key("enter"))
	if m.scr != scrToken || !strings.Contains(m.View(), "GitHub rejected the token") || m.input.Value() != "" {
		t.Fatalf("a refused token is asked for again:\n%s", m.View())
	}
	send(t, m, key("good"))
	send(t, m, key("enter"))
	if m.scr != scrRepos || m.login != "me" || len(m.all) != 3 {
		t.Fatalf("scr=%d login=%q repos=%d\n%s", m.scr, m.login, len(m.all), m.View())
	}
	return m
}

func TestCheckThenFix(t *testing.T) {
	f := &fake{infected: true}
	m := signedIn(t, f)
	if v := m.View(); strings.Contains(v, "me/forked") || !strings.Contains(v, "2 of 3 selected") {
		t.Fatalf("forks are hidden and not selected until asked for:\n%s", v)
	}
	send(t, m, key("f"))
	if v := m.View(); !strings.Contains(v, "me/forked") || !strings.Contains(v, "2 of 3 selected") {
		t.Fatalf("shown forks are not selected by themselves:\n%s", v)
	}
	send(t, m, key("f"))

	send(t, m, key("enter"))
	if m.scr != scrReport || m.final || m.todoBranches != 1 || m.code != 1 {
		t.Fatalf("after the check: scr=%d final=%v todo=%d code=%d", m.scr, m.final, m.todoBranches, m.code)
	}
	if v := m.View(); !strings.Contains(v, "me/app @ main") || !strings.Contains(v, "Press Enter to fix and push 1 branch in 1 repository.") {
		t.Fatalf("report:\n%s", v)
	}
	// nothing is pushed without an explicit yes
	send(t, m, key("enter"))
	if m.scr != scrConfirm || len(f.passes) != 1 {
		t.Fatalf("enter must ask first: scr=%d passes=%v", m.scr, f.passes)
	}
	send(t, m, key("n"))
	send(t, m, key("enter"))
	send(t, m, key("x"))
	if m.scr != scrConfirm || len(f.passes) != 1 {
		t.Fatalf("only y confirms: scr=%d passes=%v", m.scr, f.passes)
	}
	send(t, m, key("y"))
	if got := strings.Join(f.passes, "; "); got != "dry me/app me/lib; apply me/app" {
		t.Fatalf("passes: %s", got)
	}
	if v := m.View(); m.scr != scrReport || !m.final || m.code != 0 || !strings.Contains(v, "The fixes are pushed") || !strings.Contains(v, "Rotate this token") {
		t.Fatalf("after the fix: final=%v code=%d\n%s", m.final, m.code, v)
	}
	if !send(t, m, key("enter")) {
		t.Fatal("enter on the final report quits")
	}
}

func TestSelectionAndCleanResult(t *testing.T) {
	f := &fake{}
	m := signedIn(t, f)
	send(t, m, key("n"))
	send(t, m, key("enter"))
	if m.scr != scrRepos {
		t.Fatal("nothing selected: enter does nothing")
	}
	send(t, m, key("/"))
	send(t, m, key("lib"))
	send(t, m, key("enter"))
	send(t, m, key(" "))
	send(t, m, key("esc"))
	send(t, m, key("enter"))
	if got := strings.Join(f.passes, "; "); got != "dry me/lib" {
		t.Fatalf("only the ticked repository is checked: %s", got)
	}
	if v := m.View(); !m.final || m.code != 0 || !strings.Contains(v, "No PolinRider files were found") {
		t.Fatalf("clean report: final=%v code=%d\n%s", m.final, m.code, v)
	}
}

func TestStopDuringPass(t *testing.T) {
	m := signedIn(t, &fake{})
	block := make(chan struct{})
	m.be.run = func(ctx context.Context, _ string, repos []github.Repo, _ bool, emit func(ghclean.Event)) []remediate.Result {
		emit(ghclean.RepoStarted{Total: len(repos), Repo: repos[0]})
		<-block
		return nil
	}
	_, cmd := m.Update(key("enter"))
	m.Update(cmd()) // RepoStarted
	if m.scr != scrRun || !m.rows[0].started {
		t.Fatal("the pass should be running")
	}
	m.Update(key("q"))
	if !m.stopping || m.ctx.Err() == nil || !strings.Contains(m.View(), "Stopping") {
		t.Fatalf("q stops the pass and says so:\n%s", m.View())
	}
	close(block)
	if !send(t, m, waitFor(m.events)()) || !m.interrupted {
		t.Fatal("the program ends once the pass has wound down")
	}
}
