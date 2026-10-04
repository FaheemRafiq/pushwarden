// Package ghclean drives github-clean for any front end. The command line and
// the terminal UI both run it; they differ only in how they show what happens.
package ghclean

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/FaheemRafiq/threatscan/internal/github"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/journal"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/remediate"
)

// FindToken looks for a token the user already has: $GITHUB_TOKEN, $GH_TOKEN,
// then the gh CLI login. source names where it came from, for display.
func FindToken() (token, source string) {
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v, "$" + k
		}
	}
	if gh, err := exec.LookPath("gh"); err == nil {
		if out, err := exec.Command(gh, "auth", "token").Output(); err == nil && strings.TrimSpace(string(out)) != "" {
			return strings.TrimSpace(string(out)), "`gh auth token`"
		}
	}
	return "", ""
}

// Filter narrows the repositories the token can push to.
type Filter struct {
	Owners   []string // only these users/orgs; empty = all
	Forks    bool     // include forks
	Archived bool     // include archived repositories
}

// ListRepos returns the repositories the token can push to that pass the
// filter, and how many the filter hid.
func ListRepos(ctx context.Context, gh *github.Client, f Filter) (repos []github.Repo, hidden int, err error) {
	all, err := gh.ListRepos(ctx)
	if err != nil {
		return nil, 0, err
	}
	for _, r := range all {
		if r.Fork && !f.Forks || r.Archived && !f.Archived {
			continue
		}
		if len(f.Owners) > 0 && !containsFold(f.Owners, r.Owner) {
			continue
		}
		repos = append(repos, r)
	}
	return repos, len(all) - len(repos), nil
}

func containsFold(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// APIHost names the GitHub server in the progress file.
func APIHost(api string) string {
	if p, err := url.Parse(api); err == nil && p.Host != "" {
		return p.Host
	}
	return "api.github.com"
}

// ProgressTotals counts what earlier runs verified.
func ProgressTotals(s *remediate.State) (repos, branches int) {
	for _, p := range s.Progress() {
		repos++
		branches += p.Clean + p.Pushed + p.Manual
	}
	return
}

// Infected returns the repositories a dry run found infected branches in, and
// how many such branches there are.
func Infected(repos []github.Repo, results []remediate.Result) (todo []github.Repo, branches int) {
	for i, res := range results {
		if _, infected, _, _, _ := res.Counts(); infected > 0 && i < len(repos) {
			todo = append(todo, repos[i])
			branches += infected
		}
	}
	return
}

// Event is what a run reports while it works: RepoStarted, Log, BranchDone
// or RepoDone.
type Event interface{ event() }

type (
	// RepoStarted: repository Index (0-based) of Total is about to be checked.
	RepoStarted struct {
		Index, Total int
		Repo         github.Repo
	}
	// Log is a one-line note on what is happening right now.
	Log struct{ Msg string }
	// BranchDone: one branch of the current repository has its result.
	BranchDone struct {
		Repo   string
		Branch remediate.Branch
	}
	// RepoDone: the repository is finished; Result holds all its branches.
	RepoDone struct{ Result remediate.Result }
)

func (RepoStarted) event() {}
func (Log) event()         {}
func (BranchDone) event()  {}
func (RepoDone) event()    {}

// Session is one signed-in github-clean run: a dry pass, then possibly an
// apply pass over what the dry pass found.
type Session struct {
	Token   string
	API     string // GitHub API base URL
	Author  string // "Name <email>" for the fix commits
	Version string // ThreatScan version

	Branches []string // glob filters on branch names; empty = every branch
	WorkDir  string   // keep the clones here for inspection; "" = managed

	State         *remediate.State
	CloneMaxBytes int64
	Journal       *journal.Journal

	P       *platform.Info
	I       *iocs.IOCs
	DataDir string
}

// Run checks the repositories one after another, fixing and pushing when
// apply is set, and reports through emit (called on the caller's goroutine).
// It stops after the repository during which ctx was cancelled.
func (s *Session) Run(ctx context.Context, repos []github.Repo, apply bool, emit func(Event)) []remediate.Result {
	if emit == nil {
		emit = func(Event) {}
	}
	self, _ := os.Executable()
	rem := remediate.New(remediate.Options{
		Apply: apply, Token: s.Token, AskPass: self, Author: s.Author, Branches: s.Branches,
		WorkDir: s.WorkDir, KeepClones: s.WorkDir != "", Version: s.Version,
		Log:      func(m string) { emit(Log{m}) },
		OnBranch: func(repo string, b remediate.Branch) { emit(BranchDone{repo, b}) },
		State:    s.State, Host: APIHost(s.API), CloneMaxBytes: s.CloneMaxBytes,
	}, s.P, s.I, s.DataDir)
	rem.Journal = s.Journal
	var results []remediate.Result
	for i, r := range repos {
		emit(RepoStarted{i, len(repos), r})
		res := rem.Run(ctx, r.FullName, r.CloneURL, r.DefaultBranch)
		results = append(results, res)
		emit(RepoDone{res})
		if ctx.Err() != nil {
			break
		}
	}
	return results
}

// Summary is the totals of one pass.
type Summary struct {
	Apply         bool
	Repos         int
	Clean         int
	Infected      int
	Pushed        int // fixed and pushed, including PushedEarlier
	Failed        int // branches that failed or whose push was refused
	Manual        int
	Errors        int // repositories that could not be checked at all
	Earlier       int // branches taken from earlier runs, unchanged since
	PushedEarlier int
	FailedList    []string // sorted "repo @ branch: error" / "repo: error"
	ManualList    []string // "repo @ branch"
}

func Summarize(results []remediate.Result, apply bool) Summary {
	s := Summary{Apply: apply, Repos: len(results)}
	for _, r := range results {
		if r.Error != "" {
			s.Errors++
			s.FailedList = append(s.FailedList, r.Repo+": "+r.Error)
			continue
		}
		c, i, p, f, m := r.Counts()
		s.Clean, s.Infected, s.Pushed, s.Failed, s.Manual = s.Clean+c, s.Infected+i, s.Pushed+p, s.Failed+f, s.Manual+m
		for _, b := range r.Branches {
			if b.Resumed {
				s.Earlier++
				if b.Status == remediate.StatusPushed {
					s.PushedEarlier++
				}
			}
			switch b.Status {
			case remediate.StatusPushFailed, remediate.StatusError:
				s.FailedList = append(s.FailedList, r.Repo+" @ "+b.Name+": "+b.Error)
			case remediate.StatusManual:
				s.ManualList = append(s.ManualList, r.Repo+" @ "+b.Name)
			}
		}
	}
	sort.Strings(s.FailedList)
	return s
}

// PushedNow is how many branches this pass itself fixed and pushed.
func (s Summary) PushedNow() int { return s.Pushed - s.PushedEarlier }

// ExitCode: 0 = clean or all fixed, 1 = infected branches remain or failures.
func (s Summary) ExitCode() int {
	if s.Failed+s.Errors > 0 || !s.Apply && s.Infected > 0 {
		return 1
	}
	return 0
}
