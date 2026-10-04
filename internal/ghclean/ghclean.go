// Package ghclean drives github-clean for any front end. The command line and
// the terminal UI both run it; they differ only in how they show what happens.
package ghclean

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/FaheemRafiq/pushwarden/internal/github"
	"github.com/FaheemRafiq/pushwarden/internal/iocs"
	"github.com/FaheemRafiq/pushwarden/internal/journal"
	"github.com/FaheemRafiq/pushwarden/internal/platform"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
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

// Account is one GitHub login a run can sign in with.
type Account struct {
	Login  string // "" until GitHub has confirmed the token (environment tokens)
	Source string // where the token came from, for display
	Token  string
}

// Accounts lists every token the user already has for the GitHub server
// behind api: $GITHUB_TOKEN, $GH_TOKEN, then each account logged in to the gh
// CLI, the active one first.
func Accounts(api string) []Account {
	var out []Account
	add := func(a Account) {
		for _, have := range out {
			if have.Token == a.Token {
				return
			}
		}
		if a.Token != "" {
			out = append(out, a)
		}
	}
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		add(Account{Source: "$" + k, Token: strings.TrimSpace(os.Getenv(k))})
	}
	gh, err := exec.LookPath("gh")
	if err != nil {
		return out
	}
	token := func(args ...string) string {
		b, _ := exec.Command(gh, append([]string{"auth", "token"}, args...)...).Output()
		return strings.TrimSpace(string(b))
	}
	host := ghHost(api)
	status, _ := exec.Command(gh, "auth", "status", "--json", "hosts").Output()
	logins := parseGHAccounts(status, host)
	for _, l := range logins {
		add(Account{Login: l, Source: "gh login", Token: token("--hostname", host, "--user", l)})
	}
	if len(logins) == 0 { // a gh too old to list its accounts
		add(Account{Source: "gh login", Token: token()})
	}
	return out
}

// ghHost is the name the gh CLI knows the server behind api by.
func ghHost(api string) string {
	if h := APIHost(api); h != "api.github.com" {
		return h
	}
	return "github.com"
}

// parseGHAccounts reads `gh auth status --json hosts` and returns the logins
// that are usable on host, the active one first.
func parseGHAccounts(status []byte, host string) []string {
	var st struct {
		Hosts map[string][]struct {
			State  string `json:"state"`
			Active bool   `json:"active"`
			Login  string `json:"login"`
		} `json:"hosts"`
	}
	if json.Unmarshal(status, &st) != nil {
		return nil
	}
	var out []string
	for _, a := range st.Hosts[host] {
		switch {
		case a.State != "success" || a.Login == "":
		case a.Active:
			out = append([]string{a.Login}, out...)
		default:
			out = append(out, a.Login)
		}
	}
	return out
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
	Version string // PushWarden version

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
