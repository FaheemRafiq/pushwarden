package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/ghclean"
	"github.com/FaheemRafiq/threatscan/internal/github"
	"github.com/FaheemRafiq/threatscan/internal/remediate"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func init() {
	register("github-clean", "remove PolinRider from every branch of every GitHub repo you can push to", cmdGitHubClean)
}

type ghOpts struct {
	token, api, author, json, keep string
	repos, owners, branches        stringList
	apply, sel, list, forks        bool
	archived, ci, tokenStdin       bool
	fresh, progress, noAsk         bool
}

func cmdGitHubClean(args []string) int {
	var o ghOpts
	fs := newFlags("github-clean", "[options]\n\n"+
		"Clones every repository the token can push to, checks every branch, strips or deletes\n"+
		"PolinRider files, commits and pushes (one normal commit per branch; never a force-push).\n"+
		"Without --apply it only reports what would change.\n"+
		"Progress is remembered per commit: a re-run skips branches that were verified and have not\n"+
		"moved since, so an interrupted run continues where it stopped. --fresh checks everything.")
	fs.StringVar(&o.token, "token", "", "GitHub `PAT` (or GITHUB_TOKEN / GH_TOKEN env, or the gh CLI login)")
	fs.BoolVar(&o.tokenStdin, "token-stdin", false, "read the token from standard input")
	fs.StringVar(&o.api, "api", github.DefaultAPI, "GitHub API base URL (GitHub Enterprise)")
	fs.BoolVar(&o.apply, "apply", false, "commit and push the fixes (default: dry run)")
	fs.Var(&o.repos, "repo", "only this `owner/name`, in the order given (repeatable)")
	fs.BoolVar(&o.sel, "select", false, "list the reachable repos and pick which to clean, and in what order")
	fs.BoolVar(&o.list, "list", false, "list the reachable repos and exit")
	fs.Var(&o.owners, "owner", "only repos under this user/org (repeatable)")
	fs.Var(&o.branches, "branch", "only branches matching this `glob` (repeatable; default all)")
	fs.BoolVar(&o.forks, "include-forks", false, "also clean forks")
	fs.BoolVar(&o.archived, "include-archived", false, "also clean archived repos (pushes to them fail unless unarchived)")
	fs.StringVar(&o.author, "author", "", "commit identity `\"Name <email>\"` (default: your git config)")
	fs.StringVar(&o.keep, "keep-clones", "", "keep the clones under `DIR` for inspection")
	fs.StringVar(&o.json, "json", "", "write the full result to `FILE`")
	fs.BoolVar(&o.ci, "ci", false, "no colour, no interactive prompts")
	fs.BoolVar(&o.fresh, "fresh", false, "forget the progress of earlier runs and check every branch again")
	fs.BoolVar(&o.noAsk, "no-ask", false, "after a dry run, do not offer to fix what was found")
	fs.BoolVar(&o.progress, "progress", false, "show what earlier runs already verified and exit (no token, no network)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	return runGitHubClean(mustCtx(), o)
}

func resolveToken(o ghOpts, u *ui.UI) string {
	if o.token != "" {
		return o.token
	}
	if o.tokenStdin {
		b, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimSpace(b)
	}
	token, source := ghclean.FindToken()
	switch {
	case strings.HasPrefix(source, "$"):
		u.Info("Using token from " + source)
	case source != "":
		u.Info("Using the token from " + source)
	}
	return token
}

func runGitHubClean(c *ctx, o ghOpts) int {
	u := ui.New(o.ci, false)
	if !o.ci {
		u.Banner(version, c.I.Version)
	}
	state := remediate.LoadState(c.DataDir)
	if o.progress {
		printProgress(u, state)
		return 0
	}
	if _, err := exec.LookPath("git"); err != nil {
		u.Err("git is not installed or not on PATH")
		return 2
	}
	token := resolveToken(o, u)
	if token == "" {
		u.Err("No token. Pass --token, set GITHUB_TOKEN, pipe it with --token-stdin, or log in with `gh auth login`.")
		u.Info("Fine-grained token: Repository permissions > Contents: Read and write, on the repos to clean.")
		u.Info("Classic token: scope `repo`.")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	gh := github.New(token, o.api)
	login, err := gh.Viewer(ctx)
	if err != nil {
		u.Err(err.Error())
		return 2
	}
	u.Info("Authenticated as " + login)

	repos, err := pickRepos(ctx, gh, o, u)
	if err != nil {
		u.Err(err.Error())
		return 2
	}
	if len(repos) == 0 {
		u.Warn("No repositories selected.")
		return 0
	}
	if o.list {
		printRepoList(u, repos)
		return 0
	}

	mode := "DRY RUN: nothing will be committed or pushed. Re-run with --apply to fix."
	if o.apply {
		mode = "APPLY: fixes are committed and pushed to every infected branch."
	}
	u.Section("GITHUB CLEAN")
	u.P("  %s", u.C("BOLD", mode))
	u.P("  %d repositories, branches: %s", len(repos), orAll(o.branches))
	if o.fresh {
		state.Reset()
		u.Info("--fresh: earlier progress is forgotten, every branch is checked.")
	} else if repos, branches := ghclean.ProgressTotals(state); branches > 0 {
		u.Info(fmt.Sprintf("Resuming: %d branches in %d repositories were verified by earlier runs. Only branches that changed since, or were not finished, are checked. --fresh checks everything.", branches, repos))
	}
	state.PruneClones(time.Duration(c.Cfg.CloneKeepDays)*24*time.Hour, int64(c.Cfg.CloneKeepMB)<<20, false)
	sess := &ghclean.Session{
		Token: token, API: o.api, Author: o.author, Version: version, Branches: o.branches, WorkDir: o.keep,
		State: state, CloneMaxBytes: int64(c.Cfg.CloneKeepMB) << 20, Journal: openJournal(c),
		P: c.P, I: c.I, DataDir: c.DataDir,
	}
	pass := func(apply bool, repos []github.Repo) ([]remediate.Result, time.Time) {
		start := time.Now()
		results := sess.Run(ctx, repos, apply, func(e ghclean.Event) {
			switch e := e.(type) {
			case ghclean.RepoStarted:
				u.P("")
				u.P("  %s %s", u.C("BOLD_CYAN", fmt.Sprintf("[%d/%d]", e.Index+1, e.Total)), u.C("BOLD", e.Repo.FullName))
			case ghclean.Log:
				u.Progress(e.Msg)
			case ghclean.RepoDone:
				printResult(u, e.Result, apply)
			}
		})
		if ctx.Err() != nil {
			u.Warn("Interrupted. Progress is saved: run the same command again to continue where it stopped.")
		}
		return results, start
	}

	apply := o.apply
	results, start := pass(apply, repos)
	code := summarize(u, results, apply, time.Since(start))

	// A dry run that found something: offer to fix it now. The repositories
	// with infected branches are still on disk, so nothing is cloned again.
	if todo, branches := ghclean.Infected(repos, results); !apply && branches > 0 && ctx.Err() == nil && !o.ci && !o.noAsk {
		if askApply(u, fmt.Sprintf("Fix and push these %d branches in %d repositories now?", branches, len(todo))) {
			apply = true
			u.Section("GITHUB CLEAN")
			u.P("  %s", u.C("BOLD", "APPLY: fixes are committed and pushed to the infected branches found above."))
			results, start = pass(true, todo)
			code = summarize(u, results, true, time.Since(start))
		} else {
			u.Info(fmt.Sprintf("Nothing was changed. `threatscan github-clean --apply` reuses the downloaded repositories for %d days.", c.Cfg.CloneKeepDays))
		}
	}

	if o.json != "" {
		out := struct {
			Version string             `json:"version"`
			User    string             `json:"user"`
			Apply   bool               `json:"apply"`
			Started string             `json:"started"`
			Results []remediate.Result `json:"results"`
		}{version, login, apply, start.Format(time.RFC3339), results}
		b, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(o.json, b, 0o600); err != nil {
			u.Err("Could not write JSON: " + err.Error())
			return 2
		}
		u.Info("JSON written to " + o.json)
	}
	return code
}

// askApply asks a yes/no question in the terminal; without one the answer is no.
var askApply = func(u *ui.UI, question string) bool {
	if !isTTY() {
		return false
	}
	fmt.Printf("\n  %s [y/N] ", question)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

// printProgress shows what earlier runs verified.
func printProgress(u *ui.UI, s *remediate.State) {
	ps := s.Progress()
	u.Section("GITHUB CLEAN PROGRESS")
	if len(ps) == 0 {
		u.P("  Nothing is remembered yet. A run records every branch it finishes.")
		if n, size := s.Clones(); n > 0 {
			u.P("  %d repositories with branches still to fix are kept on disk for --apply (%.0f MB); removed after a few days (clone_keep_days) or by --fresh.", n, float64(size)/(1<<20))
		}
		return
	}
	w, clean, pushed, manual := 0, 0, 0, 0
	for _, p := range ps {
		w = max(w, len(p.Repo))
	}
	u.P("  %-*s  %6s %6s %6s  %s", w, "repository", "clean", "fixed", "review", "last verified")
	for _, p := range ps {
		u.P("  %-*s  %6d %6d %6d  %s", w, p.Repo, p.Clean, p.Pushed, p.Manual, short(p.Last))
		clean, pushed, manual = clean+p.Clean, pushed+p.Pushed, manual+p.Manual
	}
	u.P("")
	u.P("  %d repositories, %d branches verified: %d clean, %d fixed and pushed, %d need manual review.", len(ps), clean+pushed+manual, clean, pushed, manual)
	u.P("  A branch is checked again when its tip commit changes, or when ThreatScan or its indicators are updated.")
	if n, size := s.Clones(); n > 0 {
		u.P("  %d repositories with branches still to fix are kept on disk for --apply (%.0f MB); removed after a few days (clone_keep_days) or by --fresh.", n, float64(size)/(1<<20))
	}
	u.P("  threatscan github-clean --fresh   forget this and check everything")
}

func orAll(b []string) string {
	if len(b) == 0 {
		return "all"
	}
	return strings.Join(b, ", ")
}

// pickRepos applies --repo / --owner / --select / fork+archive filters.
func pickRepos(ctx context.Context, gh *github.Client, o ghOpts, u *ui.UI) ([]github.Repo, error) {
	var repos []github.Repo
	if len(o.repos) > 0 {
		for _, n := range o.repos {
			r, err := gh.GetRepo(ctx, n)
			if err != nil {
				return nil, err
			}
			if !r.Push {
				return nil, fmt.Errorf("the token cannot push to %s", r.FullName)
			}
			repos = append(repos, r)
		}
		return repos, nil
	}
	u.Progress("Listing repositories the token can push to...")
	repos, skipped, err := ghclean.ListRepos(ctx, gh, ghclean.Filter{Owners: o.owners, Forks: o.forks, Archived: o.archived})
	if err != nil {
		return nil, err
	}
	if skipped > 0 && !o.list {
		u.Info(fmt.Sprintf("%d repos hidden by filters (forks, archived, --owner); use --include-forks / --include-archived", skipped))
	}
	if o.sel && !o.list {
		return selectRepos(repos, u)
	}
	return repos, nil
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

func printRepoList(u *ui.UI, repos []github.Repo) {
	u.Section("REPOSITORIES")
	w := 0
	for _, r := range repos {
		w = max(w, len(r.FullName))
	}
	for i, r := range repos {
		u.P("  %3d  %-*s  %-10s %s", i+1, w, r.FullName, r.DefaultBranch, u.C("DIM", repoTag(r)))
	}
}

// selectRepos asks in the terminal which repos to clean; the order typed is the order run.
func selectRepos(repos []github.Repo, u *ui.UI) ([]github.Repo, error) {
	if !isTTY() {
		return nil, fmt.Errorf("--select needs an interactive terminal; use --repo owner/name instead")
	}
	printRepoList(u, repos)
	u.P("")
	u.P("  Pick repositories to clean, first ones first. Examples: 3   1,4,2   5-9   all   q")
	rd := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("  Select: ")
		line, err := rd.ReadString('\n')
		if err != nil && line == "" {
			return nil, fmt.Errorf("no selection")
		}
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "q", "quit", "exit", "":
			return nil, nil
		case "all", "*":
			return repos, nil
		}
		idx, err := parseSelection(line, len(repos))
		if err != nil {
			u.Warn(err.Error())
			continue
		}
		var out []github.Repo
		for _, i := range idx {
			out = append(out, repos[i-1])
		}
		return out, nil
	}
}

// parseSelection turns "1,4-6,2" into [1 4 5 6 2] (1-based, deduplicated, order kept).
func parseSelection(s string, n int) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	add := func(i int) error {
		if i < 1 || i > n {
			return fmt.Errorf("%d is not in 1..%d", i, n)
		}
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
		return nil
	}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, e1 := strconv.Atoi(strings.TrimSpace(a))
			hi, e2 := strconv.Atoi(strings.TrimSpace(b))
			if e1 != nil || e2 != nil || lo > hi {
				return nil, fmt.Errorf("bad range %q", part)
			}
			for i := lo; i <= hi; i++ {
				if err := add(i); err != nil {
					return nil, err
				}
			}
			continue
		}
		i, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", part)
		}
		if err := add(i); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nothing selected")
	}
	return out, nil
}

func printResult(u *ui.UI, res remediate.Result, apply bool) {
	if res.Error != "" {
		u.Err(res.Error)
		return
	}
	for _, b := range res.Branches {
		var line string
		switch {
		case b.Resumed && b.Status == remediate.StatusClean:
			u.P("    %-30s %s", u.C("BOLD", b.Name), u.C("DIM", "clean, unchanged since verified "+short(b.At)))
			continue
		case b.Resumed && b.Status == remediate.StatusPushed:
			u.P("    %-30s %s", u.C("BOLD", b.Name), u.C("DIM", fmt.Sprintf("fixed earlier (%s, pushed %s), unchanged since", short(b.At), b.Commit)))
			continue
		}
		switch b.Status {
		case remediate.StatusClean:
			line = u.C("BOLD_GREEN", "clean")
		case remediate.StatusInfected:
			line = u.C("BOLD_RED", fmt.Sprintf("INFECTED  %d file(s) would be fixed", len(b.Fixed)))
		case remediate.StatusPushed:
			line = u.C("BOLD_GREEN", fmt.Sprintf("fixed  %d file(s), pushed %s", len(b.Fixed), b.Commit))
		case remediate.StatusPushFailed:
			line = u.C("BOLD_RED", "fixed locally, PUSH FAILED: "+b.Error)
		case remediate.StatusManual:
			line = u.C("BOLD_YELLOW", fmt.Sprintf("needs review  %d finding(s) ThreatScan does not auto-fix", len(b.Findings)))
		default:
			line = u.C("BOLD_RED", "error: "+b.Error)
		}
		u.P("    %-30s %s", u.C("BOLD", b.Name), line)
		for _, f := range b.Fixed {
			u.P("      - %s", f)
		}
		for _, f := range b.Findings {
			switch {
			case f.Severity >= findings.High && b.Status == remediate.StatusManual:
				u.P("      ! %s  %s", f.Title, u.C("DIM", f.Path))
			case f.Severity == findings.Warning:
				u.P("      %s %s", u.C("YELLOW", "note:"), f.Title)
				for _, l := range strings.Split(f.Remediation, "\n") {
					u.P("            %s", strings.TrimSpace(l))
				}
			}
		}
	}
	for _, f := range res.History {
		u.P("    %s %s", u.C("YELLOW", "history:"), f.Title)
	}
}

func summarize(u *ui.UI, results []remediate.Result, apply bool, d time.Duration) int {
	u.Section("SUMMARY")
	s := ghclean.Summarize(results, apply)
	clean, infected, pushed, failed, manual, errs := s.Clean, s.Infected, s.Pushed, s.Failed, s.Manual, s.Errors
	earlier, pushedEarlier, failedList, manualList := s.Earlier, s.PushedEarlier, s.FailedList, s.ManualList
	u.P("  %-24s %d", "Repositories:", len(results))
	u.P("  %-24s %d", "Branches clean:", clean)
	fixed := strconv.Itoa(pushed)
	if pushedEarlier > 0 {
		fixed += fmt.Sprintf(" (%d in earlier runs)", pushedEarlier)
	}
	if apply {
		u.P("  %-24s %s", "Branches fixed+pushed:", u.C("BOLD_GREEN", fixed))
	} else {
		u.P("  %-24s %s", "Branches infected:", u.C("BOLD_RED", strconv.Itoa(infected)))
		if pushed > 0 {
			u.P("  %-24s %s", "Branches fixed+pushed:", fixed)
		}
	}
	if earlier > 0 {
		u.P("  %-24s %d of the branches above, unchanged since", "Verified by earlier runs:", earlier)
	}
	if failed+errs > 0 {
		u.P("  %-24s %s", "Failed:", u.C("BOLD_RED", strconv.Itoa(failed+errs)))
		for _, l := range failedList {
			u.P("    x %s", l)
		}
	}
	if manual > 0 {
		u.P("  %-24s %s", "Need manual review:", u.C("BOLD_YELLOW", strconv.Itoa(manual)))
		for _, l := range manualList {
			u.P("    ! %s", l)
		}
	}
	u.P("  %-24s %.0fs", "Duration:", d.Seconds())
	u.P("")
	switch {
	case !apply && infected > 0:
		u.Warn("Dry run. Re-run with --apply to commit and push these fixes. The downloaded repositories are kept, so nothing is cloned twice.")
	case apply && pushed > pushedEarlier:
		u.OK("Pushed fixes. Now: rotate this token and every secret those repos or their CI could read,")
		u.P("      review GitHub > Settings > Applications and Deploy keys, and ask collaborators to git pull.")
		u.Info("Quarantined originals: threatscan history")
	}
	if failed+errs > 0 {
		u.Info("Protected branches: allow the push temporarily or open a PR from a clean branch. Archived repos must be unarchived first.")
	}
	return s.ExitCode()
}

// isAskpassCall recognises git invoking this binary as GIT_ASKPASS. Git passes the
// prompt as the only argument and there is no way to add a subcommand, so the
// hook is identified by the prompt text plus the token github-clean exported.
func isAskpassCall(args []string) bool {
	if os.Getenv(remediate.TokenEnv) == "" || len(args) != 1 {
		return false
	}
	p := strings.ToLower(args[0])
	return strings.HasPrefix(p, "username") || strings.HasPrefix(p, "password")
}

// askpass answers git's credential prompts with the token from the environment.
// git calls: <program> "Username for 'https://github.com': " then "Password for ...".
func askpass(args []string) int {
	prompt := strings.ToLower(strings.Join(args, " "))
	if strings.Contains(prompt, "username") {
		fmt.Println("x-access-token")
		return 0
	}
	tok := os.Getenv(remediate.TokenEnv)
	if tok == "" {
		return 1
	}
	fmt.Println(tok)
	return 0
}
