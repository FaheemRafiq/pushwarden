// Package remediate cleans PolinRider artifacts out of every branch of a
// remote repository: bare clone, one worktree per branch, scan, strip or
// delete, commit, push. It never force-pushes and never rewrites history.
package remediate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/scan"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

// TokenEnv is where the askpass helper reads the token from.
const TokenEnv = "THREATSCAN_GIT_TOKEN"

type Options struct {
	Apply      bool     // commit and push; false = report what would change
	Token      string   // GitHub token handed to git through AskPass
	AskPass    string   // program git runs for credentials (this binary's __askpass)
	Author     string   // "Name <email>" for the fix commits; default: git config, then ThreatScan
	Branches   []string // glob filters on branch names; empty = every branch
	WorkDir    string   // where clones live; "" = system temp
	KeepClones bool     // leave the clones on disk for inspection
	Version    string   // ThreatScan version, mentioned in the commit message
	Log        func(string)
}

// Status values for a branch.
const (
	StatusClean      = "clean"       // nothing to do
	StatusInfected   = "infected"    // dry run: fixes are needed
	StatusPushed     = "pushed"      // fixed and pushed
	StatusPushFailed = "push-failed" // fixed locally, remote refused (protected branch, race, permission)
	StatusManual     = "manual"      // HIGH/CRITICAL findings that ThreatScan cannot fix automatically
	StatusError      = "error"
)

type Branch struct {
	Name     string              `json:"name"`
	Status   string              `json:"status"`
	Findings []*findings.Finding `json:"findings,omitempty"`
	Fixed    []string            `json:"fixed,omitempty"` // "path: action"
	Commit   string              `json:"commit,omitempty"`
	Error    string              `json:"error,omitempty"`
}

type Result struct {
	Repo     string              `json:"repo"`
	Clone    string              `json:"clone,omitempty"`
	Branches []Branch            `json:"branches"`
	History  []*findings.Finding `json:"history,omitempty"` // repo-wide git-history findings
	Error    string              `json:"error,omitempty"`
	Duration float64             `json:"duration_s"`
}

// Counts summarises a result for tables.
func (r Result) Counts() (clean, infected, pushed, failed, manual int) {
	for _, b := range r.Branches {
		switch b.Status {
		case StatusClean:
			clean++
		case StatusInfected:
			infected++
		case StatusPushed:
			pushed++
		case StatusPushFailed, StatusError:
			failed++
		case StatusManual:
			manual++
		}
	}
	return
}

type Remediator struct {
	Opts    Options
	P       *platform.Info
	I       *iocs.IOCs
	DataDir string
	ui      *ui.UI
}

func New(o Options, p *platform.Info, i *iocs.IOCs, dataDir string) *Remediator {
	if o.Log == nil {
		o.Log = func(string) {}
	}
	return &Remediator{Opts: o, P: p, I: i, DataDir: dataDir, ui: ui.New(true, true)}
}

// ── git plumbing ─────────────────────────────────────────────────────────────

type gitError struct {
	args   []string
	stderr string
	err    error
}

func (e *gitError) Error() string {
	msg := strings.TrimSpace(e.stderr)
	if msg == "" {
		msg = e.err.Error()
	}
	return "git " + e.args[0] + ": " + lastLines(msg, 3)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func (m *Remediator) git(ctx context.Context, dir string, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// A malicious global config must not run code while we work: no hooks, no fsmonitor,
	// and no stored credential helper that could point git at a different account.
	full := []string{"-c", "core.hooksPath=" + noHooksDir(), "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never"}
	if m.Opts.Token != "" {
		full = append(full, "-c", "credential.helper=")
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	if dir != "" {
		cmd.Dir = dir
	}
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	if m.Opts.Token != "" && m.Opts.AskPass != "" {
		env = append(env, "GIT_ASKPASS="+m.Opts.AskPass, TokenEnv+"="+m.Opts.Token)
	}
	cmd.Env = env
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("timed out after %s", timeout)
		}
		return out.String(), &gitError{args: args, stderr: scrub(errb.String(), m.Opts.Token), err: err}
	}
	return out.String(), nil
}

var noHooks string

func noHooksDir() string {
	if noHooks == "" {
		d, err := os.MkdirTemp("", "threatscan-nohooks-")
		if err != nil {
			d = os.TempDir()
		}
		noHooks = d
	}
	return noHooks
}

// scrub removes the token from anything we might print.
func scrub(s, token string) string {
	if token != "" {
		s = strings.ReplaceAll(s, token, "***")
	}
	return s
}

var unsafeRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string {
	s = unsafeRe.ReplaceAllString(s, "_")
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func matchBranch(globs []string, name string) bool {
	if len(globs) == 0 {
		return true
	}
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok || g == name {
			return true
		}
	}
	return false
}

// identity returns the env that names the author/committer of fix commits.
func (m *Remediator) identity(ctx context.Context, dir string) []string {
	name, email := "ThreatScan", "threatscan@users.noreply.github.com"
	if a := strings.TrimSpace(m.Opts.Author); a != "" {
		if i := strings.LastIndex(a, "<"); i > 0 && strings.HasSuffix(a, ">") {
			name, email = strings.TrimSpace(a[:i]), strings.TrimSpace(a[i+1:len(a)-1])
		} else {
			name = a
		}
	} else {
		n, _ := m.git(ctx, dir, 10*time.Second, "config", "--get", "user.name")
		e, _ := m.git(ctx, dir, 10*time.Second, "config", "--get", "user.email")
		if strings.TrimSpace(n) != "" && strings.TrimSpace(e) != "" {
			name, email = strings.TrimSpace(n), strings.TrimSpace(e)
		}
	}
	return []string{"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + email, "GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + email}
}

// ── the loop ─────────────────────────────────────────────────────────────────

// Run cleans one repository. cloneURL may be a local path (tests).
func (m *Remediator) Run(ctx context.Context, fullName, cloneURL, defaultBranch string) Result {
	start := time.Now()
	res := Result{Repo: fullName}
	defer func() { res.Duration = time.Since(start).Seconds() }()

	parent := m.Opts.WorkDir
	if parent == "" {
		parent = os.TempDir()
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		res.Error = err.Error()
		return res
	}
	base, err := os.MkdirTemp(parent, "threatscan-"+safeName(fullName)+"-")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if m.Opts.KeepClones {
		res.Clone = base
	} else {
		defer os.RemoveAll(base)
	}
	bare := filepath.Join(base, "repo.git")
	m.Opts.Log("cloning " + fullName)
	if _, err := m.git(ctx, "", 20*time.Minute, "clone", "--bare", "--quiet", "--no-tags", "--", cloneURL, bare); err != nil {
		res.Error = "clone failed: " + err.Error()
		return res
	}
	// bare clones keep hooks samples only; make sure nothing runs on commit
	_ = os.RemoveAll(filepath.Join(bare, "hooks"))

	out, err := m.git(ctx, bare, 30*time.Second, "for-each-ref", "--format=%(refname:short)", "refs/heads/")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var branches []string
	for _, b := range strings.Split(strings.TrimSpace(out), "\n") {
		if b = strings.TrimSpace(b); b != "" && matchBranch(m.Opts.Branches, b) {
			branches = append(branches, b)
		}
	}
	sort.SliceStable(branches, func(i, j int) bool {
		return branches[i] == defaultBranch && branches[j] != defaultBranch
	})
	if len(branches) == 0 {
		res.Error = "no branches matched"
		return res
	}

	hist := scan.NewRepo(bare, m.ui, m.I)
	res.History = hist.CheckHistoryPayloads(bare)

	pr := protect.New(m.P, m.I, m.DataDir, nil, !m.Opts.Apply)
	ident := m.identity(ctx, bare)
	for _, b := range branches {
		if ctx.Err() != nil {
			res.Branches = append(res.Branches, Branch{Name: b, Status: StatusError, Error: ctx.Err().Error()})
			continue
		}
		res.Branches = append(res.Branches, m.branch(ctx, fullName, base, bare, b, pr, ident))
	}
	return res
}

func (m *Remediator) branch(ctx context.Context, fullName, base, bare, name string, pr *protect.Protector, ident []string) Branch {
	br := Branch{Name: name, Status: StatusClean}
	m.Opts.Log(fullName + " @ " + name)
	wt := filepath.Join(base, "wt", safeName(name))
	if _, err := m.git(ctx, bare, 5*time.Minute, "worktree", "add", "--detach", "--quiet", wt, "refs/heads/"+name); err != nil {
		br.Status, br.Error = StatusError, err.Error()
		return br
	}
	defer m.git(context.Background(), bare, 2*time.Minute, "worktree", "remove", "--force", wt)

	r := scan.NewRepo(wt, m.ui, m.I)
	fs := r.ScanRepo(wt, false)
	fs = append(fs, r.CheckPayloadCompanions(wt)...)
	fixable := 0
	for _, f := range fs {
		if protect.NeedsDecision(f) {
			fixable++
		}
	}
	for _, f := range fs {
		if f.Severity >= findings.Warning {
			br.Findings = append(br.Findings, relFinding(f, wt))
		}
	}
	if fixable == 0 {
		if findings.AnyAtLeast(fs, findings.High) {
			br.Status = StatusManual
		}
		return br
	}

	acted := pr.Respond(fs, false, true, nil)
	for _, f := range acted {
		br.Fixed = append(br.Fixed, rel(f.Path, wt)+": "+shortAction(f))
	}
	if !m.Opts.Apply {
		br.Status = StatusInfected
		return br
	}
	if len(acted) == 0 {
		br.Status, br.Error = StatusError, "response failed for every finding"
		return br
	}

	if _, err := m.git(ctx, wt, 2*time.Minute, "add", "-A", "--", "."); err != nil {
		br.Status, br.Error = StatusError, err.Error()
		return br
	}
	st, _ := m.git(ctx, wt, time.Minute, "status", "--porcelain")
	if strings.TrimSpace(st) == "" {
		br.Status, br.Error = StatusError, "files were changed on disk but git sees no difference"
		return br
	}
	msg := m.commitMessage(name, acted, wt)
	if err := m.commit(ctx, wt, msg, ident); err != nil {
		br.Status, br.Error = StatusError, err.Error()
		return br
	}
	sha, _ := m.git(ctx, wt, 30*time.Second, "rev-parse", "--short", "HEAD")
	br.Commit = strings.TrimSpace(sha)
	if _, err := m.git(ctx, wt, 10*time.Minute, "push", "--quiet", "origin", "HEAD:refs/heads/"+name); err != nil {
		br.Status, br.Error = StatusPushFailed, err.Error()
		return br
	}
	br.Status = StatusPushed
	return br
}

func (m *Remediator) commit(ctx context.Context, wt, msg string, ident []string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-c", "core.hooksPath="+noHooksDir(), "-c", "commit.gpgsign=false",
		"commit", "--quiet", "--no-verify", "-F", "-")
	cmd.Dir = wt
	cmd.Env = append(append(os.Environ(), ident...), "GIT_TERMINAL_PROMPT=0")
	cmd.Stdin = strings.NewReader(msg)
	var errb strings.Builder
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return errors.New("git commit: " + lastLines(errb.String(), 3))
	}
	return nil
}

func (m *Remediator) commitMessage(branch string, acted []*findings.Finding, wt string) string {
	var b strings.Builder
	b.WriteString("security: remove PolinRider malware\n\n")
	fmt.Fprintf(&b, "ThreatScan %s cleaned branch %s:\n", m.Opts.Version, branch)
	for _, f := range acted {
		fmt.Fprintf(&b, "  - %s  %s (%s)\n", prompt.ThreatName(f), rel(f.Path, wt), shortAction(f))
	}
	b.WriteString("\nThis is a normal commit on top of the branch; history was not rewritten.\n")
	b.WriteString("Treat every secret this repository or its CI had access to as leaked and rotate it.\n")
	b.WriteString("https://github.com/FaheemRafiq/threatscan\n")
	return b.String()
}

func shortAction(f *findings.Finding) string {
	a := strings.TrimPrefix(f.Action, "would have: ")
	switch {
	case strings.Contains(a, "whole file quarantined") || strings.HasPrefix(a, "quarantined"):
		return "deleted"
	case strings.HasPrefix(a, "removed") && strings.Contains(a, "line(s)"):
		return "entries removed"
	case strings.HasPrefix(a, "removed"):
		return "payload stripped"
	case a == "":
		return "no action"
	}
	if i := strings.Index(a, " (original"); i > 0 {
		a = a[:i]
	}
	return a
}

func rel(p, root string) string {
	if r, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return p
}

func relFinding(f *findings.Finding, root string) *findings.Finding {
	c := *f
	c.Path = rel(f.Path, root)
	c.Remediation = strings.ReplaceAll(c.Remediation, root+string(filepath.Separator), "")
	c.Details = strings.ReplaceAll(c.Details, root+string(filepath.Separator), "")
	return &c
}
