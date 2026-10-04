package ghclean

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/github"
)

// An SSH account is a login git already has: a key GitHub accepts, reached
// through github.com or a host alias in the ssh config. SSH can clone and push
// a repository that is named, but it cannot list repositories, so the list is
// put together from local clones, the public repositories and what is typed.

// sshGitHubHosts returns the ssh hosts that lead to github.com: every alias in
// the ssh config text whose HostName is github.com, then github.com itself.
func sshGitHubHosts(config string) []string {
	var out, block []string
	seen := map[string]bool{}
	add := func(h string) {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sc := bufio.NewScanner(strings.NewReader(config))
	for sc.Scan() {
		f := strings.Fields(strings.Replace(strings.TrimSpace(sc.Text()), "=", " ", 1))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "host":
			block = block[:0]
			for _, h := range f[1:] {
				if !strings.ContainsAny(h, "*?!") { // patterns are not hosts to connect to
					block = append(block, h)
				}
			}
		case "match":
			block = block[:0]
		case "hostname":
			if strings.EqualFold(f[1], "github.com") {
				for _, h := range block {
					add(h)
				}
			}
		}
	}
	add("github.com")
	return out
}

// GitHub greets a user key with "Hi NAME! You've successfully authenticated";
// a deploy key gets "Hi owner/repo!", which is not an account.
var sshGreeting = regexp.MustCompile(`Hi ([A-Za-z0-9][A-Za-z0-9-]*)!`)

func sshGreetingLogin(out string) string {
	if m := sshGreeting.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// sshLogin asks GitHub who the key behind host belongs to. BatchMode keeps ssh
// from stopping to ask for a passphrase or about an unknown host: a login
// that would need a question is not a usable one.
func sshLogin(ctx context.Context, host string) string {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "git@"+host).CombinedOutput()
	return sshGreetingLogin(string(out))
}

// SSHAccounts lists the GitHub logins git can already use over SSH, one per
// login, in the order of the ssh config.
func SSHAccounts(ctx context.Context) []Account {
	if _, err := exec.LookPath("ssh"); err != nil {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	cfg, _ := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	hosts := sshGitHubHosts(string(cfg))
	logins := make([]string, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logins[i] = sshLogin(ctx, h)
		}()
	}
	wg.Wait()
	var out []Account
	seen := map[string]bool{}
	for i, l := range logins {
		if l != "" && !seen[strings.ToLower(l)] {
			seen[strings.ToLower(l)] = true
			out = append(out, Account{Login: l, Source: "SSH (" + hosts[i] + ")", SSHHost: hosts[i]})
		}
	}
	return out
}

// BatchSSH is the ssh command git should run for an SSH account: the user's
// own (GIT_SSH_COMMAND, else core.sshCommand, else ssh) with BatchMode, so a
// clone or push fails instead of stopping to ask something.
func BatchSSH() string {
	base := strings.TrimSpace(os.Getenv("GIT_SSH_COMMAND"))
	if base == "" {
		if out, err := exec.Command("git", "config", "--global", "--get", "core.sshCommand").Output(); err == nil {
			base = strings.TrimSpace(string(out))
		}
	}
	if base == "" {
		base = "ssh"
	}
	return base + " -o BatchMode=yes"
}

// parseSSHRemote splits an SSH remote URL: "git@host:owner/name.git" or
// "ssh://git@host[:port]/owner/name.git".
func parseSSHRemote(u string) (host, fullName string, ok bool) {
	u = strings.TrimSpace(u)
	var path string
	switch {
	case strings.HasPrefix(u, "ssh://"):
		rest := strings.TrimPrefix(u, "ssh://")
		if i := strings.Index(rest, "@"); i >= 0 {
			rest = rest[i+1:]
		}
		host, path, ok = strings.Cut(rest, "/")
		host, _, _ = strings.Cut(host, ":")
	case strings.Contains(u, "://"):
		return "", "", false
	default:
		if i := strings.Index(u, "@"); i >= 0 {
			u = u[i+1:]
		}
		host, path, ok = strings.Cut(u, ":")
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if !ok || host == "" || !ValidRepoName(path) {
		return "", "", false
	}
	return host, path, true
}

var repoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)

// ValidRepoName reports whether s looks like "owner/name".
func ValidRepoName(s string) bool { return repoName.MatchString(s) }

// remoteURLs reads the remote URLs out of a repository's git config file. The
// file is read as text: nothing in the repository is run.
func remoteURLs(repoDir string) []string {
	b, err := os.ReadFile(filepath.Join(repoDir, ".git", "config"))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && strings.EqualFold(strings.TrimSpace(k), "url") {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

// SSHRepo builds the repository entry an SSH account cleans fullName through.
func SSHRepo(a Account, fullName string) github.Repo {
	owner, name, _ := strings.Cut(fullName, "/")
	return github.Repo{FullName: fullName, Owner: owner, Name: name, Push: true,
		CloneURL: "git@" + a.SSHHost + ":" + fullName + ".git"}
}

// Where a repository listed for an SSH account was found.
const (
	FromLocal  = "local clone"
	FromPublic = "public"
	FromAdded  = "added"
)

// SSHRepos lists what can be found for an SSH account without the API: the
// clones under localRepos (repository folders) whose remote goes through the
// account's ssh host, then the account's public repositories. from tells, by
// full name, where each was found. Private repositories that are not cloned
// on this computer cannot be found; the caller lets the user add them.
func SSHRepos(ctx context.Context, gh *github.Client, a Account, localRepos []string) (repos []github.Repo, from map[string]string) {
	from = map[string]string{}
	add := func(r github.Repo, where string) {
		if k := strings.ToLower(r.FullName); from[k] == "" {
			from[k] = where
			repos = append(repos, r)
		}
	}
	for _, dir := range localRepos {
		for _, u := range remoteURLs(dir) {
			if host, full, ok := parseSSHRemote(u); ok && strings.EqualFold(host, a.SSHHost) {
				add(SSHRepo(a, full), FromLocal)
			}
		}
	}
	gh.Sleep = func(time.Duration) {} // the public listing is a bonus: never wait out a rate limit for it
	public, _ := gh.PublicRepos(ctx, a.Login)
	for _, p := range public {
		r := SSHRepo(a, p.FullName)
		r.DefaultBranch, r.Fork, r.Archived, r.HTMLURL = p.DefaultBranch, p.Fork, p.Archived, p.HTMLURL
		add(r, FromPublic)
	}
	return repos, from
}
