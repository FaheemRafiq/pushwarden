package ghclean

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/pushwarden/internal/github"
	"github.com/FaheemRafiq/pushwarden/internal/iocs"
	"github.com/FaheemRafiq/pushwarden/internal/platform"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
	"github.com/FaheemRafiq/pushwarden/internal/testfixtures"
)

func TestListReposFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"full_name":"me/a","owner":{"login":"me"},"permissions":{"push":true}},
		                {"full_name":"me/f","fork":true,"owner":{"login":"me"},"permissions":{"push":true}},
		                {"full_name":"Org/old","archived":true,"owner":{"login":"Org"},"permissions":{"push":true}},
		                {"full_name":"Org/b","owner":{"login":"Org"},"permissions":{"push":true}}]`)
	}))
	defer srv.Close()
	gh := github.New("tok", srv.URL)
	names := func(f Filter) (string, int) {
		repos, hidden, err := ListRepos(context.Background(), gh, f)
		if err != nil {
			t.Fatal(err)
		}
		var n []string
		for _, r := range repos {
			n = append(n, r.FullName)
		}
		return strings.Join(n, " "), hidden
	}
	if got, hidden := names(Filter{}); got != "me/a Org/b" || hidden != 2 {
		t.Fatalf("default: %q hidden=%d", got, hidden)
	}
	if got, hidden := names(Filter{Forks: true, Archived: true}); got != "me/a me/f Org/old Org/b" || hidden != 0 {
		t.Fatalf("everything: %q hidden=%d", got, hidden)
	}
	if got, _ := names(Filter{Owners: []string{"org"}, Archived: true}); got != "Org/old Org/b" {
		t.Fatalf("owner, case-insensitive: %q", got)
	}
}

func TestSummarize(t *testing.T) {
	b := func(name, status string) remediate.Branch { return remediate.Branch{Name: name, Status: status} }
	earlier := remediate.Branch{Name: "old", Status: remediate.StatusPushed, Resumed: true}
	results := []remediate.Result{
		{Repo: "me/a", Branches: []remediate.Branch{b("main", remediate.StatusClean), b("dev", remediate.StatusInfected), earlier}},
		{Repo: "me/b", Branches: []remediate.Branch{b("main", remediate.StatusManual)}},
	}
	s := Summarize(results, false)
	if s.Repos != 2 || s.Clean != 1 || s.Infected != 1 || s.Pushed != 1 || s.PushedEarlier != 1 || s.Earlier != 1 || s.Manual != 1 || s.PushedNow() != 0 {
		t.Fatalf("%+v", s)
	}
	if len(s.ManualList) != 1 || s.ManualList[0] != "me/b @ main" {
		t.Fatalf("manual list: %v", s.ManualList)
	}
	if s.ExitCode() != 1 {
		t.Fatal("a dry run with infected branches exits 1")
	}
	if Summarize(results, true).ExitCode() != 0 {
		t.Fatal("an apply pass without failures exits 0")
	}
	failed := []remediate.Result{{Repo: "me/z", Error: "boom"}, {Repo: "me/a", Branches: []remediate.Branch{{Name: "main", Status: remediate.StatusPushFailed, Error: "protected"}}}}
	s = Summarize(failed, true)
	if s.ExitCode() != 1 || s.Errors != 1 || s.Failed != 1 || strings.Join(s.FailedList, "|") != "me/a @ main: protected|me/z: boom" {
		t.Fatalf("%+v", s)
	}
	todo, n := Infected([]github.Repo{{FullName: "me/a"}, {FullName: "me/b"}}, results)
	if n != 1 || len(todo) != 1 || todo[0].FullName != "me/a" {
		t.Fatalf("infected: %v %d", todo, n)
	}
}

// A dry pass, the apply pass over what it found, then a later run: the events
// a front end sees, with real git and a local "remote".
func TestSessionEvents(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git missing")
	}
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git(root, "init", "--bare", "-q", origin)
	work := filepath.Join(root, "w")
	git(root, "clone", "-q", origin, work)
	os.WriteFile(filepath.Join(work, "postcss.config.mjs"), []byte(testfixtures.InfectedPostcss), 0o644)
	git(work, "add", "-A")
	git(work, "commit", "-q", "-m", "x")
	git(work, "push", "-q", "origin", "main")

	data := t.TempDir()
	i, err := iocs.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{Token: "tok", API: "https://api.example.test", Author: "T <t@t>", Version: "test",
		State: remediate.LoadState(data), P: platform.New(), I: i, DataDir: data}
	repos := []github.Repo{{FullName: "me/app", CloneURL: origin, DefaultBranch: "main"}}
	pass := func(apply bool) (kinds string, branch remediate.Branch, results []remediate.Result) {
		results = sess.Run(context.Background(), repos, apply, func(e Event) {
			switch e := e.(type) {
			case RepoStarted:
				if e.Index != 0 || e.Total != 1 || e.Repo.FullName != "me/app" {
					t.Errorf("RepoStarted %+v", e)
				}
				kinds += "S"
			case BranchDone:
				branch = e.Branch
				kinds += "B"
			case RepoDone:
				kinds += "D"
			}
		})
		return
	}

	kinds, br, results := pass(false)
	if kinds != "SBD" || br.Name != "main" || br.Status != remediate.StatusInfected {
		t.Fatalf("dry pass: %s %+v", kinds, br)
	}
	if todo, n := Infected(repos, results); n != 1 || len(todo) != 1 || Summarize(results, false).ExitCode() != 1 {
		t.Fatalf("dry pass results: %+v", results)
	}
	kinds, br, results = pass(true)
	if kinds != "SBD" || br.Status != remediate.StatusPushed || Summarize(results, true).PushedNow() != 1 {
		t.Fatalf("apply pass: %s %+v", kinds, br)
	}
	// nothing moved since: the remembered result is reported, still as a branch event
	kinds, br, results = pass(false)
	if s := Summarize(results, false); kinds != "SBD" || !br.Resumed || s.PushedEarlier != 1 || s.ExitCode() != 0 {
		t.Fatalf("resumed pass: %s %+v %+v", kinds, br, s)
	}
}

func TestParseGHAccounts(t *testing.T) {
	status := []byte(`{"hosts":{
		"github.com":[{"state":"success","active":false,"login":"work"},{"state":"success","active":true,"login":"me"},{"state":"error","active":false,"login":"expired"}],
		"ghe.example.com":[{"state":"success","active":true,"login":"corp"}]}}`)
	if got := strings.Join(parseGHAccounts(status, "github.com"), " "); got != "me work" {
		t.Fatalf("active first, unusable logins left out: %q", got)
	}
	if got := strings.Join(parseGHAccounts(status, "ghe.example.com"), " "); got != "corp" {
		t.Fatalf("other server: %q", got)
	}
	if got := parseGHAccounts([]byte("unknown flag: --json"), "github.com"); got != nil {
		t.Fatalf("an old gh lists nothing: %v", got)
	}
	if ghHost("https://api.github.com") != "github.com" || ghHost("https://ghe.example.com/api/v3") != "ghe.example.com" {
		t.Fatal("gh host names")
	}
}

func TestSSHHostsAndGreeting(t *testing.T) {
	cfg := `# personal
Host github-personal
    HostName github.com
    IdentityFile ~/.ssh/id_personal

Host github-work gh-w
    Hostname=GitHub.com
Host gitlab
    HostName gitlab.com
Host *.corp !bastion
    HostName github.com
Match host foo
    HostName github.com
`
	if got := strings.Join(sshGitHubHosts(cfg), " "); got != "github-personal github-work gh-w github.com" {
		t.Fatalf("hosts: %q", got)
	}
	if got := strings.Join(sshGitHubHosts(""), " "); got != "github.com" {
		t.Fatalf("no config: %q", got)
	}
	for out, want := range map[string]string{
		"Hi FaheemRafiq! You've successfully authenticated, but GitHub does not provide shell access.": "FaheemRafiq",
		"Hi acme/website! You've successfully authenticated":                                           "", // a deploy key is not an account
		"git@github.com: Permission denied (publickey).":                                               "",
	} {
		if got := sshGreetingLogin(out); got != want {
			t.Errorf("%q: got %q, want %q", out, got, want)
		}
	}
}

func TestParseSSHRemote(t *testing.T) {
	for u, want := range map[string]string{
		"git@github-work:acme/api.git":         "github-work acme/api",
		"git@github.com:me/site":               "github.com me/site",
		"ssh://git@github-work/acme/api.git":   "github-work acme/api",
		"ssh://git@github.com:22/me/dot.files": "github.com me/dot.files",
		"https://github.com/me/site.git":       "",
		"git@github-work:acme/api/extra.git":   "",
		"/home/me/origin.git":                  "",
		"git@github-work:../../etc/passwd":     "",
	} {
		host, full, ok := parseSSHRemote(u)
		got := ""
		if ok {
			got = host + " " + full
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", u, got, want)
		}
	}
}

func TestSSHRepos(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the public listing must not send a token")
		}
		if r.URL.Path != "/users/worker/repos" {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, `[{"full_name":"worker/api","name":"api","default_branch":"trunk","owner":{"login":"worker"}},
		                {"full_name":"worker/oss","name":"oss","default_branch":"main","fork":true,"owner":{"login":"worker"}}]`)
	}))
	defer srv.Close()
	root := t.TempDir()
	clone := func(name, config string) string {
		d := filepath.Join(root, name)
		os.MkdirAll(filepath.Join(d, ".git"), 0o755)
		os.WriteFile(filepath.Join(d, ".git", "config"), []byte(config), 0o644)
		return d
	}
	dirs := []string{
		clone("a", "[remote \"origin\"]\n\turl = git@github-work:acme/secret.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"),
		clone("b", "[remote \"origin\"]\n\turl = git@github-personal:me/blog.git\n"), // the other account
		clone("c", "[remote \"origin\"]\n\turl = git@GitHub-Work:worker/api.git\n[remote \"up\"]\n\turl = https://github.com/x/y.git\n"),
		filepath.Join(root, "missing"),
	}
	a := Account{Login: "worker", SSHHost: "github-work"}
	repos, from := SSHRepos(context.Background(), github.New("", srv.URL), a, dirs)
	var got []string
	for _, r := range repos {
		got = append(got, r.FullName+"="+from[strings.ToLower(r.FullName)]+"@"+r.CloneURL)
	}
	want := "acme/secret=local clone@git@github-work:acme/secret.git worker/api=local clone@git@github-work:worker/api.git worker/oss=public@git@github-work:worker/oss.git"
	if strings.Join(got, " ") != want {
		t.Fatalf("got  %s\nwant %s", strings.Join(got, " "), want)
	}
	if !repos[2].Fork || repos[2].DefaultBranch != "main" {
		t.Fatalf("public details are kept: %+v", repos[2])
	}
}
