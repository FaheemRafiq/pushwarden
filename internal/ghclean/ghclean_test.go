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
