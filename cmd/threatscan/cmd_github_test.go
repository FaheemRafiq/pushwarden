package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/remediate"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func TestParseSelection(t *testing.T) {
	got, err := parseSelection("3, 1-2,3", 5)
	if err != nil || len(got) != 3 || got[0] != 3 || got[1] != 1 || got[2] != 2 {
		t.Fatal(got, err)
	}
	for _, bad := range []string{"0", "6", "x", "4-2", ""} {
		if _, err := parseSelection(bad, 5); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

func TestAskpass(t *testing.T) {
	t.Setenv(remediate.TokenEnv, "sekret")
	if askpass([]string{"Username for 'https://github.com': "}) != 0 || askpass([]string{"Password for 'https://x@github.com': "}) != 0 {
		t.Fatal("askpass should succeed")
	}
	os.Unsetenv(remediate.TokenEnv)
	if askpass([]string{"Password"}) == 0 {
		t.Fatal("no token should fail")
	}
	if run([]string{"__askpass", "Username"}) != 0 {
		t.Fatal("hidden command not routed")
	}
	t.Setenv(remediate.TokenEnv, "sekret")
	if run([]string{"Username for 'https://github.com': "}) != 0 || run([]string{"Password for 'https://x@github.com': "}) != 0 {
		t.Fatal("git's bare prompt form not routed")
	}
	os.Unsetenv(remediate.TokenEnv)
	if isAskpassCall([]string{"Username for 'https://github.com': "}) {
		t.Fatal("without the token env a prompt-looking arg is not the hook")
	}
}

// Real git must be able to use the binary as GIT_ASKPASS: this is exactly what
// failed in 0.2.2 ("unable to read askpass response").
func TestGitUsesBinaryAsAskpass(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git missing")
	}
	bin := filepath.Join(t.TempDir(), "threatscan")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Skipf("cannot build binary: %v\n%s", err, out)
	}
	cmd := exec.Command("git", "-c", "credential.helper=", "credential", "fill")
	cmd.Env = append(os.Environ(), "GIT_ASKPASS="+bin, "GIT_TERMINAL_PROMPT=0", remediate.TokenEnv+"=sekret",
		"THREATSCAN_HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git credential fill: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "username=x-access-token") || !strings.Contains(string(out), "password=sekret") {
		t.Fatalf("askpass answers not used:\n%s", out)
	}
}

// End to end through the command: fake GitHub API, real git, local "remote".
func TestGitHubCleanEndToEnd(t *testing.T) {
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			fmt.Fprint(w, `{"login":"me"}`)
		case "/user/repos":
			fmt.Fprintf(w, `[{"full_name":"me/app","name":"app","default_branch":"main","clone_url":%q,"owner":{"login":"me"},"permissions":{"push":true}}]`, origin)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c, err := newCtx()
	if err != nil {
		t.Fatal(err)
	}
	c.DataDir = t.TempDir()
	js := filepath.Join(root, "out.json")
	if code := runGitHubClean(c, ghOpts{token: "tok", api: srv.URL, ci: true, json: js}); code != 1 {
		t.Fatalf("dry run should exit 1 when infected, got %d", code)
	}
	clones := filepath.Join(c.DataDir, remediate.ClonesDir)
	if ents, _ := os.ReadDir(clones); len(ents) != 1 {
		t.Fatalf("the dry run should keep the infected repository for --apply, got %d", len(ents))
	}
	if text := stdout(t, func() { runGitHubClean(c, ghOpts{progress: true, ci: true}) }); !strings.Contains(text, "1 repositories with branches still to fix are kept on disk for --apply") {
		t.Fatalf("--progress after a dry run:\n%s", text)
	}
	// --ci and --no-ask never ask; otherwise a dry run that found something offers to fix it
	asked := 0
	defer func(f func(*ui.UI, string) bool) { askApply = f }(askApply)
	askApply = func(_ *ui.UI, q string) bool { asked++; return false }
	runGitHubClean(c, ghOpts{token: "tok", api: srv.URL, ci: true})
	runGitHubClean(c, ghOpts{token: "tok", api: srv.URL, noAsk: true})
	if asked != 0 {
		t.Fatal("--ci and --no-ask must not ask")
	}
	if code := runGitHubClean(c, ghOpts{token: "tok", api: srv.URL}); code != 1 || asked != 1 {
		t.Fatalf("declined: code=%d asked=%d", code, asked)
	}
	// answering yes fixes and pushes in the same run, from the kept clone
	var question string
	askApply = func(_ *ui.UI, q string) bool { question = q; return true }
	text := stdout(t, func() {
		if code := runGitHubClean(c, ghOpts{token: "tok", api: srv.URL, author: "T <t@t>", json: js + ".apply"}); code != 0 {
			t.Errorf("dry run answered with yes: exit %d", code)
		}
	})
	if question != "Fix and push these 1 branches in 1 repositories now?" || !strings.Contains(text, "pushed") {
		t.Fatalf("question=%q\n%s", question, text)
	}
	if ents, _ := os.ReadDir(clones); len(ents) != 0 {
		t.Fatal("the kept clone should be removed once everything is fixed")
	}
	if b, _ := os.ReadFile(js + ".apply"); !strings.Contains(string(b), `"apply": true`) || !strings.Contains(string(b), `"status": "pushed"`) {
		t.Fatalf("json after answering yes: %s", b)
	}
	askApply = func(_ *ui.UI, q string) bool { t.Error("asked although nothing is infected"); return false }
	if code := runGitHubClean(c, ghOpts{token: "tok", api: srv.URL, ci: true, apply: true, author: "T <t@t>"}); code != 0 {
		t.Fatalf("apply exit %d", code)
	}
	out, err := exec.Command("git", "-C", origin, "show", "main:postcss.config.mjs").Output()
	if err != nil || string(out) != testfixtures.CleanPostcss {
		t.Fatalf("remote not cleaned: %v %q", err, out)
	}
	b, _ := os.ReadFile(js)
	if !strings.Contains(string(b), `"status": "infected"`) {
		t.Fatalf("json: %s", b)
	}

	// a later run remembers the work: nothing is cloned, the earlier fix is counted
	tip, _ := exec.Command("git", "-C", origin, "rev-parse", "main").Output()
	text = stdout(t, func() {
		if code := runGitHubClean(c, ghOpts{token: "tok", api: srv.URL, ci: true, apply: true, author: "T <t@t>", json: js}); code != 0 {
			t.Errorf("resumed apply exit %d", code)
		}
	})
	for _, want := range []string{"fixed earlier", "1 (1 in earlier runs)", "Verified by earlier runs:"} {
		if !strings.Contains(text, want) {
			t.Errorf("resumed run lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Pushed fixes. Now: rotate") {
		t.Errorf("nothing was pushed by this run, so it must not say so:\n%s", text)
	}
	if now, _ := exec.Command("git", "-C", origin, "rev-parse", "main").Output(); string(now) != string(tip) {
		t.Fatal("the resumed run pushed again")
	}
	if b, _ := os.ReadFile(js); !strings.Contains(string(b), `"resumed": true`) || !strings.Contains(string(b), `"sha": "`+strings.TrimSpace(string(tip))+`"`) {
		t.Fatalf("json of a resumed run: %s", b)
	}
	// --progress needs no token and no network
	text = stdout(t, func() {
		if code := runGitHubClean(c, ghOpts{progress: true, ci: true, api: "http://127.0.0.1:1"}); code != 0 {
			t.Errorf("--progress exit %d", code)
		}
	})
	if !strings.Contains(text, "/me/app") || !strings.Contains(text, "1 repositories, 1 branches verified: 0 clean, 1 fixed and pushed, 0 need manual review.") {
		t.Fatalf("--progress:\n%s", text)
	}
	// --fresh forgets it and checks again: the branch is clean now
	text = stdout(t, func() {
		if code := runGitHubClean(c, ghOpts{token: "tok", api: srv.URL, ci: true, apply: true, fresh: true}); code != 0 {
			t.Errorf("--fresh exit %d", code)
		}
	})
	if strings.Contains(text, "fixed earlier") || strings.Contains(text, "earlier runs") || !strings.Contains(text, "clean") {
		t.Fatalf("--fresh must check everything again:\n%s", text)
	}
}
