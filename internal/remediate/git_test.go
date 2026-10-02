// threatscan:allow-signatures
package remediate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
)

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func put(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// origin: main (infected), clean (clean), feature (infected, different file set)
func buildOrigin(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	origin := filepath.Join(root, "origin.git")
	sh(t, root, "init", "--bare", "--quiet", origin)
	work := filepath.Join(root, "work")
	sh(t, root, "clone", "--quiet", origin, work)
	put(t, filepath.Join(work, "postcss.config.mjs"), []byte(testfixtures.CleanPostcss))
	put(t, filepath.Join(work, "package.json"), []byte(`{"dependencies": {"react": "^19.0.0"}}`))
	put(t, filepath.Join(work, "README.md"), []byte("hi\n"))
	sh(t, work, "add", "-A")
	sh(t, work, "commit", "-q", "-m", "init")
	sh(t, work, "branch", "clean")
	put(t, filepath.Join(work, "postcss.config.mjs"), []byte(testfixtures.InfectedPostcss))
	put(t, filepath.Join(work, "public", "fonts", "fa-solid-900.woff2"), testfixtures.FakeWoff2)
	put(t, filepath.Join(work, ".vscode", "tasks.json"), []byte(testfixtures.TasksJSON))
	put(t, filepath.Join(work, ".gitignore"), []byte("node_modules\ntemp_auto_push.bat\nbranch_structure.json\n.gitignore\n"))
	sh(t, work, "add", "-A", "-f") // the malicious .gitignore ignores itself, as PolinRider's does
	sh(t, work, "commit", "-q", "-m", "chore: update config")
	sh(t, work, "checkout", "-q", "-b", "feature", "clean")
	put(t, filepath.Join(work, "public", "fonts", "fa-solid-900.woff2"), testfixtures.FakeWoff2)
	sh(t, work, "add", "-A")
	sh(t, work, "commit", "-q", "-m", "fonts")
	sh(t, work, "push", "-q", "origin", "main", "clean", "feature")
	return origin
}

func newRemediator(t *testing.T, apply bool) *Remediator {
	t.Helper()
	i, err := iocs.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return New(Options{Apply: apply, WorkDir: t.TempDir(), Author: "Tester <tester@example.com>", Version: "test"},
		platform.New(), i, t.TempDir())
}

func byName(r Result) map[string]Branch {
	m := map[string]Branch{}
	for _, b := range r.Branches {
		m[b.Name] = b
	}
	return m
}

func show(t *testing.T, origin, ref, file string) (string, bool) {
	cmd := exec.Command("git", "-C", origin, "show", ref+":"+file)
	out, err := cmd.Output()
	return string(out), err == nil
}

func TestDryRunChangesNothing(t *testing.T) {
	origin := buildOrigin(t)
	before := sh(t, origin, "for-each-ref")
	res := newRemediator(t, false).Run(context.Background(), "acme/app", origin, "main")
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	b := byName(res)
	if b["main"].Status != StatusInfected || b["feature"].Status != StatusInfected || b["clean"].Status != StatusClean {
		t.Fatalf("statuses: main=%s feature=%s clean=%s", b["main"].Status, b["feature"].Status, b["clean"].Status)
	}
	if len(b["main"].Fixed) < 4 {
		t.Fatalf("main should list 3 fixes, got %v", b["main"].Fixed)
	}
	if res.Branches[0].Name != "main" {
		t.Fatalf("default branch should be processed first, got %s", res.Branches[0].Name)
	}
	if after := sh(t, origin, "for-each-ref"); after != before {
		t.Fatalf("dry run touched the remote:\n%s\n%s", before, after)
	}
}

func TestApplyFixesEveryInfectedBranch(t *testing.T) {
	origin := buildOrigin(t)
	cleanBefore := strings.TrimSpace(sh(t, origin, "rev-parse", "clean"))
	res := newRemediator(t, true).Run(context.Background(), "acme/app", origin, "main")
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	b := byName(res)
	for _, n := range []string{"main", "feature"} {
		if b[n].Status != StatusPushed || b[n].Commit == "" {
			t.Fatalf("%s: status=%s err=%s", n, b[n].Status, b[n].Error)
		}
	}
	if b["clean"].Status != StatusClean {
		t.Fatalf("clean branch: %s", b["clean"].Status)
	}
	if got := strings.TrimSpace(sh(t, origin, "rev-parse", "clean")); got != cleanBefore {
		t.Fatal("clean branch was rewritten")
	}
	pc, ok := show(t, origin, "main", "postcss.config.mjs")
	if !ok || strings.Contains(pc, "global[") {
		t.Fatalf("payload still in postcss.config.mjs on main:\n%s", pc)
	}
	if pc != testfixtures.CleanPostcss {
		t.Fatalf("stripped file should equal the clean original:\n%q", pc)
	}
	for _, f := range []string{"public/fonts/fa-solid-900.woff2", ".vscode/tasks.json"} {
		if _, ok := show(t, origin, "main", f); ok {
			t.Fatalf("%s should be deleted from main", f)
		}
	}
	if gi, ok := show(t, origin, "main", ".gitignore"); !ok || gi != "node_modules\n" {
		t.Fatalf(".gitignore should keep only the legitimate entry, got %q", gi)
	}
	if _, ok := show(t, origin, "feature", "public/fonts/fa-solid-900.woff2"); ok {
		t.Fatal("fake font should be deleted from feature")
	}
	if _, ok := show(t, origin, "feature", "README.md"); !ok {
		t.Fatal("feature lost unrelated files")
	}
	log := sh(t, origin, "log", "-1", "--format=%an <%ae>%n%B", "main")
	if !strings.Contains(log, "Tester <tester@example.com>") || !strings.Contains(log, "security: remove PolinRider malware") {
		t.Fatalf("unexpected commit:\n%s", log)
	}
	if !strings.Contains(log, "postcss.config.mjs") || !strings.Contains(log, "fa-solid-900.woff2") {
		t.Fatalf("commit message should list the files:\n%s", log)
	}
	// parent of the fix commit is the old tip: no history rewrite
	if !strings.Contains(sh(t, origin, "log", "--format=%s", "main"), "chore: update config") {
		t.Fatal("history was rewritten")
	}
	// second run is a no-op
	res2 := newRemediator(t, true).Run(context.Background(), "acme/app", origin, "main")
	for _, br := range res2.Branches {
		if br.Status != StatusClean {
			t.Fatalf("second pass %s: %s %s", br.Name, br.Status, br.Error)
		}
	}
}

func TestBranchFilterAndPushFailure(t *testing.T) {
	origin := buildOrigin(t)
	m := newRemediator(t, true)
	m.Opts.Branches = []string{"feat*"}
	res := m.Run(context.Background(), "acme/app", origin, "main")
	if len(res.Branches) != 1 || res.Branches[0].Name != "feature" {
		t.Fatalf("filter: %+v", res.Branches)
	}
	// make the remote reject the update of main: a stale lock file on the ref
	// (works on every OS and as root, unlike chmod)
	lock := filepath.Join(origin, "refs", "heads", "main.lock")
	if err := os.WriteFile(lock, []byte("0000000000000000000000000000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(lock) })
	m2 := newRemediator(t, true)
	m2.Opts.Branches = []string{"main"}
	res = m2.Run(context.Background(), "acme/app", origin, "main")
	if res.Branches[0].Status != StatusPushFailed || res.Branches[0].Error == "" {
		t.Fatalf("expected push-failed, got %s %q", res.Branches[0].Status, res.Branches[0].Error)
	}
}

func TestMatchBranch(t *testing.T) {
	if !matchBranch(nil, "x") || !matchBranch([]string{"release/*"}, "release/1.2") || matchBranch([]string{"main"}, "dev") {
		t.Fatal("matchBranch")
	}
	if safeName("feature/a b") != "feature_a_b" {
		t.Fatal(safeName("feature/a b"))
	}
}

// resumable returns a remediator that remembers its progress in dataDir.
func resumable(t *testing.T, apply bool, dataDir string, logs *[]string) *Remediator {
	t.Helper()
	m := newRemediator(t, apply)
	m.DataDir = dataDir
	m.Opts.State, m.Opts.Host = LoadState(dataDir), "api.github.com"
	m.Opts.Token = "tok-must-not-be-stored"
	if logs != nil {
		m.Opts.Log = func(s string) { *logs = append(*logs, s) }
	}
	return m
}

func cloned(logs []string) bool {
	for _, l := range logs {
		if strings.HasPrefix(l, "cloning ") {
			return true
		}
	}
	return false
}

func TestInterruptedRunContinuesWhereItStopped(t *testing.T) {
	origin := buildOrigin(t)
	data := t.TempDir()
	// run 1 is interrupted when it reaches its second branch: only "main" is finished
	ctx, cancel := context.WithCancel(context.Background())
	m := resumable(t, true, data, nil)
	n := 0
	m.Opts.Log = func(s string) {
		if strings.Contains(s, " @ ") {
			if n++; n == 2 {
				cancel()
			}
		}
	}
	b := byName(m.Run(ctx, "acme/app", origin, "main"))
	if b["main"].Status != StatusPushed || b["clean"].Status != StatusError || b["feature"].Status != StatusError {
		t.Fatalf("interrupted run: main=%s clean=%s feature=%s", b["main"].Status, b["clean"].Status, b["feature"].Status)
	}
	mainTip := strings.TrimSpace(sh(t, origin, "rev-parse", "main"))
	st := LoadState(data).Repos["api.github.com/acme/app"]
	if st == nil || len(st.Branches) != 1 || st.Branches["main"].SHA != mainTip || st.Branches["main"].Status != StatusPushed {
		t.Fatalf("state after the interruption: %+v", st)
	}
	raw, _ := os.ReadFile(filepath.Join(data, StateFile))
	if strings.Contains(string(raw), "tok-must-not-be-stored") || strings.Contains(string(raw), origin) {
		t.Fatalf("the progress file must hold neither the token nor the clone URL:\n%s", raw)
	}

	// run 2: main is not touched again, the other two are done
	var logs []string
	res := resumable(t, true, data, &logs).Run(context.Background(), "acme/app", origin, "main")
	b = byName(res)
	if !b["main"].Resumed || b["main"].Status != StatusPushed || b["main"].Commit == "" || b["main"].At == "" {
		t.Fatalf("main should be taken from the earlier run: %+v", b["main"])
	}
	if b["feature"].Resumed || b["feature"].Status != StatusPushed || b["clean"].Resumed || b["clean"].Status != StatusClean {
		t.Fatalf("unfinished branches must be processed: feature=%+v clean=%+v", b["feature"], b["clean"])
	}
	for _, l := range logs {
		if strings.HasSuffix(l, " @ main") {
			t.Fatal("main was processed again")
		}
	}
	if got := strings.TrimSpace(sh(t, origin, "rev-parse", "main")); got != mainTip {
		t.Fatal("main received a second commit")
	}
	if _, ok := show(t, origin, "feature", "public/fonts/fa-solid-900.woff2"); ok {
		t.Fatal("feature was not cleaned by the second run")
	}

	// run 3: everything is verified and unchanged, so the repository is not even cloned
	logs = nil
	res = resumable(t, true, data, &logs).Run(context.Background(), "acme/app", origin, "main")
	if cloned(logs) || len(res.Branches) != 3 || res.Branches[0].Name != "main" {
		t.Fatalf("a fully verified repository must not be cloned: %v %+v", logs, res.Branches)
	}
	for _, br := range res.Branches {
		if !br.Resumed {
			t.Fatalf("%s should be resumed", br.Name)
		}
	}
	if c, _, p, f, _ := res.Counts(); c != 1 || p != 2 || f != 0 {
		t.Fatalf("counts across runs: clean=%d pushed=%d failed=%d", c, p, f)
	}

	// without a state nothing is remembered: the old behaviour
	plain := newRemediator(t, true).Run(context.Background(), "acme/app", origin, "main")
	for _, br := range plain.Branches {
		if br.Resumed || br.Status != StatusClean {
			t.Fatalf("no state: %s %s resumed=%v", br.Name, br.Status, br.Resumed)
		}
	}
}

func TestResumeRechecksWhatChanged(t *testing.T) {
	origin := buildOrigin(t)
	data := t.TempDir()
	if res := resumable(t, true, data, nil).Run(context.Background(), "acme/app", origin, "main"); res.Error != "" {
		t.Fatal(res.Error)
	}
	// the attacker pushes the payload to "clean" again; "feature" gets a harmless commit
	work := filepath.Join(t.TempDir(), "w")
	sh(t, t.TempDir(), "clone", "--quiet", origin, work)
	sh(t, work, "checkout", "-q", "clean")
	put(t, filepath.Join(work, "postcss.config.mjs"), []byte(testfixtures.InfectedPostcss))
	sh(t, work, "commit", "-q", "-am", "chore: tooling")
	sh(t, work, "checkout", "-q", "feature")
	put(t, filepath.Join(work, "NOTES.md"), []byte("notes\n"))
	sh(t, work, "add", "-A")
	sh(t, work, "commit", "-q", "-m", "notes")
	sh(t, work, "push", "-q", "origin", "clean", "feature")

	var logs []string
	b := byName(resumable(t, true, data, &logs).Run(context.Background(), "acme/app", origin, "main"))
	if !b["main"].Resumed {
		t.Fatal("main did not move: it should be resumed")
	}
	if b["clean"].Resumed || b["clean"].Status != StatusPushed {
		t.Fatalf("a re-infected branch must be found and fixed again: %+v", b["clean"])
	}
	if b["feature"].Resumed || b["feature"].Status != StatusClean {
		t.Fatalf("a branch with a new commit must be checked again: %+v", b["feature"])
	}
	if pc, _ := show(t, origin, "clean", "postcss.config.mjs"); pc != testfixtures.CleanPostcss {
		t.Fatal("re-infection was not removed")
	}

	// new indicators (or a new program version) invalidate what was remembered
	m := resumable(t, true, data, nil)
	m.I.Version += "+newer"
	for _, br := range m.Run(context.Background(), "acme/app", origin, "main").Branches {
		if br.Resumed {
			t.Fatalf("%s was resumed although the indicators changed", br.Name)
		}
	}
	m = resumable(t, true, data, nil)
	m.I.Version += "+newer"
	m.Opts.Version = "test2"
	for _, br := range m.Run(context.Background(), "acme/app", origin, "main").Branches {
		if br.Resumed {
			t.Fatalf("%s was resumed although the program version changed", br.Name)
		}
	}

	// a branch deleted on the remote is forgotten
	sh(t, origin, "branch", "-D", "feature")
	sh(t, work, "checkout", "-q", "main")
	sh(t, work, "pull", "-q", "origin", "main")
	put(t, filepath.Join(work, "x.md"), []byte("x\n"))
	sh(t, work, "add", "-A")
	sh(t, work, "commit", "-q", "-m", "x")
	sh(t, work, "push", "-q", "origin", "main")
	m = resumable(t, true, data, nil)
	m.I.Version += "+newer"
	m.Opts.Version = "test2"
	m.Run(context.Background(), "acme/app", origin, "main")
	if _, ok := LoadState(data).Repos["api.github.com/acme/app"].Branches["feature"]; ok {
		t.Fatal("a deleted branch is still remembered")
	}

	// Reset forgets everything
	s := LoadState(data)
	s.Reset()
	if len(LoadState(data).Repos) != 0 || len(s.Progress()) != 0 {
		t.Fatal("Reset must clear the progress")
	}
}

func TestUnfinishedResultsAreNeverRemembered(t *testing.T) {
	origin := buildOrigin(t)
	data := t.TempDir()
	// dry run: clean is finished; infected branches are not
	b := byName(resumable(t, false, data, nil).Run(context.Background(), "acme/app", origin, "main"))
	if b["main"].Status != StatusInfected || b["clean"].Status != StatusClean {
		t.Fatalf("dry run: %s %s", b["main"].Status, b["clean"].Status)
	}
	st := LoadState(data).Repos["api.github.com/acme/app"].Branches
	if len(st) != 1 || st["clean"].Status != StatusClean {
		t.Fatalf("a dry run remembers clean branches only: %+v", st)
	}
	// a second dry run reports the infected ones again
	b = byName(resumable(t, false, data, nil).Run(context.Background(), "acme/app", origin, "main"))
	if b["main"].Status != StatusInfected || b["main"].Resumed || !b["clean"].Resumed {
		t.Fatalf("second dry run: main=%+v clean=%+v", b["main"], b["clean"])
	}
	// a refused push is tried again on the next run
	lock := filepath.Join(origin, "refs", "heads", "main.lock")
	if err := os.WriteFile(lock, []byte("0000000000000000000000000000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b = byName(resumable(t, true, data, nil).Run(context.Background(), "acme/app", origin, "main"))
	if b["main"].Status != StatusPushFailed || b["feature"].Status != StatusPushed || !b["clean"].Resumed {
		t.Fatalf("apply after the dry run: main=%s feature=%s clean resumed=%v", b["main"].Status, b["feature"].Status, b["clean"].Resumed)
	}
	if _, ok := LoadState(data).Repos["api.github.com/acme/app"].Branches["main"]; ok {
		t.Fatal("a failed push must not be remembered as done")
	}
	os.Remove(lock)
	b = byName(resumable(t, true, data, nil).Run(context.Background(), "acme/app", origin, "main"))
	if b["main"].Status != StatusPushed || b["main"].Resumed || !b["feature"].Resumed {
		t.Fatalf("retry: main=%+v feature resumed=%v", b["main"], b["feature"].Resumed)
	}
	// a branch filter only looks at the selected branches
	var logs []string
	m := resumable(t, true, data, &logs)
	m.Opts.Branches = []string{"feat*"}
	res := m.Run(context.Background(), "acme/app", origin, "main")
	if len(res.Branches) != 1 || !res.Branches[0].Resumed || cloned(logs) {
		t.Fatalf("filtered resume: %+v", res.Branches)
	}
	ps := LoadState(data).Progress()
	if len(ps) != 1 || ps[0].Clean != 1 || ps[0].Pushed != 2 || ps[0].Last == "" {
		t.Fatalf("progress: %+v", ps)
	}
}

func keptClones(t *testing.T, data string) []string {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(data, ClonesDir))
	var out []string
	for _, e := range ents {
		out = append(out, filepath.Join(data, ClonesDir, e.Name()))
	}
	return out
}

func TestApplyAfterDryRunDoesNotCloneAgain(t *testing.T) {
	origin := buildOrigin(t)
	data := t.TempDir()
	// dry run: infected branches remain, so the clone is kept
	var logs []string
	res := resumable(t, false, data, &logs).Run(context.Background(), "acme/app", origin, "main")
	if res.Error != "" || !cloned(logs) {
		t.Fatalf("dry run: %s %v", res.Error, logs)
	}
	kept := keptClones(t, data)
	if len(kept) != 1 {
		t.Fatalf("the dry run should keep one clone, got %v", kept)
	}
	if _, err := os.Stat(filepath.Join(kept[0], "wt")); err == nil {
		if ents, _ := os.ReadDir(filepath.Join(kept[0], "wt")); len(ents) != 0 {
			t.Fatalf("checked-out files left in the kept clone: %v", ents)
		}
	}
	if n, size := LoadState(data).Clones(); n != 1 || size == 0 {
		t.Fatalf("Clones() = %d, %d", n, size)
	}
	// meanwhile the attacker also infects "clean" on the remote
	work := filepath.Join(t.TempDir(), "w")
	sh(t, t.TempDir(), "clone", "--quiet", origin, work)
	sh(t, work, "checkout", "-q", "clean")
	put(t, filepath.Join(work, "postcss.config.mjs"), []byte(testfixtures.InfectedPostcss))
	sh(t, work, "commit", "-q", "-am", "chore: tooling")
	sh(t, work, "push", "-q", "origin", "clean")

	// apply: no clone, the kept copy is updated, everything is fixed including the new infection
	logs = nil
	res = resumable(t, true, data, &logs).Run(context.Background(), "acme/app", origin, "main")
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	if cloned(logs) || !strings.Contains(strings.Join(logs, "\n"), "updating the kept copy of acme/app") {
		t.Fatalf("apply after a dry run must reuse the clone: %v", logs)
	}
	for _, br := range res.Branches {
		if br.Status != StatusPushed || br.Resumed {
			t.Fatalf("%s: %s resumed=%v %s", br.Name, br.Status, br.Resumed, br.Error)
		}
	}
	for _, name := range []string{"main", "clean"} {
		if pc, _ := show(t, origin, name, "postcss.config.mjs"); pc != testfixtures.CleanPostcss {
			t.Fatalf("%s is not clean on the remote", name)
		}
	}
	if kept := keptClones(t, data); len(kept) != 0 {
		t.Fatalf("after a complete apply nothing stays on disk: %v", kept)
	}
}

func TestKeptCloneHousekeeping(t *testing.T) {
	origin := buildOrigin(t)
	data := t.TempDir()
	resumable(t, false, data, nil).Run(context.Background(), "acme/app", origin, "main")
	kept := keptClones(t, data)
	if len(kept) != 1 {
		t.Fatalf("%v", kept)
	}
	// a damaged kept clone is replaced by a fresh one
	os.RemoveAll(filepath.Join(kept[0], "repo.git", "objects"))
	var logs []string
	b := byName(resumable(t, false, data, &logs).Run(context.Background(), "acme/app", origin, "main"))
	if !cloned(logs) || b["main"].Status != StatusInfected || !b["clean"].Resumed {
		t.Fatalf("damaged clone: logs=%v main=%s", logs, b["main"].Status)
	}
	// not used for longer than the limit: removed
	s := LoadState(data)
	s.PruneClones(CloneMaxAge, 0, false)
	if len(keptClones(t, data)) != 1 {
		t.Fatal("a recent clone was pruned")
	}
	old := time.Now().Add(-CloneMaxAge - time.Hour)
	os.Chtimes(keptClones(t, data)[0], old, old)
	s.PruneClones(CloneMaxAge, 0, false)
	if len(keptClones(t, data)) != 0 {
		t.Fatal("an expired clone was kept")
	}
	// Reset removes kept clones too
	resumable(t, false, data, nil).Run(context.Background(), "acme/app", origin, "main")
	LoadState(data).Reset()
	if len(keptClones(t, data)) != 0 {
		t.Fatal("Reset left clones behind")
	}
	// an all-clean repository keeps nothing; neither does a run without remembered progress
	clean := resumable(t, false, data, nil)
	clean.Opts.Branches = []string{"clean"}
	clean.Run(context.Background(), "acme/app", origin, "main")
	newRemediator(t, false).Run(context.Background(), "acme/app", origin, "main")
	if len(keptClones(t, data)) != 0 {
		t.Fatal("a clone was kept although nothing remains to fix")
	}
	// --keep-clones keeps its own behaviour
	kc := resumable(t, false, data, nil)
	kc.Opts.KeepClones = true
	res := kc.Run(context.Background(), "acme/app", origin, "main")
	if res.Clone == "" || len(keptClones(t, data)) != 0 {
		t.Fatalf("--keep-clones: clone=%q kept=%v", res.Clone, keptClones(t, data))
	}
}

func TestCloneSizeLimitAndStaleProgress(t *testing.T) {
	origin := buildOrigin(t)
	data := t.TempDir()
	// a repository larger than the whole limit is not kept for --apply
	m := resumable(t, false, data, nil)
	m.Opts.CloneMaxBytes = 100
	if res := m.Run(context.Background(), "acme/app", origin, "main"); res.Error != "" || len(keptClones(t, data)) != 0 {
		t.Fatalf("an over-limit clone was kept: %v %s", keptClones(t, data), res.Error)
	}
	// within the limit it is kept; the total limit removes the least recently used
	m = resumable(t, false, data, nil)
	m.Opts.CloneMaxBytes = 1 << 30
	m.Run(context.Background(), "acme/app", origin, "main")
	m.Run(context.Background(), "acme/other", origin, "main")
	if len(keptClones(t, data)) != 2 {
		t.Fatalf("kept: %v", keptClones(t, data))
	}
	s := LoadState(data)
	_, size := s.Clones()
	old := time.Now().Add(-time.Hour)
	first := s.clonePath("api.github.com/acme/app")
	os.Chtimes(first, old, old)
	if n, freed := s.PruneClones(0, size-1, true); n != 1 || freed == 0 || len(keptClones(t, data)) != 2 {
		t.Fatalf("dry run: n=%d freed=%d", n, freed)
	}
	if n, _ := s.PruneClones(0, size-1, false); n != 1 || len(keptClones(t, data)) != 1 || keptClones(t, data)[0] == first {
		t.Fatalf("size limit should remove the least recently used clone: %v", keptClones(t, data))
	}
	if n, _ := s.PruneClones(0, 0, false); n != 0 {
		t.Fatal("no limits: nothing is removed")
	}
	// clean results carry no finding details; a repository not seen for 90 days is forgotten
	for _, rs := range s.Repos {
		for name, b := range rs.Branches {
			if b.Status == StatusClean && len(b.Findings) != 0 {
				t.Fatalf("%s: findings stored for a clean branch", name)
			}
		}
	}
	rs := s.Repos["api.github.com/acme/app"]
	for name, b := range rs.Branches {
		b.At = time.Now().Add(-StateMaxAge - time.Hour).Format(time.RFC3339)
		rs.Branches[name] = b
	}
	if n := s.DropStale(StateMaxAge, true); n != 1 || s.Repos["api.github.com/acme/app"] == nil {
		t.Fatalf("dry run dropped: %d", n)
	}
	if n := s.DropStale(StateMaxAge, false); n != 1 || LoadState(data).Repos["api.github.com/acme/app"] != nil || LoadState(data).Repos["api.github.com/acme/other"] == nil {
		t.Fatalf("stale repositories dropped: %d", n)
	}
	// nothing is left in the system temp folder for hooks
	if !strings.HasSuffix(noHooksDir(), filepath.Join("guard", "nohooks")) || strings.Contains(filepath.Base(noHooksDir()), "threatscan-nohooks-") {
		t.Fatalf("the hooks folder should live in the data directory, got %s", noHooksDir())
	}
}
