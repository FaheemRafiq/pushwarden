// threatscan:allow-signatures
package remediate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
	// make the remote reject pushes
	sh(t, origin, "config", "receive.denyCurrentBranch", "ignore")
	if err := os.Chmod(filepath.Join(origin, "refs", "heads"), 0o555); err != nil {
		t.Skip("chmod not supported")
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(origin, "refs", "heads"), 0o755) })
	if os.Getuid() == 0 {
		t.Skip("root ignores permissions")
	}
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
