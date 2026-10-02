// threatscan:allow-signatures
package protect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/scan"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

type env struct {
	t    *testing.T
	I    *iocs.IOCs
	home string
	root string // parent of the fixture repo
	repo string
}

func setup(t *testing.T) *env {
	t.Helper()
	home := t.TempDir()
	i, err := iocs.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	return &env{t: t, I: i, home: home, root: root, repo: testfixtures.Infected(t, root)}
}

func (e *env) scan() []*F {
	fs, _, _ := scan.NewRepo(e.root, ui.New(true, true), e.I).ScanAll(nil, nil)
	return fs
}

func (e *env) protector(dry bool) *Protector {
	return New(platform.New(), e.I, e.home, ui.New(true, true), dry)
}

func (e *env) read(rel string) string {
	b, _ := os.ReadFile(filepath.Join(e.repo, filepath.FromSlash(rel)))
	return string(b)
}

func (e *env) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(e.repo, filepath.FromSlash(rel)))
	return err == nil
}

func findPath(fs []*F, suffix string) *F {
	for _, f := range fs {
		if strings.HasSuffix(f.Path, suffix) && NeedsDecision(f) {
			return f
		}
	}
	return nil
}

func TestRespondDeleteKeepTimeout(t *testing.T) {
	e := setup(t)
	asked := map[string]string{}
	decide := func(f *F, word string) prompt.Verdict {
		asked[filepath.Base(f.Path)] = word
		switch {
		case strings.HasSuffix(f.Path, "fa-solid-900.woff2"):
			return prompt.Delete
		case strings.HasSuffix(f.Path, "postcss.config.mjs"):
			return prompt.Keep
		}
		return prompt.Timeout
	}
	fs := e.scan()
	pr := e.protector(false)
	pr.Respond(fs, false, true, decide)

	if asked["fa-solid-900.woff2"] != "Delete the file" || asked["postcss.config.mjs"] != "Remove payload" {
		t.Fatalf("action words: %v", asked)
	}
	// delete: gone permanently, recorded with evidence, no quarantine copy
	if e.exists("public/fonts/fa-solid-900.woff2") {
		t.Error("deleted file still exists")
	}
	var del *Entry
	for _, en := range pr.Entries() {
		if en.Type == "delete" {
			en := en
			del = &en
		}
	}
	if del == nil || len(del.Evidence) == 0 {
		t.Fatalf("no delete entry with evidence: %+v", pr.Entries())
	}
	if del.Copy != "" {
		t.Error("delete kept a quarantine copy")
	}
	// keep: untouched, action set
	if !strings.Contains(e.read("postcss.config.mjs"), "global['_V']") {
		t.Error("kept file was changed")
	}
	if f := findPath(fs, "postcss.config.mjs"); f == nil || f.Action != "kept by user" {
		t.Errorf("kept action: %+v", f)
	}
	// timeout: reversible quarantine
	if e.exists("temp_auto_push.bat") {
		t.Error("timeout should fall back to quarantine")
	}
	if f := findPath(fs, "temp_auto_push.bat"); f == nil || !strings.HasPrefix(f.Action, "no decision (timeout)") {
		t.Errorf("timeout action: %+v", f)
	}

	// second run: the kept file is not asked about while unchanged
	clear(asked)
	e.protector(false).Respond(e.scan(), false, true, decide)
	if _, ok := asked["postcss.config.mjs"]; ok {
		t.Error("kept file was asked about again")
	}
	// ... but is asked again once its content changes
	os.WriteFile(filepath.Join(e.repo, "postcss.config.mjs"), []byte(testfixtures.InfectedPostcss+"// changed\n"), 0o644)
	e.protector(false).Respond(e.scan(), false, true, decide)
	if _, ok := asked["postcss.config.mjs"]; !ok {
		t.Error("changed file was not asked about")
	}
}

func TestRespondDryRunChangesNothing(t *testing.T) {
	e := setup(t)
	before := e.read("postcss.config.mjs")
	acted := e.protector(true).Respond(e.scan(), false, true, nil)
	if len(acted) == 0 {
		t.Fatal("dry run reported no actions")
	}
	for _, f := range acted {
		if !strings.HasPrefix(f.Action, "would") {
			t.Errorf("dry-run action not marked: %q", f.Action)
		}
	}
	for _, p := range []string{"temp_auto_push.bat", ".vscode/tasks.json", "public/fonts/fa-solid-900.woff2"} {
		if !e.exists(p) {
			t.Errorf("dry run removed %s", p)
		}
	}
	if e.read("postcss.config.mjs") != before {
		t.Error("dry run changed postcss.config.mjs")
	}
}

func TestMidFileInjectionQuarantinedWhole(t *testing.T) {
	e := setup(t)
	root := t.TempDir()
	repo := filepath.Join(root, "r")
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	os.MkdirAll(filepath.Join(repo, "src"), 0o755)
	var b strings.Builder
	b.WriteString("(async()=>{eval(atob(process.env.AUTH_API_KEY))})();\n")
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "export const v%d = %d;\n", i, i)
	}
	body := b.String()
	idx := filepath.Join(repo, "src", "index.js")
	os.WriteFile(idx, []byte(body), 0o644)

	fs, _, _ := scan.NewRepo(root, ui.New(true, true), e.I).ScanAll(nil, nil)
	pr := e.protector(false)
	acted := pr.Respond(fs, false, true, nil)
	if len(acted) == 0 {
		t.Fatal("nothing acted on")
	}
	if _, err := os.Stat(idx); err == nil {
		t.Fatal("file was truncated in place instead of quarantined")
	}
	f := acted[0]
	if !f.Meta.MidFileInjection || !strings.Contains(f.Action, "not a trailing append") {
		t.Errorf("action=%q mid=%v", f.Action, f.Meta.MidFileInjection)
	}
	if !pr.Restore(idx) {
		t.Fatal("restore failed")
	}
	if got, _ := os.ReadFile(idx); string(got) != body {
		t.Error("restored bytes differ")
	}
}

func TestExpiredDecisionsAreDropped(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-decisionTTL - time.Hour).Unix()
	fresh := time.Now().Add(-time.Hour).Unix()
	os.WriteFile(filepath.Join(dir, "decisions.json"), []byte(fmt.Sprintf(
		`{"/a/old.js":{"decision":"keep","sha256":"x","ts":%d,"title":"t"},"/a/new.js":{"decision":"keep","sha256":"y","ts":%d,"title":"t"}}`, old, fresh)), 0o600)
	pr := New(platform.New(), nil, dir, nil, false)
	if _, ok := pr.decisions["/a/old.js"]; ok || len(pr.decisions) != 1 {
		t.Fatalf("expired decision still loaded: %v", pr.decisions)
	}
	target := filepath.Join(dir, "x.js")
	os.WriteFile(target, []byte("x"), 0o600)
	pr.Remember(target, "t", prompt.Keep)
	b, _ := os.ReadFile(filepath.Join(dir, "decisions.json"))
	if strings.Contains(string(b), "/a/old.js") || !strings.Contains(string(b), "/a/new.js") {
		t.Fatalf("decisions.json after a save:\n%s", b)
	}
}
