// threatscan:allow-signatures
package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/helpers"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func testIOCs(t *testing.T) *iocs.IOCs {
	t.Helper()
	i, err := iocs.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func newRepo(t *testing.T, root string) *Repo {
	return NewRepo(root, ui.New(true, true), testIOCs(t))
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byCategory(fs []*F) map[string][]*F {
	m := map[string][]*F{}
	for _, f := range fs {
		m[f.Category] = append(m[f.Category], f)
	}
	return m
}

func paths(fs []*F) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.Path] = true
	}
	return m
}

func TestInfectedRepoFindings(t *testing.T) {
	d := t.TempDir()
	testfixtures.Infected(t, d)
	fs, total, infected := newRepo(t, d).ScanAll(nil, nil)
	if total != 1 || infected != 1 {
		t.Fatalf("total=%d infected=%d", total, infected)
	}
	cats := byCategory(fs)
	for _, c := range []string{"config_injection", "fake_font_loader", "vscode_autorun", "propagation_script",
		"gitignore_tampering", "compromised_package"} {
		if len(cats[c]) == 0 {
			t.Errorf("missing %s", c)
		}
	}
	if tasks := cats["vscode_autorun"]; len(tasks) > 0 {
		f := tasks[0]
		if f.Severity != findings.Critical || !f.Meta.Quarantine || len(f.Meta.Evidence) == 0 {
			t.Errorf("vscode_autorun: severity=%s quarantine=%v evidence=%v", f.Severity, f.Meta.Quarantine, f.Meta.Evidence)
		}
	}
	for _, f := range cats["compromised_package"] {
		if f.Severity != findings.Critical {
			t.Errorf("compromised_package is %s", f.Severity)
		}
	}
}

func TestCleanRepoNoHigh(t *testing.T) {
	d := t.TempDir()
	testfixtures.Clean(t, d)
	fs, total, infected := newRepo(t, d).ScanAll(nil, nil)
	if total != 1 || infected != 0 {
		t.Fatalf("total=%d infected=%d", total, infected)
	}
	for _, f := range fs {
		if f.Severity >= findings.High {
			t.Errorf("clean repo: [%s] %s %s", f.Severity, f.Title, f.Path)
		}
	}
}

func TestScanFileQuickPath(t *testing.T) {
	r := testfixtures.Infected(t, t.TempDir())
	rs := newRepo(t, r)
	if !byCategoryHas(rs.ScanFile(filepath.Join(r, "postcss.config.mjs")), "config_injection") {
		t.Error("postcss.config.mjs: no config_injection")
	}
	if fs := rs.ScanFile(filepath.Join(r, "public", "fonts", "fa-solid-900.woff2")); len(fs) == 0 || fs[0].Severity != findings.Critical {
		t.Errorf("font loader: %v", fs)
	}
	if fs := rs.ScanFile(filepath.Join(r, ".vscode", "tasks.json")); len(fs) == 0 || fs[0].Category != "vscode_autorun" {
		t.Errorf("tasks.json: %v", fs)
	}
}

func byCategoryHas(fs []*F, c string) bool { return len(byCategory(fs)[c]) > 0 }

func TestScopeDefaultDeepAndV4(t *testing.T) {
	d := t.TempDir()
	repo := filepath.Join(d, "r")
	write(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main\n")
	helper := filepath.Join(repo, "lib", "helper.js")
	write(t, helper, "module.exports = 1;"+strings.Repeat(" ", 300)+"global['!']='A10-2340';")
	nm := filepath.Join(repo, "node_modules", "x", "index.js")
	write(t, nm, "global['_V']='8-st9';")

	fs, _, _ := newRepo(t, d).ScanAll(nil, nil)
	got := paths(fs)
	if !got[helper] {
		t.Error("default scope must scan lib/helper.js")
	}
	if got[nm] {
		t.Error("default scope must skip node_modules")
	}

	deep := newRepo(t, d)
	deep.Deep = true
	fs, _, _ = deep.ScanAll(nil, nil)
	if !paths(fs)[nm] {
		t.Error("Deep must include node_modules")
	}

	v4 := newRepo(t, d)
	v4.JSAll = false
	fs, _, _ = v4.ScanAll(nil, nil)
	if byCategoryHas(fs, "config_injection") {
		t.Error("JSAll=false must restore the v4 scope (config files only)")
	}
}

func TestAllowTokenIgnoredForConfigFiles(t *testing.T) {
	d := t.TempDir()
	rs := newRepo(t, d)
	db := filepath.Join(d, "rules.yaml")
	write(t, db, "# "+helpers.AllowToken+"\nglobal['_V']='A4-1928'\n")
	if len(rs.CheckSignatures(db)) != 0 {
		t.Error("allowlisted rule file was flagged")
	}
	cfg := filepath.Join(d, "postcss.config.mjs")
	write(t, cfg, "// "+helpers.AllowToken+"\n"+testfixtures.InfectedPostcss)
	if len(rs.CheckSignatures(cfg)) == 0 {
		t.Error("the allow token must not work in config files")
	}
}

func TestExcludeIsComponentAware(t *testing.T) {
	d := t.TempDir()
	payload := "module.exports = 1;" + strings.Repeat(" ", 300) + "global['!']='A10-2340';"
	for _, sub := range []string{"third_party", "third_party-tools"} {
		write(t, filepath.Join(d, sub, "p", ".git", "HEAD"), "ref: refs/heads/main\n")
		write(t, filepath.Join(d, sub, "p", "lib", "x.js"), payload)
	}
	// third_party is not a default skip dir, so only Exclude can drop it
	rs := newRepo(t, d)
	rs.Exclude = []string{filepath.Join(d, "third_party")}
	fs, _, _ := rs.ScanAll(nil, nil)
	got := paths(fs)
	if got[filepath.Join(d, "third_party", "p", "lib", "x.js")] {
		t.Error("excluded third_party/ was scanned")
	}
	if !got[filepath.Join(d, "third_party-tools", "p", "lib", "x.js")] {
		t.Error("exclude of third_party also dropped third_party-tools")
	}
	if !helpers.IsUnder(filepath.Join(d, "third_party", "x"), []string{filepath.Join(d, "third_party")}) ||
		helpers.IsUnder(filepath.Join(d, "third_party-tools", "x"), []string{filepath.Join(d, "third_party")}) {
		t.Error("IsUnder is not component-aware")
	}
}
