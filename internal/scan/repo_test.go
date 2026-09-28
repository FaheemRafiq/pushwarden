// threatscan:allow-signatures
package scan

import (
	"crypto/sha256"
	"encoding/hex"
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

// Indicators added from analysis/polinrider-research-2026-09.md.

func TestSeptember2026Markers(t *testing.T) {
	pad := strings.Repeat(" ", 300)
	for _, m := range []string{"global.i = 'A8';", "global.i='A9-0204-3';", `global["i"]="A10-*23650";`, "helloipbot!!"} {
		d := t.TempDir()
		r := filepath.Join(d, "r")
		write(t, filepath.Join(r, ".git", "HEAD"), "ref: refs/heads/main\n")
		write(t, filepath.Join(r, "postcss.config.mjs"), "export default { plugins: {} };"+pad+m+"(function(){})();\n")
		fs, _, _ := newRepo(t, d).ScanAll(nil, nil)
		if !findings.AnyAtLeast(fs, findings.Critical) {
			t.Errorf("marker %q not detected", m)
		}
	}
	// near-misses stay clean
	d := t.TempDir()
	write(t, filepath.Join(d, "r", ".git", "HEAD"), "ref: refs/heads/main\n")
	write(t, filepath.Join(d, "r", "app.js"), "global.items = 'A8'; const x = 'A9-0204-3';\n")
	if fs, _, _ := newRepo(t, d).ScanAll(nil, nil); findings.AnyAtLeast(fs, findings.High) {
		t.Errorf("false positive: %v", fs)
	}
}

func TestKnownMaliciousFileHash(t *testing.T) {
	i := testIOCs(t)
	d := t.TempDir()
	r := filepath.Join(d, "r")
	write(t, filepath.Join(r, ".git", "HEAD"), "ref: refs/heads/main\n")
	content := "module.exports = { content: [] };\n"
	write(t, filepath.Join(r, "tailwind.config.js"), content)
	sum := sha256.Sum256([]byte(content))
	i.FileHashes[hex.EncodeToString(sum[:])] = true // pretend this exact file is a published indicator
	fs, _, _ := NewRepo(d, ui.New(true, true), i).ScanAll(nil, nil)
	if len(byCategory(fs)["known_malicious_file"]) != 1 {
		t.Fatalf("hash not matched: %v", fs)
	}
	if len(testIOCs(t).FileHashes) < 8 {
		t.Error("bundled malicious_file_sha256 not loaded")
	}
}

func TestPHPRunsNode(t *testing.T) {
	d := t.TempDir()
	r := filepath.Join(d, "r")
	write(t, filepath.Join(r, "composer.json"), `{"name": "a/b"}`)
	write(t, filepath.Join(r, "index.php"), "<?php\n$o = shell_exec(\"node -e \\\"console.log(1)\\\"\");\n")
	write(t, filepath.Join(r, "var.php"), "<?php\n$c = 'node -e \"require(1)\"';\n$o = shell_exec($c);\n")
	write(t, filepath.Join(r, "ok.php"), "<?php\n$o = shell_exec('ls -la');\necho 'run node -e in docs';\n")
	fs, _, _ := newRepo(t, d).ScanAll(nil, nil)
	got := paths(byCategory(fs)["php_node_exec"])
	if !got[filepath.Join(r, "index.php")] || !got[filepath.Join(r, "var.php")] {
		t.Errorf("shell_exec + node -e not flagged: %v", got)
	}
	if got[filepath.Join(r, "ok.php")] {
		t.Error("ok.php flagged: node -e is only in an echo string")
	}
}

func TestComposerBranchVersions(t *testing.T) {
	lock := func(ver string) string {
		return `{"packages": [{"name": "visanduma/nova-two-factor", "version": "` + ver + `"}], "packages-dev": []}`
	}
	for ver, want := range map[string]findings.Severity{"dev-main": findings.Critical, "dev-nova5": findings.Critical, "v2.2.1": findings.High} {
		d := t.TempDir()
		r := filepath.Join(d, "r")
		write(t, filepath.Join(r, "composer.json"), `{"require": {"visanduma/nova-two-factor": "^2.0"}}`)
		write(t, filepath.Join(r, "composer.lock"), lock(ver))
		fs, _, _ := newRepo(t, d).ScanAll(nil, nil)
		var sev findings.Severity = -1
		for _, f := range byCategory(fs)["compromised_package"] {
			if strings.Contains(f.Title, "visanduma") && f.Severity > sev {
				sev = f.Severity
			}
		}
		if sev != want {
			t.Errorf("%s: severity %v, want %v", ver, sev, want)
		}
	}
}

func TestNewNPMPackages(t *testing.T) {
	for deps, want := range map[string]findings.Severity{
		`"@common-stack/generate-plugin": "9.0.2-alpha.30"`: findings.Critical, // alpha prefix
		`"@common-stack/generate-plugin": "9.0.1"`:          findings.High,
		`"@dforge-core/dforge-mcp": "0.2.21"`:               findings.Critical,
		`"@dforge-core/dforge-mcp": "0.2.22"`:               findings.High,
		`"dotevn": "1.0.0"`:                                 findings.Critical, // typosquat, any version
	} {
		d := t.TempDir()
		write(t, filepath.Join(d, "p", "package.json"), `{"dependencies": {`+deps+`}}`)
		fs, _, _ := newRepo(t, d).ScanAll(nil, nil)
		var sev findings.Severity = -1
		for _, f := range byCategory(fs)["compromised_package"] {
			if f.Severity > sev {
				sev = f.Severity
			}
		}
		if sev != want {
			t.Errorf("%s: severity %v, want %v", deps, sev, want)
		}
	}
}
