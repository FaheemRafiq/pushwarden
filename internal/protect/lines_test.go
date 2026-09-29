// threatscan:allow-signatures
package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
)

func TestCleanStripsListedLinesOnly(t *testing.T) {
	i, err := iocs.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gi := filepath.Join(t.TempDir(), ".gitignore")
	orig := "node_modules\r\n/temp_auto_push.bat\r\n.env\n  branch_structure.json  \n.gitignore\ndist/\n"
	if err := os.WriteFile(gi, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	pr := New(platform.New(), i, t.TempDir(), nil, false)
	f := &findings.Finding{Severity: findings.Critical, Category: "gitignore_tampering", Path: gi,
		Meta: findings.Meta{Cleanable: true, StripLines: []string{"temp_auto_push.bat", "branch_structure.json", ".gitignore"}}}
	if !pr.Clean(f) {
		t.Fatal("clean failed: " + f.Action)
	}
	got, _ := os.ReadFile(gi)
	if string(got) != "node_modules\r\n.env\ndist/\n" {
		t.Fatalf("unexpected result %q", got)
	}
	if !strings.Contains(f.Action, "removed 3 line(s)") {
		t.Fatal(f.Action)
	}
	// reversible
	if !pr.Restore(gi) {
		t.Fatal("restore failed")
	}
	if back, _ := os.ReadFile(gi); string(back) != orig {
		t.Fatalf("restore mismatch %q", back)
	}
	// dry run touches nothing
	dry := New(platform.New(), i, t.TempDir(), nil, true)
	if !dry.Clean(f) {
		t.Fatal("dry clean should report success")
	}
	if back, _ := os.ReadFile(gi); string(back) != orig {
		t.Fatal("dry run modified the file")
	}
	// nothing to strip
	f2 := &findings.Finding{Path: gi, Meta: findings.Meta{Cleanable: true, StripLines: []string{"absent"}}}
	if pr.Clean(f2) {
		t.Fatal("should fail when no entry matches")
	}
}

func TestEntriesCarryReasons(t *testing.T) {
	i, _ := iocs.Load(t.TempDir())
	pr := New(platform.New(), i, t.TempDir(), nil, false)
	gi := filepath.Join(t.TempDir(), "fa-solid-900.woff2")
	os.WriteFile(gi, []byte("var a = 1; // not a font"), 0o644)
	f := &findings.Finding{Severity: findings.Critical, Category: "fake_font_loader", Title: "fake", Path: gi,
		Meta: findings.Meta{Quarantine: true, Evidence: []string{"woff2 extension but no magic bytes"}}}
	if !pr.Quarantine(f) {
		t.Fatal("quarantine")
	}
	es := pr.Entries()
	e := es[len(es)-1]
	if e.Type != "quarantine" || !strings.HasPrefix(e.Reason, "Quarantined") || len(e.Evidence) != 1 || e.Threat != "Trojan:JS/PolinRider.FakeFont" {
		t.Fatalf("%+v", e)
	}
	k := entryFor(&findings.Finding{Category: "malicious_process", Title: "proc", Action: "killed PID 1", Meta: findings.Meta{Kill: true}}, "kill")
	if !strings.HasPrefix(k.Reason, "Killed") || k.Type != "kill" {
		t.Fatalf("%+v", k)
	}
}
