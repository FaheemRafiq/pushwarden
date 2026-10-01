// threatscan:allow-signatures
package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/journal"
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

func TestJournalMirrorAndOneTimeImport(t *testing.T) {
	i, _ := iocs.Load(t.TempDir())
	data := t.TempDir()
	// history written before the journal existed
	old := New(platform.New(), i, data, nil, false)
	f1 := filepath.Join(t.TempDir(), "a.woff2")
	os.WriteFile(f1, []byte("var a = 1;"), 0o644)
	old.Quarantine(&findings.Finding{Severity: findings.Critical, Category: "fake_font_loader", Title: "old", Path: f1, Meta: findings.Meta{Quarantine: true}})

	j := journal.Open(data, "v", "i")
	ImportHistory(j, data)
	evs := journal.Read(data, journal.Filter{})
	if len(evs) != 1 || evs[0].Ctx != "imported" || evs[0].Action != "quarantine" || evs[0].Path != f1 || evs[0].Time().IsZero() {
		t.Fatalf("import: %+v", evs)
	}
	ImportHistory(j, data) // second call must not duplicate
	if n := len(journal.Read(data, journal.Filter{})); n != 1 {
		t.Fatalf("imported twice: %d", n)
	}
	pr := New(platform.New(), i, data, nil, false)
	pr.AttachJournal(j, "guard")
	f2 := filepath.Join(t.TempDir(), "b.woff2")
	os.WriteFile(f2, []byte("var b = 2;"), 0o644)
	pr.Quarantine(&findings.Finding{Severity: findings.Critical, Category: "fake_font_loader", Title: "new", Path: f2, Meta: findings.Meta{Quarantine: true}})
	pr.Restore(f2)
	evs = journal.Read(data, journal.Filter{Kinds: []string{journal.KindAction}})
	if len(evs) != 3 || evs[1].Ctx != "guard" || evs[1].Action != "quarantine" || evs[1].Data["copy"] == nil || evs[2].Action != "restore" {
		t.Fatalf("mirror: %+v", evs)
	}
}
