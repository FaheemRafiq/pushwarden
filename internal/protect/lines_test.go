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
