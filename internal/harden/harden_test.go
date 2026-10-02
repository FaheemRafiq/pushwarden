package harden

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEditorKeepsGlobsAndComments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	raw := "{\n  // my comment\n  \"files.exclude\": {\"**/*.pyc\": true, \"**/node_modules\": true}, /* x */\n  \"a\": \"http://h/*/y\",\n  \"task.allowAutomaticTasks\": \"on\",\n}\n"
	os.WriteFile(p, []byte(raw), 0o644)
	changed, notes, err := Editor(p, false)
	if err != nil || !changed || len(notes) == 0 {
		t.Fatal(changed, notes, err)
	}
	out, _ := os.ReadFile(p)
	s := string(out)
	t.Log("\n" + s)
	for _, want := range []string{"// my comment", "/* x */", `"**/*.pyc": true`, `"**/node_modules": true`, `"http://h/*/y"`, `"off"`, `"security.workspace.trust.enabled"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in\n%s", want, s)
		}
	}
	if EditorStatus(p) != "off" {
		t.Fatal(EditorStatus(p))
	}
	if changed, _, _ := Editor(p, false); changed {
		t.Fatal("second run should be a no-op")
	}
}

func TestEditorDryRun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"task.allowAutomaticTasks": "on"}`), 0o644)
	if changed, _, _ := Editor(p, true); !changed {
		t.Fatal("should report change")
	}
	if EditorStatus(p) != "on" {
		t.Fatal("dry run wrote the file")
	}
}

func TestOnlyTheTwoNewestSettingsBackupsAreKept(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(p, []byte(`{"editor.fontSize": 14}`), 0o644)
	for _, ts := range []string{"1700000001", "1700000002", "1700000003"} {
		os.WriteFile(p+".threatscan-"+ts+".bak", []byte("{}"), 0o600)
	}
	os.WriteFile(p+".mine.bak", []byte("{}"), 0o600) // not ours
	if changed, _, err := Editor(p, false); err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	baks, _ := filepath.Glob(p + ".threatscan-*.bak")
	if len(baks) != 2 {
		t.Fatalf("backups kept: %v", baks)
	}
	for _, b := range baks {
		if strings.Contains(b, "1700000001") || strings.Contains(b, "1700000002") {
			t.Fatalf("an old backup survived: %v", baks)
		}
	}
	if _, err := os.Stat(p + ".mine.bak"); err != nil {
		t.Fatal("a backup that is not ours was removed")
	}
}
