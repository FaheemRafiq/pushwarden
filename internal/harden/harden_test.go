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
