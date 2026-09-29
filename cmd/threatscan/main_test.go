// threatscan:allow-signatures
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
)

func isolate(t *testing.T) string {
	home := filepath.Join(t.TempDir(), "tshome")
	t.Setenv("THREATSCAN_HOME", home)
	t.Setenv("THREATSCAN_NO_BLOCK", "1") // never ask for admin rights in tests
	t.Setenv("THREATSCAN_SYSTEM_DIR", filepath.Join(t.TempDir(), "sys"))
	return home
}

func TestScanExitCodes(t *testing.T) {
	isolate(t)
	d := t.TempDir()
	clean := testfixtures.Clean(t, filepath.Join(d, "a"))
	inf := testfixtures.Infected(t, filepath.Join(d, "b"))
	if rc := run([]string{"scan", "--ci", "--no-system", "--no-report", clean}); rc != 0 {
		t.Fatalf("clean rc=%d", rc)
	}
	if rc := run([]string{"scan", "--ci", "--no-system", "--no-report", inf}); rc != 1 {
		t.Fatalf("infected rc=%d", rc)
	}
	// legacy form without subcommand, flags after the path
	if rc := run([]string{inf, "--ci", "--no-system", "--no-report"}); rc != 1 {
		t.Fatalf("legacy rc=%d", rc)
	}
	// report only: nothing changed
	if _, err := os.Stat(filepath.Join(inf, "temp_auto_push.bat")); err != nil {
		t.Fatal("scan without --fix must not change files")
	}
}

func TestFixThenHistoryRestoreAllowRemove(t *testing.T) {
	isolate(t)
	inf := testfixtures.Infected(t, t.TempDir())
	if rc := run([]string{"scan", "--ci", "--no-system", "--no-report", "--fix", inf}); rc != 1 {
		t.Fatalf("rc=%d", rc)
	}
	cfg, _ := os.ReadFile(filepath.Join(inf, "postcss.config.mjs"))
	if strings.Contains(string(cfg), "global['_V']") || !strings.Contains(string(cfg), "@tailwindcss/postcss") {
		t.Fatalf("payload not stripped cleanly: %q", cfg)
	}
	for _, p := range []string{"temp_auto_push.bat", ".vscode/tasks.json", "public/fonts/fa-solid-900.woff2"} {
		if _, err := os.Stat(filepath.Join(inf, p)); err == nil {
			t.Errorf("%s should be quarantined", p)
		}
	}
	if rc := run([]string{"history"}); rc != 0 {
		t.Fatal("history")
	}
	bat := filepath.Join(inf, "temp_auto_push.bat")
	if rc := run([]string{"history", "--allow", bat}); rc != 0 {
		t.Fatal("allow")
	}
	if _, err := os.Stat(bat); err != nil {
		t.Fatal("allow should restore the file")
	}
	if rc := run([]string{"history", "--remove", filepath.Join(inf, "public", "fonts", "fa-solid-900.woff2")}); rc != 0 {
		t.Fatal("remove")
	}
	// the allowed file is not acted on again
	run([]string{"scan", "--ci", "--no-system", "--no-report", "--fix", inf})
	if _, err := os.Stat(bat); err != nil {
		t.Fatal("allowed file was quarantined again")
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	isolate(t)
	inf := testfixtures.Infected(t, t.TempDir())
	run([]string{"scan", "--ci", "--no-system", "--no-report", "--dry-run", inf})
	b, _ := os.ReadFile(filepath.Join(inf, "postcss.config.mjs"))
	if !strings.Contains(string(b), "global['_V']") {
		t.Fatal("dry run modified the file")
	}
	if _, err := os.Stat(filepath.Join(inf, "temp_auto_push.bat")); err != nil {
		t.Fatal("dry run quarantined a file")
	}
}

func TestConfigHardenProtectStatus(t *testing.T) {
	home := isolate(t)
	if rc := run([]string{"config", "--set", "action=ask", "--set", "quick_interval=9", "--set", "exclude=/a,/b"}); rc != 0 {
		t.Fatal("config")
	}
	b, _ := os.ReadFile(filepath.Join(home, "config.json"))
	for _, want := range []string{`"action": "ask"`, `"quick_interval": 9`, `"/b"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("config.json missing %s", want)
		}
	}
	if rc := run([]string{"config", "--set", "nope=1"}); rc != 2 {
		t.Fatal("unknown key should fail")
	}
	for _, a := range [][]string{{"harden", "--dry-run"}, {"protect", "--status"}, {"status"}, {"version"}} {
		if rc := run(a); rc != 0 {
			t.Errorf("%v rc=%d", a, rc)
		}
	}
	if rc := run([]string{"bogus-cmd"}); rc != 2 {
		t.Fatal("unknown command should exit 2")
	}
}

func TestInstallDryRunWritesNothing(t *testing.T) {
	home := isolate(t)
	fake := t.TempDir()
	for _, k := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(k, fake)
	}
	t.Setenv("APPDATA", filepath.Join(fake, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(fake, "AppData", "Local"))
	t.Setenv("THREATSCAN_INSTALL_DIR", filepath.Join(t.TempDir(), "inst"))
	for _, base := range []string{".config/Code", "Library/Application Support/Code", "AppData/Roaming/Code"} {
		os.MkdirAll(filepath.Join(fake, filepath.FromSlash(base)), 0o755)
	}
	sp := platform.New().EditorSettings()["VS Code"]
	if sp == "" {
		t.Fatal("no VS Code settings path under the fake home")
	}
	os.MkdirAll(filepath.Dir(sp), 0o755)
	os.WriteFile(sp, []byte(`{"task.allowAutomaticTasks": "on"}`), 0o644)

	run([]string{"install", "--dry-run"})

	if b, _ := os.ReadFile(sp); !strings.Contains(string(b), `"on"`) {
		t.Errorf("dry run hardened the editor: %s", b)
	}
	if _, err := os.Stat(filepath.Join(home, "config.json")); err == nil {
		t.Error("dry run saved config.json")
	}
	if _, err := os.Stat(os.Getenv("THREATSCAN_INSTALL_DIR")); err == nil {
		t.Error("dry run copied the binary")
	}
	for _, p := range []string{".config/systemd/user/threatscan-guard.service", "Library/LaunchAgents/com.threatscan.guard.plist", ".local/bin/threatscan"} {
		if _, err := os.Lstat(filepath.Join(fake, filepath.FromSlash(p))); err == nil {
			t.Errorf("dry run wrote %s", p)
		}
	}
	if ents, _ := os.ReadDir(home); len(ents) != 0 {
		t.Errorf("dry run wrote into the data dir: %v", ents)
	}
}
