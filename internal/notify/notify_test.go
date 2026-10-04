// pushwarden:allow-signatures
package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/pushwarden/internal/config"
	"github.com/FaheemRafiq/pushwarden/internal/findings"
	"github.com/FaheemRafiq/pushwarden/internal/platform"
)

func killed() *findings.Finding {
	return &findings.Finding{Severity: findings.Critical, Category: "malicious_process", Title: "Malicious process running: PID 7 (node)",
		Action: "killed PID 7", Meta: findings.Meta{PID: 7, Kill: true, Cmd: "node /tmp/.x/a.js", Evidence: []string{"strict kill marker present"}}}
}

func TestBuildAlert(t *testing.T) {
	title, body := BuildAlert([]*findings.Finding{killed()})
	if title != "Threats found - actions taken" {
		t.Fatal(title)
	}
	lines := strings.Split(body, "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "Behavior:Node/PolinRider.Payload: ") || !strings.HasPrefix(lines[1], "Killed:") {
		t.Fatalf("single-finding body:\n%s", body)
	}
	var many []*findings.Finding
	for i := 0; i < 6; i++ {
		many = append(many, &findings.Finding{Severity: findings.Critical, Category: "fake_font_loader", Title: "t", Path: "/r/f.woff2"})
	}
	title, body = BuildAlert(many)
	if title != "Threats found - action needed" || !strings.Contains(body, "... and 1 more") || strings.Count(body, "\n") != 5 {
		t.Fatalf("%s\n%s", title, body)
	}
}

func TestLogAndReadAlerts(t *testing.T) {
	dir := t.TempDir()
	n := New(platform.New(), config.Default(), dir)
	n.Cfg.NotifyDesktop = false
	n.Alert([]*findings.Finding{killed()}, "guard-quick")
	n.Alert([]*findings.Finding{{Severity: findings.High, Category: "compromised_package", Title: "pkg", Path: "/r/package.json"}}, "scan")
	// a corrupt line must not break reading
	fh, _ := os.OpenFile(filepath.Join(dir, "alerts.log"), os.O_APPEND|os.O_WRONLY, 0o600)
	fh.WriteString("not json\n")
	fh.Close()
	as, err := ReadAlerts(filepath.Join(dir, "alerts.log"), 0)
	if err != nil || len(as) != 2 {
		t.Fatalf("%v %d", err, len(as))
	}
	if as[0].Context != "guard-quick" || !strings.HasPrefix(as[0].Response, "Killed") || as[0].Why == "" || as[0].Meta.PID != 7 {
		t.Fatalf("%+v", as[0])
	}
	if as[1].Response != "" || !strings.Contains(as[1].Why, "dependency") {
		t.Fatalf("%+v", as[1])
	}
	if last, _ := ReadAlerts(filepath.Join(dir, "alerts.log"), 1); len(last) != 1 || last[0].Title != "pkg" {
		t.Fatal("last N")
	}
	if as, err := ReadAlerts(filepath.Join(dir, "missing.log"), 5); err != nil || as != nil {
		t.Fatal("missing file is not an error")
	}
}

func TestWebhookCarriesReasons(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
	}))
	defer srv.Close()
	n := New(platform.New(), config.Default(), t.TempDir())
	n.Cfg.NotifyDesktop = false
	n.Cfg.WebhookURL = srv.URL
	n.Alert([]*findings.Finding{killed()}, "guard-quick")
	reasons, _ := got["reasons"].([]any)
	if len(reasons) != 1 {
		t.Fatalf("payload: %v", got)
	}
	r := reasons[0].(map[string]any)
	if !strings.HasPrefix(r["response"].(string), "Killed") || r["why"] == "" || !strings.Contains(got["text"].(string), "why: ") {
		t.Fatalf("%v", got)
	}
}

func TestMacNotifierPieces(t *testing.T) {
	s := NotifierScript("/Users/x/Library/Application Support/PushWarden/pushwarden")
	for _, want := range []string{"on run argv", "on reopen", "display notification", "alerts --gui", "'/Users/x/Library/Application Support/PushWarden/pushwarden'"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if sub, text := macArgs("T", "first line\nsecond line"); sub != "first line" || text != "second line" {
		t.Fatal(sub, text)
	}
	if sub, text := macArgs("T", "only"); sub != "only" || text != "" {
		t.Fatal(sub, text)
	}
	dir := t.TempDir()
	if msg, err := InstallMacNotifier(platform.New(), dir, "/bin/pushwarden", true); err != nil || !strings.Contains(msg, "would build") {
		t.Fatal(msg, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatal("dry run created files")
	}
	if MacAppPath(dir) != filepath.Join(dir, MacAppName) {
		t.Fatal(MacAppPath(dir))
	}
	RemoveMacNotifier(dir) // no-op when absent
}

func TestMacLauncherPieces(t *testing.T) {
	s := LauncherScript("/Users/x/Library/Application Support/PushWarden/pushwarden")
	for _, want := range []string{`tell application "Terminal"`, "'/Users/x/Library/Application Support/PushWarden/pushwarden' ui --pause"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	home := t.TempDir()
	if msg, err := InstallMacLauncher(platform.New(), home, "/bin/pushwarden", true); err != nil || !strings.Contains(msg, "would build") {
		t.Fatal(msg, err)
	}
	if ents, _ := os.ReadDir(home); len(ents) != 0 {
		t.Fatal("dry run created files")
	}
	// uninstall removes the launcher, but never another app of the same name
	app := MacLauncherPath(home)
	plist := filepath.Join(app, "Contents", "Info.plist")
	os.MkdirAll(filepath.Dir(plist), 0o755)
	os.WriteFile(plist, []byte("<string>com.example.other</string>"), 0o644)
	RemoveMacLauncher(home)
	if !exists(app) {
		t.Fatal("removed an app that is not the launcher")
	}
	os.WriteFile(plist, []byte("<string>"+MacLauncherBundleID+"</string>"), 0o644)
	RemoveMacLauncher(home)
	if exists(app) {
		t.Fatal("the launcher should be removed")
	}
}
