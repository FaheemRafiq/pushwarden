package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/journal"
	"github.com/FaheemRafiq/threatscan/internal/notify"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
)

func TestFormatAlertsAndHistory(t *testing.T) {
	if !strings.HasPrefix(formatAlerts(nil, false), "No alerts yet") {
		t.Fatal("empty")
	}
	f := &findings.Finding{Severity: findings.Critical, Category: "malicious_process", Title: "Malicious process running: PID 7 (node)",
		Action: "killed PID 7", Meta: findings.Meta{PID: 7, Kill: true}}
	out := formatAlerts([]notify.Alert{{TS: "2026-09-29T10:00:00", Context: "guard-quick", Why: findings.Why(f), Response: findings.WhyAction(f), Finding: f}}, false)
	for _, want := range []string{"2026-09-29 10:00:00", "[CRITICAL]", "Behavior:Node/PolinRider.Payload", "why: A running process", "response: Killed:"} {
		if !strings.Contains(out, want) {
			t.Errorf("alerts output lacks %q:\n%s", want, out)
		}
	}
	ok := true
	es := []protect.Entry{
		{TS: "2026-09-29T10:00:00", Type: "kill", PID: 7, Cmd: "node /tmp/.x/a.js", Threat: "Behavior:Node/PolinRider.Payload", OK: &ok,
			Reason: "Killed: strict marker", Evidence: []string{"strict kill marker present"}},
		{TS: "2026-09-29T10:00:01", Type: "quarantine", Original: "/r/f.woff2", Threat: "Trojan:JS/PolinRider.FakeFont", Evidence: []string{"woff2 but code"}},
	}
	h := formatHistory(es, false)
	if !strings.Contains(h, "pid 7") || !strings.Contains(h, "why: Killed: strict marker") || !strings.Contains(h, "why: woff2 but code") {
		t.Fatalf("history:\n%s", h)
	}
	if strings.Contains(h, "cmd: node") {
		t.Fatal("cmd only with --details")
	}
	d := formatHistory(es, true)
	if !strings.Contains(d, "cmd: node /tmp/.x/a.js") || !strings.Contains(d, "- strict kill marker present") {
		t.Fatalf("details:\n%s", d)
	}
}

func TestAlertsCommand(t *testing.T) {
	home := isolate(t)
	if rc := run([]string{"alerts"}); rc != 0 {
		t.Fatal(rc)
	}
	os.MkdirAll(home, 0o700)
	os.WriteFile(filepath.Join(home, "alerts.log"), []byte(`{"ts":"2026-09-29T10:00:00","context":"scan","severity":"HIGH","category":"compromised_package","title":"pkg","path":"/r/package.json"}`+"\n"), 0o600)
	if rc := run([]string{"alerts", "--last", "5"}); rc != 0 {
		t.Fatal(rc)
	}
	if rc := run([]string{"alerts", "--json"}); rc != 0 {
		t.Fatal(rc)
	}
	if rc := run([]string{"history", "--json"}); rc != 0 {
		t.Fatal(rc)
	}
}

func TestProtectDryRunAndStatusNeedNoRoot(t *testing.T) {
	isolate(t)
	if rc := run([]string{"protect", "--dry-run"}); rc != 0 {
		t.Fatal("dry-run", rc)
	}
	if rc := run([]string{"protect", "--status"}); rc != 0 {
		t.Fatal("status", rc)
	}
	// without admin rights and with elevation disabled, --install explains and exits 2.
	// (Never run it as admin here: CI's Windows runner is one, and it would really install.)
	if !platform.IsAdmin() {
		if rc := run([]string{"protect", "--install"}); rc != 2 {
			t.Fatal("install without root", rc)
		}
	}
	// --roots keeps the dry-run's report-only first scan away from the real home folder
	if rc := run([]string{"install", "--dry-run", "--no-harden", "--roots", t.TempDir()}); rc != 0 {
		t.Fatal("install dry-run", rc)
	}
	if ents, _ := os.ReadDir(os.Getenv("THREATSCAN_SYSTEM_DIR")); len(ents) != 0 {
		t.Fatal("dry runs wrote to the system dir")
	}
}

func TestScanWritesJournalUnlessNoReport(t *testing.T) {
	home := isolate(t)
	d := t.TempDir()
	inf := testfixtures.Infected(t, d)
	run([]string{"scan", "--ci", "--no-system", "--no-report", inf})
	if journal.Exists(home) {
		t.Fatal("--no-report must leave no journal")
	}
	run([]string{"scan", "--ci", "--no-system", "--fix", inf})
	evs := journal.Read(home, journal.Filter{})
	kinds := map[string]int{}
	for _, e := range evs {
		kinds[e.Kind]++
		if e.Ctx != "scan" {
			t.Fatalf("ctx: %+v", e)
		}
	}
	if kinds[journal.KindSweep] != 2 || kinds[journal.KindFinding] < 4 || kinds[journal.KindAction] < 3 {
		t.Fatalf("kinds: %v", kinds)
	}
}
