// threatscan:allow-signatures
package guard

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/protect"
	"github.com/FaheemRafiq/threatscan/internal/report"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
)

func setup(t *testing.T, mutate func(*config.Config)) (*Guard, string, string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "tshome")
	root := filepath.Join(t.TempDir(), "root")
	c := config.Default()
	c.ScanRoots = []string{root}
	c.NotifyDesktop = false
	c.AutoKill = false
	c.IOCUpdate = false
	if mutate != nil {
		mutate(c)
	}
	if _, err := c.Save(home); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(root, 0o755)
	g, err := New(platform.New(), home, "0.1.0-test", true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return g, home, root
}

func TestOnceQuarantinesAndWritesState(t *testing.T) {
	restore := prompt.SetDialogForTest(func(string, string, string, string, time.Duration) prompt.Verdict { return prompt.Timeout })
	defer restore()
	g, home, root := setup(t, nil)
	inf := testfixtures.Infected(t, root)
	if rc := g.Run(); rc != 0 {
		t.Fatal(rc)
	}
	hb, _, alive := ReadHeartbeat(home)
	if !alive || hb.Repos != 1 || hb.Version != "0.1.0-test" {
		t.Fatalf("heartbeat %+v alive=%v", hb, alive)
	}
	if _, err := os.Stat(filepath.Join(home, "reports", "latest.json")); err != nil {
		t.Fatal("no report")
	}
	if _, err := os.Stat(filepath.Join(inf, "temp_auto_push.bat")); err == nil {
		t.Fatal("propagation script not quarantined")
	}
	if b, _ := os.ReadFile(filepath.Join(inf, "postcss.config.mjs")); strings.Contains(string(b), "global['_V']") {
		t.Fatal("payload not stripped")
	}
	if _, err := os.Stat(filepath.Join(home, "alerts.log")); err != nil {
		t.Fatal("no alert log")
	}
}

func TestQuarantineThenDialogDecisions(t *testing.T) {
	var mu sync.Mutex
	asked := map[string]int{}
	restore := prompt.SetDialogForTest(func(title, msg, ok, cancel string, _ time.Duration) prompt.Verdict {
		mu.Lock()
		defer mu.Unlock()
		if ok != "Remove" || cancel != "Restore & allow" || !strings.Contains(msg, "Evidence:") {
			t.Errorf("unexpected dialog %q %q", ok, cancel)
		}
		switch {
		case strings.Contains(msg, "fa-solid-900.woff2"):
			asked["font"]++
			return prompt.Delete
		case strings.Contains(msg, "postcss.config.mjs"):
			asked["postcss"]++
			return prompt.Keep
		}
		return prompt.Timeout
	})
	defer restore()
	g, _, root := setup(t, nil)
	proj := filepath.Join(root, "proj")
	os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
	os.WriteFile(filepath.Join(proj, "postcss.config.mjs"), []byte(testfixtures.CleanPostcss), 0o644)
	g.startDialogWorker()
	// the watcher delivers two freshly written files
	os.WriteFile(filepath.Join(proj, "postcss.config.mjs"), []byte(testfixtures.InfectedPostcss), 0o644)
	font := filepath.Join(proj, "public", "fonts", "fa-solid-900.woff2")
	os.MkdirAll(filepath.Dir(font), 0o755)
	os.WriteFile(font, testfixtures.FakeWoff2, 0o644)
	g.OnEvents([]string{filepath.Join(proj, "postcss.config.mjs"), font})
	// acted immediately, before any dialog answer
	if b, _ := os.ReadFile(filepath.Join(proj, "postcss.config.mjs")); strings.Contains(string(b), "global['_V']") {
		t.Fatal("not stripped before the dialog")
	}
	if _, err := os.Stat(font); err == nil {
		t.Fatal("font not quarantined before the dialog")
	}
	close(g.dialogs)
	g.dialogWG.Wait()
	if asked["font"] != 1 || asked["postcss"] != 1 {
		t.Fatalf("asked=%v", asked)
	}
	// Keep restored + allowed the config; Delete purged the font copy
	if b, _ := os.ReadFile(filepath.Join(proj, "postcss.config.mjs")); !strings.Contains(string(b), "global['_V']") {
		t.Fatal("Restore & allow did not restore")
	}
	var purged, restored bool
	for _, e := range g.Prot.Entries() {
		purged = purged || e.Type == "purge"
		restored = restored || e.Type == "restore"
	}
	if !purged || !restored {
		t.Fatal("history missing purge/restore")
	}
	// allowed file is left alone afterwards
	g.dialogs = make(chan *F, 4)
	g.OnEvents([]string{filepath.Join(proj, "postcss.config.mjs")})
	if b, _ := os.ReadFile(filepath.Join(proj, "postcss.config.mjs")); !strings.Contains(string(b), "global['_V']") {
		t.Fatal("allowed file was acted on again")
	}
}

func TestReportPolicyNeverChangesFiles(t *testing.T) {
	g, _, root := setup(t, func(c *config.Config) { c.Action = "report" })
	inf := testfixtures.Infected(t, root)
	g.Run()
	if _, err := os.Stat(filepath.Join(inf, "temp_auto_push.bat")); err != nil {
		t.Fatal("report policy quarantined a file")
	}
}

func TestAlertDedup(t *testing.T) {
	g, _, root := setup(t, func(c *config.Config) { c.Action = "report" })
	f := &F{Severity: 3, Category: "config_injection", Title: "x", Path: filepath.Join(root, "a.js")}
	g.Handle([]*F{f}, "t")
	first := g.seen[f.Key()]
	time.Sleep(1100 * time.Millisecond)
	g.Handle([]*F{{Severity: 3, Category: "config_injection", Title: "x", Path: f.Path}}, "t")
	if g.seen[f.Key()] != first {
		t.Fatal("seen timestamp refreshed without alerting (v5 review bug)")
	}
	_ = protect.ActionWord
}

func TestRecentReportSkipsInitialSweep(t *testing.T) {
	g, home, root := setup(t, nil)
	testfixtures.Infected(t, root)
	if _, ok := g.recentReport(); ok {
		t.Fatal("no report yet")
	}
	st := &findings.Stats{ReposScanned: 1}
	if _, err := report.Save(home, report.New("0.1.0-test", g.I.Version, st, nil), 10, "scan"); err != nil {
		t.Fatal(err)
	}
	age, ok := g.recentReport()
	if !ok || age > time.Minute {
		t.Fatalf("fresh report not recognised: %v %v", age, ok)
	}
	g.lightStart()
	hb, _, alive := ReadHeartbeat(home)
	if !alive || hb.Phase != "idle" || hb.Repos != 1 {
		t.Fatalf("heartbeat after light start: %+v", hb)
	}
	if time.Since(g.lastFull) > time.Minute {
		t.Fatal("lastFull not dated from the report")
	}
	// the infected fixture was NOT scanned: its propagation script is still there
	if _, err := os.Stat(filepath.Join(root, "victim", "temp_auto_push.bat")); err != nil {
		t.Fatal("light start must not scan")
	}
}

func TestProgressInHeartbeatAndSweepSummary(t *testing.T) {
	g, home, _ := setup(t, nil)
	g.progress(7, 17, "/home/x/Coding/A-Bot-Ledger")
	hb, _, _ := ReadHeartbeat(home)
	if hb.Phase != "full" || hb.Done != 7 || hb.Total != 17 || hb.Current != "A-Bot-Ledger" {
		t.Fatalf("%+v", hb)
	}
	g.heartbeat("idle", nil)
	hb, _, _ = ReadHeartbeat(home)
	if hb.Done != 0 || hb.Total != 0 || hb.Current != "" {
		t.Fatalf("progress must be cleared outside a sweep: %+v", hb)
	}
	if s := sweepSummary(17, &findings.Stats{}, 3*time.Minute); !strings.Contains(s, "17 repositories in 3m0s. Nothing found.") {
		t.Fatal(s)
	}
	if s := sweepSummary(17, &findings.Stats{Critical: 1, High: 2}, time.Minute); !strings.Contains(s, "1 threat(s) handled, 2 need review") {
		t.Fatal(s)
	}
}
