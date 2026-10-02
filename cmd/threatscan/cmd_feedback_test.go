package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/guard"
	"github.com/FaheemRafiq/threatscan/internal/journal"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
)

func TestFeedbackBundleAndFalsePositive(t *testing.T) {
	home := isolate(t)
	inf := testfixtures.Infected(t, t.TempDir())
	run([]string{"scan", "--ci", "--no-system", "--fix", inf})
	out := filepath.Join(t.TempDir(), "fb.zip")
	if rc := run([]string{"feedback", "--out", out, "--days", "1"}); rc != 0 {
		t.Fatal(rc)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		names[f.Name] = string(b)
	}
	zr.Close()
	for _, want := range []string{"README.txt", "summary.txt", "journal.jsonl", "latest-report.json", "config.json"} {
		if names[want] == "" {
			t.Errorf("bundle lacks %s (has %d files)", want, len(names))
		}
	}
	if !strings.Contains(names["journal.jsonl"], `"kind":"finding"`) || !strings.Contains(names["summary.txt"], "ThreatScan") {
		t.Fatal("bundle content")
	}
	if rc := run([]string{"feedback", "--false-positive", filepath.Join(inf, "postcss.config.mjs"), "--note", "ours"}); rc != 0 {
		t.Fatal(rc)
	}
	fb := journal.Read(home, journal.Filter{Kinds: []string{journal.KindFeedback}})
	if len(fb) != 1 || fb[0].Note != "ours" {
		t.Fatalf("%+v", fb)
	}
	if rc := run([]string{"feedback", "--digest"}); rc != 0 {
		t.Fatal(rc)
	}
}

func TestDailyDigestIsPostedOnceAndCarriesNoPaths(t *testing.T) {
	home := isolate(t)
	inf := testfixtures.Infected(t, t.TempDir())
	run([]string{"scan", "--ci", "--no-system", "--fix", inf})
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
	}))
	defer srv.Close()
	cfg := config.Default()
	logs := []string{}
	log := func(m string) { logs = append(logs, m) }
	postDigest(home, cfg, "iocs", "linux", "my-host", log) // not opted in
	if len(bodies) != 0 {
		t.Fatal("posted without feedback_url")
	}
	cfg.FeedbackURL = srv.URL
	postDigest(home, cfg, "iocs", "linux", "my-host", log)
	postDigest(home, cfg, "iocs", "linux", "my-host", log) // same day: no second post
	if len(bodies) != 1 {
		t.Fatalf("posts: %d (%v)", len(bodies), logs)
	}
	body := bodies[0]
	for _, leak := range []string{inf, filepath.Dir(inf), "my-host", "postcss.config.mjs\"", home} {
		if leak != "" && strings.Contains(body, leak) {
			t.Errorf("digest leaks %q", leak)
		}
	}
	var got struct {
		Text   string `json:"text"`
		Digest struct {
			MachineID string         `json:"machine_id"`
			Host      string         `json:"host"`
			Sev       map[string]int `json:"findings_by_severity"`
			Actions   map[string]int `json:"actions"`
			Sweeps    int            `json:"sweeps"`
		} `json:"digest"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Digest.MachineID) != 16 || got.Digest.Host != "" || got.Digest.Sev["CRITICAL"] < 4 || got.Digest.Actions["quarantine"] < 2 || got.Digest.Sweeps != 1 || got.Text == "" {
		t.Fatalf("%+v", got)
	}
	if _, err := os.Stat(filepath.Join(home, "feedback-last")); err != nil {
		t.Fatal("last-post marker missing")
	}
	// a failing receiver must not mark the digest as sent
	os.Remove(filepath.Join(home, "feedback-last"))
	cfg.FeedbackURL = "http://127.0.0.1:1/unreachable"
	postDigest(home, cfg, "iocs", "linux", "h", log)
	if _, err := os.Stat(filepath.Join(home, "feedback-last")); err == nil {
		t.Fatal("marked as sent although the post failed")
	}
}

// stdout runs f and returns what it printed.
func stdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestEventUploadIsOptInPreviewableAndRedacted(t *testing.T) {
	home := isolate(t)
	inf := testfixtures.Infected(t, t.TempDir())
	run([]string{"scan", "--ci", "--no-system", "--fix", inf})
	// an event that names this machine and user's home, and carries a made-up secret
	c := mustCtx()
	secretPath := filepath.Join(c.P.Home, "work", "client-x", "loader.js")
	journal.Open(home, "t", "t").Write(journal.Event{Ctx: "cli", Kind: journal.KindFeedback, Title: "marked as a false positive",
		Path: secretPath, Note: "seen on " + c.P.Hostname + " token=abcdef123456"})
	want := len(journal.Read(home, journal.Filter{Archives: true}))
	if want < 6 {
		t.Fatalf("journal has only %d events", want)
	}

	var bodies []string
	var keys []string
	srvTarget := "" // non-empty: the table is unreachable, as when the machine is offline
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srvTarget != "" {
			http.Error(w, "down", 503)
			return
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		keys = append(keys, r.Header.Get("apikey")+"|"+r.Header.Get("Authorization"))
		w.WriteHeader(201)
	}))
	defer srv.Close()

	// not opted in: the guard task is off and --upload refuses
	var task *guard.PeriodicTask
	for i := range guardHooks.Periodic {
		if guardHooks.Periodic[i].Name == "event-upload" {
			task = &guardHooks.Periodic[i]
		}
	}
	if task == nil || task.Interval(config.Default()) != 0 {
		t.Fatal("the event-upload task must exist and be off by default")
	}
	if rc := run([]string{"feedback", "--upload"}); rc != 2 {
		t.Fatalf("--upload without upload_url: rc=%d", rc)
	}
	if rc := run([]string{"config", "--set", "upload_url=" + srv.URL + "/rest/v1/threatscan_events", "upload_key=the-anon-key"}); rc != 0 {
		t.Fatal(rc)
	}
	if cfg := config.Load(home); task.Interval(cfg) != time.Minute {
		t.Fatal("with upload_url set the guard checks every minute whether an upload is due")
	}
	up := newUploader(home, config.Load(home), c.P.Home, c.P.Hostname, "linux")
	if sum := uploadSummary(up); !strings.Contains(sum, fmt.Sprintf("on, 0 uploaded, %d waiting (no upload yet)", want)) {
		t.Fatalf("status before the first upload: %s", sum)
	}
	if out := stdout(t, func() { run([]string{"history", "--all", "--limit", "500"}) }); !strings.Contains(out, "upload") || !strings.Contains(out, " waiting ") || strings.Contains(out, " uploaded ") {
		t.Fatalf("history --all before the upload:\n%s", out)
	}

	// preview shows the rows and sends nothing
	out := stdout(t, func() {
		if rc := run([]string{"feedback", "--preview"}); rc != 0 {
			t.Errorf("preview rc=%d", rc)
		}
	})
	if len(bodies) != 0 {
		t.Fatal("--preview contacted the server")
	}
	if !strings.Contains(out, `"event_id"`) || !strings.Contains(out, `"machine_id"`) || !strings.Contains(out, "Nothing was sent") {
		t.Fatalf("preview output:\n%s", out)
	}

	if rc := run([]string{"feedback", "--upload"}); rc != 0 {
		t.Fatalf("upload rc=%d", rc)
	}
	all := strings.Join(bodies, "\n")
	var rows []map[string]any
	for _, b := range bodies {
		var batch []map[string]any
		if err := json.Unmarshal([]byte(b), &batch); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, batch...)
	}
	if len(rows) != want {
		t.Fatalf("uploaded %d rows, the journal has %d events", len(rows), want)
	}
	if keys[0] != "the-anon-key|Bearer the-anon-key" {
		t.Fatalf("key headers: %q", keys[0])
	}
	for _, leak := range []string{c.P.Home, c.P.Hostname, "abcdef123456", "the-anon-key"} {
		if len(leak) >= 3 && strings.Contains(all, leak) {
			t.Errorf("upload leaks %q", leak)
		}
	}
	if !strings.Contains(all, `"path":"~/work/client-x/loader.js"`) && !strings.Contains(all, `"path":"~\\work\\client-x\\loader.js"`) {
		t.Errorf("home-relative path missing from the upload")
	}
	if !strings.Contains(all, `"kind":"finding"`) || !strings.Contains(all, `"kind":"sweep"`) {
		t.Error("findings and sweeps should both be uploaded")
	}

	if sum := uploadSummary(up); !strings.Contains(sum, fmt.Sprintf("on, %d uploaded, 0 waiting (last upload ", want)) {
		t.Fatalf("status after the upload: %s", sum)
	}
	if out := stdout(t, func() { run([]string{"history", "--all", "--limit", "500"}) }); !strings.Contains(out, " uploaded ") || strings.Contains(out, " waiting ") {
		t.Fatalf("history --all after the upload:\n%s", out)
	}
	if out := stdout(t, func() { run([]string{"history", "--json", "--limit", "1"}) }); !strings.Contains(out, `"uploaded": true`) {
		t.Fatalf("history --json lacks the flag:\n%s", out)
	}

	// nothing new: a second upload sends no request
	n := len(bodies)
	if rc := run([]string{"feedback", "--upload"}); rc != 0 || len(bodies) != n {
		t.Fatalf("second upload rc=%d, extra requests=%d", rc, len(bodies)-n)
	}

	// the guard while the server is unreachable: one log line, not one per retry; the event waits
	journal.Open(home, "t", "t").Write(journal.Event{Kind: journal.KindGuard, Title: "guard started while offline"})
	cfg := config.Load(home)
	var logs []string
	log := func(m string) { logs = append(logs, m) }
	srvTarget = "down" // same upload_url, but the server behind it answers 503
	for i := 0; i < 3; i++ {
		uploadEvents(newUploader(home, cfg, c.P.Home, c.P.Hostname, "linux"), log)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "event upload failed, 1 events are kept and waiting") || len(bodies) != n {
		t.Fatalf("logs while offline: %v", logs)
	}
	if sum := uploadSummary(up); !strings.Contains(sum, "1 waiting; server not reached since ") || !strings.Contains(sum, "HTTP 503") {
		t.Fatalf("status while offline: %s", sum)
	}
	if out := stdout(t, func() { run([]string{"history", "--not-uploaded"}) }); !strings.Contains(out, "guard started while offline") || strings.Contains(out, " uploaded ") {
		t.Fatalf("history --not-uploaded:\n%s", out)
	}
	if up.Due(time.Now()) || !up.Due(time.Now().Add(5*time.Minute)) {
		t.Fatal("after three failures the next try is due in 4 minutes")
	}
	// back online: delivered, and said once
	srvTarget = ""
	uploadEvents(newUploader(home, cfg, c.P.Home, c.P.Hostname, "linux"), log)
	if len(bodies) != n+1 || len(logs) != 2 || !strings.Contains(logs[1], "back online, 1 redacted events sent, 0 waiting") {
		t.Fatalf("logs=%v requests=%d", logs, len(bodies)-n)
	}
	if out := stdout(t, func() { run([]string{"history", "--not-uploaded"}) }); !strings.Contains(out, "Nothing recorded") {
		t.Fatalf("history --not-uploaded after recovery:\n%s", out)
	}

	// the bundle a user sends by hand must not carry the upload key or URL
	zipPath := filepath.Join(t.TempDir(), "fb.zip")
	if rc := run([]string{"feedback", "--out", zipPath}); rc != 0 {
		t.Fatal(rc)
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if strings.Contains(string(b), "the-anon-key") || strings.Contains(string(b), srv.URL) {
			t.Errorf("%s in the bundle carries the upload key or URL", f.Name)
		}
	}
}

func TestCleanupCommandStatusLineAndDailyTask(t *testing.T) {
	home := isolate(t)
	run([]string{"scan", "--ci", "--no-system", "--fix", testfixtures.Infected(t, t.TempDir())})
	// an expired quarantine slot, old log archives and a year-old journal archive
	old := filepath.Join(home, "quarantine", time.Now().Add(-200*24*time.Hour).Format("20060102-150405"))
	os.MkdirAll(filepath.Join(old, "1"), 0o700)
	os.WriteFile(filepath.Join(old, "1", "big.bin"), make([]byte, 3<<20), 0o600)
	for i := 1; i <= 7; i++ {
		os.WriteFile(filepath.Join(home, fmt.Sprintf("guard-2026080%d-100000000.log.gz", i)), make([]byte, 100), 0o600)
	}
	os.WriteFile(filepath.Join(home, "journal-20240101-100000000.jsonl.gz"), []byte("not even gzip"), 0o600)

	c := mustCtx()
	if sum := diskSummary(c); !strings.Contains(sum, "quarantine 3") || !strings.Contains(sum, "threatscan cleanup") {
		t.Fatalf("status disk line: %s", sum)
	}
	if out := stdout(t, func() { run([]string{"status"}) }); !strings.Contains(out, "Disk use:") {
		t.Fatalf("status lacks the disk line:\n%s", out)
	}
	out := stdout(t, func() {
		if rc := run([]string{"cleanup", "--dry-run"}); rc != 0 {
			t.Errorf("rc=%d", rc)
		}
	})
	for _, want := range []string{"Would remove 1 quarantined copies", "Would remove 2 old guard logs", "Would remove 1 journal archives", "Dry run: nothing was removed", "journal_keep_mb", "90 days"} {
		if !strings.Contains(out, want) {
			t.Errorf("cleanup --dry-run lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatal("--dry-run removed something")
	}
	out = stdout(t, func() { run([]string{"cleanup"}) })
	if !strings.Contains(out, "Removed 1 quarantined copies") || !strings.Contains(out, "freed.") {
		t.Fatalf("cleanup:\n%s", out)
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("the expired quarantine copy is still there")
	}
	left, _ := filepath.Glob(filepath.Join(home, "guard-*.log.gz"))
	arch, _ := filepath.Glob(filepath.Join(home, "journal-2024*"))
	if len(left) != 5 || len(arch) != 1 || !strings.HasSuffix(arch[0], ".pruned") {
		t.Fatalf("guard archives=%d journal leftovers=%v", len(left), arch)
	}
	// what the scan quarantined a moment ago is untouched and can still be restored
	if out := stdout(t, func() { run([]string{"cleanup"}) }); !strings.Contains(out, "Nothing is past its limit") {
		t.Fatalf("second cleanup:\n%s", out)
	}
	if ents, _ := os.ReadDir(filepath.Join(home, "quarantine")); len(ents) < 2 {
		t.Fatal("recent quarantine copies were removed")
	}
	// the guard does the same once a day
	var task *guard.PeriodicTask
	for i := range guardHooks.Periodic {
		if guardHooks.Periodic[i].Name == "housekeeping" {
			task = &guardHooks.Periodic[i]
		}
	}
	if task == nil || task.Interval(config.Default()) != 24*time.Hour {
		t.Fatal("the guard must run housekeeping daily")
	}
	// defaults: every store is limited out of the box
	d := config.Default()
	if d.JournalKeepMB != 100 || d.JournalKeepDays != 365 || d.QuarantineKeepDays != 90 || d.QuarantineKeepMB != 500 || d.CloneKeepDays != 3 || d.CloneKeepMB != 2048 {
		t.Fatalf("default limits: %+v", d)
	}
}
