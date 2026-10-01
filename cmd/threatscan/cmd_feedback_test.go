package main

import (
	"archive/zip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/config"
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
