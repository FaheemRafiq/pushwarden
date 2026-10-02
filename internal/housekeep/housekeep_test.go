package housekeep

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/config"
	"github.com/FaheemRafiq/threatscan/internal/journal"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.Local)

// archive writes a journal archive rotated `age` ago with n events and
// about `pad` bytes of incompressible payload.
func archive(t *testing.T, dir string, age time.Duration, n, pad int) string {
	t.Helper()
	p := filepath.Join(dir, "journal-"+now.Add(-age).Format("20060102-150405")+"000.jsonl.gz")
	fh, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(fh, gzip.NoCompression)
	for i := 0; i < n; i++ {
		fmt.Fprintf(zw, `{"ts":"%s","kind":"guard","note":"%s"}`+"\n", now.Add(-age).Format(time.RFC3339), strings.Repeat("x", pad/n))
	}
	zw.Close()
	fh.Close()
	return p
}

func write(t *testing.T, p string, size int, age time.Duration) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	at := now.Add(-age)
	os.Chtimes(p, at, at)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func find(r Report, what string) Line {
	for _, l := range r.Lines {
		if strings.Contains(l.What, what) {
			return l
		}
	}
	return Line{}
}

func TestJournalArchivesAreCappedBySizeAndAge(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.JournalKeepMB, cfg.JournalKeepDays = 2, 365
	ancient := archive(t, dir, 400*24*time.Hour, 10, 1000)  // older than a year
	old := archive(t, dir, 30*24*time.Hour, 20, 900<<10)    // 1 MB
	mid := archive(t, dir, 20*24*time.Hour, 30, 900<<10)    // 1 MB
	recent := archive(t, dir, 10*24*time.Hour, 40, 900<<10) // 1 MB: together over 2 MB
	os.WriteFile(filepath.Join(dir, journal.FileName), []byte(`{"ts":"2026-10-02T11:00:00+05:00","kind":"guard"}`+"\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600)

	dry := Run(Options{DataDir: dir, Cfg: cfg, Dry: true, Now: now, TempDir: t.TempDir()})
	if l := find(dry, "journal"); l.Count != 2 || !exists(ancient) || !exists(old) {
		t.Fatalf("dry run must list 2 archives and remove nothing: %+v", dry.Lines)
	}
	if journal.PrunedEvents(dir) != 0 {
		t.Fatal("a dry run wrote a marker")
	}
	r := Run(Options{DataDir: dir, Cfg: cfg, Now: now, TempDir: t.TempDir()})
	l := find(r, "journal")
	if l.Count != 2 || l.Bytes < 900<<10 || exists(ancient) || exists(old) || !exists(mid) || !exists(recent) {
		t.Fatalf("expected the year-old and the oldest archive to go: %+v", r.Lines)
	}
	if !exists(filepath.Join(dir, journal.FileName)) || !exists(filepath.Join(dir, "config.json")) {
		t.Fatal("the active journal and unrelated files must never be touched")
	}
	// the removed events still count, so every later event keeps its position
	if got := journal.PrunedEvents(dir); got != 30 {
		t.Fatalf("pruned events = %d, want 30", got)
	}
	if evs := journal.Read(dir, journal.Filter{Archives: true}); len(evs) != 71 {
		t.Fatalf("remaining events: %d", len(evs))
	}
	if r := Run(Options{DataDir: dir, Cfg: cfg, Now: now, TempDir: t.TempDir()}); len(r.Lines) != 0 {
		t.Fatalf("a second pass has nothing to do: %+v", r.Lines)
	}
	// 0 turns a limit off
	cfg.JournalKeepMB, cfg.JournalKeepDays = 0, 0
	archive(t, dir, 900*24*time.Hour, 5, 3<<20)
	if r := Run(Options{DataDir: dir, Cfg: cfg, Now: now, TempDir: t.TempDir()}); find(r, "journal").Count != 0 {
		t.Fatalf("limits set to 0 must delete nothing: %+v", r.Lines)
	}
}

func TestUnsentArchivesWaitUntilTwiceTheLimit(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.JournalKeepMB, cfg.JournalKeepDays = 0, 100
	a := archive(t, dir, 150*24*time.Hour, 10, 100) // past the limit, not past twice the limit
	unsent := func(string) bool { return true }
	if r := Run(Options{DataDir: dir, Cfg: cfg, Now: now, Unsent: unsent, TempDir: t.TempDir()}); len(r.Lines) != 0 || !exists(a) {
		t.Fatalf("an archive waiting for upload must be kept: %+v", r.Lines)
	}
	if r := Run(Options{DataDir: dir, Cfg: cfg, Now: now, TempDir: t.TempDir()}); find(r, "journal").Count != 1 {
		t.Fatal("the same archive, uploaded, is removed")
	}
	b := archive(t, dir, 250*24*time.Hour, 7, 100) // past twice the limit: the disk limit wins
	r := Run(Options{DataDir: dir, Cfg: cfg, Now: now, Unsent: unsent, TempDir: t.TempDir()})
	if l := find(r, "journal"); l.Count != 1 || exists(b) || !strings.Contains(l.Note, "7 of them were never uploaded") {
		t.Fatalf("%+v", r.Lines)
	}
}

func TestLogsQuarantineTempAndUsage(t *testing.T) {
	dir, tmp := t.TempDir(), t.TempDir()
	cfg := config.Default()
	cfg.QuarantineKeepDays, cfg.QuarantineKeepMB = 90, 1
	for i := 1; i <= 8; i++ {
		write(t, filepath.Join(dir, fmt.Sprintf("guard-2026090%d-120000000.log.gz", i)), 1000, 0)
		write(t, filepath.Join(dir, fmt.Sprintf("alerts-2026090%d-120000000.log.gz", i)), 1000, 0)
	}
	write(t, filepath.Join(dir, "guard.log"), 500, 0)
	write(t, filepath.Join(dir, "alerts.log"), 500, 0)
	// quarantine: one slot past 90 days, two recent ones that together exceed 1 MB
	q := filepath.Join(dir, "quarantine")
	slot := func(age time.Duration, size int) string {
		d := filepath.Join(q, now.Add(-age).Format("20060102-150405"))
		write(t, filepath.Join(d, "123", "file.js"), size, 0)
		return d
	}
	expired, older, newer := slot(100*24*time.Hour, 100), slot(5*24*time.Hour, 700<<10), slot(24*time.Hour, 700<<10)
	os.WriteFile(filepath.Join(q, "index.jsonl"), []byte(
		`{"ts":"2026-06-24T12:00:00","type":"quarantine","original":"/home/u/app/fa.woff2","copy":"`+filepath.ToSlash(filepath.Join(expired, "123", "file.js"))+`"}`+"\n"), 0o600)
	write(t, filepath.Join(q, "notes-from-user"), 10, 200*24*time.Hour) // not a slot: never touched
	// temp folder: ours and old, ours and fresh, someone else's
	write(t, filepath.Join(tmp, "threatscan-acme_app-1", "repo.git", "HEAD"), 10, 0)
	write(t, filepath.Join(tmp, "threatscan-acme_app-2", "repo.git", "HEAD"), 10, 0)
	write(t, filepath.Join(tmp, "threatscan-installer-download", "threatscan"), 10, 0)
	write(t, filepath.Join(tmp, "other-tool", "x"), 10, 0)
	os.MkdirAll(filepath.Join(tmp, "threatscan-nohooks-99"), 0o700)
	twoDays := now.Add(-48 * time.Hour)
	for _, d := range []string{"threatscan-acme_app-1", "threatscan-installer-download", "other-tool", "threatscan-nohooks-99"} {
		os.Chtimes(filepath.Join(tmp, d), twoDays, twoDays)
	}
	write(t, filepath.Join(dir, "upload-state.json.tmp"), 10, 48*time.Hour)
	write(t, filepath.Join(dir, "config.json.tmp"), 10, time.Minute)

	before := Total(Usage(dir, cfg))
	j := journal.Open(dir, "t", "t")
	r := Run(Options{DataDir: dir, Cfg: cfg, Now: now, TempDir: tmp, Journal: j})
	if find(r, "guard logs").Count != 3 || find(r, "alert logs").Count != 5 {
		t.Fatalf("log archives: %+v", r.Lines)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "guard-*.log.gz"))
	if len(left) != 5 || !strings.Contains(left[0], "20260904") || !exists(filepath.Join(dir, "guard.log")) || !exists(filepath.Join(dir, "alerts.log")) {
		t.Fatalf("the newest 5 guard archives and the live logs stay: %v", left)
	}
	if find(r, "quarantined").Count != 2 || exists(expired) || exists(older) || !exists(newer) {
		t.Fatalf("quarantine: %+v", r.Lines)
	}
	if !exists(filepath.Join(q, "index.jsonl")) || !exists(filepath.Join(q, "notes-from-user")) {
		t.Fatal("only slot folders may be removed from the quarantine")
	}
	idx, _ := os.ReadFile(filepath.Join(q, "index.jsonl"))
	if !strings.Contains(string(idx), `"type":"purge","original":"/home/u/app/fa.woff2"`) || !strings.Contains(string(idx), "expired: quarantined copies are kept for 90 days") {
		t.Fatalf("the history must say the copy expired:\n%s", idx)
	}
	if evs := journal.Read(dir, journal.Filter{Kinds: []string{journal.KindAction}}); len(evs) != 1 || evs[0].Action != "purge" {
		t.Fatalf("journal: %+v", evs)
	}
	if find(r, "temp folder").Count != 2 || exists(filepath.Join(tmp, "threatscan-acme_app-1")) || exists(filepath.Join(tmp, "threatscan-nohooks-99")) {
		t.Fatalf("temp: %+v", r.Lines)
	}
	for _, keep := range []string{"threatscan-acme_app-2", "threatscan-installer-download", "other-tool"} {
		if !exists(filepath.Join(tmp, keep)) {
			t.Fatalf("%s must not be removed", keep)
		}
	}
	if exists(filepath.Join(dir, "upload-state.json.tmp")) || !exists(filepath.Join(dir, "config.json.tmp")) {
		t.Fatal("only temporary files older than a day are removed")
	}
	after := Usage(dir, cfg)
	if Total(after) >= before || before-Total(after) < 700<<10 {
		t.Fatalf("usage before %d, after %d", before, Total(after))
	}
	if after[1].Name != "quarantine" || after[1].Bytes < 700<<10 || after[2].Name != "logs" || after[2].Bytes != 9000 {
		t.Fatalf("usage: %+v", after)
	}
	if s := r.String(); !strings.Contains(s, "freed: ") || !strings.Contains(s, "2 quarantined copies") {
		t.Fatal(s)
	}
	if MB(5<<20) != "5.0 MB" || MB(300<<20) != "300 MB" || MB(2048) != "2 KB" || MB(12) != "12 B" {
		t.Fatal("MB formatting")
	}
}
