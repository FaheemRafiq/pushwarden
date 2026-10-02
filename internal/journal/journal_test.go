package journal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
)

func TestWriteReadFilter(t *testing.T) {
	dir := t.TempDir()
	j := Open(dir, "0.4.0", "2026.10.01.1")
	if Exists(dir) {
		t.Fatal("no journal yet")
	}
	crit := &findings.Finding{Severity: findings.Critical, Category: "malicious_process", Title: "Malicious process running: PID 7 (node)",
		Action: "killed PID 7", Meta: findings.Meta{PID: 7, Kill: true, Cmd: "node x", Matched: "global['_V']=", Evidence: []string{"e1"}}}
	warn := &findings.Finding{Severity: findings.Warning, Category: "history_payload", Title: "1 commit(s)", Path: "/r/.git"}
	info := &findings.Finding{Severity: findings.Info, Category: "credential_exposure", Title: "info"}
	j.Finding("guard-quick", "s1", crit, "Behavior:Node/PolinRider.Payload")
	j.Finding("guard-full", "s1", warn, "")
	j.Finding("guard-full", "s1", info, "") // below the minimum severity: dropped
	ok := true
	j.Write(Event{Kind: KindAction, Action: "kill", PID: 7, OK: &ok, Ctx: "guard-quick"})
	j.Write(Event{Kind: KindSweep, Ctx: "guard-full", Sweep: "s1", Data: map[string]any{"phase": "end", "repos": 17}})
	if !Exists(dir) {
		t.Fatal("journal should exist")
	}
	all := Read(dir, Filter{})
	if len(all) != 4 {
		t.Fatalf("want 4 events, got %d", len(all))
	}
	e := all[0]
	if e.Kind != KindFinding || e.Sev != "CRITICAL" || e.Ver != "0.4.0" || e.IOCs != "2026.10.01.1" || e.Matched != "global['_V']=" ||
		!strings.HasPrefix(e.Response, "Killed") || e.Why == "" || e.Key == "" || e.Time().IsZero() {
		t.Fatalf("%+v", e)
	}
	if got := Read(dir, Filter{Kinds: []string{KindFinding}, MinSeverity: findings.Critical}); len(got) != 1 {
		t.Fatalf("severity filter: %d", len(got))
	}
	if got := Read(dir, Filter{Kinds: []string{KindAction, KindSweep}}); len(got) != 2 {
		t.Fatalf("kind filter: %d", len(got))
	}
	if got := Read(dir, Filter{PathSubstr: ".GIT"}); len(got) != 1 {
		t.Fatalf("path filter: %d", len(got))
	}
	if got := Read(dir, Filter{Since: time.Now().Add(time.Hour)}); len(got) != 0 {
		t.Fatalf("since filter: %d", len(got))
	}
	// a torn line must not break reading
	fh, _ := os.OpenFile(filepath.Join(dir, FileName), os.O_APPEND|os.O_WRONLY, 0o600)
	fh.WriteString("{\"kind\":\"finding\",\"ti\n")
	fh.Close()
	if got := Read(dir, Filter{}); len(got) != 4 {
		t.Fatalf("torn line: %d", len(got))
	}
	var nilJ *Journal
	nilJ.Write(Event{Kind: KindGuard}) // must not panic
	nilJ.Finding("x", "", crit, "")
	off := Open(t.TempDir(), "v", "i")
	off.Disabled = true
	off.Write(Event{Kind: KindGuard})
	if Exists(off.Dir) {
		t.Fatal("disabled journal wrote")
	}
}

func TestRotationKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	j := Open(dir, "v", "i")
	j.MaxSize = 2000
	for i := 0; i < 60; i++ {
		j.Write(Event{Kind: KindGuard, Title: fmt.Sprintf("event %03d %s", i, strings.Repeat("x", 80))})
		time.Sleep(time.Millisecond)
	}
	arch, _ := filepath.Glob(filepath.Join(dir, "journal-*.jsonl.gz"))
	if len(arch) < 2 {
		t.Fatalf("expected several gzip archives, got %v", arch)
	}
	if plain, _ := filepath.Glob(filepath.Join(dir, "journal-*.jsonl")); len(plain) != 0 {
		t.Fatalf("uncompressed archives left behind: %v", plain)
	}
	active := Read(dir, Filter{})
	all := Read(dir, Filter{Archives: true})
	if len(all) != 60 || len(active) >= 60 {
		t.Fatalf("all=%d active=%d", len(all), len(active))
	}
	for i, e := range all {
		if !strings.HasPrefix(e.Title, fmt.Sprintf("event %03d", i)) {
			t.Fatalf("order broken at %d: %s", i, e.Title)
		}
	}
}

func TestConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			j := Open(dir, "v", "i") // separate handles, like separate processes
			for i := 0; i < 50; i++ {
				j.Write(Event{Kind: KindGuard, Title: fmt.Sprintf("w%d-%d", w, i)})
			}
		}(w)
	}
	wg.Wait()
	if got := Read(dir, Filter{}); len(got) != 400 {
		t.Fatalf("lost or torn events: %d of 400", len(got))
	}
}

func TestOldArchivesAreNotOpenedForRecentReads(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	line := func(title string) []byte {
		return []byte(`{"ts":"` + now.Format(time.RFC3339) + `","kind":"guard","title":"` + title + `"}` + "\n")
	}
	old := "journal-" + now.Add(-30*24*time.Hour).Format("20060102-150405") + "000.jsonl"
	recent := "journal-" + now.Add(-time.Hour).Format("20060102-150405") + "000.jsonl"
	os.WriteFile(filepath.Join(dir, old), line("in old archive"), 0o600)
	os.WriteFile(filepath.Join(dir, recent), line("in recent archive"), 0o600)
	os.WriteFile(filepath.Join(dir, "journal-imported.jsonl"), line("oddly named"), 0o600)
	os.WriteFile(filepath.Join(dir, FileName), line("active"), 0o600)
	titles := func(f Filter) string {
		var out []string
		for _, e := range Read(dir, f) {
			out = append(out, e.Title)
		}
		return strings.Join(out, ", ")
	}
	if got := titles(Filter{Archives: true}); got != "in old archive, in recent archive, oddly named, active" {
		t.Fatalf("without Since every archive is read: %s", got)
	}
	// rotated a month before the period asked for: it cannot hold such an event, so it is skipped unopened
	if got := titles(Filter{Archives: true, Since: now.Add(-24 * time.Hour)}); got != "in recent archive, oddly named, active" {
		t.Fatalf("with Since: %s", got)
	}
}
