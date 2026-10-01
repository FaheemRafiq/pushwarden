package feedback

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/journal"
)

func TestRedactor(t *testing.T) {
	r := Redactor{Home: "/home/faheem", User: "faheem", Host: "fedora-box"}
	in := `path /home/faheem/Coding/app/x.js on fedora-box by faheem; ` +
		`ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0000 github_pat_11ABCDEFG0abcdefghijklmnop AKIAIOSFODNN7EXAMPLE xoxb-123456789012-abcdef ` +
		`{"webhook_url": "https://hooks.slack.com/services/T0/B0/XXXX"} token=abcdef123456 password: hunter2secret ` +
		`https://bob:s3cr3tpw@github.com/x/y.git node /home/faheem/.cache/font/l.js faheemx stays`
	out := r.Text(in)
	for _, leak := range []string{"/home/faheem", "fedora-box", "ghp_FAKEfake", "github_pat_11", "AKIAIOSFODNN7EXAMPLE", "xoxb-1234", "hooks.slack.com/services",
		"abcdef123456", "hunter2secret", "s3cr3tpw", " by faheem;"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in:\n%s", leak, out)
		}
	}
	for _, keep := range []string{"~/Coding/app/x.js", "<host>", "node ~/.cache/font/l.js", "faheemx stays", "by <user>;"} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %q in:\n%s", keep, out)
		}
	}
	if (Redactor{}).Text("plain /tmp/x") != "plain /tmp/x" {
		t.Error("empty redactor must not change text")
	}
}

func sample(t *testing.T) (string, []journal.Event) {
	t.Helper()
	dir := t.TempDir()
	j := journal.Open(dir, "0.4.0", "2026.10.01.1")
	no := false
	for _, e := range []journal.Event{
		{Kind: journal.KindGuard, Title: "guard started"},
		{Kind: journal.KindFinding, Sev: "CRITICAL", Category: "malicious_process", Title: "PID 5 (git)", Matched: "Cot%3t=shtP", Cmd: "git -C /home/faheem/secret-repo log", Action: "killed PID 5", Key: "k1"},
		{Kind: journal.KindFinding, Sev: "CRITICAL", Category: "malicious_process", Title: "PID 6 (git)", Matched: "Cot%3t=shtP", Cmd: "git -C /home/faheem/secret-repo log", Action: "killed PID 6", Key: "k2"},
		{Kind: journal.KindFinding, Sev: "WARNING", Category: "history_payload", Title: "3 commits", Path: "/home/faheem/secret-repo/.git", Key: "k3"},
		{Kind: journal.KindFinding, Sev: "CRITICAL", Category: "gitignore_tampering", Title: "hides", Path: "/home/faheem/secret-repo/.gitignore", Action: "clean failed: entries not found", Key: "k4"},
		{Kind: journal.KindAction, Action: "kill", PID: 5},
		{Kind: journal.KindAction, Action: "kill", PID: 6, OK: &no, Threat: "Behavior:Node/PolinRider.Payload"},
		{Kind: journal.KindDecision, Action: "keep", Path: "/home/faheem/secret-repo/a.woff2"},
		{Kind: journal.KindFeedback, Path: "/home/faheem/secret-repo/icons.woff2", Note: "our own icon font"},
		{Kind: journal.KindSweep, Data: map[string]any{"phase": "start"}},
		{Kind: journal.KindSweep, Data: map[string]any{"phase": "end", "seconds": 170}},
		{Kind: journal.KindSweep, Data: map[string]any{"phase": "end", "seconds": 90}},
		{Kind: journal.KindError, Title: "full pass panicked", Note: "index out of range at /home/faheem/x"},
		{Kind: journal.KindUpdate, Title: "program update v0.4.1 installed; restarting"},
	} {
		j.Write(e)
	}
	return dir, journal.Read(dir, journal.Filter{})
}

func TestDigestHasCountsAndNoPaths(t *testing.T) {
	_, evs := sample(t)
	d := BuildDigest(evs, "abc123", "0.4.0", "linux", "2026.10.01.1", time.Now().Add(-24*time.Hour), time.Now())
	if d.BySeverity["CRITICAL"] != 3 || d.BySeverity["WARNING"] != 1 || d.ByCategory["malicious_process"] != 1 || d.ByCategory["gitignore_tampering"] != 1 {
		t.Fatalf("counts: %+v %+v", d.BySeverity, d.ByCategory)
	}
	if d.Actions["kill"] != 2 || len(d.FailedActions) != 2 || d.Decisions["keep"] != 1 || d.Sweeps != 2 || d.SweepAvgSec != 130 || d.SweepMaxSec != 170 || d.GuardStarts != 1 {
		t.Fatalf("%+v", d)
	}
	if len(d.FalsePositive) != 1 || d.FalsePositive[0].File != "icons.woff2" || d.FalsePositive[0].Note != "our own icon font" {
		t.Fatalf("%+v", d.FalsePositive)
	}
	body := d.Text()
	for _, leak := range []string{"/home/faheem", "secret-repo", "git -C"} {
		if strings.Contains(body, leak) {
			t.Fatalf("digest text leaks %q:\n%s", leak, body)
		}
	}
	if !strings.Contains(body, "FAILED:") || !strings.Contains(body, "false positive reported: icons.woff2 our own icon font") || !strings.Contains(body, "malicious_process=1") {
		t.Fatalf("digest text:\n%s", body)
	}
}

func TestMachineIDIsStableAndRandom(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if MachineID(a) != MachineID(a) || MachineID(a) == MachineID(b) || len(MachineID(a)) != 16 {
		t.Fatal("machine id")
	}
}

func TestBundleIsRedacted(t *testing.T) {
	dir, _ := sample(t)
	os.WriteFile(filepath.Join(dir, "guard.log"), []byte("2026-10-01 scanning /home/faheem/secret-repo token=ghp_abcdefghijklmnopqrstuvwxyz0123\n"), 0o600)
	out := filepath.Join(t.TempDir(), "fb.zip")
	cfg := `{"webhook_url": "https://hooks.slack.com/services/T/B/SECRETVALUE", "action": "quarantine"}`
	b, err := WriteBundle(out, dir, "summary for fedora-box", cfg, time.Now().Add(-time.Hour), &Redactor{Home: "/home/faheem", User: "faheem", Host: "fedora-box"})
	if err != nil || b.Events != 14 || len(b.Files) < 5 {
		t.Fatalf("%v %+v", err, b)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	all := ""
	for _, f := range zr.File {
		rc, _ := f.Open()
		c, _ := io.ReadAll(rc)
		rc.Close()
		all += "\n== " + f.Name + "\n" + string(c)
	}
	for _, leak := range []string{"/home/faheem", "fedora-box", "ghp_abcdefghijklmnop", "SECRETVALUE", "hooks.slack.com"} {
		if strings.Contains(all, leak) {
			t.Errorf("bundle leaks %q", leak)
		}
	}
	for _, want := range []string{"== journal.jsonl", "~/secret-repo/.gitignore", "\"action\": \"quarantine\"", "== README.txt", "== summary.txt"} {
		if !strings.Contains(all, want) {
			t.Errorf("bundle lacks %q", want)
		}
	}
	// unredacted on request
	out2 := filepath.Join(t.TempDir(), "raw.zip")
	if _, err := WriteBundle(out2, dir, "s", "{}", time.Time{}, nil); err != nil {
		t.Fatal(err)
	}
}
