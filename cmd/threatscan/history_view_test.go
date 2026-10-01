package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/journal"
	"github.com/FaheemRafiq/threatscan/internal/testfixtures"
)

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)
	for in, want := range map[string]time.Time{
		"30m": now.Add(-30 * time.Minute), "24h": now.Add(-24 * time.Hour), "7d": now.Add(-7 * 24 * time.Hour),
		"2w": now.Add(-14 * 24 * time.Hour), "2026-09-28": time.Date(2026, 9, 28, 0, 0, 0, 0, time.Local), "": {},
	} {
		got, err := parseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"x", "7y", "d", "-3d", "yesterday"} {
		if _, err := parseSince(bad, now); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func ev(ts, kind, sev, cat, title, path, action string) journal.Event {
	return journal.Event{TS: ts, Kind: kind, Sev: sev, Category: cat, Title: title, Path: path, Action: action,
		Key: cat + "|" + title + "|" + path, Why: "why " + cat, Ctx: "guard-full", Ver: "0.4.0", IOCs: "i"}
}

func TestCollapseAndFormat(t *testing.T) {
	ok := true
	evs := []journal.Event{
		ev("2026-10-01T06:00:00+05:00", journal.KindFinding, "WARNING", "history_payload", "3 commit(s)", "/r/a/.git", ""),
		ev("2026-10-01T06:00:01+05:00", journal.KindFinding, "CRITICAL", "fake_font_loader", "Font file contains code", "/r/a/f.woff2", "quarantined to /q/1"),
		{TS: "2026-10-01T06:00:01+05:00", Kind: journal.KindAction, Action: "quarantine", Path: "/r/a/f.woff2", Threat: "Trojan:JS/PolinRider.FakeFont",
			Response: "Quarantined: it is code", Data: map[string]any{"copy": "/q/1"}},
		{TS: "2026-10-01T06:03:00+05:00", Kind: journal.KindDecision, Action: "delete", Path: "/r/a/f.woff2"},
		ev("2026-10-01T12:00:00+05:00", journal.KindFinding, "WARNING", "history_payload", "3 commit(s)", "/r/a/.git", ""),
		ev("2026-10-01T18:00:00+05:00", journal.KindFinding, "WARNING", "history_payload", "3 commit(s)", "/r/a/.git", ""),
		// two kills of different pids, same marker: one group
		{TS: "2026-10-01T18:00:05+05:00", Kind: journal.KindFinding, Sev: "CRITICAL", Category: "malicious_process", Title: "PID 10 (node)", Matched: "global['_V']=", Action: "killed PID 10", Why: "w", Key: "a"},
		{TS: "2026-10-01T18:00:10+05:00", Kind: journal.KindFinding, Sev: "CRITICAL", Category: "malicious_process", Title: "PID 11 (node)", Matched: "global['_V']=", Action: "kill PID 11 failed (permission?)", Why: "w", Key: "b"},
		{TS: "2026-10-01T18:00:10+05:00", Kind: journal.KindAction, Action: "kill", PID: 11, OK: new(bool)},
		{TS: "2026-10-01T18:01:00+05:00", Kind: journal.KindSweep, Title: "full sweep finished", Data: map[string]any{"repos": 17, "critical": 1, "high": 0, "warning": 3, "seconds": 170}},
	}
	_ = ok
	gs := collapse(evs)
	if len(gs) != 3 {
		t.Fatalf("groups: %d", len(gs))
	}
	if gs[1].count != 3 || state(gs[1].last) != "open" || state(gs[0].last) != "handled" || gs[2].count != 2 || state(gs[2].last) != "FAILED" {
		t.Fatalf("%+v", gs)
	}
	out := formatJournal(evs, 50, false)
	for _, want := range []string{"DETECTIONS", "3x", "first seen: 2026-10-01 06:00", "ACTIONS AND DECISIONS", "user:delete", "why: Quarantined: it is code", "[failed]", "FAILED"} {
		if !strings.Contains(out, want) {
			t.Errorf("default view lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "full sweep finished") {
		t.Error("sweeps belong in --all / --kind sweep, not the default view")
	}
	all := formatJournalAll(evs, 50, true)
	if strings.Count(all, "3 commit(s)") < 3 || !strings.Contains(all, "17 repos, 1 critical, 0 high, 3 warning in 170s") || !strings.Contains(all, "copy: /q/1") {
		t.Errorf("--all view:\n%s", all)
	}
	if got := formatJournalAll(evs, 2, false); strings.Count(got, "\n") > 4 {
		t.Errorf("limit not applied:\n%s", got)
	}
}

func TestHistoryCommandOverJournal(t *testing.T) {
	home := isolate(t)
	inf := testfixtures.Infected(t, t.TempDir())
	run([]string{"scan", "--ci", "--no-system", "--fix", inf})
	for _, args := range [][]string{
		{"history"}, {"history", "--all"}, {"history", "--details"}, {"history", "--severity", "critical"},
		{"history", "--kind", "sweep"}, {"history", "--since", "1d", "--path", "woff2"}, {"history", "--json", "--archive"},
	} {
		if rc := run(args); rc != 0 {
			t.Fatalf("%v rc=%d", args, rc)
		}
	}
	if rc := run([]string{"history", "--since", "soon"}); rc != 2 {
		t.Fatal("bad --since must exit 2")
	}
	// allow with a note records feedback
	target := filepath.Join(inf, "public", "fonts", "fa-solid-900.woff2")
	if rc := run([]string{"history", "--allow", target, "--note", "our own icon font"}); rc != 0 {
		t.Fatal("allow failed")
	}
	fb := journal.Read(home, journal.Filter{Kinds: []string{journal.KindFeedback}})
	if len(fb) != 1 || fb[0].Note != "our own icon font" || fb[0].Path != target {
		t.Fatalf("feedback event: %+v", fb)
	}
}
