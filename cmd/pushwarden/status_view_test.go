package main

import (
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/ui"
)

func healthy() health {
	now := time.Date(2026, 10, 4, 15, 0, 0, 0, time.UTC)
	return health{guardAlive: true, guardVersion: "0.5.1", realtime: "inotify", service: "active",
		firewall:   "active (persistent; 25 IPs, 15 hosts; applied 1h ago; indicators 2026.09.28.2)",
		editors:    map[string]string{"VS Code": "off"},
		iocVersion: "2026.09.28.2", lastFull: now.Add(-2 * time.Hour), repos: 18, haveReport: true, now: now}
}

func TestHealthScore(t *testing.T) {
	verdict := func(h health) (int, string) {
		score, level, _, _ := h.verdict(h.checks())
		return score, level
	}
	h := healthy()
	total := 0
	for _, c := range h.checks() {
		total += c.max
		if c.fix != "" {
			t.Errorf("%s: a full check needs no fix, got %q", c.name, c.fix)
		}
	}
	if score, level := verdict(h); total != 100 || score != 100 || level != "PROTECTED" {
		t.Fatalf("everything in place: total=%d score=%d level=%s", total, score, level)
	}

	h = healthy()
	h.guardAlive = false
	if score, level := verdict(h); score != 60 || level != "AT RISK" {
		t.Fatalf("no guard means no real-time protection either: %d %s", score, level)
	}

	h = healthy()
	h.firewall, h.editors = "not active - run: pushwarden protect --install (asks for administrator rights)", map[string]string{"VS Code": "off", "Cursor": "<unset>"}
	if score, level := verdict(h); score != 85 || level != "PARTLY PROTECTED" {
		t.Fatalf("no firewall block, one of two editors hardened: %d %s", score, level)
	}
	fixes := ""
	for _, c := range h.checks() {
		fixes += c.fix + ";"
	}
	if !strings.Contains(fixes, "pushwarden protect --install") || !strings.Contains(fixes, "pushwarden harden") {
		t.Fatalf("each missing layer names its fix: %s", fixes)
	}

	h = healthy()
	h.critical = 1
	if score, level := verdict(h); score != 80 || level != "THREATS FOUND" {
		t.Fatalf("findings outrank the score: %d %s", score, level)
	}

	h = healthy()
	h.realtime, h.iocVersion, h.lastFull = "polling", "2026.07.01.1", h.now.Add(-48*time.Hour)
	if score, _ := verdict(h); score != 100-7-3-5 {
		t.Fatalf("polling, old indicators, stale sweep: %d", score)
	}
	h.firewall = "active until reboot (25 IPs, 15 hosts) - make it permanent: pushwarden protect --install"
	if score, _ := verdict(h); score != 100-7-3-5-5 {
		t.Fatalf("a block that is lost on restart counts half: %d", score)
	}
}

// Piped or in CI the header is plain text: no logo, no block characters.
func TestStatusHeaderPlain(t *testing.T) {
	h := healthy()
	text := strings.Join(statusHeader(ui.New(true, false), h, h.checks()), "\n")
	if !strings.Contains(text, "Protection:  PROTECTED  100/100  [########################]") || strings.ContainsAny(text, "█▄▀░●") {
		t.Fatalf("plain header:\n%s", text)
	}
}
