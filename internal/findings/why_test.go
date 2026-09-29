package findings

import (
	"strings"
	"testing"
)

var allCategories = []string{"config_injection", "xor_key", "entry_hook", "fake_font_loader", "disguised_payload", "vscode_autorun",
	"propagation_script", "blockchain_c2", "c2_reference", "telegram_exfil", "git_hook", "compromised_package", "malicious_process",
	"c2_connection", "rat_footprint", "stage4_runtime", "stage4_python", "editor_injection", "gitignore_tampering", "credential_exposure",
	"hosts_tampering", "shell_injection", "known_malicious_file", "history_payload", "forged_timestamp", "git_tampering", "file_anomaly",
	"payload_companions", "lifecycle_script", "php_node_exec", "persistence_systemd", "persistence_cron", "persistence_launchd",
	"persistence_schtasks", "persistence_registry", "persistence_startup", "persistence_autostart"}

func TestWhyCoversEveryCategory(t *testing.T) {
	for _, c := range allCategories {
		for _, s := range []Severity{Critical, High, Warning} {
			w := Why(&Finding{Category: c, Severity: s})
			if w == "" || w == bySeverity[s] {
				t.Errorf("%s/%s: no specific explanation (%q)", c, s, w)
			}
			if len(w) > 200 {
				t.Errorf("%s: too long (%d)", c, len(w))
			}
		}
	}
	if w := Why(&Finding{Category: "brand_new", Severity: High}); w != bySeverity[High] {
		t.Errorf("unknown category should fall back: %q", w)
	}
	if w := Why(&Finding{Category: "credential_exposure", Severity: Info}); !strings.Contains(w, "rotate") {
		t.Errorf("info credential text: %q", w)
	}
}

func TestWhyAction(t *testing.T) {
	killed := &Finding{Category: "malicious_process", Meta: Meta{Kill: true, Matched: "global['_V']='8-st17'"}, Action: "killed PID 5"}
	notKilled := &Finding{Category: "malicious_process", Meta: Meta{Kill: false, Matched: "/home/x/.cache/font/l.js"}}
	if a, b := WhyAction(killed), WhyAction(notKilled); a == b || !strings.HasPrefix(a, "Killed") || !strings.HasPrefix(b, "Not killed") {
		t.Fatalf("kill reasons: %q / %q", a, b)
	}
	if a := WhyAction(killed); !strings.Contains(a, `"global['_V']='8-st17'"`) {
		t.Fatalf("kill reason must quote the exact marker: %q", a)
	}
	if b := WhyAction(notKilled); !strings.Contains(b, `.cache/font/l.js`) {
		t.Fatalf("not-killed reason must quote the match: %q", b)
	}
	ev := &Finding{Category: "fake_font_loader", Severity: Critical, Meta: Meta{Quarantine: true,
		Evidence: []string{`literal signature "global['!']='A10-010'"`, "other"}}}
	if got := Because(ev); got != "global['!']='A10-010'" {
		t.Fatalf("Because from evidence: %q", got)
	}
	if w := Why(ev); !strings.Contains(w, `Found: "global['!']='A10-010'"`) {
		t.Fatalf("Why must cite the trigger: %q", w)
	}
	if Because(&Finding{}) != "" {
		t.Fatal("no evidence, no trigger")
	}
	if w := WhyAction(&Finding{Category: "malicious_process", Meta: Meta{Kill: true}, Action: "would kill PID 5"}); !strings.HasPrefix(w, "Would kill") {
		t.Fatal(w)
	}
	if w := WhyAction(&Finding{Category: "malicious_process", Meta: Meta{Kill: true}, Action: "kill PID 5 failed (permission?)"}); !strings.Contains(w, "failed") {
		t.Fatal(w)
	}
	if w := WhyAction(&Finding{Category: "c2_connection", Meta: Meta{PID: 0}}); !strings.Contains(w, "threatscan protect") {
		t.Fatal(w)
	}
	cases := map[string]*Finding{
		"Payload stripped":           {Category: "config_injection", Meta: Meta{Cleanable: true}, Action: "removed 300 bytes of payload"},
		"Whole file":                 {Category: "config_injection", Meta: Meta{Cleanable: true, MidFileInjection: true}, Action: "whole file quarantined"},
		"Removed only the entries x": {Category: "gitignore_tampering", Meta: Meta{Cleanable: true, StripLines: []string{"x"}}, Action: "removed 1 line(s)"},
		"Quarantined":                {Category: "fake_font_loader", Meta: Meta{Quarantine: true}, Action: "quarantined to /q"},
		"Start-up entry":             {Category: "persistence_systemd", Meta: Meta{Quarantine: true}, Action: "quarantined to /q"},
		"Left in place":              {Category: "fake_font_loader", Meta: Meta{Quarantine: true}, Action: "kept by user"},
		"Not changed":                {Category: "fake_font_loader", Severity: Critical, Meta: Meta{Quarantine: true}},
		"Deleted permanent":          {Category: "fake_font_loader", Action: "deleted (user confirmed)"},
	}
	for want, f := range cases {
		if got := WhyAction(f); !strings.HasPrefix(got, want) {
			t.Errorf("%s: got %q", want, got)
		}
	}
	if ex := Explain(&Finding{Category: "entry_hook", Severity: Critical, Meta: Meta{Cleanable: true}}); len(ex) != 2 || !strings.HasPrefix(ex[0], "Why: ") || !strings.HasPrefix(ex[1], "Response: ") {
		t.Fatalf("%v", ex)
	}
	if ex := Explain(&Finding{Category: "history_payload", Severity: Warning}); len(ex) != 1 {
		t.Fatalf("warning without action should only explain: %v", ex)
	}
}
