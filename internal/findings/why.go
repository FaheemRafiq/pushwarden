package findings

import (
	"fmt"
	"regexp"
	"strings"
)

var quoted = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// Because returns the concrete trigger of a finding: the matched text when the
// scanner recorded it, otherwise the quoted part of the first evidence line,
// otherwise the first evidence line itself. Empty when there is none.
func Because(f *Finding) string {
	if f.Meta.Matched != "" {
		return f.Meta.Matched
	}
	if len(f.Meta.Evidence) == 0 {
		return ""
	}
	e := f.Meta.Evidence[0]
	if m := quoted.FindStringSubmatch(e); m != nil {
		s, err := strconvUnquote(m[0])
		if err == nil {
			return s
		}
		return m[1]
	}
	return e
}

func strconvUnquote(s string) (string, error) {
	var out strings.Builder
	esc := false
	for _, r := range strings.Trim(s, `"`) {
		switch {
		case esc:
			esc = false
			switch r {
			case 'n':
				out.WriteRune('\n')
			case 't':
				out.WriteRune('\t')
			default:
				out.WriteRune(r)
			}
		case r == '\\':
			esc = true
		default:
			out.WriteRune(r)
		}
	}
	return out.String(), nil
}

func short(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", "")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// why explains, per category, what the evidence means and why it carries the
// severity it does. One sentence, short enough for a desktop notification.
var why = map[string]string{
	"config_injection":     "A framework config file carries PolinRider loader code; it runs on every build or dev-server start.",
	"xor_key":              "The file holds the XOR key PolinRider uses to unpack its second stage; only the loader needs it.",
	"entry_hook":           "The app entry file decodes a URL from the environment and evals what it downloads: PolinRider stage 1.",
	"fake_font_loader":     "A .woff2/.ttf that is JavaScript, not font data; PolinRider hides its loader behind a font name.",
	"disguised_payload":    "An image or dictionary file that contains code instead of data: a disguised PolinRider payload.",
	"vscode_autorun":       "A VS Code task or setting that runs a command the moment the folder opens: the PolinRider entry point.",
	"propagation_script":   "The script PolinRider uses to rewrite git history and force-push the backdoor to every branch.",
	"blockchain_c2":        "Code reads its command server address from a blockchain contract, PolinRider's dead-drop resolver.",
	"c2_reference":         "The file references a known PolinRider command-and-control host or path.",
	"telegram_exfil":       "Credential-stealing code that uploads to a Telegram bot: the OmniStealer stage of the campaign.",
	"git_hook":             "A git hook or fsmonitor setting runs code on every git command; PolinRider uses it to persist.",
	"compromised_package":  "A dependency pinned to a version known to ship the PolinRider loader.",
	"malicious_process":    "A running process's command line matches a PolinRider indicator.",
	"c2_connection":        "A live network connection to an IP address on the PolinRider command-and-control list.",
	"rat_footprint":        "Files or directories left by the runtimedev-link remote access tool that PolinRider installs.",
	"stage4_runtime":       "The runtimedev-link remote access tool, PolinRider's final stage, is present.",
	"stage4_python":        "Python remote access tool components from the campaign are present.",
	"editor_injection":     "Code injected into an editor's own files, so it runs every time the editor starts.",
	"gitignore_tampering":  ".gitignore lists the files PolinRider drops, so they never show up in git status.",
	"credential_exposure":  "A secrets file the stealer reads; on an infected machine treat every value in it as leaked.",
	"hosts_tampering":      "The hosts file redirects a security or package host, a technique used to block updates.",
	"shell_injection":      "A shell start-up file downloads and runs code on every new terminal.",
	"known_malicious_file": "The file's hash matches a confirmed PolinRider sample.",
	"history_payload":      "Commits in this repository's history added or touched PolinRider payload code.",
	"forged_timestamp":     "Commits whose committer date is far before the author date: PolinRider backdates its pushes.",
	"git_tampering":        "The reflog shows amends and forced updates, the pattern PolinRider leaves when it rewrites history.",
	"file_anomaly":         "A config file has a suspiciously long line, the shape of a payload hidden after whitespace.",
	"payload_companions":   "These files arrived in the same commit as the loader; PolinRider ships fonts and configs as camouflage.",
	"lifecycle_script":     "A package.json lifecycle script runs code on install, a common PolinRider hook.",
	"php_node_exec":        "PHP code shells out to node on a non-script file, the way PolinRider chains into its loader.",
	"persistence_":         "A start-up entry (service, launch agent, scheduled task, cron, autostart) that relaunches the malware.",
}

var bySeverity = map[Severity]string{
	Critical: "Confirmed PolinRider artifact or activity.",
	High:     "Strong indicator that needs a human decision.",
	Warning:  "Context worth checking; not malicious on its own.",
	Info:     "Informational.",
}

// Why returns one sentence: what this finding is and why it has its severity.
func Why(f *Finding) string {
	s, ok := why[f.Category]
	if !ok && strings.HasPrefix(f.Category, "persistence_") {
		s, ok = why["persistence_"], true
	}
	if f.Category == "credential_exposure" && f.Severity < High {
		s = "A secrets file is present; nothing read it as far as the scanner knows, but rotate if this host was infected."
	}
	if !ok {
		s = bySeverity[f.Severity]
	}
	if f.Severity < Critical && f.Severity > Info && ok {
		s += " " + strings.TrimSuffix(bySeverity[f.Severity], ".") + "."
	}
	if b := Because(f); b != "" {
		s += fmt.Sprintf(" Found: %q.", short(b, 80))
	}
	return s
}

// WhyAction explains the response: why a process was killed or not, why a
// file was stripped or quarantined, or why nothing was done.
func WhyAction(f *Finding) string {
	a := f.Action
	past := func(did, would string) string {
		switch {
		case strings.HasPrefix(a, "would"):
			return would
		case strings.Contains(a, "failed"):
			return did + " (the action failed: " + a + ")"
		}
		return did
	}
	b := Because(f)
	found := ""
	if b != "" {
		found = fmt.Sprintf(" It contains %q.", short(b, 80))
	}
	switch f.Category {
	case "malicious_process":
		if f.Meta.Kill {
			return past(fmt.Sprintf("Killed: its command line contains %q, a marker that only the PolinRider payload uses.", short(b, 80)),
				fmt.Sprintf("Would kill: its command line contains %q, a marker that only the PolinRider payload uses.", short(b, 80)))
		}
		return fmt.Sprintf("Not killed automatically: its command line contains %q, which matches a broad PolinRider indicator that legitimate tools can also produce; review it.", short(b, 80))
	case "c2_connection":
		if f.Meta.PID <= 0 {
			return fmt.Sprintf("Not killed: the process talking to %s is unknown. Block the address with: threatscan protect", f.Meta.IP)
		}
		return past(fmt.Sprintf("Killed PID %d: it had an open connection to %s, a known PolinRider command server.", f.Meta.PID, f.Meta.IP),
			fmt.Sprintf("Would kill PID %d: it has an open connection to %s, a known PolinRider command server.", f.Meta.PID, f.Meta.IP))
	}
	switch {
	case strings.HasPrefix(a, "kept"):
		return "Left in place: you chose to keep this file; that decision is remembered for this exact content."
	case a == "" && f.Severity >= Critical:
		return "Not changed: run with --fix, or answer the dialog, to strip or quarantine it (reversible)."
	case a == "":
		return "No automatic action at this severity; see the remediation hint."
	case len(f.Meta.StripLines) > 0:
		return past(fmt.Sprintf("Removed only the entries %s; every other line was kept and the original is in quarantine.", strings.Join(f.Meta.StripLines, ", ")),
			fmt.Sprintf("Would remove only the entries %s and keep the original in quarantine.", strings.Join(f.Meta.StripLines, ", ")))
	case f.Meta.MidFileInjection:
		return past("Whole file quarantined: the payload is woven into the file, so it cannot be stripped safely."+found,
			"Would quarantine the whole file: the payload is woven into it."+found)
	case f.Meta.Cleanable:
		at := ""
		if f.Meta.Cut > 0 {
			at = fmt.Sprintf(" at byte %d", f.Meta.Cut)
		}
		return past(fmt.Sprintf("Payload stripped: %q was appended after the legitimate code%s, so only that tail was removed; original kept.", short(b, 80), at),
			fmt.Sprintf("Would strip the payload %q appended after the legitimate code and keep the original in quarantine.", short(b, 80)))
	case strings.HasPrefix(f.Category, "persistence_") || f.Category == "rat_footprint" || f.Category == "stage4_runtime":
		return past("Start-up entry disabled and quarantined so the malware no longer relaunches at sign-in."+found,
			"Would disable the start-up entry and quarantine it."+found)
	case f.Meta.Quarantine:
		return past("Quarantined: the file is executable malware, not data; moved out so it cannot run, restorable."+found,
			"Would quarantine the file so it cannot run; restorable."+found)
	case strings.HasPrefix(a, "deleted"):
		return "Deleted permanently at your request; a record is kept in the protection history."
	}
	return a
}

// Explain is the two-line form used by dialogs and --details.
func Explain(f *Finding) []string {
	out := []string{"Why: " + Why(f)}
	if r := WhyAction(f); r != "" && (f.Action != "" || f.Severity >= Critical) {
		out = append(out, "Response: "+r)
	}
	return out
}
