// Package prompt shows native dialogs (Win32 on Windows, osascript on macOS,
// zenity/qarma/matedialog on Linux) and names threats Defender-style.
package prompt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/ncruces/zenity"
)

type Verdict string

const (
	Delete      Verdict = "delete"
	Keep        Verdict = "keep"
	Timeout     Verdict = "timeout"
	Unavailable Verdict = "unavailable"
)

var threatNames = map[string]string{
	"config_injection": "Trojan:JS/PolinRider.ConfigInject", "xor_key": "Trojan:JS/PolinRider.ConfigInject",
	"entry_hook": "Trojan:JS/PolinRider.EntryHook", "fake_font_loader": "Trojan:JS/PolinRider.FakeFont",
	"disguised_payload": "Trojan:JS/PolinRider.Disguised", "vscode_autorun": "Trojan:Script/PolinRider.TaskJacker",
	"propagation_script": "Trojan:BAT/PolinRider.AutoPush", "blockchain_c2": "Trojan:JS/PolinRider.DeadDrop",
	"c2_reference": "Trojan:JS/PolinRider.C2", "telegram_exfil": "Trojan:JS/OmniStealer.Exfil",
	"git_hook": "Trojan:Script/PolinRider.GitHook", "compromised_package": "Trojan:JS/PolinRider.Package",
	"malicious_process": "Behavior:Node/PolinRider.Payload", "c2_connection": "Behavior:Net/PolinRider.C2",
	"rat_footprint": "Backdoor:JS/RuntimeDevLink", "stage4_runtime": "Backdoor:JS/RuntimeDevLink",
	"editor_injection": "Trojan:JS/PolinRider.EditorInject", "gitignore_tampering": "Trojan:Script/PolinRider.Hide",
}

func ThreatName(f *findings.Finding) string {
	if strings.HasPrefix(f.Category, "persistence_") {
		return "Backdoor:Script/PolinRider.Persist"
	}
	if n, ok := threatNames[f.Category]; ok {
		return n
	}
	return "Trojan:Script/PolinRider"
}

func evidenceLines(f *findings.Finding) []string {
	var l []string
	if len(f.Meta.Evidence) > 0 {
		l = append(l, "Evidence:")
		for i, e := range f.Meta.Evidence {
			if i == 8 {
				l = append(l, fmt.Sprintf("  - ... %d more", len(f.Meta.Evidence)-8))
				break
			}
			l = append(l, "  - "+e)
		}
	} else if d := strings.TrimSpace(f.Details); d != "" {
		l = append(l, d)
	}
	return l
}

// BuildMessage is the before-action dialog text.
func BuildMessage(f *findings.Finding, action string) string {
	l := []string{"Threat: " + ThreatName(f), "File:   " + f.Path, ""}
	l = append(l, evidenceLines(f)...)
	l = append(l, "")
	if action == "Delete the file" {
		l = append(l, action+"?  This removes it permanently (a record is kept in ~/.threatscan/quarantine/index.jsonl).")
	} else {
		l = append(l, action+"?  The original is kept in ~/.threatscan/quarantine and can be restored.")
	}
	return strings.Join(l, "\n")
}

// QuarantinedMessage is the Defender-style after-action dialog text.
func QuarantinedMessage(f *findings.Finding) string {
	l := []string{"Threat: " + ThreatName(f), "File:   " + f.Path, "", "The file was quarantined and can no longer run.", ""}
	l = append(l, evidenceLines(f)...)
	l = append(l, "", "Remove it permanently, or restore it and allow this exact file?")
	return strings.Join(l, "\n")
}

// dialogFn is swapped in tests.
var dialogFn = nativeDialog

func nativeDialog(title, msg, ok, cancel string, timeout time.Duration) Verdict {
	ensureDisplay()
	ctx, stop := context.WithTimeout(context.Background(), timeout)
	defer stop()
	err := zenity.Question(msg, zenity.Title(title), zenity.OKLabel(ok), zenity.CancelLabel(cancel),
		zenity.DefaultCancel(), zenity.WarningIcon, zenity.Width(620), zenity.Context(ctx))
	switch {
	case err == nil:
		return Delete
	case errors.Is(err, zenity.ErrCanceled):
		return Keep
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
		return Timeout
	default:
		return Unavailable
	}
}

// Dialog shows ok/cancel with a timeout.  A destructive answer that arrives when
// the dialog would have timed out is treated as a timeout: nothing is ever
// deleted because nobody answered.
func Dialog(title, msg, ok, cancel string, timeout time.Duration) Verdict {
	start := time.Now()
	v := dialogFn(title, msg, ok, cancel, timeout)
	if v == Delete && time.Since(start) >= timeout-500*time.Millisecond {
		return Timeout
	}
	return v
}

func Ask(f *findings.Finding, action string, timeout time.Duration) Verdict {
	return Dialog(fmt.Sprintf("ThreatScan: %s - %s", f.Severity, f.Title), BuildMessage(f, action), action, "Keep", timeout)
}

func AskQuarantined(f *findings.Finding, timeout time.Duration) Verdict {
	return Dialog("ThreatScan: threat quarantined - "+ThreatName(f), QuarantinedMessage(f), "Remove", "Restore & allow", timeout)
}

// AskTerminal is the TTY fallback for interactive scans.
func AskTerminal(f *findings.Finding, action string) Verdict {
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return Unavailable
	}
	fmt.Println()
	fmt.Println(BuildMessage(f, action))
	fmt.Printf("  [%s] %s / [k] keep > ", strings.ToLower(action[:1]), action)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return Unavailable
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case strings.ToLower(action[:1]), "y", "yes", "delete", "remove":
		return Delete
	}
	return Keep
}

// SetDialogForTest replaces the native dialog (tests only).
func SetDialogForTest(fn func(title, msg, ok, cancel string, timeout time.Duration) Verdict) func() {
	old := dialogFn
	dialogFn = fn
	return func() { dialogFn = old }
}
