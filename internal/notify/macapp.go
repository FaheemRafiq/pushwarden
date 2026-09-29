package notify

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/platform"
)

// macOS notifications posted through osascript belong to Script Editor, so a
// click opens Script Editor with nothing in it. `threatscan install` therefore
// compiles a tiny AppleScript applet: called with arguments it posts the
// notification under its own name; launched with none (that is what a click
// does) it opens the alert details.
const (
	MacAppName  = "ThreatScan Notifier.app"
	MacBundleID = "com.threatscan.notifier"
)

func MacAppPath(installDir string) string { return filepath.Join(installDir, MacAppName) }

// NotifierScript is the applet source; bin is the threatscan binary it calls back.
func NotifierScript(bin string) string {
	q := "'" + strings.ReplaceAll(bin, "'", `'\''`) + "'"
	return `on run argv
	if (count of argv) >= 3 then
		display notification (item 3 of argv) with title (item 1 of argv) subtitle (item 2 of argv)
	else if (count of argv) = 2 then
		display notification (item 2 of argv) with title (item 1 of argv)
	else
		openAlerts()
	end if
end run

on reopen
	openAlerts()
end reopen

on openAlerts()
	do shell script "` + q + ` alerts --gui >/dev/null 2>&1 &"
end openAlerts
`
}

// macArgs splits a notification body: the first line becomes the subtitle,
// the rest the text (macOS shows title, subtitle and one or two text lines).
func macArgs(title, body string) (subtitle, text string) {
	sub, rest, _ := strings.Cut(strings.TrimSpace(body), "\n")
	return strings.TrimSpace(sub), strings.TrimSpace(rest)
}

// InstallMacNotifier builds the applet under installDir. It returns what it did
// (or would do); a failure is reported, never fatal for the caller.
func InstallMacNotifier(p *platform.Info, installDir, bin string, dry bool) (string, error) {
	app := MacAppPath(installDir)
	if dry {
		return "would build " + app + " (osacompile) with bundle id " + MacBundleID, nil
	}
	if !p.IsMac() {
		return "", errors.New("macOS only")
	}
	for _, tool := range []string{"osacompile", "plutil"} {
		if _, err := exec.LookPath(tool); err != nil {
			return "", fmt.Errorf("%s not found; notifications fall back to osascript", tool)
		}
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return "", err
	}
	src := filepath.Join(installDir, "notifier.applescript")
	if err := os.WriteFile(src, []byte(NotifierScript(bin)), 0o644); err != nil {
		return "", err
	}
	defer os.Remove(src)
	_ = os.RemoveAll(app)
	if rc, _, se := p.RunRC(60*time.Second, "osacompile", "-o", app, src); rc != 0 {
		return "", errors.New("osacompile failed: " + strings.TrimSpace(se))
	}
	plist := filepath.Join(app, "Contents", "Info.plist")
	for _, kv := range [][]string{
		{"CFBundleIdentifier", "-string", MacBundleID},
		{"CFBundleName", "-string", "ThreatScan"},
		{"CFBundleDisplayName", "-string", "ThreatScan"},
		{"LSUIElement", "-bool", "true"},
	} {
		if rc, _, se := p.RunRC(20*time.Second, "plutil", "-replace", kv[0], kv[1], kv[2], plist); rc != 0 {
			return "", errors.New("plutil failed: " + strings.TrimSpace(se))
		}
	}
	// ad-hoc signature: keeps the notification permission stable across rebuilds
	p.RunRC(60*time.Second, "codesign", "-s", "-", "-f", "--deep", app)
	return "built " + app, nil
}

// RemoveMacNotifier deletes the applet (uninstall).
func RemoveMacNotifier(installDir string) { _ = os.RemoveAll(MacAppPath(installDir)) }
