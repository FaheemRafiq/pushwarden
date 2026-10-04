package notify

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/platform"
)

// macOS notifications posted through osascript belong to Script Editor, so a
// click opens Script Editor with nothing in it. `pushwarden install` therefore
// compiles a tiny AppleScript applet: called with arguments it posts the
// notification under its own name; launched with none (that is what a click
// does) it opens the alert details.
const (
	MacAppName  = "PushWarden Notifier.app"
	MacBundleID = "com.pushwarden.notifier"
)

func MacAppPath(installDir string) string { return filepath.Join(installDir, MacAppName) }

// NotifierScript is the applet source; bin is the pushwarden binary it calls back.
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
	err := buildApplet(p, app, NotifierScript(bin), [][]string{
		{"CFBundleIdentifier", "-string", MacBundleID},
		{"CFBundleName", "-string", "PushWarden"},
		{"CFBundleDisplayName", "-string", "PushWarden"},
		{"LSUIElement", "-bool", "true"},
	})
	if err != nil {
		return "", err
	}
	return "built " + app, nil
}

// buildApplet compiles an AppleScript applet at app and sets its Info.plist keys.
func buildApplet(p *platform.Info, app, script string, plistKeys [][]string) error {
	for _, tool := range []string{"osacompile", "plutil"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("%s not found", tool)
		}
	}
	dir := filepath.Dir(app)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	src := filepath.Join(dir, ".pushwarden-applet.applescript")
	if err := os.WriteFile(src, []byte(script), 0o644); err != nil {
		return err
	}
	defer os.Remove(src)
	_ = os.RemoveAll(app)
	if rc, _, se := p.RunRC(60*time.Second, "osacompile", "-o", app, src); rc != 0 {
		return errors.New("osacompile failed: " + strings.TrimSpace(se))
	}
	plist := filepath.Join(app, "Contents", "Info.plist")
	for _, kv := range plistKeys {
		if rc, _, se := p.RunRC(20*time.Second, "plutil", "-replace", kv[0], kv[1], kv[2], plist); rc != 0 {
			return errors.New("plutil failed: " + strings.TrimSpace(se))
		}
	}
	// ad-hoc signature: keeps the app's permissions stable across rebuilds
	p.RunRC(60*time.Second, "codesign", "-s", "-", "-f", "--deep", app)
	return nil
}

// RemoveMacNotifier deletes the applet (uninstall).
func RemoveMacNotifier(installDir string) { _ = os.RemoveAll(MacAppPath(installDir)) }

// The launcher is what people who do not use a terminal click: an app in
// ~/Applications that opens Terminal on `pushwarden ui`.
const (
	MacLauncherName     = "PushWarden.app"
	MacLauncherBundleID = "com.pushwarden.launcher"
)

func MacLauncherPath(home string) string {
	return filepath.Join(home, "Applications", MacLauncherName)
}

// LauncherScript is the launcher's source; bin is the pushwarden binary it runs.
func LauncherScript(bin string) string {
	q := "'" + strings.ReplaceAll(bin, "'", `'\''`) + "'"
	return `on run
	tell application "Terminal"
		activate
		do script "exec ` + q + ` ui --pause"
	end tell
end run
`
}

// InstallMacLauncher builds the launcher under home/Applications. It returns
// what it did (or would do); a failure is reported, never fatal for the caller.
func InstallMacLauncher(p *platform.Info, home, bin string, dry bool) (string, error) {
	app := MacLauncherPath(home)
	if dry {
		return "would build " + app + " (opens `pushwarden ui` in Terminal)", nil
	}
	if !p.IsMac() {
		return "", errors.New("macOS only")
	}
	if exists(app) && !isMacLauncher(app) {
		return "", errors.New(app + " exists and is not PushWarden's")
	}
	err := buildApplet(p, app, LauncherScript(bin), [][]string{
		{"CFBundleIdentifier", "-string", MacLauncherBundleID},
		{"CFBundleName", "-string", "PushWarden"},
		{"CFBundleDisplayName", "-string", "PushWarden"},
	})
	if err != nil {
		return "", err
	}
	return "built " + app, nil
}

// isMacLauncher reports whether app carries the launcher's bundle id.
func isMacLauncher(app string) bool {
	b, err := os.ReadFile(filepath.Join(app, "Contents", "Info.plist"))
	return err == nil && strings.Contains(string(b), MacLauncherBundleID)
}

// RemoveMacLauncher deletes the launcher (uninstall), and nothing else that
// happens to have its name.
func RemoveMacLauncher(home string) {
	if app := MacLauncherPath(home); isMacLauncher(app) {
		_ = os.RemoveAll(app)
	}
}
