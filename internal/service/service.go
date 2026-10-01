// Package service starts the guard at sign-in as a per-user service.
//
//	Linux   systemd --user unit      ~/.config/systemd/user/threatscan-guard.service
//	macOS   LaunchAgent              ~/Library/LaunchAgents/com.threatscan.guard.plist
//	Windows Scheduled Task (ONLOGON) "ThreatScan Guard", falling back to a Startup
//	        folder .vbs launcher when schtasks is refused for the current user.
//
// None of these need administrator rights. Names match the Python v5 build so a
// Go install replaces a v5 (Python) one in place.
package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/update"
)

const (
	ServiceName  = "threatscan-guard"
	LaunchdLabel = "com.threatscan.guard"
	WinTask      = "ThreatScan Guard"
)

const cmdTimeout = 60 * time.Second

type Manager struct {
	P       *platform.Info
	DataDir string
	Log     string
	// Src is the executable PlaceBinary copies; defaults to the running one.
	Src string
	// Version is Src's version. When set, PlaceBinary keeps an installed binary
	// that reports a newer one (a self-updated copy survives a package upgrade).
	Version string
}

// ErrNewerInstalled means PlaceBinary left a newer installed binary in place.
type ErrNewerInstalled struct{ Installed string }

func (e *ErrNewerInstalled) Error() string {
	return "a newer version (" + e.Installed + ") is already installed"
}

// InstalledVersion runs `<exe> version` and returns the version it prints.
func InstalledVersion(exe string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "version").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	if len(f) >= 2 && f[0] == "ThreatScan" {
		return strings.TrimPrefix(f[1], "v")
	}
	return ""
}

func New(p *platform.Info, dataDir string) *Manager {
	return &Manager{P: p, DataDir: dataDir, Log: filepath.Join(dataDir, "guard.log"), Src: platform.Exe()}
}

// Exe is where the installed binary lives and what the service runs.
func (m *Manager) Exe() string { return filepath.Join(m.P.InstallDir(), m.P.ExeName()) }

// Command is the registered command line: <InstallDir>/<ExeName> guard.
func (m *Manager) Command() []string { return []string{m.Exe(), "guard"} }

// UnitPath is the unit file, plist, or (Windows) the Startup-folder fallback launcher.
func (m *Manager) UnitPath() string {
	switch {
	case m.P.IsLinux():
		return filepath.Join(m.P.Home, ".config", "systemd", "user", ServiceName+".service")
	case m.P.IsMac():
		return filepath.Join(m.P.Home, "Library", "LaunchAgents", LaunchdLabel+".plist")
	}
	return filepath.Join(m.P.AppData(), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "ThreatScanGuard.vbs")
}

// ── definitions ─────────────────────────────────────────────────────────────

func shQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./-_", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// SystemdUnit renders the Linux user unit. No After=default.target: that made an
// ordering cycle with WantedBy=default.target in v5.0.
func SystemdUnit(cmd []string, log, envHome string) string {
	q := make([]string, len(cmd))
	for i, c := range cmd {
		q[i] = shQuote(c)
	}
	env := ""
	if envHome != "" {
		env = "Environment=THREATSCAN_HOME=" + envHome + "\n"
	}
	return `[Unit]
Description=ThreatScan guard (PolinRider detector / responder)

[Service]
Type=simple
ExecStart=` + strings.Join(q, " ") + `
Restart=always
RestartSec=30
Nice=10
IOSchedulingClass=idle
` + env + `StandardOutput=append:` + log + `
StandardError=append:` + log + `

[Install]
WantedBy=default.target
`
}

func xmlEsc(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// LaunchdPlist renders the macOS LaunchAgent.
func LaunchdPlist(cmd []string, log, envHome, path string) string {
	var args strings.Builder
	for _, c := range cmd {
		args.WriteString("\t\t<string>" + xmlEsc(c) + "</string>\n")
	}
	env := "\t\t<key>PATH</key>\n\t\t<string>" + xmlEsc(path) + "</string>\n"
	if envHome != "" {
		env += "\t\t<key>THREATSCAN_HOME</key>\n\t\t<string>" + xmlEsc(envHome) + "</string>\n"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + LaunchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
` + args.String() + `	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LowPriorityIO</key>
	<true/>
	<key>Nice</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>` + xmlEsc(log) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEsc(log) + `</string>
	<key>EnvironmentVariables</key>
	<dict>
` + env + `	</dict>
</dict>
</plist>
`
}

// launchdPath is the PATH the guard sees; launchd's default lacks Homebrew.
func launchdPath() string {
	parts := []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"}
	seen := map[string]bool{}
	var out []string
	for _, p := range append(filepath.SplitList(os.Getenv("PATH")), parts...) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return strings.Join(out, ":")
}

// taskRun is the schtasks /TR value.
func taskRun(cmd []string) string {
	s := `"` + cmd[0] + `"`
	for _, a := range cmd[1:] {
		if strings.Contains(a, " ") {
			a = `"` + a + `"`
		}
		s += " " + a
	}
	return s
}

func vbsLauncher(cmd []string) string {
	return "Set s = CreateObject(\"WScript.Shell\")\r\ns.Run \"" + strings.ReplaceAll(taskRun(cmd), `"`, `""`) + "\", 0, False\r\n"
}

// Preview describes what Install would register, for --dry-run.
func (m *Manager) Preview() string {
	cmd := m.Command()
	envHome := os.Getenv("THREATSCAN_HOME")
	s := fmt.Sprintf("would copy %s -> %s\n", m.Src, m.Exe())
	switch {
	case m.P.IsLinux():
		s += "would write " + m.UnitPath() + ":\n" + SystemdUnit(cmd, m.Log, envHome)
	case m.P.IsMac():
		s += "would write " + m.UnitPath() + ":\n" + LaunchdPlist(cmd, m.Log, envHome, launchdPath())
	case m.P.IsWindows():
		s += fmt.Sprintf("would register scheduled task '%s' running: %s\n  fallback: %s", WinTask, taskRun(cmd), m.UnitPath())
	default:
		s += "unsupported platform " + m.P.OS
	}
	return s
}

// ── binary placement ────────────────────────────────────────────────────────

func fileHash(p string) ([]byte, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return h.Sum(nil), n, err
}

// PlaceBinary copies Src into InstallDir. It returns false when there was
// nothing to do (already running from there, or an identical copy exists).
func (m *Manager) PlaceBinary() (bool, error) {
	dst := m.Exe()
	if m.Src == "" {
		return false, fmt.Errorf("cannot locate the running executable")
	}
	si, err := os.Stat(m.Src)
	if err != nil {
		return false, err
	}
	if di, err := os.Stat(dst); err == nil {
		if os.SameFile(si, di) {
			return false, nil
		}
		hs, _, e1 := fileHash(m.Src)
		hd, _, e2 := fileHash(dst)
		if e1 == nil && e2 == nil && bytes.Equal(hs, hd) {
			return false, nil
		}
		if m.Version != "" {
			if iv := InstalledVersion(dst); iv != "" && !update.IsWithdrawn(iv) && update.CompareVersions(iv, m.Version) > 0 {
				return false, &ErrNewerInstalled{iv}
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	in, err := os.Open(m.Src)
	if err != nil {
		return false, err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return false, err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return false, err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// LinkCLI makes `threatscan` callable from a terminal: a symlink in
// ~/.local/bin on Linux/macOS, the install dir on the user PATH on Windows.
// A v5 launcher that is a real file is left alone (the v5.2 migration removes it).
func (m *Manager) LinkCLI(dry bool) string {
	if m.P.IsWindows() {
		return addUserPath(m.P.InstallDir(), dry)
	}
	bin := filepath.Join(m.P.Home, ".local", "bin")
	link := filepath.Join(bin, "threatscan")
	if st, err := os.Lstat(link); err == nil {
		if st.Mode()&os.ModeSymlink == 0 {
			return "kept existing launcher " + link + " (v5); it is replaced by the v5.2 migration"
		}
		if cur, _ := os.Readlink(link); cur == m.Exe() {
			return link + " -> " + m.Exe()
		}
	}
	if dry {
		return "would link " + link + " -> " + m.Exe()
	}
	if err := os.MkdirAll(bin, 0o755); err != nil {
		return "could not create " + bin + ": " + err.Error()
	}
	tmp := link + ".new"
	os.Remove(tmp)
	if err := os.Symlink(m.Exe(), tmp); err != nil {
		return "could not link " + link + ": " + err.Error()
	}
	if err := os.Rename(tmp, link); err != nil {
		os.Remove(tmp)
		return "could not link " + link + ": " + err.Error()
	}
	msg := link + " -> " + m.Exe()
	onPath := false
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		onPath = onPath || filepath.Clean(d) == bin
	}
	if !onPath {
		if files := m.addToShellPath(); len(files) > 0 {
			msg += "\nadded ~/.local/bin to PATH in " + strings.Join(files, ", ") + " (open a new terminal)"
		} else {
			msg += fmt.Sprintf("\nadd %s to your PATH (e.g. echo 'export PATH=\"%s:$PATH\"' >> ~/.zshrc)", bin, bin)
		}
	}
	return msg
}

const pathLine = `export PATH="$HOME/.local/bin:$PATH"  # added by threatscan install`

// addToShellPath appends the ~/.local/bin PATH line to the shell start-up
// files that exist (zsh on macOS, bash/profile on Linux), once. It returns
// the files it changed.
func (m *Manager) addToShellPath() []string {
	var candidates []string
	switch {
	case m.P.IsMac():
		candidates = []string{".zshrc", ".zprofile", ".bash_profile"}
	default:
		candidates = []string{".zshrc", ".bashrc", ".profile"}
	}
	var done []string
	wrote := false
	for i, name := range candidates {
		p := filepath.Join(m.P.Home, name)
		b, err := os.ReadFile(p)
		// create the default shell's file when nothing exists; others only if present
		if err != nil && !(i == 0 && !wrote && os.IsNotExist(err)) {
			continue
		}
		if strings.Contains(string(b), ".local/bin") {
			wrote = true // already on the PATH for this shell
			continue
		}
		fh, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			continue
		}
		sep := ""
		if len(b) > 0 && !strings.HasSuffix(string(b), "\n") {
			sep = "\n"
		}
		if _, err := fh.WriteString(sep + "\n" + pathLine + "\n"); err == nil {
			done = append(done, "~/"+name)
			wrote = true
		}
		fh.Close()
	}
	return done
}

// UnlinkCLI removes the ~/.local/bin symlink (only if it points at our binary)
// or the Windows PATH entry.
func (m *Manager) UnlinkCLI() {
	if m.P.IsWindows() {
		removeUserPath(m.P.InstallDir())
		return
	}
	link := filepath.Join(m.P.Home, ".local", "bin", "threatscan")
	if cur, err := os.Readlink(link); err == nil && cur == m.Exe() {
		os.Remove(link)
	}
}

// ── install / uninstall / status ────────────────────────────────────────────

func (m *Manager) run(name string, args ...string) (int, string, string) {
	return m.P.RunRC(cmdTimeout, name, args...)
}

func firstLine(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// Install copies the binary into InstallDir, then registers and starts the guard.
func (m *Manager) Install() (bool, string) {
	if err := os.MkdirAll(m.DataDir, 0o700); err != nil {
		return false, err.Error()
	}
	if m.P.IsWindows() {
		// the running guard locks the exe; stop it before overwriting
		m.stopWindows()
	}
	copied, err := m.PlaceBinary()
	var newer *ErrNewerInstalled
	note := ""
	switch {
	case errors.As(err, &newer):
		note = "kept " + m.Exe() + ": " + err.Error() + "\n"
	case err != nil:
		return false, "could not copy the program to " + m.Exe() + ": " + err.Error()
	case copied:
		note = "installed " + m.Exe() + "\n"
	}
	var ok bool
	var msg string
	switch {
	case m.P.IsLinux():
		ok, msg = m.installSystemd()
	case m.P.IsMac():
		ok, msg = m.installLaunchd()
	case m.P.IsWindows():
		ok, msg = m.installWindows()
	default:
		return false, "unsupported platform"
	}
	return ok, note + msg
}

func (m *Manager) installSystemd() (bool, string) {
	unit := m.UnitPath()
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		return false, err.Error()
	}
	if err := os.WriteFile(unit, []byte(SystemdUnit(m.Command(), m.Log, os.Getenv("THREATSCAN_HOME"))), 0o644); err != nil {
		return false, err.Error()
	}
	for _, c := range [][]string{
		{"systemctl", "--user", "daemon-reload"},
		{"systemctl", "--user", "enable", ServiceName + ".service"},
		// restart, not start: a reinstall must pick up the new binary
		{"systemctl", "--user", "restart", ServiceName + ".service"},
	} {
		if rc, _, e := m.run(c[0], c[1:]...); rc != 0 {
			return false, strings.Join(c, " ") + " failed: " + firstLine(e, 200)
		}
	}
	// Keep the user manager alive after logout so the guard keeps running.
	if _, err := exec.LookPath("loginctl"); err == nil {
		user := os.Getenv("USER")
		if user == "" {
			user = strconv.Itoa(os.Getuid())
		}
		m.run("loginctl", "enable-linger", user)
	}
	return true, "systemd --user unit installed and started: " + unit
}

func (m *Manager) installLaunchd() (bool, string) {
	pl := m.UnitPath()
	if err := os.MkdirAll(filepath.Dir(pl), 0o755); err != nil {
		return false, err.Error()
	}
	dom := "gui/" + strconv.Itoa(os.Getuid())
	m.run("launchctl", "bootout", dom, pl)
	if err := os.WriteFile(pl, []byte(LaunchdPlist(m.Command(), m.Log, os.Getenv("THREATSCAN_HOME"), launchdPath())), 0o644); err != nil {
		return false, err.Error()
	}
	if rc, _, _ := m.run("launchctl", "bootstrap", dom, pl); rc != 0 {
		if rc, _, e := m.run("launchctl", "load", "-w", pl); rc != 0 {
			return false, "launchctl failed: " + firstLine(e, 200)
		}
	}
	return true, "LaunchAgent installed and started: " + pl
}

func (m *Manager) installWindows() (bool, string) {
	tr := taskRun(m.Command())
	m.run("schtasks", "/Delete", "/TN", WinTask, "/F")
	rc, _, e := m.run("schtasks", "/Create", "/TN", WinTask, "/SC", "ONLOGON", "/TR", tr, "/RL", "LIMITED", "/F")
	if rc == 0 {
		os.Remove(m.UnitPath()) // a previous fallback launcher would start a second guard
		m.run("schtasks", "/Run", "/TN", WinTask)
		return true, "scheduled task '" + WinTask + "' registered (runs at logon) and started"
	}
	// Fallback: Startup-folder VBS launcher (hidden window)
	vbs := m.UnitPath()
	if err := os.MkdirAll(filepath.Dir(vbs), 0o755); err != nil {
		return false, err.Error()
	}
	if err := os.WriteFile(vbs, []byte(vbsLauncher(m.Command())), 0o644); err != nil {
		return false, err.Error()
	}
	c := exec.Command("wscript.exe", vbs)
	platform.Detach(c)
	if err := c.Start(); err == nil {
		go c.Wait()
	}
	return true, fmt.Sprintf("schtasks refused (%s); installed Startup launcher %s and started guard", firstLine(e, 80), vbs)
}

// stopWindows ends the scheduled task, any guard the Startup launcher started,
// and anything else running the installed exe (e.g. the background first scan),
// since a running exe cannot be replaced or deleted.
func (m *Manager) stopWindows() {
	m.run("schtasks", "/End", "/TN", WinTask)
	installed := strings.ToLower(m.Exe())
	for _, pr := range m.P.Processes() {
		lc := strings.ToLower(pr.Cmd)
		guard := strings.Contains(lc, "threatscan") && strings.Contains(lc, "guard")
		if (guard || strings.Contains(lc, installed)) && pr.PID != os.Getpid() {
			m.P.Kill(pr.PID)
		}
	}
	time.Sleep(500 * time.Millisecond) // let Windows release the file lock
}

// Uninstall stops and unregisters the guard. The binary and data are left.
func (m *Manager) Uninstall() (bool, string) {
	p := m.UnitPath()
	switch {
	case m.P.IsLinux():
		m.run("systemctl", "--user", "disable", "--now", ServiceName+".service")
		os.Remove(p)
		m.run("systemctl", "--user", "daemon-reload")
		return true, "systemd unit removed"
	case m.P.IsMac():
		m.run("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid()), p)
		os.Remove(p)
		return true, "LaunchAgent removed"
	case m.P.IsWindows():
		m.stopWindows()
		m.run("schtasks", "/Delete", "/TN", WinTask, "/F")
		os.Remove(p)
		return true, "scheduled task / startup launcher removed"
	}
	return false, "unsupported platform"
}

// Status is a one-line description of the registered service.
func (m *Manager) Status() string {
	switch {
	case m.P.IsLinux():
		_, out, _ := m.run("systemctl", "--user", "is-active", ServiceName+".service")
		if s := strings.TrimSpace(out); s != "" {
			if _, err := os.Stat(m.UnitPath()); err != nil && s == "inactive" {
				return "not installed"
			}
			return s
		}
		return "not installed"
	case m.P.IsMac():
		if rc, _, _ := m.run("launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/"+LaunchdLabel); rc == 0 {
			return "running"
		}
		return "not installed"
	case m.P.IsWindows():
		if rc, _, _ := m.run("schtasks", "/Query", "/TN", WinTask); rc == 0 {
			return "scheduled task registered"
		}
		if _, err := os.Stat(m.UnitPath()); err == nil {
			return "startup launcher"
		}
		return "not installed"
	}
	return "unknown"
}

// ── restart (after an update or a rollback) ─────────────────────────────────

// Restart asks the service manager to restart the guard with the binary now on
// disk. For use from the CLI, not from inside the guard (see RestartFromGuard).
func (m *Manager) Restart() (bool, string) {
	switch {
	case m.P.IsLinux():
		if _, err := os.Stat(m.UnitPath()); err != nil {
			return false, "guard service not installed"
		}
		if rc, _, e := m.run("systemctl", "--user", "--no-block", "restart", ServiceName+".service"); rc != 0 {
			return false, "systemctl restart failed: " + firstLine(e, 200)
		}
	case m.P.IsMac():
		if _, err := os.Stat(m.UnitPath()); err != nil {
			return false, "guard service not installed"
		}
		if rc, _, e := m.run("launchctl", "kickstart", "-k", "gui/"+strconv.Itoa(os.Getuid())+"/"+LaunchdLabel); rc != 0 {
			return false, "launchctl kickstart failed: " + firstLine(e, 200)
		}
	case m.P.IsWindows():
		m.stopWindows()
		if rc, _, _ := m.run("schtasks", "/Run", "/TN", WinTask); rc != 0 {
			if _, err := os.Stat(m.UnitPath()); err != nil {
				return false, "guard service not installed"
			}
			c := exec.Command("wscript.exe", m.UnitPath())
			platform.Detach(c)
			if err := c.Start(); err != nil {
				return false, err.Error()
			}
			go c.Wait()
		}
	default:
		return false, "unsupported platform"
	}
	return true, "guard restarted"
}

// underServiceManager reports whether this process was started by our unit/agent.
func underServiceManager(p *platform.Info) bool {
	switch {
	case p.IsLinux():
		return os.Getenv("INVOCATION_ID") != ""
	case p.IsMac():
		return os.Getenv("XPC_SERVICE_NAME") == LaunchdLabel
	}
	return false
}

// RestartFromGuard is called by a running guard that must restart itself.
// Under systemd/launchd the service manager restarts it; otherwise (Windows,
// or a guard in a terminal) a new detached guard is started. Either way the
// caller must stop afterwards.
func (m *Manager) RestartFromGuard(exe string) error {
	if underServiceManager(m.P) {
		if ok, msg := m.Restart(); !ok {
			return errors.New(msg)
		}
		return nil
	}
	c := exec.Command(exe, "guard")
	platform.Detach(c)
	if err := c.Start(); err != nil {
		return err
	}
	return c.Process.Release()
}
