// threatscan:allow-signatures
package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	h "github.com/FaheemRafiq/threatscan/internal/helpers"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

type System struct {
	P  *platform.Info
	UI *ui.UI
	I  *iocs.IOCs
}

// own dialog / notification helpers quote malware indicators in their args.
var ownTools = map[string]bool{"zenity": true, "yad": true, "kdialog": true, "xmessage": true, "osascript": true,
	"notify-send": true, "qarma": true, "matedialog": true}

func (s *System) CheckProcesses() []*F {
	s.UI.Progress("Checking running processes")
	me := os.Getpid()
	var out []*F
	for _, pr := range s.P.Processes() {
		low := strings.ToLower(pr.Cmd)
		if pr.PID == me || strings.Contains(low, "threatscan") || ownTools[strings.ToLower(strings.TrimSuffix(pr.Name, ".exe"))] {
			continue
		}
		for _, re := range s.I.Process {
			if !re.MatchString(pr.Cmd) {
				continue
			}
			killable := false
			for _, k := range s.I.ProcessKill {
				killable = killable || k.MatchString(pr.Cmd)
			}
			kill := fmt.Sprintf("kill -9 %d", pr.PID)
			if s.P.IsWindows() {
				kill = fmt.Sprintf("taskkill /PID %d /F", pr.PID)
			}
			cmd := pr.Cmd
			if len(cmd) > 200 {
				cmd = cmd[:200] + "..."
			}
			out = append(out, &F{Severity: crit, Category: "malicious_process",
				Title:       fmt.Sprintf("Malicious process running: PID %d (%s)", pr.PID, pr.Name),
				Details:     "Pattern: " + h.Trunc(re.String(), 50) + "\nCmd: " + cmd,
				Remediation: kill + "\n  Then find its parent and persistence (see persistence findings).",
				Meta:        findings.Meta{PID: pr.PID, Kill: killable, Cmd: h.Trunc(pr.Cmd, 500)}})
			break
		}
	}
	return out
}

func (s *System) CheckNetwork() []*F {
	s.UI.Progress("Checking network connections")
	bad := map[string]bool{}
	for _, ip := range s.I.MaliciousIPs {
		bad[ip] = true
	}
	seen := map[string]bool{}
	var out []*F
	for _, c := range s.P.Connections() {
		key := fmt.Sprintf("%s:%d", c.IP, c.Port)
		if !bad[c.IP] || seen[key] {
			continue
		}
		seen[key] = true
		block := "sudo iptables -A OUTPUT -d " + c.IP + " -j DROP"
		if s.P.IsWindows() {
			block = `netsh advfirewall firewall add rule name="PolinRider C2" dir=out action=block remoteip=` + c.IP
		} else if s.P.IsMac() {
			block = "echo 'block drop out to " + c.IP + "' | sudo pfctl -ef -"
		}
		out = append(out, &F{Severity: crit, Category: "c2_connection", Title: "Live connection to PolinRider C2 " + key,
			Details:     fmt.Sprintf("PID: %d", c.PID),
			Remediation: block + fmt.Sprintf("\n  Then kill PID %d.  Or: sudo threatscan protect --block-c2", c.PID),
			Meta:        findings.Meta{PID: c.PID, Kill: c.PID > 0, IP: c.IP}})
	}
	return out
}

func containsAny(s string, keys ...string) bool {
	for _, k := range keys {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func (s *System) CheckCron() []*F {
	if s.P.IsWindows() {
		return nil
	}
	var out []*F
	for _, line := range strings.Split(s.P.Run(15*time.Second, "crontab", "-l"), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		low := strings.ToLower(t)
		if !containsAny(low, s.I.ScheduledTaskKeywords...) && !strings.Contains(low, "@reboot") {
			continue
		}
		f := &F{Severity: warn, Category: "persistence_cron", Title: "Suspicious crontab entry", Details: h.Trunc(t, 160),
			Remediation: "crontab -e   # remove the line you didn't add"}
		if containsAny(low, s.I.ScheduledTaskCritical...) {
			f.Severity = crit
			f.Meta.CronLine = line
		}
		out = append(out, f)
	}
	for _, d := range []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"} {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			if !e.IsDir() && containsAny(strings.ToLower(h.ReadText(p, 1<<20)), "runtimedev", "vscodeupdater", "node -e", "curl", "wget") {
				out = append(out, &F{Severity: high, Category: "persistence_cron", Title: "Suspicious system cron file: " + e.Name(),
					Path: p, Remediation: "sudo rm " + p})
			}
		}
	}
	return out
}

func (s *System) CheckSystemdUser() []*F {
	if !s.P.IsLinux() {
		return nil
	}
	var out []*F
	dir := filepath.Join(s.P.Home, ".config", "systemd", "user")
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".service") || strings.HasPrefix(d.Name(), "threatscan") {
			return nil
		}
		if _, err := os.Stat(p); err != nil { // dangling symlink
			return nil
		}
		c := h.ReadText(p, 1<<20)
		if containsAny(d.Name(), s.I.RatServiceNames...) || containsAny(c, "VSCodeUpdater", "runtimedev", "node -e", "start.sh", "SSTAR_", "SvcHostUpdate") {
			out = append(out, &F{Severity: crit, Category: "persistence_systemd", Title: "RAT systemd --user unit: " + d.Name(), Path: p,
				Details:     h.Trunc(c, 300),
				Remediation: "systemctl --user disable --now " + d.Name() + "\n  rm " + p + "\n  systemctl --user daemon-reload",
				Meta:        findings.Meta{Quarantine: true, SystemdUnit: d.Name(), Evidence: []string{"unit references RAT indicators"}}})
		}
		return nil
	})
	units := s.P.Run(15*time.Second, "systemctl", "--user", "list-units", "--all", "--no-pager", "--plain")
	for _, line := range strings.Split(units, "\n") {
		if containsAny(line, s.I.RatServiceNames...) {
			out = append(out, &F{Severity: crit, Category: "persistence_systemd", Title: "RAT unit loaded in systemd --user",
				Details: strings.TrimSpace(line), Remediation: "systemctl --user disable --now runtimedev-link.service"})
		}
	}
	return out
}

func (s *System) CheckXDGAutostart() []*F {
	var out []*F
	d := filepath.Join(s.P.Home, ".config", "autostart")
	ents, _ := os.ReadDir(d)
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".desktop") {
			continue
		}
		p := filepath.Join(d, e.Name())
		c := h.ReadText(p, 1<<20)
		if containsAny(c, "runtimedev", "VSCodeUpdater", "node -e", "RuntimeDev", "start.sh", "SvcHostUpdate") {
			out = append(out, &F{Severity: crit, Category: "persistence_autostart", Title: "RAT XDG autostart: " + e.Name(), Path: p,
				Details: h.Trunc(c, 200), Remediation: "rm " + p, Meta: findings.Meta{Quarantine: true}})
		}
	}
	return out
}

func (s *System) CheckLaunchd() []*F {
	if !s.P.IsMac() {
		return nil
	}
	var out []*F
	for _, d := range []string{filepath.Join(s.P.Home, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"} {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".plist") || strings.Contains(e.Name(), "threatscan") {
				continue
			}
			p := filepath.Join(d, e.Name())
			c := h.ReadText(p, 1<<20)
			if containsAny(e.Name(), s.I.RatServiceNames...) || containsAny(c, "runtimedev", "VSCodeUpdater", "SSTAR_", "node -e", "SvcHostUpdate", ".woff2") {
				out = append(out, &F{Severity: crit, Category: "persistence_launchd", Title: "RAT LaunchAgent: " + e.Name(), Path: p,
					Details: h.Trunc(c, 200), Remediation: "launchctl bootout gui/$(id -u) " + p + "\n  rm " + p,
					Meta: findings.Meta{Quarantine: true, LaunchdPlist: p}})
			}
		}
	}
	return out
}

var csvTask = regexp.MustCompile(`^"[^"]*","([^"]+)"`)

func (s *System) CheckWindowsTasks() []*F {
	if !s.P.IsWindows() {
		return nil
	}
	var out []*F
	bad := []string{"runtimedev", "vscodeupdater", "microsoftclroptimization", "svchostupdate", "wscript.exe //b", "node -e", "python -c"}
	for _, line := range strings.Split(s.P.Run(40*time.Second, "schtasks", "/query", "/fo", "CSV", "/v"), "\n") {
		low := strings.ToLower(line)
		if strings.Contains(low, "threatscan") || !containsAny(low, bad...) {
			continue
		}
		task := ""
		if m := csvTask.FindStringSubmatch(line); m != nil {
			task = m[1]
		}
		out = append(out, &F{Severity: crit, Category: "persistence_schtasks", Title: "RAT scheduled task", Details: h.Trunc(line, 200),
			Remediation: fmt.Sprintf(`schtasks /Delete /TN "%s" /F`, task), Meta: findings.Meta{Schtask: task}})
	}
	startup := filepath.Join(s.P.AppData(), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	ents, _ := os.ReadDir(startup)
	for _, e := range ents {
		n := strings.ToLower(e.Name())
		if !e.IsDir() && !strings.Contains(n, "threatscan") && containsAny(n, "runtimedev", "vscode", "updater", "svchost", "clroptim") {
			p := filepath.Join(startup, e.Name())
			out = append(out, &F{Severity: high, Category: "persistence_startup", Title: "Suspicious Startup item: " + e.Name(), Path: p,
				Remediation: `del "` + p + `"`})
		}
	}
	for name, val := range runKeys() {
		low := strings.ToLower(val)
		if containsAny(low, "runtimedev", "vscodeupdater", "microsoftclroptimization", "svchostupdate", "node -e", "python -c", ".woff2") {
			out = append(out, &F{Severity: crit, Category: "persistence_registry", Title: "Suspicious HKCU Run key: " + name,
				Details:     h.Trunc(val, 200),
				Remediation: `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "` + name + `" /f`})
		}
	}
	return out
}

func (s *System) CheckRAT() []*F {
	s.UI.Progress("Checking for RAT footprint")
	var out []*F
	roots := []string{s.P.LocalShare(), s.P.ConfigDir(), s.P.Home}
	if s.P.IsWindows() {
		pd := os.Getenv("PROGRAMDATA")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		roots = append(roots, pd)
	}
	for _, root := range roots {
		for _, n := range s.I.RatDirNames {
			p := filepath.Join(root, n)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				var scripts []string
				for _, g := range []string{"*.js", "*.py"} {
					m, _ := filepath.Glob(filepath.Join(p, g))
					for i, x := range m {
						if i < 3 {
							scripts = append(scripts, filepath.Base(x))
						}
					}
				}
				c := strings.Join(scripts, ", ")
				if c == "" {
					c = "(no scripts at top level)"
				}
				out = append(out, &F{Severity: crit, Category: "rat_footprint", Title: "RAT directory: " + p, Path: p,
					Details:     "Contains: " + c + "\nDisguised as an updater; polls C2 for shell commands and exfiltrates files.",
					Remediation: `rm -rf "` + p + `"`, Meta: findings.Meta{Quarantine: true, Evidence: []string{"directory name " + n + " is the runtimedev-link RAT"}}})
			}
		}
		for _, n := range s.I.RatFiles {
			p := filepath.Join(root, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				out = append(out, &F{Severity: crit, Category: "rat_footprint", Title: "RAT file: " + n, Path: p,
					Details: h.Trunc(h.ReadText(p, 1<<20), 200), Remediation: `rm "` + p + `"`,
					Meta: findings.Meta{Quarantine: true, Evidence: []string{"file name " + n + " belongs to the RAT"}}})
			}
		}
	}
	env := filepath.Join(s.P.ConfigDir(), "runtimedev-link", "agent.env")
	if _, err := os.Stat(env); err == nil {
		out = append(out, &F{Severity: crit, Category: "rat_footprint", Title: "RAT config with C2 URL", Path: env,
			Details: h.Trunc(h.ReadText(env, 1<<20), 200), Remediation: `rm -rf "` + filepath.Dir(env) + `"`, Meta: findings.Meta{Quarantine: true}})
	}
	log := filepath.Join(s.P.Home, "runtimedev-link.log")
	if c := h.ReadText(log, 5<<20); c != "" {
		out = append(out, &F{Severity: high, Category: "rat_footprint", Title: "RAT log file (proves it ran)", Path: log,
			Details: c[max(0, len(c)-400):], Remediation: `Review then rm "` + log + `"`})
	}
	for _, k := range s.I.RatEnvKeys {
		if v := os.Getenv(k); v != "" {
			out = append(out, &F{Severity: crit, Category: "rat_footprint", Title: "RAT environment variable set: " + k, Details: h.Trunc(v, 120),
				Remediation: "Find where it is exported (shell rc, systemd unit, agent.env) and remove it."})
		}
	}
	return out
}

func (s *System) CheckShellRC() []*F {
	var out []*F
	for _, rc := range s.P.ShellRCFiles() {
		c := h.ReadText(rc, 5<<20)
		for _, re := range s.I.Shell {
			if m := re.FindString(c); m != "" {
				out = append(out, &F{Severity: high, Category: "shell_injection", Title: "Suspicious code in " + filepath.Base(rc), Path: rc,
					Details: h.Trunc(m, 120), Remediation: "Edit " + rc + "; remove anything you didn't add."})
				break
			}
		}
	}
	return out
}

var tokenRe = regexp.MustCompile(`(_authToken|password|token|ghp_|gho_|npm_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})`)

func (s *System) CheckCredentials(infected bool) []*F {
	s.UI.Progress("Checking credential files")
	var out []*F
	sev := info
	if infected {
		sev = high
	}
	for _, f := range s.P.CredentialFiles() {
		if !tokenRe.MatchString(h.ReadText(f, 5<<20)) {
			continue
		}
		fd := &F{Severity: sev, Category: "credential_exposure", Title: "Stored credential: " + filepath.Base(f), Path: f,
			Details: "OmniStealer harvests this file. Prefer keyring/ssh-agent.", Remediation: "Consider removing plaintext tokens from " + f + "."}
		if infected {
			fd.Details = "OmniStealer harvests this file. Treat as leaked."
			fd.Remediation = "Revoke the token at its provider, then delete/rewrite the file."
		}
		out = append(out, fd)
	}
	ssh := filepath.Join(s.P.Home, ".ssh")
	ents, _ := os.ReadDir(ssh)
	var keys []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "id_") && !strings.HasSuffix(e.Name(), ".pub") {
			keys = append(keys, e.Name())
		}
	}
	if len(keys) > 0 && infected {
		out = append(out, &F{Severity: high, Category: "credential_exposure", Title: fmt.Sprintf("%d SSH private key(s) present on infected host", len(keys)),
			Path: ssh, Details: strings.Join(keys, ", "), Remediation: "Generate new keys; remove the old public keys from GitHub/servers."})
	}
	ak := filepath.Join(ssh, "authorized_keys")
	n := 0
	for _, l := range strings.Split(h.ReadText(ak, 1<<20), "\n") {
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	if n > 0 {
		sv := info
		if infected {
			sv = warn
		}
		out = append(out, &F{Severity: sv, Category: "credential_exposure", Title: fmt.Sprintf("authorized_keys has %d key(s)", n), Path: ak,
			Details: "Verify each one is yours.", Remediation: "cat " + ak})
	}
	return out
}

func (s *System) CheckEditorInjection() []*F {
	s.UI.Progress("Checking editor and app injection points")
	var out []*F
	for _, d := range s.P.EditorDirs() {
		_ = filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				if e.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(p)
			if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
				return nil
			}
			c := h.ReadText(p, 5<<20)
			hit := c != "" && (s.I.Marker.MatchString(c) || containsAny(c, s.I.XorKeys...) || containsAny(c, s.I.TronWallets...))
			if hit {
				out = append(out, &F{Severity: crit, Category: "editor_injection", Title: "Injected payload in editor/app file: " + e.Name(), Path: p,
					Details: "Joyfill variant injects into VS Code, Cursor, Discord, GitHub Desktop.", Remediation: "Reinstall the affected app; delete " + p + "."})
			}
			return nil
		})
	}
	npm := "npm"
	if s.P.IsWindows() {
		npm = "npm.cmd"
	}
	root := strings.TrimSpace(s.P.Run(8*time.Second, npm, "root", "-g"))
	if root == "" {
		return out
	}
	for name := range s.I.CompromisedNPM {
		if st, err := os.Stat(filepath.Join(root, name)); err == nil && st.IsDir() {
			out = append(out, &F{Severity: crit, Category: "compromised_package", Title: "Compromised package installed globally: " + name,
				Path: filepath.Join(root, name), Remediation: "npm uninstall -g " + name})
		}
	}
	cli := filepath.Join(root, "npm", "lib", "cli.js")
	if st, err := os.Stat(cli); err == nil {
		c := h.ReadText(cli, 5<<20)
		switch {
		case s.I.Marker.MatchString(c) || containsAny(c, s.I.XorKeys...) || containsAny(c, "C260521A", "RS260605"):
			out = append(out, &F{Severity: crit, Category: "editor_injection", Title: "Global npm CLI is backdoored", Path: cli,
				Details: fmt.Sprintf("size %d bytes", st.Size()), Remediation: "Reinstall Node/npm from nodejs.org; do not use the current npm to do it."})
		case st.Size() > 8192:
			out = append(out, &F{Severity: high, Category: "editor_injection", Title: fmt.Sprintf("Global npm cli.js is unusually large (%d bytes)", st.Size()),
				Path: cli, Details: "npm's lib/cli.js is normally a few hundred bytes; infected copies are 280 KB to 1 MB.",
				Remediation: "Compare with a fresh npm tarball; reinstall Node/npm if it differs."})
		}
	}
	return out
}

func (s *System) CheckHosts() []*F {
	var out []*F
	hf := s.P.HostsFile()
	for _, line := range strings.Split(h.ReadText(hf, 5<<20), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if (strings.HasPrefix(t, "0.0.0.0") || strings.HasPrefix(t, "127.0.0.1") || strings.HasPrefix(t, "::1")) && containsAny(t, s.I.MaliciousHosts...) {
			continue
		}
		if containsAny(t, "registry.npmjs.org", "github.com", "nodejs.org", "pypi.org") {
			out = append(out, &F{Severity: high, Category: "hosts_tampering", Title: "Hosts file redirects a package registry", Path: hf,
				Details: t, Remediation: "Edit " + hf + " and remove the line."})
		}
	}
	return out
}

func (s *System) CheckPortableRuntime() []*F {
	var out []*F
	if s.P.IsWindows() {
		for _, v := range []string{"Python3127", "Python312"} {
			p := filepath.Join(s.P.LocalAppData(), "Programs", "Python", v)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				if _, err := os.Stat(filepath.Join(p, "Lib", "site-packages", "pip")); err != nil {
					out = append(out, &F{Severity: high, Category: "stage4_python", Title: "Suspicious portable Python: " + p, Path: p,
						Details: "PolinRider stage 4 drops a portable interpreter here for OmniStealer.", Remediation: `rmdir /s /q "` + p + `" if you did not install it.`})
				}
			}
		}
		return out
	}
	rt := filepath.Join(s.P.LocalShare(), "runtimedev-link", "runtime")
	if st, err := os.Stat(rt); err == nil && st.IsDir() {
		out = append(out, &F{Severity: crit, Category: "stage4_runtime", Title: "RAT portable Node runtime", Path: rt,
			Remediation: `rm -rf "` + filepath.Dir(rt) + `"`, Meta: findings.Meta{Quarantine: true}})
	}
	return out
}

// Quick is the cheap behaviour pass the guard runs every few seconds.
func (s *System) Quick() []*F { return append(s.CheckProcesses(), s.CheckNetwork()...) }

func (s *System) ScanAll(repoInfected bool) []*F {
	var f []*F
	for _, c := range []func() []*F{s.CheckProcesses, s.CheckNetwork, s.CheckRAT, s.CheckCron, s.CheckSystemdUser,
		s.CheckXDGAutostart, s.CheckLaunchd, s.CheckWindowsTasks, s.CheckShellRC, s.CheckEditorInjection, s.CheckHosts, s.CheckPortableRuntime} {
		f = append(f, c()...)
	}
	f = append(f, s.CheckCredentials(repoInfected || findings.AnyAtLeast(f, high))...)
	return f
}
