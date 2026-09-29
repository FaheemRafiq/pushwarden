// Package platform abstracts OS paths, processes, sockets and commands.
package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

type Info struct {
	OS       string // linux | darwin | windows
	Hostname string
	Arch     string
	Home     string
}

func New() *Info {
	h, _ := os.Hostname()
	home, _ := os.UserHomeDir()
	return &Info{OS: runtime.GOOS, Hostname: h, Arch: runtime.GOARCH, Home: home}
}

func (p *Info) IsLinux() bool   { return p.OS == "linux" }
func (p *Info) IsMac() bool     { return p.OS == "darwin" }
func (p *Info) IsWindows() bool { return p.OS == "windows" }

func (p *Info) DisplayName() string {
	if hi, err := host.Info(); err == nil {
		switch p.OS {
		case "darwin":
			return "macOS " + hi.PlatformVersion
		case "windows":
			return strings.TrimSpace(hi.Platform + " " + hi.PlatformVersion)
		default:
			return "Linux " + hi.KernelVersion
		}
	}
	return p.OS
}

// DataDir is ~/.threatscan (override with THREATSCAN_HOME), shared with the Python v5 build.
func (p *Info) DataDir() string {
	if d := os.Getenv("THREATSCAN_HOME"); d != "" {
		return d
	}
	return filepath.Join(p.Home, ".threatscan")
}

// InstallDir is the per-user, user-writable location the binary runs from.
func (p *Info) InstallDir() string {
	if d := os.Getenv("THREATSCAN_INSTALL_DIR"); d != "" {
		return d
	}
	switch p.OS {
	case "windows":
		return filepath.Join(p.LocalAppData(), "Programs", "ThreatScan")
	case "darwin":
		return filepath.Join(p.Home, "Library", "Application Support", "ThreatScan")
	default:
		return filepath.Join(p.Home, ".local", "share", "threatscan")
	}
}

func (p *Info) ExeName() string {
	if p.IsWindows() {
		return "threatscan.exe"
	}
	return "threatscan"
}

func (p *Info) LocalAppData() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	return filepath.Join(p.Home, "AppData", "Local")
}

func (p *Info) AppData() string {
	if v := os.Getenv("APPDATA"); v != "" {
		return v
	}
	return filepath.Join(p.Home, "AppData", "Roaming")
}

func (p *Info) LocalShare() string {
	switch p.OS {
	case "windows":
		return p.LocalAppData()
	case "darwin":
		return filepath.Join(p.Home, "Library", "Application Support")
	}
	return filepath.Join(p.Home, ".local", "share")
}

func (p *Info) ConfigDir() string {
	if p.IsWindows() {
		return p.AppData()
	}
	return filepath.Join(p.Home, ".config")
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }
func isDir(path string) bool  { st, err := os.Stat(path); return err == nil && st.IsDir() }

func (p *Info) ShellRCFiles() []string {
	var out []string
	for _, n := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".config/fish/config.fish",
		"Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1", "Documents/PowerShell/Microsoft.PowerShell_profile.ps1"} {
		f := filepath.Join(p.Home, filepath.FromSlash(n))
		if exists(f) {
			out = append(out, f)
		}
	}
	return out
}

func (p *Info) CredentialFiles() []string {
	var out []string
	for _, n := range []string{".npmrc", ".git-credentials", ".netrc", "_netrc", ".config/gh/hosts.yml", ".config/hub",
		".docker/config.json", ".aws/credentials", ".yarnrc", ".yarnrc.yml", ".pypirc", ".config/runtimedev-link/agent.env"} {
		f := filepath.Join(p.Home, filepath.FromSlash(n))
		if exists(f) {
			out = append(out, f)
		}
	}
	return out
}

func (p *Info) EditorDirs() []string {
	c := []string{".vscode/extensions", ".cursor/extensions", ".vscode-oss/extensions", ".windsurf/extensions"}
	var d []string
	for _, x := range c {
		d = append(d, filepath.Join(p.Home, filepath.FromSlash(x)))
	}
	switch p.OS {
	case "linux":
		d = append(d, filepath.Join(p.Home, ".config/discord"), filepath.Join(p.Home, ".config/GitHub Desktop"))
	case "darwin":
		d = append(d, filepath.Join(p.LocalShare(), "discord"), filepath.Join(p.LocalShare(), "GitHub Desktop"))
	case "windows":
		d = append(d, filepath.Join(p.AppData(), "discord"), filepath.Join(p.LocalAppData(), "GitHubDesktop"))
	}
	var out []string
	for _, x := range d {
		if isDir(x) {
			out = append(out, x)
		}
	}
	return out
}

// EditorSettings maps editor label -> user settings.json for every VS Code-family editor present.
func (p *Info) EditorSettings() map[string]string {
	names := [][2]string{{"VS Code", "Code"}, {"VS Code Insiders", "Code - Insiders"}, {"VSCodium", "VSCodium"},
		{"Cursor", "Cursor"}, {"Windsurf", "Windsurf"}, {"Positron", "Positron"}}
	out := map[string]string{}
	for _, n := range names {
		var base string
		switch p.OS {
		case "windows":
			base = filepath.Join(p.AppData(), n[1])
		case "darwin":
			base = filepath.Join(p.Home, "Library", "Application Support", n[1])
		default:
			base = filepath.Join(p.Home, ".config", n[1])
		}
		if isDir(base) {
			out[n[0]] = filepath.Join(base, "User", "settings.json")
		}
	}
	return out
}

func (p *Info) HostsFile() string {
	if p.IsWindows() {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

func (p *Info) CommonProjectDirs() []string {
	names := []string{"projects", "Projects", "dev", "Dev", "code", "Code", "work", "src", "repos",
		"Documents/projects", "Documents/dev", "Documents/code", "Documents/GitHub",
		"Desktop/projects", "Desktop/dev", "Developer", "Coding", "workspace", "www", "sites",
		"source", "source/repos", "git", "GitHub", "Downloads", "Desktop"}
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		d := filepath.Join(p.Home, filepath.FromSlash(n))
		if isDir(d) {
			real, _ := filepath.EvalSymlinks(d)
			if real == "" {
				real = d
			}
			if !seen[strings.ToLower(real)] {
				seen[strings.ToLower(real)] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// ── commands ────────────────────────────────────────────────────────────────

// Run executes a command with a timeout and returns stdout ("" on error).
func (p *Info) Run(timeout time.Duration, name string, args ...string) string {
	_, out, _ := p.RunRC(timeout, name, args...)
	return out
}

// RunRC executes a command and returns (exit code, stdout, stderr).
func (p *Info) RunRC(timeout time.Duration, name string, args ...string) (int, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), so.String(), se.String()
		}
		return 127, so.String(), err.Error()
	}
	return 0, so.String(), se.String()
}

// RunInput is RunRC with stdin.
func (p *Info) RunInput(timeout time.Duration, input string, name string, args ...string) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	cmd.Stdin = strings.NewReader(input)
	var se strings.Builder
	cmd.Stderr = &se
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), se.String()
		}
		return 127, err.Error()
	}
	return 0, ""
}

// ── live system ─────────────────────────────────────────────────────────────

type Proc struct {
	PID  int
	Name string
	Cmd  string
}

func (p *Info) Processes() []Proc {
	ps, err := process.Processes()
	if err != nil {
		return nil
	}
	out := make([]Proc, 0, len(ps))
	for _, pr := range ps {
		cmd, err := pr.Cmdline()
		if err != nil || cmd == "" {
			continue
		}
		name, _ := pr.Name()
		out = append(out, Proc{PID: int(pr.Pid), Name: name, Cmd: cmd})
	}
	return out
}

type Conn struct {
	IP   string
	Port uint32
	PID  int
}

// Connections returns established/connecting TCP sockets with their owner PID.
func (p *Info) Connections() []Conn {
	cs, err := gnet.Connections("tcp")
	if err != nil {
		return nil
	}
	var out []Conn
	for _, c := range cs {
		if c.Raddr.IP == "" || strings.HasPrefix(c.Raddr.IP, "127.") || c.Raddr.IP == "::1" {
			continue
		}
		if c.Status != "ESTABLISHED" && c.Status != "SYN_SENT" {
			continue
		}
		out = append(out, Conn{IP: c.Raddr.IP, Port: c.Raddr.Port, PID: int(c.Pid)})
	}
	return out
}

func (p *Info) Kill(pid int) bool {
	if pid <= 0 || pid == os.Getpid() {
		return false
	}
	if p.IsWindows() {
		rc, _, _ := p.RunRC(20*time.Second, "taskkill", "/PID", itoa(pid), "/F", "/T")
		return rc == 0
	}
	pr, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return pr.Kill() == nil
}

func itoa(i int) string { return strconv.Itoa(i) }

// BootTime is the host boot time as a unix timestamp (0 when unknown).
func BootTime() int64 {
	if t, err := host.BootTime(); err == nil {
		return int64(t)
	}
	return 0
}

// Exe returns the path of the running executable (symlinks resolved).
func Exe() string {
	e, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(e); err == nil {
		return r
	}
	return e
}
