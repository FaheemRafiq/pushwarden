package protect

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/iocs"
	"github.com/FaheemRafiq/pushwarden/internal/platform"
	"github.com/FaheemRafiq/pushwarden/internal/update"
)

// The C2 block must survive reboots and follow new indicators, and both need
// root. A small privileged job (systemd oneshot + timer, LaunchDaemon, or a
// SYSTEM scheduled task) runs `pushwarden protect --refresh` at boot and once a
// day. It reads only root-owned files: a user-writable iocs.json or binary
// must never drive a hosts-file edit or a firewall rule as root.

const (
	NetblockUnit  = "pushwarden-netblock"
	NetblockLabel = "com.pushwarden.netblock"
	NetblockTask  = "PushWarden NetBlock"
	SysDirEnv     = "PUSHWARDEN_SYSTEM_DIR" // tests only
)

// State is what the last refresh did; readable without root, so `status`
// can report the block for normal users.
type State struct {
	TS         string `json:"ts"`
	BootTime   int64  `json:"boot_time"`
	Persistent bool   `json:"persistent"`
	Mode       string `json:"mode"`
	IPs        int    `json:"ips"`
	Hosts      int    `json:"hosts"`
	IOCVersion string `json:"ioc_version"`
	Version    string `json:"version"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

// SystemDir is the root-owned directory for the privileged job's iocs.json and state.
func (n *NetBlocker) SystemDir() string {
	if n.SysDir != "" {
		return n.SysDir
	}
	if d := os.Getenv(SysDirEnv); d != "" {
		return d
	}
	switch {
	case n.P.IsWindows():
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "PushWarden")
	case n.P.IsMac():
		return "/Library/Application Support/PushWarden"
	}
	return "/etc/pushwarden"
}

// SystemBin is where the privileged copy of the program lives.
func (n *NetBlocker) SystemBin() string {
	switch {
	case n.P.IsWindows():
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			pf = `C:\Program Files`
		}
		return filepath.Join(pf, "PushWarden", "pushwarden.exe")
	case n.P.IsMac():
		return "/usr/local/libexec/pushwarden/pushwarden"
	}
	return "/usr/local/lib/pushwarden/pushwarden"
}

func (n *NetBlocker) statePath() string { return filepath.Join(n.SystemDir(), "netblock-state.json") }

// ReadState returns the last recorded state, if any.
func (n *NetBlocker) ReadState() (*State, bool) {
	b, err := os.ReadFile(n.statePath())
	if err != nil {
		return nil, false
	}
	var st State
	if json.Unmarshal(b, &st) != nil {
		return nil, false
	}
	return &st, true
}

func (n *NetBlocker) writeState(st State) {
	st.TS = time.Now().Format(time.RFC3339)
	st.BootTime = platform.BootTime()
	st.Version = Version
	b, _ := json.MarshalIndent(st, "", "  ")
	_ = os.MkdirAll(n.SystemDir(), 0o755)
	tmp := n.statePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, n.statePath())
	}
}

// Version is the program version, set by main (recorded in the state file).
var Version = "dev"

// ── job definitions (pure) ──────────────────────────────────────────────────

func NetblockService(bin string) string {
	return `[Unit]
Description=PushWarden: block PolinRider C2 servers at the firewall
After=network.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=` + shQuote(bin) + ` protect --refresh
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
`
}

func NetblockTimer() string {
	return `[Unit]
Description=PushWarden: refresh the C2 block daily

[Timer]
OnBootSec=15min
OnUnitActiveSec=1d
Persistent=true

[Install]
WantedBy=timers.target
`
}

func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func NetblockLaunchd(bin, log string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + NetblockLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEsc(bin) + `</string>
		<string>protect</string>
		<string>--refresh</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>86400</integer>
	<key>StandardOutPath</key>
	<string>` + xmlEsc(log) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEsc(log) + `</string>
</dict>
</plist>
`
}

func NetblockTaskXML(bin string) string {
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>PushWarden: block PolinRider C2 servers in Windows Firewall</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger>
    <CalendarTrigger><StartBoundary>2026-01-01T03:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author"><Exec><Command>` + xmlEsc(bin) + `</Command><Arguments>protect --refresh</Arguments></Exec></Actions>
</Task>
`
}

// ── install / refresh / uninstall (root) ────────────────────────────────────

func (n *NetBlocker) unitPaths() (service, timer string) {
	return "/etc/systemd/system/" + NetblockUnit + ".service", "/etc/systemd/system/" + NetblockUnit + ".timer"
}

const launchdPlist = "/Library/LaunchDaemons/" + NetblockLabel + ".plist"
const launchdLog = "/var/log/pushwarden-netblock.log"

// JobInstalled reports whether the privileged job is registered.
func (n *NetBlocker) JobInstalled() bool {
	switch {
	case n.P.IsLinux():
		_, timer := n.unitPaths()
		_, err := os.Stat(timer)
		return err == nil
	case n.P.IsMac():
		_, err := os.Stat(launchdPlist)
		return err == nil
	case n.P.IsWindows():
		rc, _, _ := n.sh("schtasks", "/Query", "/TN", NetblockTask)
		return rc == 0
	}
	return false
}

// systemIOCs loads the newer of the bundled indicators and the root-owned copy.
func (n *NetBlocker) systemIOCs() *iocs.IOCs {
	if i, err := iocs.Load(n.SystemDir()); err == nil {
		return i
	}
	i, _ := iocs.Load("")
	return i
}

// placeBinary returns the path the job should run: the current executable when
// it is already safe (root-owned, not writable by others), otherwise a copy.
func (n *NetBlocker) placeBinary(dry bool) (string, error) {
	src := platform.Exe()
	if src == "" {
		return "", fmt.Errorf("cannot locate the running executable")
	}
	if !n.P.IsWindows() && rootOwnedReadOnly(src) {
		return src, nil
	}
	dst := n.SystemBin()
	if dry {
		return dst, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return dst, nil
}

// PreviewInstall describes what InstallPersistent would do.
func (n *NetBlocker) PreviewInstall() string {
	bin, _ := n.placeBinary(true)
	var b strings.Builder
	fmt.Fprintf(&b, "would keep a root-owned copy of the indicators in %s\n", n.SystemDir())
	fmt.Fprintf(&b, "would run the block from %s\n", bin)
	switch {
	case n.P.IsLinux():
		svc, timer := n.unitPaths()
		fmt.Fprintf(&b, "would write %s and %s, enable the timer (boot + daily)\n", svc, timer)
	case n.P.IsMac():
		fmt.Fprintf(&b, "would write %s (RunAtLoad + daily)\n", launchdPlist)
	case n.P.IsWindows():
		fmt.Fprintf(&b, "would register scheduled task %q (SYSTEM, at boot + daily)\n", NetblockTask)
	}
	i := n.systemIOCs()
	fmt.Fprintf(&b, "would block %d IPs at the firewall and sinkhole %d hostnames (indicators %s)", len(i.MaliciousIPs), len(i.MaliciousHosts), i.Version)
	return b.String()
}

// InstallPersistent registers the job and applies the block once. Root only.
func (n *NetBlocker) InstallPersistent() (bool, string) {
	if !platform.IsAdmin() {
		return false, "needs root/Administrator"
	}
	if err := os.MkdirAll(n.SystemDir(), 0o755); err != nil {
		return false, err.Error()
	}
	bin, err := n.placeBinary(false)
	if err != nil {
		return false, "could not place the program: " + err.Error()
	}
	switch {
	case n.P.IsLinux():
		svc, timer := n.unitPaths()
		if err := os.WriteFile(svc, []byte(NetblockService(bin)), 0o644); err != nil {
			return false, err.Error()
		}
		if err := os.WriteFile(timer, []byte(NetblockTimer()), 0o644); err != nil {
			return false, err.Error()
		}
		n.sh("systemctl", "daemon-reload")
		if rc, _, se := n.sh("systemctl", "enable", "--now", NetblockUnit+".timer"); rc != 0 {
			return false, "systemctl enable failed: " + strings.TrimSpace(se)
		}
		n.sh("systemctl", "enable", NetblockUnit+".service")
	case n.P.IsMac():
		n.sh("launchctl", "bootout", "system/"+NetblockLabel)
		if err := os.WriteFile(launchdPlist, []byte(NetblockLaunchd(bin, launchdLog)), 0o644); err != nil {
			return false, err.Error()
		}
		if rc, _, se := n.sh("launchctl", "bootstrap", "system", launchdPlist); rc != 0 {
			if rc, _, se2 := n.sh("launchctl", "load", "-w", launchdPlist); rc != 0 {
				return false, "launchctl failed: " + strings.TrimSpace(se+" "+se2)
			}
		}
	case n.P.IsWindows():
		tmp := filepath.Join(n.SystemDir(), "netblock-task.xml")
		if err := os.WriteFile(tmp, utf16le(NetblockTaskXML(bin)), 0o644); err != nil {
			return false, err.Error()
		}
		rc, _, se := n.sh("schtasks", "/Create", "/TN", NetblockTask, "/XML", tmp, "/F")
		os.Remove(tmp)
		if rc != 0 {
			return false, "schtasks failed: " + strings.TrimSpace(se)
		}
	default:
		return false, "unsupported platform"
	}
	ok, msg := n.Refresh()
	return ok, "persistent C2 block installed (" + bin + "); " + msg
}

// utf16le encodes text with a BOM, the encoding schtasks expects for /XML.
func utf16le(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, r := range s {
		if r > 0xFFFF {
			r = '?'
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// Refresh applies the block from the root-owned indicators, records the state,
// then fetches newer indicators and re-applies if they changed. The apply comes
// first so a boot without network still ends up blocked.
func (n *NetBlocker) Refresh() (bool, string) {
	n.I = n.systemIOCs()
	apply := func() (bool, State) {
		ok1 := n.BlockIPs()
		ok2 := n.SinkholeHosts()
		st := State{Persistent: n.JobInstalled(), Mode: n.mode, IPs: len(n.I.MaliciousIPs), Hosts: len(n.I.MaliciousHosts),
			IOCVersion: n.I.Version, OK: ok1 || ok2}
		if !ok1 {
			st.Error = "firewall rules could not be applied"
		}
		if !ok2 {
			st.Error = strings.TrimPrefix(st.Error+"; hosts file could not be written", "; ")
		}
		n.writeState(st)
		return st.OK, st
	}
	ok, st := apply()
	msg := fmt.Sprintf("%d IPs blocked, %d hosts sinkholed (indicators %s)", st.IPs, st.Hosts, st.IOCVersion)
	if !ok {
		return false, st.Error
	}
	if blob, ni, err := update.FetchIOCs(""); err == nil && ni.Version > n.I.Version {
		dest := iocs.UserPath(n.SystemDir())
		if os.WriteFile(dest+".tmp", blob, 0o644) == nil && os.Rename(dest+".tmp", dest) == nil {
			n.I = ni
			ok, st = apply()
			msg = fmt.Sprintf("%d IPs blocked, %d hosts sinkholed (indicators updated to %s)", st.IPs, st.Hosts, st.IOCVersion)
		}
	}
	return ok, msg
}

// UninstallPersistent removes the job, the rules, the hosts block and the state.
func (n *NetBlocker) UninstallPersistent() (bool, string) {
	if !platform.IsAdmin() {
		return false, "needs root/Administrator"
	}
	switch {
	case n.P.IsLinux():
		svc, timer := n.unitPaths()
		n.sh("systemctl", "disable", "--now", NetblockUnit+".timer")
		n.sh("systemctl", "disable", NetblockUnit+".service")
		os.Remove(svc)
		os.Remove(timer)
		n.sh("systemctl", "daemon-reload")
	case n.P.IsMac():
		n.sh("launchctl", "bootout", "system/"+NetblockLabel)
		os.Remove(launchdPlist)
	case n.P.IsWindows():
		n.sh("schtasks", "/Delete", "/TN", NetblockTask, "/F")
	}
	n.UnblockIPs()
	n.UnsinkholeHosts()
	os.Remove(n.statePath())
	os.Remove(iocs.UserPath(n.SystemDir()))
	if bin := n.SystemBin(); filepath.Dir(bin) != "" {
		os.Remove(bin)
		os.Remove(filepath.Dir(bin))
	}
	os.Remove(n.SystemDir())
	return true, "persistent C2 block removed"
}

// Describe is the one-line firewall status for `pushwarden status`.
func (n *NetBlocker) Describe() string {
	st, ok := n.ReadState()
	job := n.JobInstalled()
	hint := "run: pushwarden protect --install (asks for administrator rights)"
	switch {
	case ok && st.Persistent && job:
		age := "unknown age"
		if t, err := time.Parse(time.RFC3339, st.TS); err == nil {
			age = "applied " + humanAge(time.Since(t)) + " ago"
		}
		s := fmt.Sprintf("active (persistent; %d IPs, %d hosts; %s; indicators %s)", st.IPs, st.Hosts, age, st.IOCVersion)
		if !st.OK {
			s += " - last refresh failed: " + st.Error
		}
		if platform.IsAdmin() && n.Status() == "not active" {
			s += " - RULES MISSING; run: pushwarden protect --refresh"
		}
		return s
	case ok && st.BootTime != 0 && st.BootTime == platform.BootTime():
		return fmt.Sprintf("active until reboot (%d IPs, %d hosts) - make it permanent: pushwarden protect --install", st.IPs, st.Hosts)
	case ok:
		return "not active (rules from a previous boot were lost) - " + hint
	case platform.IsAdmin() && n.Status() != "not active":
		return n.Status() + " (not persistent) - " + hint
	}
	return "not active - " + hint
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
