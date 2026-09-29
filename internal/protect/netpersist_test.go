package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
)

func TestJobDefinitions(t *testing.T) {
	svc := NetblockService("/usr/local/lib/threatscan/threatscan")
	for _, want := range []string{"Type=oneshot", "ExecStart=/usr/local/lib/threatscan/threatscan protect --refresh", "WantedBy=multi-user.target"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service lacks %q", want)
		}
	}
	if s := NetblockService("/path with space/threatscan"); !strings.Contains(s, "'/path with space/threatscan' protect") {
		t.Error("unquoted path in unit")
	}
	tm := NetblockTimer()
	for _, want := range []string{"OnBootSec=15min", "OnUnitActiveSec=1d", "Persistent=true", "WantedBy=timers.target"} {
		if !strings.Contains(tm, want) {
			t.Errorf("timer lacks %q", want)
		}
	}
	pl := NetblockLaunchd("/usr/local/libexec/threatscan/threatscan", "/var/log/x.log")
	for _, want := range []string{"<string>" + NetblockLabel + "</string>", "<key>RunAtLoad</key>", "<integer>86400</integer>", "<string>--refresh</string>"} {
		if !strings.Contains(pl, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
	x := NetblockTaskXML(`C:\Program Files\ThreatScan\threatscan.exe`)
	for _, want := range []string{"S-1-5-18", "HighestAvailable", "<BootTrigger>", "<DaysInterval>1</DaysInterval>", "<Arguments>protect --refresh</Arguments>"} {
		if !strings.Contains(x, want) {
			t.Errorf("task xml lacks %q", want)
		}
	}
	if b := utf16le("A"); len(b) != 4 || b[0] != 0xFF || b[1] != 0xFE || b[2] != 'A' {
		t.Errorf("utf16le: %v", b)
	}
}

func TestStateAndDescribe(t *testing.T) {
	dir := t.TempDir()
	nb := &NetBlocker{P: &platform.Info{OS: "linux"}, SysDir: dir}
	if _, ok := nb.ReadState(); ok {
		t.Fatal("no state yet")
	}
	if d := nb.Describe(); !strings.HasPrefix(d, "not active") || !strings.Contains(d, "protect --install") {
		t.Fatalf("empty: %q", d)
	}
	// active but not persistent, same boot
	nb.writeState(State{Persistent: false, IPs: 25, Hosts: 15, IOCVersion: "v1", OK: true})
	if d := nb.Describe(); !strings.HasPrefix(d, "active until reboot") {
		t.Fatalf("until reboot: %q", d)
	}
	// previous boot
	st, _ := nb.ReadState()
	st.BootTime = 1
	b, _ := os.ReadFile(nb.statePath())
	_ = b
	nb.writeState(*st)
	st2, _ := nb.ReadState()
	st2.BootTime = 1
	// writeState overrides boot time, so write the file directly
	os.WriteFile(nb.statePath(), []byte(`{"ts":"2026-01-01T00:00:00Z","boot_time":1,"persistent":false,"ips":25,"hosts":15,"ok":true}`), 0o644)
	if d := nb.Describe(); !strings.Contains(d, "previous boot") {
		t.Fatalf("lost: %q", d)
	}
	// persistent with the job registered (fake the timer file through an override dir)
	nb.writeState(State{Persistent: true, IPs: 25, Hosts: 15, IOCVersion: "v2", OK: true, Mode: "nftables"})
	st3, _ := nb.ReadState()
	if st3.Version != Version || st3.Mode != "nftables" || time.Since(mustTime(st3.TS)) > time.Minute {
		t.Fatalf("%+v", st3)
	}
	// JobInstalled looks at /etc/systemd; without it Describe must not claim persistence
	if d := nb.Describe(); strings.HasPrefix(d, "active (persistent") && !nb.JobInstalled() {
		t.Fatalf("claims persistence without the job: %q", d)
	}
	if humanAge(90*time.Second) != "1m" || humanAge(3*24*time.Hour) != "3d" {
		t.Fatal("humanAge")
	}
}

func mustTime(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

func TestSystemIOCsIgnoreUserCopy(t *testing.T) {
	sys := t.TempDir()
	user := t.TempDir()
	bundled, _ := iocs.Load("")
	// a "newer" user file must not be picked up by the privileged job
	os.WriteFile(filepath.Join(user, "iocs.json"), []byte(`{"version":"9999.01.01.1"}`), 0o600)
	t.Setenv("THREATSCAN_HOME", user)
	nb := &NetBlocker{P: platform.New(), SysDir: sys}
	if got := nb.systemIOCs(); got.Version != bundled.Version {
		t.Fatalf("privileged job read %s, want bundled %s", got.Version, bundled.Version)
	}
	if nb.SystemDir() != sys {
		t.Fatal(nb.SystemDir())
	}
	t.Setenv(SysDirEnv, filepath.Join(sys, "env"))
	if (&NetBlocker{P: platform.New()}).SystemDir() != filepath.Join(sys, "env") {
		t.Fatal("env override")
	}
	pv := nb.PreviewInstall()
	if !strings.Contains(pv, "would block") || !strings.Contains(pv, sys) {
		t.Fatalf("preview: %s", pv)
	}
	if ents, _ := os.ReadDir(sys); len(ents) != 0 {
		t.Fatal("preview wrote files")
	}
}

func TestSystemPaths(t *testing.T) {
	for _, c := range []struct{ os, dir, bin string }{
		{"linux", "/etc/threatscan", "/usr/local/lib/threatscan/threatscan"},
		{"darwin", "/Library/Application Support/ThreatScan", "/usr/local/libexec/threatscan/threatscan"},
	} {
		nb := &NetBlocker{P: &platform.Info{OS: c.os}}
		os.Unsetenv(SysDirEnv)
		if nb.SystemDir() != c.dir || nb.SystemBin() != c.bin {
			t.Errorf("%s: %s %s", c.os, nb.SystemDir(), nb.SystemBin())
		}
	}
}
