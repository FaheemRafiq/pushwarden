package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/platform"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	t.Setenv("THREATSCAN_INSTALL_DIR", filepath.Join(t.TempDir(), "install dir"))
	t.Setenv("THREATSCAN_HOME", t.TempDir())
	p := platform.New()
	p.Home = t.TempDir()
	return New(p, p.DataDir())
}

func TestPreview(t *testing.T) {
	m := testManager(t)
	pv := m.Preview()
	if !strings.Contains(pv, m.Exe()) || !strings.Contains(pv, "guard") {
		t.Fatalf("preview lacks binary path or guard:\n%s", pv)
	}
	if _, err := os.Stat(m.P.InstallDir()); err == nil {
		t.Fatal("Preview must not create the install dir")
	}
}

func TestSystemdUnit(t *testing.T) {
	u := SystemdUnit([]string{"/home/a b/.local/share/threatscan/threatscan", "guard"}, "/home/a/.threatscan/guard.log", "/tmp/th")
	for _, want := range []string{"Restart=always", "Nice=10", "IOSchedulingClass=idle", "WantedBy=default.target",
		"ExecStart='/home/a b/.local/share/threatscan/threatscan' guard", "Environment=THREATSCAN_HOME=/tmp/th",
		"StandardOutput=append:/home/a/.threatscan/guard.log"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if strings.Contains(u, "After=default.target") {
		t.Error("unit has After=default.target (ordering cycle)")
	}
	if strings.Contains(SystemdUnit([]string{"/x", "guard"}, "/l", ""), "THREATSCAN_HOME") {
		t.Error("THREATSCAN_HOME set although empty")
	}
}

func TestLaunchdPlist(t *testing.T) {
	pl := LaunchdPlist([]string{"/Users/a/Library/Application Support/ThreatScan/threatscan", "guard"}, "/Users/a/.threatscan/guard.log", "", launchdPath())
	for _, want := range []string{"<string>com.threatscan.guard</string>", "<key>RunAtLoad</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<true/>", "<integer>10</integer>", "<string>Background</string>",
		"/opt/homebrew/bin", "<string>guard</string>"} {
		if !strings.Contains(pl, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
}

func TestVBSLauncher(t *testing.T) {
	v := vbsLauncher([]string{`C:\Users\a b\AppData\Local\Programs\ThreatScan\threatscan.exe`, "guard"})
	if !strings.Contains(v, `s.Run """C:\Users\a b\AppData\Local\Programs\ThreatScan\threatscan.exe"" guard", 0, False`) {
		t.Fatal(v)
	}
}

func TestPlaceBinary(t *testing.T) {
	m := testManager(t)
	copied, err := m.PlaceBinary()
	if err != nil || !copied {
		t.Fatalf("first PlaceBinary: copied=%v err=%v", copied, err)
	}
	a, _ := os.ReadFile(m.Src)
	b, _ := os.ReadFile(m.Exe())
	if string(a) != string(b) {
		t.Fatal("installed binary differs from the source")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(m.Exe()); st.Mode()&0o111 == 0 {
			t.Fatal("installed binary is not executable")
		}
	}
	st1, _ := os.Stat(m.Exe())
	copied, err = m.PlaceBinary()
	if err != nil || copied {
		t.Fatalf("second PlaceBinary should be a no-op: copied=%v err=%v", copied, err)
	}
	st2, _ := os.Stat(m.Exe())
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("second PlaceBinary rewrote the file")
	}
	// running from the install dir itself is also a no-op
	m.Src = m.Exe()
	if copied, err = m.PlaceBinary(); err != nil || copied {
		t.Fatalf("PlaceBinary from install dir: copied=%v err=%v", copied, err)
	}
}

func TestLinkCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH is edited in the registry on Windows")
	}
	m := testManager(t)
	link := filepath.Join(m.P.Home, ".local", "bin", "threatscan")
	if msg := m.LinkCLI(true); !strings.Contains(msg, "would link") {
		t.Fatal(msg)
	}
	if _, err := os.Lstat(link); err == nil {
		t.Fatal("dry run created the link")
	}
	m.LinkCLI(false)
	if cur, _ := os.Readlink(link); cur != m.Exe() {
		t.Fatalf("link points at %q", cur)
	}
	// an old symlink (v5 venv) is replaced
	os.Remove(link)
	os.Symlink("/old/venv/bin/threatscan", link)
	m.LinkCLI(false)
	if cur, _ := os.Readlink(link); cur != m.Exe() {
		t.Fatalf("old symlink not replaced: %q", cur)
	}
	m.UnlinkCLI()
	if _, err := os.Lstat(link); err == nil {
		t.Fatal("UnlinkCLI left the link")
	}
	// a real file is a v5 shim: keep it
	os.WriteFile(link, []byte("#!/bin/sh\n"), 0o755)
	if msg := m.LinkCLI(false); !strings.Contains(msg, "kept") {
		t.Fatal(msg)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("v5 shim was replaced")
	}
	m.UnlinkCLI()
	if _, err := os.Lstat(link); err != nil {
		t.Fatal("UnlinkCLI removed a file it does not own")
	}
}
