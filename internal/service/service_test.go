package service

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/FaheemRafiq/pushwarden/internal/platform"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	t.Setenv("PUSHWARDEN_INSTALL_DIR", filepath.Join(t.TempDir(), "install dir"))
	t.Setenv("PUSHWARDEN_HOME", t.TempDir())
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
	u := SystemdUnit([]string{"/home/a b/.local/share/pushwarden/pushwarden", "guard"}, "/home/a/.pushwarden/guard.log", "/tmp/th")
	for _, want := range []string{"Restart=always", "Nice=10", "IOSchedulingClass=idle", "WantedBy=default.target",
		"ExecStart='/home/a b/.local/share/pushwarden/pushwarden' guard", "Environment=PUSHWARDEN_HOME=/tmp/th",
		"StandardOutput=append:/home/a/.pushwarden/guard.log"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if strings.Contains(u, "After=default.target") {
		t.Error("unit has After=default.target (ordering cycle)")
	}
	if strings.Contains(SystemdUnit([]string{"/x", "guard"}, "/l", ""), "PUSHWARDEN_HOME") {
		t.Error("PUSHWARDEN_HOME set although empty")
	}
}

func TestLaunchdPlist(t *testing.T) {
	pl := LaunchdPlist([]string{"/Users/a/Library/Application Support/PushWarden/pushwarden", "guard"}, "/Users/a/.pushwarden/guard.log", "", launchdPath())
	for _, want := range []string{"<string>com.pushwarden.guard</string>", "<key>RunAtLoad</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<true/>", "<integer>10</integer>", "<string>Background</string>",
		"/opt/homebrew/bin", "<string>guard</string>"} {
		if !strings.Contains(pl, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
}

func TestVBSLauncher(t *testing.T) {
	v := vbsLauncher([]string{`C:\Users\a b\AppData\Local\Programs\PushWarden\pushwarden.exe`, "guard"})
	if !strings.Contains(v, `s.Run """C:\Users\a b\AppData\Local\Programs\PushWarden\pushwarden.exe"" guard", 0, False`) {
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
	link := filepath.Join(m.P.Home, ".local", "bin", "pushwarden")
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
	os.Symlink("/old/venv/bin/pushwarden", link)
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

func TestPlaceBinaryKeepsNewerInstalled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as the installed binary")
	}
	m := testManager(t)
	os.MkdirAll(m.P.InstallDir(), 0o755)
	newer := "#!/bin/sh\necho 'PushWarden 99.0.0'\n"
	os.WriteFile(m.Exe(), []byte(newer), 0o755)
	if v := InstalledVersion(m.Exe()); v != "99.0.0" {
		t.Fatalf("InstalledVersion = %q", v)
	}
	m.Version = "0.1.0"
	copied, err := m.PlaceBinary()
	var e *ErrNewerInstalled
	if copied || !errors.As(err, &e) || e.Installed != "99.0.0" {
		t.Fatalf("copied=%v err=%v", copied, err)
	}
	if b, _ := os.ReadFile(m.Exe()); string(b) != newer {
		t.Fatal("newer binary was overwritten")
	}
	// an older installed binary is replaced
	os.WriteFile(m.Exe(), []byte("#!/bin/sh\necho 'PushWarden 0.0.9'\n"), 0o755)
	if copied, err := m.PlaceBinary(); !copied || err != nil {
		t.Fatalf("older binary not replaced: %v %v", copied, err)
	}
	// so is the withdrawn 6.0.0 line, although its number is higher
	for _, v := range []string{"6.0.0", "6.0.0-rc1", "6.0.0-dev"} {
		os.WriteFile(m.Exe(), []byte("#!/bin/sh\necho 'PushWarden "+v+"'\n"), 0o755)
		if copied, err := m.PlaceBinary(); !copied || err != nil {
			t.Fatalf("withdrawn %s not replaced: %v %v", v, copied, err)
		}
	}
}

func TestLinkCLIAddsLocalBinToShellPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH is edited in the registry on Windows")
	}
	m := testManager(t)
	t.Setenv("PATH", "/usr/bin:/bin")
	os.WriteFile(filepath.Join(m.P.Home, ".zshrc"), []byte("alias ll='ls -l'"), 0o644) // no trailing newline
	os.WriteFile(filepath.Join(m.P.Home, ".bashrc"), []byte("export PATH=\"$HOME/.local/bin:$PATH\"\n"), 0o644)
	msg := m.LinkCLI(false)
	if !strings.Contains(msg, "added ~/.local/bin to PATH in ~/.zshrc") || strings.Contains(msg, ".bashrc") {
		t.Fatalf("msg: %s", msg)
	}
	z, _ := os.ReadFile(filepath.Join(m.P.Home, ".zshrc"))
	if !strings.HasPrefix(string(z), "alias ll='ls -l'\n") || strings.Count(string(z), ".local/bin") != 1 || !strings.Contains(string(z), "# added by pushwarden install") {
		t.Fatalf("zshrc:\n%s", z)
	}
	// second install: nothing added again
	if msg := m.LinkCLI(false); strings.Contains(msg, "added") {
		t.Fatalf("second run added again: %s", msg)
	}
	// already on PATH: untouched
	os.Remove(filepath.Join(m.P.Home, ".zshrc"))
	t.Setenv("PATH", filepath.Join(m.P.Home, ".local", "bin")+":/usr/bin")
	m.LinkCLI(false)
	if _, err := os.Stat(filepath.Join(m.P.Home, ".zshrc")); err == nil {
		t.Fatal("wrote .zshrc although ~/.local/bin is on PATH")
	}
}

// Upgrading from a build that linked ~/.local/bin without touching the PATH:
// the link already exists, and the PATH line must still be added.
func TestLinkCLIAddsPathWhenLinkAlreadyExists(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH is edited in the registry on Windows")
	}
	m := testManager(t)
	t.Setenv("PATH", "/usr/bin:/bin")
	bin := filepath.Join(m.P.Home, ".local", "bin")
	os.MkdirAll(bin, 0o755)
	os.Symlink(m.Exe(), filepath.Join(bin, "pushwarden"))
	msg := m.LinkCLI(false)
	if !strings.Contains(msg, "added ~/.local/bin to PATH") {
		t.Fatalf("existing link skipped the PATH step: %s", msg)
	}
	if b, _ := os.ReadFile(filepath.Join(m.P.Home, ".zshrc")); !strings.Contains(string(b), ".local/bin") {
		t.Fatal("no PATH line written")
	}
}
