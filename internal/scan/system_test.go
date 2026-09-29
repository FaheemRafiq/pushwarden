// threatscan:allow-signatures
package scan

import (
	"strings"
	"testing"

	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

// The exact command line GNOME's sandboxed image loader ran on Fedora 44; the
// guard alerted on it every 5 s because "\.cache/font" matched ".cache/fontconfig".
const glycinBwrap = "bwrap --unshare-all --die-with-parent --chdir / --ro-bind /usr /usr --dev /dev " +
	"--ro-bind-try /etc/ld.so.cache /etc/ld.so.cache --tmpfs /tmp-home --clearenv --setenv HOME /tmp-home " +
	"--symlink /usr/lib /lib --ro-bind-try /etc/fonts/conf.d /etc/fonts/conf.d " +
	"--ro-bind-try /home/faheem/.cache/fontconfig /home/faheem/.cache/fontconfig " +
	"--ro-bind-try /home/faheem/.cache/font /home/faheem/.cache/font " +
	"--seccomp 49 /usr/libexec/glycin-loaders/2+/glycin-image-rs --dbus-fd 48"

func TestMatchProcess(t *testing.T) {
	s := &System{P: platform.New(), UI: ui.New(true, true), I: testIOCs(t)}
	clean := map[string]string{
		"bwrap":      glycinBwrap,
		"fc-cache":   "fc-cache -f /home/faheem/.cache/fontconfig",
		"node":       "node /home/faheem/proj/server.js",
		"chrome":     "chrome --user-data-dir=/home/x/.cache/fontconfig-cache",
		"flatpak":    "flatpak run --filesystem=/home/x/.cache/font/ org.example.App",
		"zenity":     "zenity --info --text global['_V']='8-st17' /home/x/.cache/font/a.js",
		"threatscan": "threatscan scan /home/x/.cache/font/",
	}
	for name, cmd := range clean {
		if re, _ := s.matchProcess(name, cmd); re != nil {
			t.Errorf("%s: false positive on %q via %s", name, cmd, re)
		}
	}
	bad := map[string]string{
		"node":   "node /home/faheem/.cache/font/loader.js",
		"sh":     "sh -c 'cd ~/.cache/font && node index.js'",
		"python": "python3 /home/x/.cache/font",
		"node2":  "node -e \"global['!']='A10-010';eval(atob('aGk='))\"",
		"bwrap":  "bwrap --ro-bind /usr /usr node /home/x/.cache/font/loader.js",
	}
	for name, cmd := range bad {
		if re, _ := s.matchProcess(name, cmd); re == nil {
			t.Errorf("%s: missed %q", name, cmd)
		}
	}
	if re, kill := s.matchProcess("node", "node -e \"global['_V']='8-st17'\""); re == nil || kill == nil {
		t.Fatal("kill-list indicator should be killable")
	}
	if _, kill := s.matchProcess("node", "node /home/x/.cache/font/l.js"); kill != nil {
		t.Fatal(".cache/font alone must not be on the kill list")
	}
}

func TestStripSandboxMounts(t *testing.T) {
	got := stripSandboxMounts("bwrap", glycinBwrap)
	for _, keep := range []string{"bwrap", "--unshare-all", "glycin-image-rs"} {
		if !contains(got, keep) {
			t.Errorf("stripped too much: %q missing from %q", keep, got)
		}
	}
	for _, gone := range []string{".cache/font", "/etc/fonts", "/usr/lib /lib"} {
		if contains(got, gone) {
			t.Errorf("mount spec %q still present in %q", gone, got)
		}
	}
	if stripSandboxMounts("node", glycinBwrap) != glycinBwrap {
		t.Error("only sandbox wrappers are rewritten")
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestProcessAndC2FindingsCarryEvidence(t *testing.T) {
	s := &System{P: platform.New(), UI: ui.New(true, true), I: testIOCs(t)}
	re, kill := s.matchProcess("node", "node -e \"global['_V']='8-st17'\"")
	f := processFinding(platform.Proc{PID: 42, Name: "node", Cmd: "node -e \"global['_V']='8-st17'\""}, re, kill, false)
	if !f.Meta.Kill || len(f.Meta.Evidence) != 4 || !strings.Contains(f.Meta.Evidence[1], "strict kill marker") || !strings.Contains(f.Remediation, "kill -9 42") {
		t.Fatalf("%+v", f)
	}
	re, kill = s.matchProcess("node", "node /home/x/.cache/font/l.js")
	f = processFinding(platform.Proc{PID: 43, Name: "node", Cmd: "node /home/x/.cache/font/l.js"}, re, kill, true)
	if f.Meta.Kill || !strings.Contains(f.Meta.Evidence[1], "not auto-killed") || !strings.Contains(f.Remediation, "taskkill /PID 43") {
		t.Fatalf("%+v", f)
	}
	c := c2Finding(platform.Conn{IP: "1.2.3.4", Port: 443, PID: 9}, "node /tmp/.x/a.js", "2026.09.28.2", "linux")
	if !c.Meta.Kill || c.Meta.Cmd != "node /tmp/.x/a.js" || len(c.Meta.Evidence) != 3 || !strings.Contains(c.Meta.Evidence[2], "pid 9 node") {
		t.Fatalf("%+v", c)
	}
	if c := c2Finding(platform.Conn{IP: "1.2.3.4", Port: 443}, "", "v", "darwin"); c.Meta.Kill || !strings.Contains(c.Meta.Evidence[2], "unknown") || !strings.Contains(c.Remediation, "pfctl") {
		t.Fatalf("%+v", c)
	}
}
