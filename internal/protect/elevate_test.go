package protect

import (
	"errors"
	"strings"
	"testing"

	"github.com/FaheemRafiq/pushwarden/internal/platform"
)

func TestElevateCommand(t *testing.T) {
	have := func(bins ...string) func(string) (string, error) {
		return func(b string) (string, error) {
			for _, x := range bins {
				if x == b {
					return "/usr/bin/" + b, nil
				}
			}
			return "", errors.New("nope")
		}
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	args := []string{"protect", "--install"}

	mac := ElevateCommand(&platform.Info{OS: "darwin"}, "/Users/x/Library/Application Support/PushWarden/pushwarden", args, true, have(), env(nil), false)
	if len(mac) != 1 || mac[0][0] != "osascript" || !strings.Contains(mac[0][2], "with administrator privileges") ||
		!strings.Contains(mac[0][2], `'/Users/x/Library/Application Support/PushWarden/pushwarden' protect --install`) {
		t.Fatalf("mac: %v", mac)
	}
	win := ElevateCommand(&platform.Info{OS: "windows"}, `C:\Users\x\pushwarden.exe`, args, true, have(), env(nil), false)
	if len(win) != 1 || win[0][0] != "powershell" || !strings.Contains(win[0][4], "-Verb RunAs") || !strings.Contains(win[0][4], "'protect','--install'") {
		t.Fatalf("win: %v", win)
	}
	// desktop Linux with pkexec and sudo, GUI preferred: pkexec first, then sudo -n, then interactive sudo
	lin := ElevateCommand(&platform.Info{OS: "linux"}, "/home/x/bin/pushwarden", args, true, have("pkexec", "sudo"), env(map[string]string{"DISPLAY": ":0"}), true)
	if len(lin) != 3 || lin[0][0] != "pkexec" || lin[1][1] != "-n" || lin[2][1] != "-p" {
		t.Fatalf("linux gui: %v", lin)
	}
	// terminal, no display: sudo only
	lin = ElevateCommand(&platform.Info{OS: "linux"}, "/home/x/bin/pushwarden", args, false, have("pkexec", "sudo"), env(nil), true)
	if len(lin) != 2 || lin[0][0] != "sudo" || lin[1][0] != "sudo" {
		t.Fatalf("linux tty: %v", lin)
	}
	// nothing available
	if got := ElevateCommand(&platform.Info{OS: "linux"}, "/x", args, true, have(), env(nil), false); len(got) != 0 {
		t.Fatalf("none: %v", got)
	}
	t.Setenv(NoBlockEnv, "1")
	if rc, how := Elevate(&platform.Info{OS: "linux"}, "/x", args, true); rc != 125 || !strings.Contains(how, "disabled") {
		t.Fatal(rc, how)
	}
	if shQuote("a b") != "'a b'" || shQuote("plain") != "plain" {
		t.Fatal("shQuote")
	}
}
