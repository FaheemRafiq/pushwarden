package protect

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/platform"
)

// NoBlockEnv disables every attempt to obtain administrator rights (installers
// that already did it, CI, people who opted out).
const NoBlockEnv = "THREATSCAN_NO_BLOCK"

const elevatePrompt = "ThreatScan needs administrator rights to block the PolinRider command servers at the firewall."

// shQuote quotes for /bin/sh.
func shQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!&|;<>()*?[]{}~#") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// ElevateCommand lists, in order, the commands that would run exe args with
// administrator rights on this platform. gui prefers a graphical prompt.
// lookPath, getenv and haveTTY are injected so the choice is testable.
func ElevateCommand(p *platform.Info, exe string, args []string, gui bool,
	lookPath func(string) (string, error), getenv func(string) string, haveTTY bool) [][]string {
	var out [][]string
	full := append([]string{exe}, args...)
	switch {
	case p.IsMac():
		var sh []string
		for _, a := range full {
			sh = append(sh, shQuote(a))
		}
		script := fmt.Sprintf(`do shell script "%s" with administrator privileges with prompt "%s"`,
			strings.ReplaceAll(strings.Join(sh, " "), `"`, `\"`), elevatePrompt)
		out = append(out, []string{"osascript", "-e", script})
	case p.IsWindows():
		var list []string
		for _, a := range args {
			list = append(list, "'"+strings.ReplaceAll(a, "'", "''")+"'")
		}
		ps := fmt.Sprintf("Start-Process -FilePath '%s' -ArgumentList %s -Verb RunAs -Wait", strings.ReplaceAll(exe, "'", "''"), strings.Join(list, ","))
		out = append(out, []string{"powershell", "-NoProfile", "-NonInteractive", "-Command", ps})
	default:
		display := getenv("DISPLAY") != "" || getenv("WAYLAND_DISPLAY") != ""
		if gui && display {
			if _, err := lookPath("pkexec"); err == nil {
				out = append(out, append([]string{"pkexec"}, full...))
			}
		}
		if _, err := lookPath("sudo"); err == nil {
			out = append(out, append([]string{"sudo", "-n"}, full...))
			if haveTTY {
				out = append(out, append([]string{"sudo", "-p", "[threatscan] password for %u (to block the C2 servers): "}, full...))
			}
		}
		if !gui && display {
			if _, err := lookPath("pkexec"); err == nil {
				out = append(out, append([]string{"pkexec"}, full...))
			}
		}
	}
	return out
}

func haveTTY() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// Elevated reports whether elevation is disabled for this process.
func ElevationDisabled() bool {
	return os.Getenv(NoBlockEnv) != "" || os.Getenv("CI") != ""
}

// Elevate runs exe args with administrator rights, trying each candidate until
// one succeeds. It returns the exit code and a description of what ran.
func Elevate(p *platform.Info, exe string, args []string, gui bool) (int, string) {
	if ElevationDisabled() {
		return 125, "elevation disabled (" + NoBlockEnv + " or CI set)"
	}
	cands := ElevateCommand(p, exe, args, gui, exec.LookPath, os.Getenv, haveTTY())
	if len(cands) == 0 {
		return 127, "no way to ask for administrator rights here (no pkexec, sudo or terminal)"
	}
	var last string
	for _, c := range cands {
		var rc int
		var se string
		if c[0] == "sudo" && len(c) > 1 && c[1] == "-p" {
			// interactive sudo needs the terminal; run it attached
			cmd := exec.Command(c[0], c[1:]...)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					rc = ee.ExitCode()
				} else {
					rc = 127
				}
				se = err.Error()
			}
		} else {
			rc, _, se = p.RunRC(5*time.Minute, c[0], c[1:]...)
		}
		if rc == 0 {
			return 0, c[0]
		}
		last = fmt.Sprintf("%s exited %d: %s", c[0], rc, strings.TrimSpace(lastLine(se)))
	}
	return 1, last
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
