//go:build linux || freebsd

package prompt

import (
	"fmt"
	"os"
)

// ensureDisplay fills in DISPLAY/WAYLAND_DISPLAY/DBUS for services started without them.
func ensureDisplay() {
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return
	}
	run := fmt.Sprintf("/run/user/%d", os.Getuid())
	for _, c := range []string{"wayland-0", "wayland-1"} {
		if _, err := os.Stat(run + "/" + c); err == nil {
			os.Setenv("WAYLAND_DISPLAY", c)
			break
		}
	}
	for n := 0; n < 3; n++ {
		if _, err := os.Stat(fmt.Sprintf("/tmp/.X11-unix/X%d", n)); err == nil {
			os.Setenv("DISPLAY", fmt.Sprintf(":%d", n))
			break
		}
	}
	if _, err := os.Stat(run + "/bus"); err == nil && os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		os.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+run+"/bus")
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		os.Setenv("XDG_RUNTIME_DIR", run)
	}
}
