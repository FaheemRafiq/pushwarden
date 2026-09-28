//go:build !windows

package platform

import (
	"os"
	"os/exec"
	"syscall"
)

func hideWindow(cmd *exec.Cmd) {}

// Detach makes a child survive the parent's process group being killed.
func Detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func IsAdmin() bool { return os.Geteuid() == 0 }
