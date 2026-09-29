//go:build !windows

package protect

import (
	"os"
	"syscall"
)

// rootOwnedReadOnly reports whether path is owned by root and not writable by
// group or others, i.e. safe for a privileged job to execute.
func rootOwnedReadOnly(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != 0 {
		return false
	}
	return st.Mode().Perm()&0o022 == 0
}
