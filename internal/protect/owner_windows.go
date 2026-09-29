//go:build windows

package protect

// On Windows the program is always copied to Program Files for the SYSTEM task.
func rootOwnedReadOnly(string) bool { return false }
