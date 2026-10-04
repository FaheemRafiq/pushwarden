//go:build windows

package service

import (
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func readUserPath() (registry.Key, string, uint32, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, "Environment", registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return 0, "", 0, err
	}
	v, typ, err := k.GetStringValue("Path")
	if err == registry.ErrNotExist {
		return k, "", registry.EXPAND_SZ, nil
	}
	if err != nil {
		k.Close()
		return 0, "", 0, err
	}
	return k, v, typ, nil
}

func writeUserPath(k registry.Key, v string, typ uint32) error {
	var err error
	if typ == registry.SZ {
		err = k.SetStringValue("Path", v)
	} else {
		err = k.SetExpandStringValue("Path", v)
	}
	if err == nil {
		broadcastEnvChange()
	}
	return err
}

func splitPath(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ";") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func samePath(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, `\`), strings.TrimRight(b, `\`))
}

// addUserPath appends dir to the user PATH in HKCU\Environment.
func addUserPath(dir string, dry bool) string {
	k, v, typ, err := readUserPath()
	if err != nil {
		return "could not read the user PATH: " + err.Error()
	}
	defer k.Close()
	for _, p := range splitPath(v) {
		if samePath(p, dir) {
			return dir + " is on your user PATH"
		}
	}
	if dry {
		return "would add " + dir + " to your user PATH"
	}
	if err := writeUserPath(k, strings.Join(append(splitPath(v), dir), ";"), typ); err != nil {
		return "could not update the user PATH: " + err.Error()
	}
	return "added " + dir + " to your user PATH (open a new terminal to use 'pushwarden')"
}

func removeUserPath(dir string) {
	k, v, typ, err := readUserPath()
	if err != nil {
		return
	}
	defer k.Close()
	var keep []string
	for _, p := range splitPath(v) {
		if !samePath(p, dir) {
			keep = append(keep, p)
		}
	}
	if len(keep) != len(splitPath(v)) {
		_ = writeUserPath(k, strings.Join(keep, ";"), typ)
	}
}

// broadcastEnvChange tells Explorer to reload the environment so new terminals see PATH.
func broadcastEnvChange() {
	const hwndBroadcast = 0xffff
	const wmSettingChange = 0x001A
	const smtoAbortIfHung = 0x0002
	env, _ := syscall.UTF16PtrFromString("Environment")
	proc := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	var res uintptr
	proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&res)))
}
