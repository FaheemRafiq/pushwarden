//go:build windows

package scan

import "golang.org/x/sys/windows/registry"

func runKeys() map[string]string {
	out := map[string]string{}
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	for _, n := range names {
		if v, _, err := k.GetStringValue(n); err == nil {
			out[n] = v
		}
	}
	return out
}
