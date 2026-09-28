//go:build !windows

package service

func addUserPath(dir string, dry bool) string { return "" }

func removeUserPath(dir string) {}
