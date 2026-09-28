package main

import (
	"testing"

	"github.com/FaheemRafiq/threatscan/docs"
)

// Every registered command must have a section in docs/CLI.md.
func TestEveryCommandIsDocumented(t *testing.T) {
	for _, c := range commands {
		if c.name == "help" {
			continue
		}
		if _, ok := docs.Lookup(c.name); !ok {
			t.Errorf("command %q has no section in docs/CLI.md", c.name)
		}
	}
	t.Setenv("THREATSCAN_NO_PAGER", "1")
	if run([]string{"help", "install"}) != 0 || run([]string{"help", "nope"}) != 2 || run([]string{"--help"}) != 0 {
		t.Fatal("help exit codes")
	}
}
