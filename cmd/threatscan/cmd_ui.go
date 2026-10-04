package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/ghclean"
	"github.com/FaheemRafiq/threatscan/internal/github"
	"github.com/FaheemRafiq/threatscan/internal/remediate"
	"github.com/FaheemRafiq/threatscan/internal/tui"
)

func init() {
	register("ui", "guided screens for github-clean: sign in, pick repositories, check, fix", cmdUI)
}

func cmdUI(args []string) int {
	var api string
	var fresh, pause bool
	fs := newFlags("ui", "[options]\n\n"+
		"The same work as github-clean, on guided screens instead of flags: sign in, choose the\n"+
		"repositories, check them (nothing is changed), review what was found, then fix and push\n"+
		"after you confirm. An interrupted run continues where it stopped.")
	fs.StringVar(&api, "api", github.DefaultAPI, "GitHub API base URL (GitHub Enterprise)")
	fs.BoolVar(&fresh, "fresh", false, "forget the progress of earlier runs and check every branch again")
	fs.BoolVar(&pause, "pause", false, "if it cannot start, wait for Enter before closing (the desktop shortcuts use this)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	if out, err := os.Stdout.Stat(); !isTTY() || err != nil || out.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "threatscan: ui needs an interactive terminal; use `threatscan github-clean` instead")
		return 2
	}
	// Started from a shortcut, the window closes with the program: keep a
	// message on screen until it is read.
	fail := func(msg string) int {
		fmt.Fprintln(os.Stderr, "threatscan: "+msg)
		if pause {
			fmt.Fprint(os.Stderr, "\nPress Enter to close. ")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
		return 2
	}
	if _, err := exec.LookPath("git"); err != nil {
		return fail("git is not installed or not on PATH. ThreatScan uses it to download and fix your repositories: https://git-scm.com/downloads")
	}
	c := mustCtx()
	state := remediate.LoadState(c.DataDir)
	if fresh {
		state.Reset()
	}
	state.PruneClones(time.Duration(c.Cfg.CloneKeepDays)*24*time.Hour, int64(c.Cfg.CloneKeepMB)<<20, false)
	code, err := tui.Run(&ghclean.Session{
		API: api, Version: version, State: state, CloneMaxBytes: int64(c.Cfg.CloneKeepMB) << 20,
		Journal: openJournal(c), P: c.P, I: c.I, DataDir: c.DataDir,
	})
	if err != nil {
		return fail(err.Error())
	}
	return code
}
