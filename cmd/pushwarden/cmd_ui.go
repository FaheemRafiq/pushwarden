package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/ghclean"
	"github.com/FaheemRafiq/pushwarden/internal/github"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
	"github.com/FaheemRafiq/pushwarden/internal/scan"
	"github.com/FaheemRafiq/pushwarden/internal/tui"
	"github.com/FaheemRafiq/pushwarden/internal/ui"
)

func init() {
	register("ui", "guided screens for github-clean: sign in, pick repositories, check, fix", cmdUI)
}

func cmdUI(args []string) int {
	var api string
	var fresh, pause bool
	fs := newFlags("ui", "[options]\n\n"+
		"The easy way to clean your GitHub repositories. Guided screens walk you through it:\n"+
		"sign in, choose the repositories, check them (nothing is changed), review what was\n"+
		"found, then fix and push after you confirm. An interrupted run continues where it stopped.")
	fs.StringVar(&api, "api", github.DefaultAPI, "GitHub API base URL (GitHub Enterprise)")
	fs.BoolVar(&fresh, "fresh", false, "forget the progress of earlier runs and check every branch again")
	fs.BoolVar(&pause, "pause", false, "if it cannot start, wait for Enter before closing (the desktop shortcuts use this)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	if out, err := os.Stdout.Stat(); !isTTY() || err != nil || out.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "pushwarden: ui needs an interactive terminal; use `pushwarden github-clean` instead")
		return 2
	}
	// Started from a shortcut, the window closes with the program: keep a
	// message on screen until it is read.
	fail := func(msg string) int {
		fmt.Fprintln(os.Stderr, "pushwarden: "+msg)
		if pause {
			fmt.Fprint(os.Stderr, "\nPress Enter to close. ")
			bufio.NewReader(os.Stdin).ReadString('\n')
		}
		return 2
	}
	if _, err := exec.LookPath("git"); err != nil {
		return fail("git is not installed or not on PATH. PushWarden uses it to download and fix your repositories: https://git-scm.com/downloads")
	}
	c := mustCtx()
	state := remediate.LoadState(c.DataDir)
	if fresh {
		state.Reset()
	}
	state.PruneClones(time.Duration(c.Cfg.CloneKeepDays)*24*time.Hour, int64(c.Cfg.CloneKeepMB)<<20, false)
	// An SSH account cannot list its repositories through the API; the
	// clones on this computer tell which ones it has.
	localRepos := func() []string {
		var out []string
		for _, root := range c.Cfg.Roots(c.P.CommonProjectDirs) {
			repos, _ := scan.NewRepo(root, ui.New(true, true), c.I).Discover()
			out = append(out, repos...)
		}
		return out
	}
	code, err := tui.Run(&ghclean.Session{
		API: api, Version: version, State: state, CloneMaxBytes: int64(c.Cfg.CloneKeepMB) << 20,
		Journal: openJournal(c), P: c.P, I: c.I, DataDir: c.DataDir,
	}, localRepos)
	if err != nil {
		return fail(err.Error())
	}
	return code
}
