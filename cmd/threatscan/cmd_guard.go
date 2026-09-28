package main

import (
	"fmt"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/guard"
)

func init() {
	register("guard", "run the background protection loop in this terminal", cmdGuard)
	prev := statusServiceRows
	statusServiceRows = func(c *ctx) [][2]string {
		rows := prev(c)
		hb, age, alive := guard.ReadHeartbeat(c.DataDir)
		state := "not running"
		if alive {
			state = fmt.Sprintf("alive, %s, %ds ago, v%s, real-time: %s", hb.Phase, int(age.Seconds()), hb.Version, hb.Realtime)
		}
		last := "never"
		if hb != nil && hb.LastFull > 0 {
			last = time.Unix(int64(hb.LastFull), 0).Format("2006-01-02 15:04")
		}
		repos := "?"
		if hb != nil {
			repos = fmt.Sprint(hb.Repos)
		}
		return append(rows[:0:0], append([][2]string{{"Guard", state}, {"Last full sweep", last}, {"Repos tracked", repos}}, rows[1:]...)...)
	}
}

// guardHooks is filled in by later phases (real-time watcher, updates).
var guardHooks guard.Hooks

// guardPreStart runs before a long-running guard's first pass; returning true
// means this process must exit (e.g. it rolled back and restarted the guard).
var guardPreStart func(c *ctx, g *guard.Guard) bool

func cmdGuard(args []string) int {
	fs := newFlags("guard", "[--once] [--dry-run] [--verbose]")
	once := fs.Bool("once", false, "one full pass, then exit")
	dry := fs.Bool("dry-run", false, "detect and alert but never kill or quarantine")
	verbose := fs.Bool("verbose", false, "print the log to the terminal")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	g, err := guard.New(c.P, c.DataDir, version, *once, *dry, *verbose)
	if err != nil {
		fmt.Println("threatscan:", err)
		return 2
	}
	g.Hooks = guardHooks
	if !*once && guardPreStart != nil && guardPreStart(c, g) {
		return 0
	}
	return g.Run()
}
