package main

import (
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/config"
	"github.com/FaheemRafiq/pushwarden/internal/guard"
	"github.com/FaheemRafiq/pushwarden/internal/protect"
)

func init() {
	guardHooks.Periodic = append(guardHooks.Periodic, guard.PeriodicTask{
		Name: "netblock-check",
		Interval: func(cfg *config.Config) time.Duration {
			if !cfg.BlockC2 {
				return 0
			}
			return 24 * time.Hour
		},
		Run: func(g *guard.Guard) {
			nb := &protect.NetBlocker{P: g.P}
			if d := nb.Describe(); !strings.HasPrefix(d, "active (persistent") {
				g.Log("network blocking: " + d)
			}
		},
	})
}
