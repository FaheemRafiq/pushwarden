package main

import (
	"time"

	"github.com/FaheemRafiq/threatscan/internal/realtime"
)

func init() {
	guardHooks.StartRealtime = func(roots []string, skip func(string) bool, onEvents func([]string), log func(string)) (string, func()) {
		w := realtime.New(roots, skip, onEvents, log)
		w.Start()
		return w.Backend(30 * time.Second), w.Stop
	}
}
