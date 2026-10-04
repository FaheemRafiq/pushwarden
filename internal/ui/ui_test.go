package ui

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func capture(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var b bytes.Buffer
	io.Copy(&b, r)
	return b.String()
}

func TestStepWithoutTerminal(t *testing.T) {
	u := New(false, false) // stdout is a pipe here: no colour, no live bar
	out := capture(t, func() {
		u.Step(0, 3, "a")
		u.Step(1, 3, "b")
		u.Step(3, 3, "done")
	})
	if !strings.Contains(out, "[0/3] a") || !strings.Contains(out, "[3/3] done") || u.Live() {
		t.Fatalf("plain progress lines expected:\n%s", out)
	}
	ci := New(true, false)
	out = capture(t, func() { ci.Step(1, 3, "b"); ci.Step(3, 3, "done") })
	if strings.Contains(out, "[1/3]") || !strings.Contains(out, "[3/3]") {
		t.Fatalf("CI prints only the final step:\n%s", out)
	}
	if out := capture(t, func() { New(false, true).Step(1, 2, "x") }); out != "" {
		t.Fatal("quiet UI printed")
	}
}

func TestLiveBarIsClearedBeforeLines(t *testing.T) {
	u := New(false, false)
	u.color = true // pretend we are on a terminal
	out := capture(t, func() {
		u.Step(1, 4, "repo-a")
		u.Info("found something")
		u.Step(4, 4, "done")
	})
	if !strings.Contains(out, "\r\033[K  \033[1;36m"+strings.Repeat(BarFull, 6)) || !strings.Contains(out, "\r\033[K  i ") {
		t.Fatalf("bar not drawn in place / not cleared before a line:\n%q", out)
	}
	if u.Live() {
		t.Fatal("bar should be finished")
	}
}

func TestBarIsTheSameEverywhere(t *testing.T) {
	full, empty := BarCells(0.5, BarWidth)
	if full != strings.Repeat(BarFull, 12) || empty != strings.Repeat(BarEmpty, 12) {
		t.Fatalf("half: %q %q", full, empty)
	}
	for frac, want := range map[float64]int{-1: 0, 0: 0, 0.02: 0, 0.03: 1, 0.99: 24, 1: 24, 7: 24} {
		full, empty := BarCells(frac, BarWidth)
		if n := len([]rune(full)); n != want || n+len([]rune(empty)) != BarWidth {
			t.Errorf("%v: %d filled, want %d", frac, n, want)
		}
	}
	if got := PlainBar(0.25, 8); got != "[##------]" {
		t.Fatalf("plain: %s", got)
	}
	// without a terminal the coloured bar falls back to the plain one
	if got := New(true, false).Bar(1, "BOLD_CYAN"); got != "["+strings.Repeat("#", BarWidth)+"]" {
		t.Fatalf("no colour: %s", got)
	}
}
