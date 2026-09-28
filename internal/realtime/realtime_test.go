package realtime

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	h "github.com/FaheemRafiq/threatscan/internal/helpers"
)

type collector struct {
	mu  sync.Mutex
	got map[string]bool
}

func (c *collector) add(ps []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range ps {
		c.got[p] = true
	}
}

func (c *collector) waitFor(t *testing.T, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		ok := c.got[want]
		c.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("never saw %s; got %v", want, c.got)
}

func (c *collector) saw(p string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got[p]
}

func exercise(t *testing.T, force func(*Watcher)) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(root, "proj", "node_modules", "x"), 0o755)
	c := &collector{got: map[string]bool{}}
	w := New([]string{root}, h.SkipDir, c.add, func(m string) { t.Log(m) })
	w.PollInterval = 300 * time.Millisecond
	if force != nil {
		force(w)
	}
	w.Start()
	defer w.Stop()
	time.Sleep(700 * time.Millisecond)

	cfg := filepath.Join(root, "proj", "postcss.config.mjs")
	os.WriteFile(cfg, []byte("export default {};"), 0o644)
	c.waitFor(t, cfg, 8*time.Second)

	// in-place append to an existing file
	c.mu.Lock()
	c.got = map[string]bool{}
	c.mu.Unlock()
	f, _ := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("   // changed")
	f.Close()
	c.waitFor(t, cfg, 8*time.Second)

	// a new tree appears, then a loader is written two levels down
	// (the case that failed on macOS and Windows in v5.1)
	deep := filepath.Join(root, "proj", "newdir", "public", "fonts")
	os.MkdirAll(deep, 0o755)
	time.Sleep(1500 * time.Millisecond)
	loader := filepath.Join(deep, "fa-solid-900.woff2")
	os.WriteFile(loader, []byte("var x=1;"), 0o644)
	c.waitFor(t, loader, 8*time.Second)

	// skipped directories are not reported
	nm := filepath.Join(root, "proj", "node_modules", "x", "index.js")
	os.WriteFile(nm, []byte("x"), 0o644)
	time.Sleep(1500 * time.Millisecond)
	if c.saw(nm) {
		t.Fatal("node_modules should be skipped")
	}
	t.Logf("backend=%s", w.Backend(time.Second))
}

func TestNative(t *testing.T) { exercise(t, nil) }

func TestBackendReported(t *testing.T) {
	w := New([]string{t.TempDir()}, h.SkipDir, func([]string) {}, nil)
	w.MaxDirs = 0
	w.Start()
	defer w.Stop()
	if b := w.Backend(5 * time.Second); b != "poll" {
		t.Fatalf("backend=%s, want poll", b)
	}
}

func TestPollingFallback(t *testing.T) {
	// MaxDirs=1 forces the native watcher to give up and poll
	exercise(t, func(w *Watcher) { w.MaxDirs = 1 })
}
