// Package realtime watches project directories and reports written files.
//
// Backend: fsnotify (inotify on Linux, kqueue on macOS, ReadDirectoryChangesW
// on Windows).  fsnotify watches single directories, so every directory is
// added individually and new subdirectories are added as they appear; files
// that arrive together with a new directory (git checkout, unzip) are reported
// as well.  If the OS refuses more watches, the watcher switches to polling.
package realtime

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const debounce = 500 * time.Millisecond

type Watcher struct {
	Roots        []string
	Skip         func(name string) bool
	OnEvents     func(paths []string)
	Log          func(string)
	PollInterval time.Duration
	MaxDirs      int

	backend string
	ready   chan struct{}
	mu      sync.Mutex
	pending map[string]bool
	watched map[string]bool
	done    chan struct{}
	wg      sync.WaitGroup
}

func New(roots []string, skip func(string) bool, onEvents func([]string), log func(string)) *Watcher {
	if log == nil {
		log = func(string) {}
	}
	return &Watcher{Roots: roots, Skip: skip, OnEvents: onEvents, Log: log, PollInterval: 3 * time.Second,
		MaxDirs: 50000, pending: map[string]bool{}, watched: map[string]bool{}, done: make(chan struct{}), ready: make(chan struct{})}
}

// Start begins watching in the background.
func (w *Watcher) Start() {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		if err := w.runNotify(); err != nil {
			w.Log("realtime: native watcher unavailable (" + err.Error() + "); falling back to polling")
			w.runPoll()
		}
	}()
}

func (w *Watcher) setBackend(b string) {
	w.mu.Lock()
	w.backend = b
	w.mu.Unlock()
	select {
	case <-w.ready:
	default:
		close(w.ready)
	}
}

// Backend waits up to timeout for the initial walk and returns "fsnotify" or "poll".
func (w *Watcher) Backend(timeout time.Duration) string {
	select {
	case <-w.ready:
	case <-time.After(timeout):
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.backend == "" {
		return "starting"
	}
	return w.backend
}

// Stop ends watching and waits for the goroutine.
func (w *Watcher) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	w.wg.Wait()
}

func (w *Watcher) emit(paths ...string) {
	w.mu.Lock()
	for _, p := range paths {
		w.pending[p] = true
	}
	w.mu.Unlock()
}

func (w *Watcher) flush() {
	w.mu.Lock()
	if len(w.pending) == 0 {
		w.mu.Unlock()
		return
	}
	batch := make([]string, 0, len(w.pending))
	for p := range w.pending {
		batch = append(batch, p)
	}
	w.pending = map[string]bool{}
	w.mu.Unlock()
	func() {
		defer func() {
			if r := recover(); r != nil {
				w.Log("realtime handler error")
			}
		}()
		w.OnEvents(batch)
	}()
}

// walk visits every non-skipped directory under root.
func (w *Watcher) walk(root string, fn func(dir string, files []string) bool) {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (w.Skip(d.Name()) || d.Type()&os.ModeSymlink != 0) {
				return filepath.SkipDir
			}
			ents, _ := os.ReadDir(p)
			var files []string
			for _, e := range ents {
				if !e.IsDir() {
					files = append(files, filepath.Join(p, e.Name()))
				}
			}
			if !fn(p, files) {
				return filepath.SkipAll
			}
		}
		return nil
	})
}

// ── native (fsnotify) ────────────────────────────────────────────────────────

func (w *Watcher) runNotify() error {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer fw.Close()
	var addErr error
	add := func(dir string) bool {
		if w.watched[dir] {
			return true
		}
		if len(w.watched) >= w.MaxDirs {
			addErr = errTooMany
			return false
		}
		if err := fw.Add(dir); err != nil {
			addErr = err
			return false
		}
		w.watched[dir] = true
		return true
	}
	for _, r := range w.Roots {
		w.walk(r, func(dir string, _ []string) bool { return add(dir) })
		if addErr != nil {
			return addErr
		}
	}
	w.setBackend("fsnotify")
	w.Log("realtime: watching " + itoa(len(w.watched)) + " directories under " + itoa(len(w.Roots)) + " roots")
	tick := time.NewTicker(debounce)
	defer tick.Stop()
	for {
		select {
		case <-w.done:
			return nil
		case ev, ok := <-fw.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Chmod) == 0 {
				continue
			}
			st, err := os.Lstat(ev.Name)
			if err != nil {
				continue
			}
			if st.IsDir() {
				if ev.Op&fsnotify.Create != 0 && !w.Skip(filepath.Base(ev.Name)) {
					// watch the new tree and report files that came with it
					w.walk(ev.Name, func(dir string, files []string) bool {
						add(dir)
						w.emit(files...)
						return true
					})
					if addErr != nil {
						w.Log("realtime: " + addErr.Error() + "; new directories are covered by the full sweep")
						addErr = nil
					}
				}
				continue
			}
			w.emit(ev.Name)
		case err, ok := <-fw.Errors:
			if !ok {
				return nil
			}
			if err == fsnotify.ErrEventOverflow {
				// the kernel dropped events: rescan everything on the next flush
				for _, r := range w.Roots {
					w.walk(r, func(_ string, files []string) bool { w.emit(files...); return true })
				}
			}
		case <-tick.C:
			w.flush()
		}
	}
}

// ── fallback: polling ────────────────────────────────────────────────────────

type stamp struct {
	mod  time.Time
	size int64
}

func (w *Watcher) snapshot() map[string]stamp {
	out := map[string]stamp{}
	for _, r := range w.Roots {
		w.walk(r, func(_ string, files []string) bool {
			for _, f := range files {
				if st, err := os.Stat(f); err == nil {
					out[f] = stamp{st.ModTime(), st.Size()}
				}
			}
			return true
		})
	}
	return out
}

func (w *Watcher) runPoll() {
	w.setBackend("poll")
	w.Log("realtime: polling every " + w.PollInterval.String())
	snap := w.snapshot()
	t := time.NewTicker(w.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-t.C:
			cur := w.snapshot()
			for p, s := range cur {
				if old, ok := snap[p]; !ok || !old.mod.Equal(s.mod) || old.size != s.size {
					w.emit(p)
				}
			}
			snap = cur
			w.flush()
		}
	}
}

type tooMany struct{}

func (tooMany) Error() string { return "directory count exceeds the watch limit" }

var errTooMany error = tooMany{}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
