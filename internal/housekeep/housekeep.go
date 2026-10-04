// Package housekeep keeps PushWarden's footprint on disk bounded: every
// store in the data directory has a size or age limit, and one pass enforces
// them all. The guard runs it daily; `pushwarden cleanup` runs it on demand.
//
// It only ever deletes files it recognises by name inside the data directory
// (and its own leftovers in the temp folder). No path read from stored data
// is used for a deletion.
package housekeep

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/config"
	"github.com/FaheemRafiq/pushwarden/internal/journal"
	"github.com/FaheemRafiq/pushwarden/internal/protect"
	"github.com/FaheemRafiq/pushwarden/internal/remediate"
)

const (
	guardLogArchives = 5 // guard-*.log.gz kept (5 MB of log each before compression)
	alertLogArchives = 3 // alerts-*.log.gz kept
	tempMaxAge       = 24 * time.Hour
)

type Options struct {
	DataDir string
	Cfg     *config.Config
	Dry     bool             // report what would be removed, remove nothing
	Journal *journal.Journal // records quarantine expiry in the history; may be nil
	// Unsent reports whether a journal archive still has events waiting for
	// the central upload; such archives are kept until twice the limits.
	Unsent  func(archive string) bool
	TempDir string // "" = the system temp folder
	Now     time.Time
}

// Line is one thing the pass removed.
type Line struct {
	What  string
	Count int
	Bytes int64
	Note  string
}

type Report struct{ Lines []Line }

func (r Report) Bytes() (n int64) {
	for _, l := range r.Lines {
		n += l.Bytes
	}
	return
}

// MB formats a size for people.
func MB(n int64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprintf("%d MB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

// String is the one-line summary for the guard log.
func (r Report) String() string {
	var parts []string
	for _, l := range r.Lines {
		parts = append(parts, fmt.Sprintf("%d %s", l.Count, l.What))
	}
	return fmt.Sprintf("%s freed: %s", MB(r.Bytes()), strings.Join(parts, ", "))
}

func days(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }
func mb(n int) int64           { return int64(n) << 20 }

// Run enforces every limit once.
func Run(o Options) Report {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Cfg == nil {
		o.Cfg = config.Default()
	}
	var r Report
	add := func(what string, n int, bytes int64, note string) {
		if n > 0 {
			r.Lines = append(r.Lines, Line{what, n, bytes, note})
		}
	}
	c := o.Cfg

	p := journal.Prune(o.DataDir, mb(c.JournalKeepMB), days(c.JournalKeepDays), o.Unsent, o.Dry, o.Now)
	note := fmt.Sprintf("%d events older than the journal limit", p.Events)
	if p.Unsent > 0 {
		note += fmt.Sprintf("; %d of them were never uploaded (server unreachable for too long)", p.Unsent)
	}
	add("journal archives", p.Files, p.Bytes, note)

	n, b := journal.KeepNewest(o.DataDir, "guard-*.log.gz", guardLogArchives, o.Dry)
	add("old guard logs", n, b, "")
	n, b = journal.KeepNewest(o.DataDir, "alerts-*.log.gz", alertLogArchives, o.Dry)
	add("old alert logs", n, b, "")

	q := protect.ExpireQuarantine(o.DataDir, days(c.QuarantineKeepDays), mb(c.QuarantineKeepMB), o.Dry, o.Journal, o.Now)
	add("quarantined copies", q.Copies, q.Bytes, "past the quarantine limit; they can no longer be restored")

	if _, err := os.Stat(filepath.Join(o.DataDir, remediate.StateFile)); err == nil || dirExists(filepath.Join(o.DataDir, remediate.ClonesDir)) {
		st := remediate.LoadState(o.DataDir)
		n, b = st.PruneClones(days(c.CloneKeepDays), mb(c.CloneKeepMB), o.Dry)
		add("repository copies kept for github-clean --apply", n, b, "not used within the limit; --apply downloads them again")
		add("repositories in the github-clean progress", st.DropStale(remediate.StateMaxAge, o.Dry), 0, "not seen for 90 days")
	}

	n, b = stale(o.DataDir, o.Dry, o.Now, func(name string, dir bool) bool { return !dir && strings.HasSuffix(name, ".tmp") })
	add("unfinished temporary files", n, b, "")

	tmp := o.TempDir
	if tmp == "" {
		tmp = os.TempDir()
	}
	n, b = stale(tmp, o.Dry, o.Now, func(name string, dir bool) bool {
		if !dir || !strings.HasPrefix(name, "pushwarden-") {
			return false
		}
		// ours for certain: the hooks folder of older versions, or a clone of an interrupted github-clean
		return strings.HasPrefix(name, "pushwarden-nohooks-") || dirExists(filepath.Join(tmp, name, "repo.git"))
	})
	add("leftover folders in the temp folder", n, b, "")
	return r
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// stale removes the entries of dir that match and are older than a day.
func stale(dir string, dry bool, now time.Time, match func(name string, isDir bool) bool) (int, int64) {
	ents, _ := os.ReadDir(dir)
	n, bytes := 0, int64(0)
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil || !match(e.Name(), e.IsDir()) || now.Sub(fi.ModTime()) < tempMaxAge {
			continue
		}
		p := filepath.Join(dir, e.Name())
		size := sizeOf(p)
		if dry || os.RemoveAll(p) == nil {
			n++
			bytes += size
		}
	}
	return n, bytes
}

func sizeOf(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// Item is one store in the data directory and what limits it.
type Item struct {
	Name  string
	Bytes int64
	Limit string
}

func limit(n int, unit string) string {
	if n <= 0 {
		return "no limit"
	}
	return fmt.Sprintf("%d %s", n, unit)
}

// Usage measures what PushWarden occupies in its data directory.
func Usage(dataDir string, c *config.Config) []Item {
	if c == nil {
		c = config.Default()
	}
	items := []Item{
		{"journal", 0, limit(c.JournalKeepMB, "MB") + " of archives, " + limit(c.JournalKeepDays, "days")},
		{"quarantine", 0, limit(c.QuarantineKeepMB, "MB") + ", " + limit(c.QuarantineKeepDays, "days")},
		{"logs", 0, fmt.Sprintf("5 MB each, %d + %d archives", guardLogArchives, alertLogArchives)},
		{"reports", 0, limit(c.ReportKeep, "reports")},
		{"clones", 0, limit(c.CloneKeepMB, "MB") + ", " + limit(c.CloneKeepDays, "days")},
		{"other", 0, "settings, indicators, state"},
	}
	ents, _ := os.ReadDir(dataDir)
	for _, e := range ents {
		name, i := e.Name(), 5
		switch {
		case strings.HasPrefix(name, "journal"):
			i = 0
		case name == "quarantine":
			i = 1
		case strings.HasPrefix(name, "guard.log") || strings.HasPrefix(name, "guard-") || strings.HasPrefix(name, "alerts"):
			i = 2
		case name == "reports":
			i = 3
		case name == remediate.ClonesDir:
			i = 4
		}
		items[i].Bytes += sizeOf(filepath.Join(dataDir, name))
	}
	return items
}

// Total sums a usage listing.
func Total(items []Item) (n int64) {
	for _, it := range items {
		n += it.Bytes
	}
	return
}
