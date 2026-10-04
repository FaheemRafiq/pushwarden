package protect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/journal"
)

// Expired describes what ExpireQuarantine removed (or would remove).
type Expired struct {
	Copies int
	Bytes  int64
}

func dirSize(p string) int64 {
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

// ExpireQuarantine deletes quarantined originals that are older than maxAge,
// then the oldest ones while the folder is larger than maxBytes; zero
// disables a limit. Each deletion is written to the history as a purge with
// the reason, so `history` shows that the copy is gone and why.
//
// Only the tool's own slot folders (quarantine/<YYYYMMDD-HHMMSS>/) are
// removed; a path stored in the index is never trusted for deletion.
func ExpireQuarantine(dataDir string, maxAge time.Duration, maxBytes int64, dry bool, j *journal.Journal, now time.Time) Expired {
	var res Expired
	if maxAge <= 0 && maxBytes <= 0 {
		return res
	}
	pr := &Protector{QDir: filepath.Join(dataDir, "quarantine")}
	pr.Index = filepath.Join(pr.QDir, "index.jsonl")
	pr.AttachJournal(j, "housekeeping")
	ents, err := os.ReadDir(pr.QDir)
	if err != nil {
		return res
	}
	type slot struct {
		path string
		at   time.Time
		size int64
	}
	var slots []slot
	var total int64
	for _, e := range ents {
		at, err := time.ParseInLocation("20060102-150405", e.Name(), time.Local)
		if err != nil || !e.IsDir() {
			continue // index.jsonl and anything that is not one of our slots
		}
		s := slot{filepath.Join(pr.QDir, e.Name()), at, 0}
		s.size = dirSize(s.path)
		total += s.size
		slots = append(slots, s)
	}
	sort.Slice(slots, func(a, b int) bool { return slots[a].at.Before(slots[b].at) })
	var index []Entry
	for _, s := range slots {
		reason := ""
		switch {
		case maxAge > 0 && now.Sub(s.at) > maxAge:
			reason = fmt.Sprintf("expired: quarantined copies are kept for %d days", int(maxAge.Hours()/24))
		case maxBytes > 0 && total > maxBytes:
			reason = fmt.Sprintf("expired: the quarantine is limited to %d MB and the oldest copies go first", maxBytes>>20)
		default:
			continue
		}
		if !dry && os.RemoveAll(s.path) != nil {
			continue
		}
		res.Copies++
		res.Bytes += s.size
		total -= s.size
		if dry {
			continue
		}
		if index == nil {
			index = pr.Entries()
		}
		seen := map[string]bool{}
		prefix := s.path + string(filepath.Separator)
		for _, e := range index {
			if e.Copy != "" && strings.HasPrefix(filepath.Clean(e.Copy), prefix) && !seen[e.Original] {
				seen[e.Original] = true
				pr.record(Entry{Type: "purge", Original: e.Original, Copies: 1, Title: reason})
			}
		}
	}
	return res
}
