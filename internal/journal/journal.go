// Package journal is the machine's complete activity record: every finding at
// every sighting, every action, every user decision, every sweep, update and
// error, one JSON object per line in <data_dir>/journal.jsonl.
//
// The file is append-only and opened per write, so the guard, `scan` and
// `github-clean` can all write to it. When it passes MaxBytes it is rotated
// into a gzip archive beside it. Prune deletes the oldest archives once they
// pass the configured size or age.
package journal

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/findings"
)

const (
	FileName       = "journal.jsonl"
	DefaultMaxSize = 10 << 20
)

// Event kinds.
const (
	KindFinding  = "finding"  // a detection, recorded at every sighting
	KindAction   = "action"   // kill, quarantine, strip, delete, restore, purge, allow
	KindDecision = "decision" // the user answered a dialog
	KindSweep    = "sweep"    // start / end of a full pass
	KindGuard    = "guard"    // guard lifecycle
	KindUpdate   = "update"   // indicator or program update
	KindError    = "error"    // failed action, recovered panic, refused update
	KindFeedback = "feedback" // the user marked a false positive
)

type Event struct {
	TS       string         `json:"ts"`
	Ver      string         `json:"ver,omitempty"`
	IOCs     string         `json:"iocs,omitempty"`
	Ctx      string         `json:"ctx,omitempty"` // guard-full, guard-quick, realtime, scan, github-clean, install, update
	Kind     string         `json:"kind"`
	Sev      string         `json:"sev,omitempty"`
	Category string         `json:"category,omitempty"`
	Threat   string         `json:"threat,omitempty"`
	Title    string         `json:"title,omitempty"`
	Path     string         `json:"path,omitempty"`
	PID      int            `json:"pid,omitempty"`
	Cmd      string         `json:"cmd,omitempty"`
	Matched  string         `json:"matched,omitempty"`
	Why      string         `json:"why,omitempty"`
	Response string         `json:"response,omitempty"`
	Action   string         `json:"action,omitempty"`
	OK       *bool          `json:"ok,omitempty"`
	Evidence []string       `json:"evidence,omitempty"`
	Sweep    string         `json:"sweep,omitempty"` // ties the events of one pass together
	Key      string         `json:"key,omitempty"`   // stable identity of a finding, for grouping
	Note     string         `json:"note,omitempty"`
	Data     map[string]any `json:"data,omitempty"`

	// Set when reading, never stored: which journal file the event is in and
	// its position among that file's events. Together they are the event's
	// fixed place in the record, which the central upload counts by.
	File string `json:"-"`
	Line int    `json:"-"`
	// Uploaded is filled in by views when the central upload is on: whether
	// this event has been stored at the configured upload_url.
	Uploaded *bool `json:"uploaded,omitempty"`
}

// Time parses the event timestamp (zero when malformed).
func (e Event) Time() time.Time {
	t, _ := time.ParseInLocation(time.RFC3339, e.TS, time.Local)
	return t
}

type Journal struct {
	Dir     string
	Ver     string
	IOCs    string
	MaxSize int64
	// MinSeverity drops findings below it (default WARNING).
	MinSeverity findings.Severity
	Disabled    bool
	mu          sync.Mutex
}

// Open returns the journal for a data directory. A nil *Journal is valid and
// records nothing, so callers never need to check.
func Open(dataDir, ver, iocs string) *Journal {
	return &Journal{Dir: dataDir, Ver: ver, IOCs: iocs, MaxSize: DefaultMaxSize, MinSeverity: findings.Warning}
}

func (j *Journal) path() string { return filepath.Join(j.Dir, FileName) }

// Exists reports whether this machine already has a journal (active or archived).
func Exists(dataDir string) bool {
	if _, err := os.Stat(filepath.Join(dataDir, FileName)); err == nil {
		return true
	}
	m, _ := filepath.Glob(filepath.Join(dataDir, "journal-*.jsonl*"))
	return len(m) > 0
}

// Write appends one event. Errors are swallowed: the journal must never break
// protection.
func (j *Journal) Write(e Event) {
	if j == nil || j.Disabled || j.Dir == "" {
		return
	}
	if e.TS == "" {
		e.TS = time.Now().Format(time.RFC3339)
	}
	if e.Ver == "" {
		e.Ver = j.Ver
	}
	if e.IOCs == "" {
		e.IOCs = j.IOCs
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = os.MkdirAll(j.Dir, 0o700)
	fh, err := os.OpenFile(j.path(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = fh.Write(append(b, '\n'))
	st, _ := fh.Stat()
	fh.Close()
	if st != nil && j.MaxSize > 0 && st.Size() >= j.MaxSize {
		j.rotate()
	}
}

// rotate archives the active journal.
func (j *Journal) rotate() { archive(j.path()) }

// RotateFile archives p (name-STAMP.ext.gz beside it) once it reaches max bytes.
// Used for guard.log as well; archives are never deleted.
func RotateFile(p string, max int64) {
	if st, err := os.Stat(p); err == nil && max > 0 && st.Size() >= max {
		archive(p)
	}
}

// archive renames p to a timestamped sibling and gzips it.
func archive(p string) {
	stamp := strings.ReplaceAll(time.Now().Format("20060102-150405.000"), ".", "")
	ext := filepath.Ext(p)
	plain := strings.TrimSuffix(p, ext) + "-" + stamp + ext
	if err := os.Rename(p, plain); err != nil {
		return
	}
	if gzipFile(plain, plain+".gz") != nil {
		os.Remove(plain + ".gz") // keep the plain archive rather than lose data
		return
	}
	os.Remove(plain) // every handle is closed by now, which Windows requires
}

func gzipFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	if e := zw.Close(); err == nil {
		err = e
	}
	if e := out.Close(); err == nil {
		err = e
	}
	return err
}

// Finding records one sighting of a finding.
func (j *Journal) Finding(ctx, sweep string, f *findings.Finding, threat string) {
	if j == nil || f.Severity < j.MinSeverity {
		return
	}
	resp := ""
	if f.Action != "" {
		resp = findings.WhyAction(f)
	}
	j.Write(Event{Ctx: ctx, Kind: KindFinding, Sev: f.Severity.String(), Category: f.Category, Threat: threat, Title: f.Title,
		Path: f.Path, PID: f.Meta.PID, Cmd: f.Meta.Cmd, Matched: findings.Because(f), Why: findings.Why(f), Response: resp,
		Action: f.Action, Evidence: f.Meta.Evidence, Sweep: sweep, Key: f.Key()})
}

// Filter selects events when reading.
type Filter struct {
	Kinds       []string
	MinSeverity findings.Severity // applies to events that carry a severity
	Since       time.Time
	PathSubstr  string
	Archives    bool // also read rotated archives
}

func (f Filter) match(e Event) bool {
	if len(f.Kinds) > 0 {
		ok := false
		for _, k := range f.Kinds {
			ok = ok || k == e.Kind
		}
		if !ok {
			return false
		}
	}
	if f.MinSeverity > findings.Info {
		if e.Sev == "" || findings.ParseSeverity(e.Sev) < f.MinSeverity {
			return false
		}
	}
	if !f.Since.IsZero() && e.Time().Before(f.Since) {
		return false
	}
	if f.PathSubstr != "" && !strings.Contains(strings.ToLower(e.Path+" "+e.Title+" "+e.Cmd), strings.ToLower(f.PathSubstr)) {
		return false
	}
	return true
}

func readFile(p string, f Filter, out *[]Event) {
	fh, err := os.Open(p)
	if err != nil {
		return
	}
	defer fh.Close()
	var r io.Reader = fh
	if strings.HasSuffix(p, ".gz") {
		zr, err := gzip.NewReader(fh)
		if err != nil {
			return
		}
		defer zr.Close()
		r = zr
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	name, n := ArchiveName(p), 0
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Kind == "" {
			continue // a torn or foreign line never stops the read
		}
		e.File, e.Line, e.Uploaded = name, n, nil
		n++
		if f.match(e) {
			*out = append(*out, e)
		}
	}
}

// archivedAt returns when an archive was rotated, from its name
// (journal-20060102-150405000.jsonl.gz). Zero when the name has another shape.
func archivedAt(p string) time.Time {
	name := strings.TrimPrefix(filepath.Base(p), "journal-")
	if len(name) < 15 {
		return time.Time{}
	}
	t, _ := time.ParseInLocation("20060102-150405", name[:15], time.Local)
	return t
}

// ArchiveName is the name a journal file is known by: its base name without
// the .gz suffix, so it stays the same while an archive is being compressed.
func ArchiveName(p string) string { return strings.TrimSuffix(filepath.Base(p), ".gz") }

// Archives returns the rotated journal files, oldest first. While an archive
// is being compressed both forms exist; the plain one is complete and the
// gzip may not be, so only the plain one is listed.
func Archives(dataDir string) []string {
	all, _ := filepath.Glob(filepath.Join(dataDir, "journal-*.jsonl*"))
	sort.Strings(all)
	plain := map[string]bool{}
	for _, p := range all {
		if !strings.HasSuffix(p, ".gz") {
			plain[p] = true
		}
	}
	var out []string
	for _, p := range all {
		if strings.HasSuffix(p, ".gz") && plain[strings.TrimSuffix(p, ".gz")] {
			continue
		}
		if _, err := os.Stat(tombstone(p)); err == nil {
			continue // pruned: its events are counted by the marker, the file is going away
		}
		out = append(out, p)
	}
	return out
}

// tombstone is the small marker left for a pruned archive. It holds how many
// events the archive had, so every later event keeps its position in the
// record (the central upload counts by position).
func tombstone(archive string) string {
	return filepath.Join(filepath.Dir(archive), strings.TrimSuffix(ArchiveName(archive), ".jsonl")+".pruned")
}

// PrunedEvents returns how many events were in archives that have been
// deleted to save space. They precede everything still on disk.
func PrunedEvents(dataDir string) int {
	marks, _ := filepath.Glob(filepath.Join(dataDir, "journal-*.pruned"))
	n := 0
	for _, m := range marks {
		if b, err := os.ReadFile(m); err == nil {
			c, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			n += c
		}
	}
	return n
}

// Pruned describes what Prune removed (or, on a dry run, would remove).
type Pruned struct {
	Files  int
	Bytes  int64
	Events int
	Unsent int // events removed although the caller wanted them kept (hard limit reached)
}

// Prune deletes the oldest archives until those left are at most maxBytes in
// total and none is older than maxAge; zero disables a limit. The active
// journal is never touched. hold, when set, names archives that should
// survive (not yet uploaded): they are kept until twice the limits, after
// which the disk limit wins. Oldest first, so what remains is contiguous.
func Prune(dataDir string, maxBytes int64, maxAge time.Duration, hold func(archive string) bool, dry bool, now time.Time) Pruned {
	var res Pruned
	arch := Archives(dataDir)
	sizes := make([]int64, len(arch))
	var total int64
	for i, p := range arch {
		if fi, err := os.Stat(p); err == nil {
			sizes[i] = fi.Size()
			total += fi.Size()
		}
	}
	for i, p := range arch {
		at := archivedAt(p)
		if at.IsZero() {
			if fi, err := os.Stat(p); err == nil {
				at = fi.ModTime()
			}
		}
		over := func(f int64) bool {
			return (maxBytes > 0 && total > maxBytes*f) || (maxAge > 0 && now.Sub(at) > maxAge*time.Duration(f))
		}
		if !over(1) {
			break // archives are in time order: the rest are newer and the total is within the limit
		}
		held := hold != nil && hold(p)
		if held && !over(2) {
			break // waiting to be uploaded and not yet past the hard limit; later ones wait too
		}
		n := len(ReadFile(p))
		if !dry {
			// the marker first: from this moment the archive counts through it
			if os.WriteFile(tombstone(p), []byte(strconv.Itoa(n)+"\n"), 0o600) != nil {
				break
			}
			if os.Remove(p) != nil {
				_ = os.Remove(tombstone(p))
				break
			}
		}
		res.Files++
		res.Bytes += sizes[i]
		res.Events += n
		if held {
			res.Unsent += n
		}
		total -= sizes[i]
	}
	return res
}

// KeepNewest deletes all but the newest keep files matching pattern (a glob
// in dir whose names sort by time). It returns how many were removed and
// their size.
func KeepNewest(dir, pattern string, keep int, dry bool) (int, int64) {
	files, _ := filepath.Glob(filepath.Join(dir, pattern))
	sort.Strings(files)
	n, bytes := 0, int64(0)
	for i := 0; i < len(files)-keep; i++ {
		fi, err := os.Stat(files[i])
		if err != nil || fi.IsDir() {
			continue
		}
		if dry || os.Remove(files[i]) == nil {
			n++
			bytes += fi.Size()
		}
	}
	return n, bytes
}

// ReadFile returns every event of one journal file (plain or gzip), in order.
func ReadFile(p string) []Event {
	var out []Event
	readFile(p, Filter{}, &out)
	return out
}

// Read returns the matching events, oldest first.
func Read(dataDir string, f Filter) []Event {
	var out []Event
	if f.Archives {
		for _, p := range Archives(dataDir) {
			// An archive holds nothing newer than its rotation, so one rotated
			// well before Since is not opened. Two days of slack cover the
			// name being wall-clock time without a zone.
			if at := archivedAt(p); !f.Since.IsZero() && !at.IsZero() && at.Add(48*time.Hour).Before(f.Since) {
				continue
			}
			readFile(p, f, &out)
		}
	}
	readFile(filepath.Join(dataDir, FileName), f, &out)
	return out
}
