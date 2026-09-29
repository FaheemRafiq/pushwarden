// Package protect performs responses: kill, quarantine, strip, delete, purge,
// restore, persistence removal.  Every step keeps a copy under
// <data_dir>/quarantine/ and appends to quarantine/index.jsonl (same format as v5).
package protect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	h "github.com/FaheemRafiq/threatscan/internal/helpers"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/platform"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

type F = findings.Finding

type Entry struct {
	TS           string   `json:"ts"`
	Type         string   `json:"type"`
	Original     string   `json:"original,omitempty"`
	Copy         string   `json:"copy,omitempty"`
	Title        string   `json:"title,omitempty"`
	Threat       string   `json:"threat,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
	PID          int      `json:"pid,omitempty"`
	Cmd          string   `json:"cmd,omitempty"`
	OK           *bool    `json:"ok,omitempty"`
	Cut          int      `json:"cut,omitempty"`
	RemovedBytes int      `json:"removed_bytes,omitempty"`
	SHA256       string   `json:"sha256,omitempty"`
	Name         string   `json:"name,omitempty"`
	Line         string   `json:"line,omitempty"`
	Copies       int      `json:"copies,omitempty"`
	DryRun       bool     `json:"dry_run,omitempty"`
	Reason       string   `json:"reason,omitempty"` // why this response was taken (findings.WhyAction)
}

// entryFor starts a history entry for a finding: what it was, the threat name,
// the evidence and the reason for the response taken.
func entryFor(f *F, typ string) Entry {
	return Entry{Type: typ, Original: f.Path, Title: f.Title, Threat: prompt.ThreatName(f), Evidence: f.Meta.Evidence,
		Reason: findings.WhyAction(f)}
}

type decision struct {
	Decision string  `json:"decision"`
	SHA256   string  `json:"sha256"`
	TS       float64 `json:"ts"`
	Title    string  `json:"title"`
}

type Protector struct {
	P         *platform.Info
	I         *iocs.IOCs
	UI        *ui.UI
	DryRun    bool
	QDir      string
	Index     string
	decisions map[string]decision
	decPath   string
	mu        sync.Mutex
	seq       int
}

func New(p *platform.Info, i *iocs.IOCs, dataDir string, u *ui.UI, dry bool) *Protector {
	q := filepath.Join(dataDir, "quarantine")
	_ = os.MkdirAll(q, 0o700)
	pr := &Protector{P: p, I: i, UI: u, DryRun: dry, QDir: q, Index: filepath.Join(q, "index.jsonl"),
		decPath: filepath.Join(dataDir, "decisions.json"), decisions: map[string]decision{}}
	if b, err := os.ReadFile(pr.decPath); err == nil {
		_ = json.Unmarshal(b, &pr.decisions)
	}
	return pr
}

func (pr *Protector) say(m string) {
	if pr.UI != nil {
		if pr.DryRun {
			m = "[dry-run] " + m
		}
		pr.UI.Info(m)
	}
}

func (pr *Protector) record(e Entry) {
	e.TS = time.Now().Format("2006-01-02T15:04:05")
	e.DryRun = pr.DryRun
	pr.mu.Lock()
	defer pr.mu.Unlock()
	f, err := os.OpenFile(pr.Index, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	f.Write(append(b, '\n'))
}

func (pr *Protector) slot(name string) string {
	pr.mu.Lock()
	pr.seq++
	n := pr.seq
	pr.mu.Unlock()
	return filepath.Join(pr.QDir, time.Now().Format("20060102-150405"), strconv.Itoa(int(time.Now().UnixMilli()%100000)+n), name)
}

func copyTree(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(src, p)
			t := filepath.Join(dst, rel)
			if info.IsDir() {
				return os.MkdirAll(t, 0o700)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				l, _ := os.Readlink(p)
				return os.Symlink(l, t)
			}
			return copyFile(p, t, info.Mode())
		})
	}
	return copyFile(src, dst, st.Mode())
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm()&0o600|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (pr *Protector) stash(src string) (string, error) {
	dst := pr.slot(filepath.Base(src))
	if pr.DryRun {
		return dst, nil
	}
	return dst, copyTree(src, dst)
}

// ── decisions ────────────────────────────────────────────────────────────────

func (pr *Protector) Remember(path, title string, d prompt.Verdict) {
	if path == "" {
		return
	}
	pr.mu.Lock()
	pr.decisions[path] = decision{Decision: string(d), SHA256: h.SHA256(path), TS: float64(time.Now().Unix()), Title: title}
	b, _ := json.MarshalIndent(pr.decisions, "", " ")
	pr.mu.Unlock()
	if !pr.DryRun {
		_ = os.WriteFile(pr.decPath, b, 0o600)
	}
}

func (pr *Protector) KeptByUser(f *F) bool {
	pr.mu.Lock()
	d, ok := pr.decisions[f.Path]
	pr.mu.Unlock()
	if !ok || d.Decision != string(prompt.Keep) || time.Since(time.Unix(int64(d.TS), 0)) > 30*24*time.Hour {
		return false
	}
	return h.SHA256(f.Path) == d.SHA256
}

func isPersistence(f *F) bool {
	return strings.HasPrefix(f.Category, "persistence_") || f.Category == "rat_footprint" || f.Category == "stage4_runtime"
}

func ActionWord(f *F) string {
	switch {
	case len(f.Meta.StripLines) > 0:
		return "Remove hidden entries"
	case f.Meta.Cleanable:
		return "Remove payload"
	case isPersistence(f):
		return "Remove persistence"
	}
	return "Delete the file"
}

// NeedsDecision: strong evidence about a file (not a live process).
func NeedsDecision(f *F) bool {
	return f.Severity == findings.Critical && f.Path != "" && (f.Meta.Cleanable || f.Meta.Quarantine || isPersistence(f))
}

// ── actions ──────────────────────────────────────────────────────────────────

func (pr *Protector) Kill(f *F) bool {
	pid := f.Meta.PID
	if pid <= 0 || pid == os.Getpid() {
		return false
	}
	if pr.DryRun {
		f.Action = fmt.Sprintf("would kill PID %d", pid)
		return true
	}
	ok := pr.P.Kill(pid)
	if ok {
		f.Action = fmt.Sprintf("killed PID %d", pid)
	} else {
		f.Action = fmt.Sprintf("kill PID %d failed (permission?)", pid)
	}
	e := entryFor(f, "kill")
	e.Original, e.PID, e.Cmd, e.OK = "", pid, f.Meta.Cmd, &ok
	pr.record(e)
	return ok
}

func (pr *Protector) Quarantine(f *F) bool {
	if f.Path == "" {
		return false
	}
	if _, err := os.Lstat(f.Path); err != nil {
		return false
	}
	cp, err := pr.stash(f.Path)
	if err != nil {
		f.Action = "quarantine failed (copy error)"
		return false
	}
	if !pr.DryRun {
		if err := os.RemoveAll(f.Path); err != nil {
			f.Action = "quarantine failed: " + err.Error()
			return false
		}
	}
	f.Action = "quarantined to " + cp
	e := entryFor(f, "quarantine")
	e.Copy = cp
	pr.record(e)
	pr.say("Quarantined " + f.Path)
	return true
}

// Clean strips an appended single-line payload; anything else quarantines the whole file.
// A finding with StripLines removes those entries (whole lines) instead.
func (pr *Protector) Clean(f *F) bool {
	if len(f.Meta.StripLines) > 0 {
		return pr.cleanLines(f)
	}
	raw := h.ReadBytes(f.Path, 20<<20)
	if raw == nil {
		return false
	}
	text := string(raw)
	cut := h.PayloadCut(text, pr.I)
	tail := ""
	if cut > 0 {
		tail = strings.TrimRight(text[cut:], " \t\r\n")
	}
	if cut <= 0 || tail == "" || strings.Contains(tail, "\n") {
		f.Meta.MidFileInjection = true
		if pr.Quarantine(f) {
			f.Action = "payload is not a trailing append; whole file " + f.Action
			return true
		}
		return false
	}
	cleaned := strings.TrimRight(text[:cut], " \t")
	if !strings.HasSuffix(cleaned, "\n") {
		cleaned += "\n"
	}
	removed := len(text) - len(cleaned)
	cp, err := pr.stash(f.Path)
	if err != nil {
		f.Action = "clean failed (backup error)"
		return false
	}
	if !pr.DryRun {
		st, _ := os.Stat(f.Path)
		if err := os.WriteFile(f.Path, []byte(cleaned), st.Mode().Perm()); err != nil {
			f.Action = "clean failed: " + err.Error()
			return false
		}
	}
	f.Meta.Cut = cut
	f.Action = fmt.Sprintf("removed %d bytes of payload (original in %s)", removed, cp)
	e := entryFor(f, "clean")
	e.Copy, e.Cut, e.RemovedBytes = cp, cut, removed
	pr.record(e)
	pr.say("Stripped payload from " + f.Path)
	return true
}

// cleanLines removes every line whose entry (ignoring whitespace and a leading
// slash) is one of Meta.StripLines. Other lines and line endings are kept.
func (pr *Protector) cleanLines(f *F) bool {
	raw := h.ReadBytes(f.Path, 20<<20)
	if raw == nil {
		return false
	}
	drop := map[string]bool{}
	for _, l := range f.Meta.StripLines {
		drop[l] = true
	}
	lines := strings.SplitAfter(string(raw), "\n")
	var kept, removed []string
	for _, l := range lines {
		entry := strings.TrimPrefix(strings.TrimSpace(l), "/")
		if drop[entry] {
			removed = append(removed, entry)
			continue
		}
		kept = append(kept, l)
	}
	if len(removed) == 0 {
		f.Action = "clean failed: entries not found"
		return false
	}
	cleaned := strings.Join(kept, "")
	cp, err := pr.stash(f.Path)
	if err != nil {
		f.Action = "clean failed (backup error)"
		return false
	}
	if !pr.DryRun {
		st, _ := os.Stat(f.Path)
		if err := os.WriteFile(f.Path, []byte(cleaned), st.Mode().Perm()); err != nil {
			f.Action = "clean failed: " + err.Error()
			return false
		}
	}
	f.Action = fmt.Sprintf("removed %d line(s): %s (original in %s)", len(removed), strings.Join(removed, ", "), cp)
	e := entryFor(f, "clean")
	e.Copy, e.RemovedBytes, e.Line = cp, len(raw)-len(cleaned), strings.Join(removed, ", ")
	pr.record(e)
	pr.say("Removed " + strings.Join(removed, ", ") + " from " + f.Path)
	return true
}

// Delete removes permanently (user confirmed); only a record is kept.
func (pr *Protector) Delete(f *F) bool {
	if _, err := os.Lstat(f.Path); err != nil {
		return false
	}
	sum := h.SHA256(f.Path)
	if !pr.DryRun {
		if err := os.RemoveAll(f.Path); err != nil {
			f.Action = "delete failed: " + err.Error()
			return false
		}
	}
	f.Action = "deleted (user confirmed)"
	e := entryFor(f, "delete")
	e.SHA256 = sum
	pr.record(e)
	pr.say("Deleted " + f.Path)
	return true
}

func (pr *Protector) RemovePersistence(f *F) bool {
	m := f.Meta
	switch {
	case m.SystemdUnit != "" && pr.P.IsLinux():
		if !pr.DryRun {
			pr.P.RunRC(20*time.Second, "systemctl", "--user", "disable", "--now", m.SystemdUnit)
		}
		ok := pr.Quarantine(f)
		if !pr.DryRun {
			pr.P.RunRC(20*time.Second, "systemctl", "--user", "daemon-reload")
		}
		return ok
	case m.LaunchdPlist != "" && pr.P.IsMac():
		if !pr.DryRun {
			pr.P.RunRC(20*time.Second, "launchctl", "bootout", fmt.Sprintf("gui/%d", os.Getuid()), m.LaunchdPlist)
		}
		return pr.Quarantine(f)
	case m.Schtask != "" && pr.P.IsWindows():
		if !pr.DryRun {
			pr.P.RunRC(30*time.Second, "schtasks", "/Delete", "/TN", m.Schtask, "/F")
		}
		f.Action = "deleted scheduled task " + m.Schtask
		e := entryFor(f, "schtask")
		e.Original, e.Name = "", m.Schtask
		pr.record(e)
		return true
	case m.CronLine != "" && !pr.P.IsWindows():
		rc, cur, _ := pr.P.RunRC(15*time.Second, "crontab", "-l")
		if rc != 0 || !strings.Contains(cur, strings.TrimSpace(m.CronLine)) {
			f.Action = fmt.Sprintf("crontab could not be read safely; edit it by hand (rc=%d)", rc)
			return false
		}
		var keep []string
		for _, l := range strings.Split(cur, "\n") {
			if strings.TrimSpace(l) != strings.TrimSpace(m.CronLine) {
				keep = append(keep, l)
			}
		}
		if !pr.DryRun {
			bak := pr.slot("crontab.bak")
			_ = os.MkdirAll(filepath.Dir(bak), 0o700)
			_ = os.WriteFile(bak, []byte(cur), 0o600)
			if rc, se := pr.P.RunInput(20*time.Second, strings.TrimRight(strings.Join(keep, "\n"), "\n")+"\n", "crontab", "-"); rc != 0 {
				f.Action = "crontab rewrite failed: " + h.Trunc(strings.TrimSpace(se), 120)
				return false
			}
		}
		f.Action = "removed crontab line (backup in quarantine)"
		e := entryFor(f, "cron")
		e.Original, e.Line = "", m.CronLine
		pr.record(e)
		return true
	case m.Quarantine:
		return pr.Quarantine(f)
	}
	return false
}

// ── policy ───────────────────────────────────────────────────────────────────

func (pr *Protector) reversible(f *F) bool {
	switch {
	case isPersistence(f):
		return pr.RemovePersistence(f)
	case f.Meta.Cleanable:
		return pr.Clean(f)
	case f.Meta.Quarantine:
		return pr.Quarantine(f)
	}
	return false
}

func (pr *Protector) confirmed(f *F) bool {
	switch {
	case f.Meta.Cleanable:
		return pr.Clean(f)
	case isPersistence(f):
		return pr.RemovePersistence(f)
	}
	return pr.Delete(f)
}

// DecideFn asks the user; nil means act without asking (reversible actions only).
type DecideFn func(f *F, action string) prompt.Verdict

// Respond applies policy and returns the findings that were acted on.
// Live processes are never put to a vote: they are killed when autoKill is set.
func (pr *Protector) Respond(fs []*F, autoKill, autoClean bool, decide DecideFn) []*F {
	var acted []*F
	for _, f := range fs {
		if f.Severity < findings.Critical {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					f.Action = fmt.Sprintf("response failed: %v", r)
				}
			}()
			if f.Category == "malicious_process" || f.Category == "c2_connection" {
				if autoKill && f.Meta.Kill && pr.Kill(f) {
					acted = append(acted, f)
				}
				return
			}
			if !NeedsDecision(f) {
				return
			}
			if pr.KeptByUser(f) {
				f.Action = "kept (user decision, unchanged file)"
				return
			}
			if decide != nil {
				switch v := decide(f, ActionWord(f)); v {
				case prompt.Delete:
					if pr.confirmed(f) {
						acted = append(acted, f)
					}
				case prompt.Keep:
					pr.Remember(f.Path, f.Title, prompt.Keep)
					f.Action = "kept by user"
				default:
					if !autoClean {
						f.Action = fmt.Sprintf("no decision (%s); left in place", v)
					} else if pr.reversible(f) {
						f.Action = fmt.Sprintf("no decision (%s); %s", v, f.Action)
						acted = append(acted, f)
					}
				}
			} else if autoClean && pr.reversible(f) {
				acted = append(acted, f)
			}
		}()
		if pr.DryRun && f.Action != "" && !strings.HasPrefix(f.Action, "would") {
			f.Action = "would have: " + f.Action
		}
	}
	return acted
}

// ── history ──────────────────────────────────────────────────────────────────

func (pr *Protector) Entries() []Entry {
	fh, err := os.Open(pr.Index)
	if err != nil {
		return nil
	}
	defer fh.Close()
	var out []Entry
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// Restore puts the most recent copy of original back.
func (pr *Protector) Restore(original string) bool {
	es := pr.Entries()
	for i := len(es) - 1; i >= 0; i-- {
		e := es[i]
		if e.Original != original || e.Copy == "" || e.DryRun {
			continue
		}
		if _, err := os.Lstat(e.Copy); err != nil {
			continue
		}
		_ = os.RemoveAll(original)
		if err := copyTree(e.Copy, original); err != nil {
			return false
		}
		pr.record(Entry{Type: "restore", Original: original, Copy: e.Copy})
		return true
	}
	return false
}

// Purge deletes the quarantined copies of original permanently.
func (pr *Protector) Purge(original string) int {
	n := 0
	for _, e := range pr.Entries() {
		if e.Original == original && e.Copy != "" && !e.DryRun {
			if _, err := os.Lstat(e.Copy); err == nil && os.RemoveAll(e.Copy) == nil {
				n++
			}
		}
	}
	if n > 0 {
		pr.record(Entry{Type: "purge", Original: original, Copies: n, Title: "user removed from quarantine"})
	}
	return n
}
