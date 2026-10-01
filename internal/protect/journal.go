package protect

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/journal"
)

// eventFor converts a history entry into a journal action event.
func eventFor(e Entry, ctx string) journal.Event {
	ev := journal.Event{Ctx: ctx, Kind: journal.KindAction, Action: e.Type, Path: e.Original, PID: e.PID, Cmd: e.Cmd, OK: e.OK,
		Threat: e.Threat, Title: e.Title, Evidence: e.Evidence, Response: e.Reason}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", e.TS, time.Local); err == nil {
		ev.TS = t.Format(time.RFC3339)
	}
	data := map[string]any{}
	if e.Copy != "" {
		data["copy"] = e.Copy
	}
	if e.RemovedBytes > 0 {
		data["removed_bytes"] = e.RemovedBytes
	}
	if e.SHA256 != "" {
		data["sha256"] = e.SHA256
	}
	if e.Name != "" {
		data["name"] = e.Name
	}
	if e.Line != "" {
		data["line"] = e.Line
	}
	if e.Copies > 0 {
		data["copies"] = e.Copies
	}
	if e.DryRun {
		data["dry_run"] = true
	}
	if len(data) > 0 {
		ev.Data = data
	}
	return ev
}

// AttachJournal mirrors every history entry this protector writes into j.
func (pr *Protector) AttachJournal(j *journal.Journal, ctx string) {
	if j == nil {
		return
	}
	pr.OnRecord = func(e Entry) { j.Write(eventFor(e, ctx)) }
}

// ImportHistory copies the actions recorded before the journal existed into
// it, once: the journal must be the complete record from the first install.
func ImportHistory(j *journal.Journal, dataDir string) {
	if j == nil || j.Disabled || journal.Exists(dataDir) {
		return
	}
	fh, err := os.Open(filepath.Join(dataDir, "quarantine", "index.jsonl"))
	if err != nil {
		return
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Type != "" {
			j.Write(eventFor(e, "imported"))
		}
	}
}
