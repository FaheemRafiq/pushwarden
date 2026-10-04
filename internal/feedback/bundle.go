package feedback

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/FaheemRafiq/pushwarden/internal/journal"
)

// Bundle describes what was written, for the summary shown to the user.
type Bundle struct {
	Path   string
	Files  []string
	Events int
}

func tailLines(p string, n int) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}

// WriteBundle writes a zip with the journal for the period, the guard log
// tail, the latest report, the effective config and a summary. Every file goes through
// the redactor unless it is nil.
func WriteBundle(out, dataDir, summary, configJSON string, since time.Time, red *Redactor) (*Bundle, error) {
	fh, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	zw := zip.NewWriter(fh)
	b := &Bundle{Path: out}
	add := func(name, content string) error {
		if content == "" {
			return nil
		}
		if red != nil {
			content = red.Text(content)
		}
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		b.Files = append(b.Files, name)
		return err
	}
	evs := journal.Read(dataDir, journal.Filter{Since: since, Archives: true})
	b.Events = len(evs)
	var jl strings.Builder
	for _, e := range evs {
		line, _ := json.Marshal(e)
		jl.Write(line)
		jl.WriteByte('\n')
	}
	readme := fmt.Sprintf("PushWarden feedback bundle, created %s\n\nPeriod: since %s\nEvents: %d\nRedacted: %v (home folder -> ~, user and host names removed, token-shaped strings masked)\n\n"+
		"journal.jsonl      every finding, action, decision, sweep, update and error in the period\n"+
		"guard.log          the last 2000 lines of the guard's log\n"+
		"latest-report.json the most recent full scan report\n"+
		"config.json        settings (webhook, feedback and upload URLs and keys masked)\n"+
		"summary.txt        version, system and protection status\n",
		time.Now().Format(time.RFC3339), since.Format("2006-01-02 15:04"), len(evs), red != nil)
	for _, f := range []struct{ name, content string }{
		{"README.txt", readme},
		{"summary.txt", summary},
		{"journal.jsonl", jl.String()},
		{"guard.log", tailLines(filepath.Join(dataDir, "guard.log"), 2000)},
		{"latest-report.json", tailLines(filepath.Join(dataDir, "reports", "latest.json"), 100000)},
		{"config.json", configJSON}, // the settings in effect, defaults included
	} {
		if err := add(f.name, f.content); err != nil {
			zw.Close()
			return nil, err
		}
	}
	return b, zw.Close()
}
