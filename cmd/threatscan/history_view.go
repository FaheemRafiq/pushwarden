package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/journal"
)

// parseSince accepts 30m, 24h, 7d, 2w or a date (2026-10-01).
func parseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("--since %q: use 30m, 24h, 7d, 2w or a date like 2026-10-01", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n < 0 {
		return time.Time{}, fmt.Errorf("--since %q: use 30m, 24h, 7d, 2w or a date like 2026-10-01", s)
	}
	unit := map[byte]time.Duration{'m': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour}[s[len(s)-1]]
	if unit == 0 {
		return time.Time{}, fmt.Errorf("--since %q: use 30m, 24h, 7d, 2w or a date like 2026-10-01", s)
	}
	return now.Add(-time.Duration(n) * unit), nil
}

// group is one distinct finding across all its sightings.
type group struct {
	first, last journal.Event
	count       int
}

// groupKey identifies a finding across sightings. Process and connection
// findings carry the pid in their title, so they group by what matched.
func groupKey(e journal.Event) string {
	switch e.Category {
	case "malicious_process", "c2_connection":
		return e.Category + "|" + e.Matched
	}
	if e.Key != "" {
		return e.Key
	}
	return e.Category + "|" + e.Title + "|" + e.Path
}

func collapse(evs []journal.Event) []group {
	idx := map[string]int{}
	var out []group
	for _, e := range evs {
		if e.Kind != journal.KindFinding {
			continue
		}
		k := groupKey(e)
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, group{first: e, last: e, count: 1})
			continue
		}
		out[i].last = e
		out[i].count++
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].last.TS < out[b].last.TS })
	return out
}

// state summarises where a finding stands after its latest sighting.
func state(e journal.Event) string {
	a := e.Action
	switch {
	case strings.HasPrefix(a, "kept"):
		return "allowed"
	case strings.Contains(a, "failed"):
		return "FAILED"
	case strings.HasPrefix(a, "would"):
		return "dry-run"
	case a != "":
		return "handled"
	}
	return "open"
}

func short(ts string) string {
	if len(ts) >= 16 {
		return strings.Replace(ts[:16], "T", " ", 1)
	}
	return ts
}

func tail[T any](xs []T, n int) []T {
	if n > 0 && len(xs) > n {
		return xs[len(xs)-n:]
	}
	return xs
}

func label(e journal.Event) string {
	l := e.Threat
	if l == "" || (e.Kind == journal.KindFinding && e.Sev != "CRITICAL") {
		l = e.Title
	}
	if len(l) > 44 {
		l = l[:43] + "…"
	}
	return l
}

func target(e journal.Event) string {
	switch {
	case e.Path != "":
		return e.Path
	case e.PID > 0:
		return "pid " + strconv.Itoa(e.PID)
	}
	if n, ok := e.Data["name"].(string); ok && n != "" {
		return n
	}
	if n, ok := e.Data["line"].(string); ok {
		return n
	}
	return ""
}

func details(b *strings.Builder, e journal.Event) {
	if e.Title != "" && e.Title != label(e) {
		fmt.Fprintf(b, "      finding: %s\n", e.Title)
	}
	if e.Matched != "" {
		fmt.Fprintf(b, "      matched: %s\n", e.Matched)
	}
	for _, ev := range e.Evidence {
		fmt.Fprintf(b, "      - %s\n", ev)
	}
	if e.Cmd != "" {
		fmt.Fprintf(b, "      cmd: %s\n", e.Cmd)
	}
	if c, ok := e.Data["copy"].(string); ok {
		fmt.Fprintf(b, "      copy: %s\n", c)
	}
	if e.Note != "" {
		fmt.Fprintf(b, "      note: %s\n", e.Note)
	}
	fmt.Fprintf(b, "      via: %s, v%s, indicators %s\n", e.Ctx, e.Ver, e.IOCs)
	if s := uploadState(e); s != "" {
		fmt.Fprintf(b, "      central upload: %s\n", s)
	}
}

// uploadState says whether an event is stored at upload_url: "uploaded",
// "waiting", or "" when the central upload is off.
func uploadState(e journal.Event) string {
	switch {
	case e.Uploaded == nil:
		return ""
	case *e.Uploaded:
		return "uploaded"
	}
	return "waiting"
}

// formatJournalAll prints every event in time order.
func formatJournalAll(evs []journal.Event, limit int, det bool) string {
	var b strings.Builder
	upCol := len(evs) > 0 && evs[0].Uploaded != nil // central upload is on: show each event's state
	if upCol {
		fmt.Fprintf(&b, "  %-16s %-9s %-9s %-9s %s\n", "when", "kind", "severity", "upload", "what")
	} else {
		fmt.Fprintf(&b, "  %-16s %-9s %-9s %s\n", "when", "kind", "severity", "what")
	}
	for _, e := range tail(evs, limit) {
		what := e.Title
		switch e.Kind {
		case journal.KindAction:
			what = e.Action + "  " + label(e) + "  " + target(e)
			if e.OK != nil && !*e.OK {
				what += "  [failed]"
			}
		case journal.KindDecision:
			what = "user answered " + e.Action + "  " + target(e)
		case journal.KindFinding:
			what = label(e) + "  " + target(e)
			if e.Action != "" {
				what += "  -> " + e.Action
			}
		case journal.KindSweep:
			if s, ok := e.Data["seconds"]; ok {
				what = fmt.Sprintf("%s: %v repos, %v critical, %v high, %v warning in %vs", e.Title, e.Data["repos"], e.Data["critical"], e.Data["high"], e.Data["warning"], s)
			}
		}
		if upCol {
			fmt.Fprintf(&b, "  %-16s %-9s %-9s %-9s %s\n", short(e.TS), e.Kind, e.Sev, uploadState(e), strings.TrimSpace(what))
		} else {
			fmt.Fprintf(&b, "  %-16s %-9s %-9s %s\n", short(e.TS), e.Kind, e.Sev, strings.TrimSpace(what))
		}
		if e.Kind == journal.KindFinding || e.Kind == journal.KindAction {
			if e.Why != "" {
				fmt.Fprintf(&b, "      why: %s\n", e.Why)
			}
			if e.Response != "" {
				fmt.Fprintf(&b, "      response: %s\n", e.Response)
			}
		}
		if e.Kind == journal.KindError && e.Note != "" && !det {
			fmt.Fprintf(&b, "      %s\n", e.Note)
		}
		if det {
			details(&b, e)
		}
	}
	return b.String()
}

// formatJournal is the default history view: each distinct finding once, with
// how often and when it was seen and where it stands, then what was done.
func formatJournal(evs []journal.Event, limit int, det bool) string {
	var b strings.Builder
	groups := tail(collapse(evs), limit)
	if len(groups) > 0 {
		b.WriteString("  DETECTIONS (each finding once; --all shows every sighting)\n")
		fmt.Fprintf(&b, "  %-16s %-9s %-8s %-6s %s\n", "last seen", "severity", "state", "seen", "what")
		for _, g := range groups {
			e := g.last
			fmt.Fprintf(&b, "  %-16s %-9s %-8s %-6s %s  %s\n", short(e.TS), e.Sev, state(e), strconv.Itoa(g.count)+"x", label(e), target(e))
			fmt.Fprintf(&b, "      why: %s\n", e.Why)
			if e.Response != "" {
				fmt.Fprintf(&b, "      response: %s\n", e.Response)
			}
			if g.count > 1 {
				fmt.Fprintf(&b, "      first seen: %s\n", short(g.first.TS))
			}
			if det {
				details(&b, e)
			}
		}
		b.WriteString("\n")
	}
	var acts []journal.Event
	for _, e := range evs {
		switch e.Kind {
		case journal.KindAction, journal.KindDecision, journal.KindError, journal.KindFeedback:
			acts = append(acts, e)
		}
	}
	if len(acts) > 0 {
		b.WriteString("  ACTIONS AND DECISIONS\n")
		fmt.Fprintf(&b, "  %-16s %-11s %-44s %s\n", "when", "action", "threat", "target")
		for _, e := range tail(acts, limit) {
			kind, extra := e.Action, ""
			switch e.Kind {
			case journal.KindDecision:
				kind = "user:" + e.Action
			case journal.KindError:
				kind = "ERROR"
			case journal.KindFeedback:
				kind = "feedback"
			}
			if n, ok := e.Data["removed_bytes"]; ok {
				extra += fmt.Sprintf("  (%v bytes stripped)", n)
			}
			if e.OK != nil && !*e.OK {
				extra += "  [failed]"
			}
			if d, _ := e.Data["dry_run"].(bool); d {
				extra += "  [dry-run]"
			}
			fmt.Fprintf(&b, "  %-16s %-11s %-44s %s%s\n", short(e.TS), kind, label(e), target(e), extra)
			if e.Response != "" {
				fmt.Fprintf(&b, "      why: %s\n", e.Response)
			}
			if e.Note != "" && e.Kind != journal.KindAction {
				fmt.Fprintf(&b, "      note: %s\n", e.Note)
			}
			if det {
				details(&b, e)
			}
		}
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return "  Nothing recorded for this selection.\n"
	}
	b.WriteString("  threatscan history --all | --details | --severity critical | --since 7d | --kind sweep | --path TEXT | --archive\n")
	b.WriteString("  threatscan history --restore <path> | --allow <path> [--note \"why\"] | --remove <path>\n")
	return b.String()
}
