package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	"github.com/FaheemRafiq/threatscan/internal/notify"
	"github.com/FaheemRafiq/threatscan/internal/prompt"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

func init() {
	register("alerts", "recent alerts with the reason for each one", cmdAlerts)
}

func cmdAlerts(args []string) int {
	fs := newFlags("alerts", "[--last N] [--gui] [--json]")
	last := fs.Int("last", 10, "number of alerts to show")
	gui := fs.Bool("gui", false, "show them in a native dialog (what a notification click opens)")
	asJSON := fs.Bool("json", false, "print the raw alert records")
	if _, err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	c := mustCtx()
	u := ui.New(false, false)
	as, err := notify.ReadAlerts(filepath.Join(c.DataDir, "alerts.log"), *last)
	if err != nil {
		u.Err("Could not read alerts.log: " + err.Error())
		return 2
	}
	if *asJSON {
		b, _ := json.MarshalIndent(as, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	text := formatAlerts(as, false)
	if *gui {
		if err := prompt.ShowInfo("ThreatScan alerts", text); err == nil {
			return 0
		}
	}
	fmt.Print(formatAlerts(as, u.C("BOLD", "x") != "x"))
	return 0
}

// formatAlerts renders alerts oldest first, one block each.
func formatAlerts(as []notify.Alert, color bool) string {
	if len(as) == 0 {
		return "No alerts yet. The guard writes one here for every HIGH or CRITICAL finding.\n"
	}
	u := ui.New(!color, false)
	var b strings.Builder
	for _, a := range as {
		f := a.Finding
		name := f.Severity.String()
		if f.Severity >= findings.Critical {
			name = prompt.ThreatName(f)
		}
		ts := strings.Replace(a.TS, "T", " ", 1)
		fmt.Fprintf(&b, "%s  %s  %s\n", ts, u.C("BOLD", "["+f.Severity.String()+"]"), u.C("BOLD", name))
		fmt.Fprintf(&b, "      %s\n", f.Title)
		if f.Path != "" {
			fmt.Fprintf(&b, "      %s\n", f.Path)
		}
		fmt.Fprintf(&b, "      why: %s\n", a.Why)
		switch {
		case a.Response != "":
			fmt.Fprintf(&b, "      response: %s\n", a.Response)
		case f.Action != "":
			fmt.Fprintf(&b, "      response: %s\n", f.Action)
		}
		b.WriteString("\n")
	}
	b.WriteString("threatscan history   # restore / allow / remove quarantined files\n")
	return b.String()
}
