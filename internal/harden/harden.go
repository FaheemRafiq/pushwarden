// Package harden applies preventive settings: VS Code-family editors, npm, pre-commit hook.
package harden

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

// Settings that neutralise stage 1 (folderOpen tasks) and enforce workspace trust.
var EditorSettings = []struct {
	Key   string
	Value any
}{
	{"task.allowAutomaticTasks", "off"},
	{"security.workspace.trust.enabled", true},
	{"security.workspace.trust.startupPrompt", "always"},
	{"security.workspace.trust.untrustedFiles", "prompt"},
	{"security.workspace.trust.emptyWindow", false},
	{"git.openRepositoryInParentFolders", "prompt"},
}

func jsonPointer(key string) string {
	return "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

// Editor merges EditorSettings into settings.json, keeping comments and formatting.
func Editor(path string, dry bool) (bool, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		raw = []byte("{}")
	}
	v, err := hujson.Parse(raw)
	if err != nil {
		return false, nil, fmt.Errorf("could not parse %s (%v); set task.allowAutomaticTasks=off by hand", path, err)
	}
	std := v.Clone()
	std.Standardize()
	var cur map[string]any
	if json.Unmarshal(std.Pack(), &cur) != nil {
		return false, nil, fmt.Errorf("%s is not a JSON object", path)
	}
	var notes []string
	var ops []string
	added := map[string]bool{}
	for _, s := range EditorSettings {
		old, had := cur[s.Key]
		if had && fmt.Sprint(old) == fmt.Sprint(s.Value) {
			continue
		}
		val, _ := json.Marshal(s.Value)
		op := "add"
		if had {
			op = "replace"
		} else {
			added[s.Key] = true
		}
		ops = append(ops, fmt.Sprintf(`{"op":%q,"path":%q,"value":%s}`, op, jsonPointer(s.Key), val))
		o := "<unset>"
		if had {
			o = fmt.Sprintf("%v", old)
		}
		notes = append(notes, fmt.Sprintf("%s: %s -> %v", s.Key, o, s.Value))
	}
	if len(ops) == 0 {
		return false, nil, nil
	}
	if err := v.Patch([]byte("[" + strings.Join(ops, ",") + "]")); err != nil {
		return false, nil, err
	}
	indentAdded(&v, added)

	if !dry {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if len(raw) > 2 {
			_ = os.WriteFile(fmt.Sprintf("%s.threatscan-%d.bak", path, time.Now().Unix()), raw, 0o600)
			// keep the two newest backups of this file; older ones only pile up
			if baks, _ := filepath.Glob(path + ".threatscan-*.bak"); len(baks) > 2 {
				sort.Slice(baks, func(a, b int) bool { return bakTime(baks[a]) < bakTime(baks[b]) })
				for _, old := range baks[:len(baks)-2] {
					_ = os.Remove(old)
				}
			}
		}
		if err := os.WriteFile(path, v.Pack(), 0o644); err != nil {
			return false, nil, err
		}
	}
	return true, notes, nil
}

// indentAdded puts each newly added member on its own line, using the
// indentation of the file's existing members (so the user's style is kept).
func indentAdded(v *hujson.Value, added map[string]bool) {
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		return
	}
	indent := "    "
	for _, m := range obj.Members {
		lit, _ := m.Name.Value.(hujson.Literal)
		if added[lit.String()] {
			continue
		}
		b := string(m.Name.BeforeExtra)
		if i := strings.LastIndex(b, "\n"); i >= 0 {
			indent = b[i+1:]
			break
		}
	}
	for i := range obj.Members {
		m := &obj.Members[i]
		lit, _ := m.Name.Value.(hujson.Literal)
		if added[lit.String()] {
			m.Name.BeforeExtra = hujson.Extra("\n" + indent)
			m.Value.BeforeExtra = hujson.Extra(" ")
		}
	}
	if !strings.Contains(string(obj.AfterExtra), "\n") {
		obj.AfterExtra = hujson.Extra("\n")
	}
}

// EditorStatus returns task.allowAutomaticTasks for display.
func EditorStatus(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "<no settings.json>"
	}
	v, err := hujson.Standardize(raw)
	if err != nil {
		return "<parse error>"
	}
	var m map[string]any
	if json.Unmarshal(v, &m) != nil {
		return "<parse error>"
	}
	if x, ok := m["task.allowAutomaticTasks"]; ok {
		return fmt.Sprint(x)
	}
	return "<unset>"
}

var ignoreScripts = regexp.MustCompile(`(?m)^\s*ignore-scripts\s*=.*\n?`)

func NPM(home string, dry bool) (bool, string) {
	rc := filepath.Join(home, ".npmrc")
	b, _ := os.ReadFile(rc)
	c := string(b)
	if regexp.MustCompile(`(?m)^\s*ignore-scripts\s*=\s*true\s*$`).MatchString(c) {
		return false, "already set"
	}
	c = ignoreScripts.ReplaceAllString(c, "")
	if strings.TrimSpace(c) != "" {
		c = strings.TrimRight(c, "\n") + "\n"
	}
	c += "ignore-scripts=true\n"
	if !dry {
		_ = os.WriteFile(rc, []byte(c), 0o600)
	}
	return true, "ignore-scripts=true written (run `npm install --ignore-scripts=false` for packages that need it)"
}

func UndoNPM(home string) bool {
	rc := filepath.Join(home, ".npmrc")
	b, err := os.ReadFile(rc)
	if err != nil {
		return false
	}
	n := regexp.MustCompile(`(?m)^\s*ignore-scripts\s*=\s*true\s*\n?`).ReplaceAllString(string(b), "")
	if n == string(b) {
		return false
	}
	return os.WriteFile(rc, []byte(n), 0o600) == nil
}

const preCommit = `#!/bin/sh
# ThreatScan pre-commit hook: refuse to commit files with PolinRider indicators.
if command -v threatscan >/dev/null 2>&1; then
  threatscan check-staged || exit 1
fi
`

func PreCommit(repo string, dry bool) (bool, string) {
	hooks := filepath.Join(repo, ".git", "hooks")
	if st, err := os.Stat(hooks); err != nil || !st.IsDir() {
		return false, repo + " is not a git repository"
	}
	hook := filepath.Join(hooks, "pre-commit")
	body := preCommit + "exit 0\n"
	if b, err := os.ReadFile(hook); err == nil {
		if strings.Contains(string(b), "threatscan") {
			return false, "already installed"
		}
		if !dry {
			_ = os.Rename(hook, filepath.Join(hooks, "pre-commit.pre-threatscan"))
		}
		body = preCommit + `exec "$(dirname "$0")/pre-commit.pre-threatscan" "$@"` + "\n"
	}
	if !dry {
		if err := os.WriteFile(hook, []byte(body), 0o755); err != nil {
			return false, err.Error()
		}
	}
	return true, "installed " + hook
}

// bakTime reads the timestamp out of "<file>.threatscan-<unix>.bak".
func bakTime(p string) int64 {
	p = strings.TrimSuffix(p, ".bak")
	n, _ := strconv.ParseInt(p[strings.LastIndex(p, "-")+1:], 10, 64)
	return n
}
