// threatscan:allow-signatures
// Package scan contains the repository and host scanners (read-only).
package scan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FaheemRafiq/threatscan/internal/findings"
	h "github.com/FaheemRafiq/threatscan/internal/helpers"
	"github.com/FaheemRafiq/threatscan/internal/iocs"
	"github.com/FaheemRafiq/threatscan/internal/ui"
)

type F = findings.Finding

const (
	crit = findings.Critical
	high = findings.High
	warn = findings.Warning
	info = findings.Info
)

type Repo struct {
	Root         string
	UI           *ui.UI
	I            *iocs.IOCs
	JSAll        bool
	Deep         bool
	Verbose      bool
	Exclude      []string
	FilesChecked int
}

func NewRepo(root string, u *ui.UI, i *iocs.IOCs) *Repo {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	return &Repo{Root: abs, UI: u, I: i, JSAll: true}
}

func (r *Repo) skip(name string) bool {
	if r.Deep && (name == "node_modules" || name == "vendor") {
		return false
	}
	return h.SkipDir(name)
}

// ── discovery ────────────────────────────────────────────────────────────────

func (r *Repo) walkDirs(fn func(dir string, entries []fs.DirEntry) (descend bool)) {
	var walk func(string)
	walk = func(dir string) {
		if h.IsUnder(dir, r.Exclude) {
			return
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		if !fn(dir, ents) {
			return
		}
		for _, e := range ents {
			if e.IsDir() && !r.skip(e.Name()) && e.Type()&fs.ModeSymlink == 0 {
				walk(filepath.Join(dir, e.Name()))
			}
		}
	}
	walk(r.Root)
}

func has(ents []fs.DirEntry, name string) bool {
	for _, e := range ents {
		if e.Name() == name {
			return true
		}
	}
	return false
}

// Discover returns (git repos, non-git projects) under Root.
func (r *Repo) Discover() ([]string, []string) {
	var repos, projects []string
	r.walkDirs(func(dir string, ents []fs.DirEntry) bool {
		if has(ents, ".git") {
			repos = append(repos, dir)
			return true // nested repos/submodules still scanned; .git itself is skipped
		}
		if has(ents, "package.json") || has(ents, "go.mod") || has(ents, "composer.json") {
			if !insideAny(dir, repos) {
				projects = append(projects, dir)
				return false
			}
		}
		return true
	})
	return repos, projects
}

func insideAny(dir string, roots []string) bool {
	for _, r := range roots {
		if strings.HasPrefix(dir, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ── file-level checks ────────────────────────────────────────────────────────

func (r *Repo) withEvidence(f *F, content string) *F {
	f.Meta.Evidence = h.Evidence(content, r.I, 12)
	var lines []string
	for i, e := range f.Meta.Evidence {
		if i >= 6 {
			break
		}
		lines = append(lines, "- "+e)
	}
	if len(lines) > 0 {
		if f.Details != "" {
			f.Details += "\n"
		}
		f.Details += strings.Join(lines, "\n")
	}
	return f
}

func (r *Repo) CheckSignatures(fp string) []*F {
	content := h.ReadText(fp, 20<<20)
	if content == "" {
		return nil
	}
	r.FilesChecked++
	if h.IsAllowlisted(fp, r.I) {
		return nil
	}
	I := r.I
	name := filepath.Base(fp)
	var out []*F
	for _, sig := range I.LiteralSignatures {
		if strings.Contains(content, sig) {
			out = append(out, r.withEvidence(&F{Severity: crit, Category: "config_injection",
				Title: "PolinRider signature in " + name, Path: fp, Details: "Literal: " + h.Trunc(sig, 70),
				Remediation: "Remove everything after the legitimate config in:\n  " + fp +
					"\n  Look for global['!'], global['_V'], _$_1e42, MDy(, or Cot%3t=shtP.",
				Meta: findings.Meta{Cleanable: true}}, content))
			break
		}
	}
	if len(out) == 0 && I.Marker.MatchString(content) {
		out = append(out, r.withEvidence(&F{Severity: crit, Category: "config_injection",
			Title: "PolinRider marker regex in " + name, Path: fp,
			Details:     "Generalised campaign marker matched (covers all A#- / 8-stN rotations).",
			Remediation: "Inspect and strip the obfuscated block from:\n  " + fp, Meta: findings.Meta{Cleanable: true}}, content))
	}
	for _, k := range I.XorKeys {
		if strings.Contains(content, k) {
			out = append(out, r.withEvidence(&F{Severity: crit, Category: "xor_key", Title: "PolinRider XOR key in " + name,
				Path: fp, Details: "Key: " + k, Remediation: "This file contains the payload decryption key. Delete or clean:\n  " + fp,
				Meta: findings.Meta{Cleanable: true}}, content))
			break
		}
	}
	var hosts, wallets []string
	for _, x := range I.BlockchainRPCHosts {
		if strings.Contains(content, x) {
			hosts = append(hosts, x)
		}
	}
	low := strings.ToLower(content)
	for _, w := range I.Wallets {
		if strings.Contains(low, strings.ToLower(w)) {
			wallets = append(wallets, w)
		}
	}
	if len(wallets) > 0 || (len(hosts) > 0 && I.HasMarker(content)) {
		out = append(out, r.withEvidence(&F{Severity: crit, Category: "blockchain_c2",
			Title: "Blockchain dead-drop indicators in " + name, Path: fp,
			Details:     "RPC hosts: " + join(hosts) + "\nWallets: " + join(wallets),
			Remediation: "File references PolinRider dead-drop wallets/RPCs. Clean or delete:\n  " + fp}, content))
	}
	var ips, c2hosts, paths []string
	for _, x := range I.MaliciousIPs {
		if strings.Contains(content, x) {
			ips = append(ips, x)
		}
	}
	for _, x := range I.MaliciousHosts {
		if strings.Contains(content, x) {
			c2hosts = append(c2hosts, x)
		}
	}
	for _, x := range I.C2URLPaths {
		if strings.Contains(content, x) {
			paths = append(paths, x)
		}
	}
	if len(ips) > 0 || len(c2hosts) > 0 || (len(paths) > 0 && strings.Contains(content, "http")) {
		out = append(out, r.withEvidence(&F{Severity: crit, Category: "c2_reference", Title: "C2 reference in " + name, Path: fp,
			Details:     "IPs: " + join(ips) + "\nHosts: " + join(c2hosts) + "\nPaths: " + join(paths),
			Remediation: "Hard-coded C2 infrastructure. Clean or delete:\n  " + fp}, content))
	}
	for _, t := range I.TelegramIndicators {
		if strings.Contains(content, t) {
			out = append(out, r.withEvidence(&F{Severity: crit, Category: "telegram_exfil", Title: "Telegram exfiltration bot in " + name,
				Path: fp, Details: "Indicator: " + t, Remediation: "OmniStealer exfil channel. Delete:\n  " + fp}, content))
			break
		}
	}
	if len(I.FileHashes) > 0 {
		sum := sha256.Sum256([]byte(content))
		if d := hex.EncodeToString(sum[:]); I.FileHashes[d] {
			out = append(out, &F{Severity: crit, Category: "known_malicious_file", Title: "Known PolinRider file: " + name,
				Path: fp, Details: "SHA-256 " + d + " is a published indicator.",
				Remediation: "Delete or restore a clean copy of:\n  " + fp, Meta: findings.Meta{Quarantine: true}})
		}
	}
	if strings.EqualFold(filepath.Ext(fp), ".php") && phpRunsNode(content) {
		out = append(out, r.withEvidence(&F{Severity: high, Category: "php_node_exec", Title: "PHP file runs Node.js code: " + name,
			Path: fp, Details: "shell_exec/exec/system together with node -e: the PHP route the PolinRider Packagist compromise used (Sept 2026).",
			Remediation: "Review " + fp + "; a legitimate PHP file rarely runs inline JavaScript through the shell."}, content))
	}
	return out
}

var (
	phpExecNodeRe = regexp.MustCompile(`(?is)\b(?:shell_exec|exec|system|passthru|proc_open|popen)\s*\(\s*[^;]{0,400}?\bnode(?:\.exe)?['"]?\s+(?:-e|--eval|-p|--print)\b`)
	phpNodeVarRe  = regexp.MustCompile(`(?i)\$(\w+)\s*=\s*['"]\s*node(?:\.exe)?\s+(?:-e|--eval|-p|--print)\b`)
)

// phpRunsNode: a shell call in PHP whose command is `node -e ...`, either inline
// or through a variable assigned such a string.
func phpRunsNode(content string) bool {
	if phpExecNodeRe.MatchString(content) {
		return true
	}
	for _, m := range phpNodeVarRe.FindAllStringSubmatch(content, 20) {
		call := regexp.MustCompile(`(?i)\b(?:shell_exec|exec|system|passthru|proc_open|popen)\s*\(\s*\$` + regexp.QuoteMeta(m[1]) + `\b`)
		if call.MatchString(content) {
			return true
		}
	}
	return false
}

func join(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ", ")
}

var trailingPad = regexp.MustCompile(`\s{40,}\S`)

func (r *Repo) CheckSizeAndLines(fp string) []*F {
	st, err := os.Stat(fp)
	if err != nil {
		return nil
	}
	var out []*F
	name := filepath.Base(fp)
	if st.Size() > 4096 {
		out = append(out, &F{Severity: warn, Category: "file_anomaly", Title: fmt.Sprintf("%s is large (%d bytes)", name, st.Size()),
			Path: fp, Details: "Framework config files are normally <1 KB. PolinRider appends 5-80 KB payloads.",
			Remediation: "Inspect " + fp + "; strip anything after the real export."})
	}
	for i, line := range strings.Split(h.ReadText(fp, 20<<20), "\n") {
		if len(line) > 400 {
			sev, title := warn, fmt.Sprintf("%s line %d is %d chars", name, i+1, len(line))
			if trailingPad.MatchString(line) {
				sev, title = high, title+" with hidden payload after whitespace"
			}
			out = append(out, &F{Severity: sev, Category: "file_anomaly", Title: title, Path: fp,
				Details:     "PolinRider hides its payload after ~280 spaces on the export line.",
				Remediation: fmt.Sprintf("Open %s, go to line %d, scroll right, delete the trailing code.", fp, i+1)})
			break
		}
	}
	return out
}

var (
	hookRe1 = regexp.MustCompile(`atob\s*\(\s*process\.env[^)]*\)?`)
	hookRe2 = regexp.MustCompile(`eval\s*\(\s*atob[^)]*\)?`)
)

func (r *Repo) CheckEntryHook(fp string) []*F {
	content := h.ReadText(fp, 20<<20)
	loc := hookRe1.FindStringIndex(content)
	if loc == nil {
		loc = hookRe2.FindStringIndex(content)
	}
	if loc == nil {
		return nil
	}
	ev := append([]string{fmt.Sprintf("stage-1 hook %q at offset %d", h.Trunc(content[loc[0]:loc[1]], 50), loc[0])}, h.Evidence(content, r.I, 6)...)
	return []*F{{Severity: crit, Category: "entry_hook", Title: "Malicious entry hook in " + filepath.Base(fp), Path: fp,
		Details:     "atob(process.env...)/eval(atob...) decodes a base64 URL from env and evals the response.",
		Remediation: "Remove the injected async IIFE from:\n  " + fp, Meta: findings.Meta{Cleanable: true, Evidence: ev}}}
}

// ── repo-level checks ────────────────────────────────────────────────────────

func lineRe(name string, leadingSlash bool) *regexp.Regexp {
	p := `(?m)^\s*`
	if leadingSlash {
		p += `/?`
	}
	return regexp.MustCompile(p + regexp.QuoteMeta(name) + `\s*$`)
}

func (r *Repo) CheckPropagation(repo string) []*F {
	var out []*F
	for _, name := range r.I.PropagationScripts {
		p := filepath.Join(repo, name)
		if _, err := os.Stat(p); err == nil {
			ev := []string{fmt.Sprintf("file name %q is the PolinRider git-rewrite orchestrator", name)}
			c := h.ReadText(p, 1<<20)
			for _, k := range []string{"--amend", "GIT_COMMITTER_DATE", "--force", "--no-verify"} {
				if strings.Contains(c, k) {
					ev = append(ev, fmt.Sprintf("contains %q", k))
				}
			}
			out = append(out, &F{Severity: crit, Category: "propagation_script", Title: "Propagation script: " + name, Path: p,
				Details:     "Rewrites git history with forged GIT_COMMITTER_DATE and force-pushes.",
				Remediation: "Delete " + p + ". Then audit every branch this repo pushed to.",
				Meta:        findings.Meta{Quarantine: true, Evidence: ev}})
		}
	}
	gi := filepath.Join(repo, ".gitignore")
	content := h.ReadText(gi, 1<<20)
	if content == "" {
		return out
	}
	// strong: names only PolinRider uses. weak: entries that are odd but have innocent uses
	// (a stray "nul" file on Windows, .gitignore ignoring itself).
	var strong, weak []string
	for _, name := range r.I.PropagationScripts {
		if lineRe(name, false).MatchString(content) {
			strong = append(strong, name)
		}
	}
	if _, err := os.Stat(filepath.Join(repo, ".git")); err == nil {
		for _, name := range r.I.GitignoreIOCs {
			if !lineRe(name, true).MatchString(content) {
				continue
			}
			if name == "branch_structure.json" {
				strong = append(strong, name)
			} else {
				weak = append(weak, name)
			}
		}
	}
	if len(strong) > 0 {
		all := append(strong, weak...)
		ev := make([]string, 0, len(all))
		for _, n := range all {
			ev = append(ev, ".gitignore entry "+n)
		}
		out = append(out, &F{Severity: crit, Category: "gitignore_tampering",
			Title: ".gitignore hides PolinRider files: " + strings.Join(all, ", "), Path: gi,
			Details:     "PolinRider adds its orchestrator and artefacts to .gitignore so they never show in git status.",
			Remediation: "Remove these entries from " + gi + ", then run: git status --ignored",
			Meta:        findings.Meta{Cleanable: true, StripLines: all, Evidence: ev}})
		return out
	}
	for _, name := range weak {
		out = append(out, &F{Severity: high, Category: "gitignore_tampering", Title: ".gitignore hides " + name, Path: gi,
			Details:     "PolinRider ignores its own artefacts (and .gitignore itself) to hide the tampering.",
			Remediation: fmt.Sprintf("Remove '%s' from %s, then run: git status --ignored", name, gi)})
	}
	return out
}

func (r *Repo) CheckVSCodeTasks(repo string) []*F {
	tasks := filepath.Join(repo, ".vscode", "tasks.json")
	content := h.ReadText(tasks, 5<<20)
	if content == "" {
		return nil
	}
	I := r.I
	var c2 []string
	for _, x := range I.MaliciousHosts {
		if strings.Contains(content, x) {
			c2 = append(c2, x)
		}
	}
	if strings.Contains(content, "folderOpen") {
		loader := I.LoaderExt.FindString(content)
		var kws []string
		for _, k := range I.TasksJSONLoaderKeywords {
			if strings.Contains(content, k) {
				kws = append(kws, k)
			}
		}
		details := "runOptions.runOn=folderOpen executes the moment the folder opens in VS Code/Cursor/GitHub Desktop.\n"
		f := &F{Severity: crit, Category: "vscode_autorun", Title: "VS Code folderOpen autorun task", Path: tasks,
			Remediation: "Delete " + tasks + " unless you wrote it.\n  Run: threatscan harden   (sets task.allowAutomaticTasks=off)."}
		if loader != "" || len(c2) > 0 || len(kws) > 0 {
			f.Details = details + "Task body references a loader/font/shell/C2 host: this is the PolinRider stage-1 entry point."
			ev := []string{`"runOn": "folderOpen" (runs when the folder is opened)`}
			if loader != "" {
				ev = append(ev, fmt.Sprintf("node executes a non-script file: %q", h.Trunc(loader, 60)))
			}
			for _, x := range c2 {
				ev = append(ev, "C2 host "+x)
			}
			for i, k := range kws {
				if i < 4 {
					ev = append(ev, fmt.Sprintf("loader keyword %q", k))
				}
			}
			if strings.Contains(content, `"reveal": "never"`) || strings.Contains(content, `"echo": false`) {
				ev = append(ev, "terminal output hidden (reveal: never / echo: false)")
			}
			f.Meta = findings.Meta{Quarantine: true, Evidence: ev}
		} else {
			f.Severity = high
			f.Details = details + "No obvious loader in the task body, but folderOpen autorun is itself the PolinRider signature."
		}
		return []*F{f}
	}
	if len(c2) > 0 {
		var ev []string
		for _, x := range c2 {
			ev = append(ev, "C2 host "+x)
		}
		return []*F{{Severity: crit, Category: "vscode_autorun", Title: "VS Code task references PolinRider C2 host", Path: tasks,
			Details: "tasks.json downloads from a known stage-1 host.", Remediation: "Delete " + tasks + ".",
			Meta: findings.Meta{Quarantine: true, Evidence: ev}}}
	}
	return nil
}

var autoTasksRe = regexp.MustCompile(`"task\.allowAutomaticTasks"\s*:\s*(true|"on")`)

func (r *Repo) CheckVSCodeSettings(repo string) []*F {
	s := filepath.Join(repo, ".vscode", "settings.json")
	content := h.ReadText(s, 5<<20)
	if !autoTasksRe.MatchString(content) {
		return nil
	}
	var extras []string
	for _, k := range []string{`"terminal.integrated.hideOnStartup"`, `"runOn": "folderOpen"`, `"debug.openDebug"`} {
		if strings.Contains(content, k) {
			extras = append(extras, k)
		}
	}
	d := "task.allowAutomaticTasks suppresses the 'allow automatic tasks?' prompt, so a folderOpen task runs silently."
	if len(extras) > 0 {
		d += "\nAlso sets: " + strings.Join(extras, ", ")
	}
	return []*F{{Severity: high, Category: "vscode_autorun", Title: "VS Code settings force automatic tasks on", Path: s,
		Details: d, Remediation: "Remove task.allowAutomaticTasks from " + s + " unless you added it."}}
}

func isAssetExt(ext string) bool {
	_, ok := h.AssetMagic[ext]
	return ok || h.TextAssetExt[ext]
}

func (r *Repo) assetFinding(p string) *F {
	I := r.I
	name, ext := filepath.Base(p), strings.ToLower(filepath.Ext(p))
	isFont := h.FontExt[ext]
	cat, kind := "disguised_payload", "Image"
	if isFont {
		cat, kind = "fake_font_loader", "Font"
	} else if h.TextAssetExt[ext] {
		kind = "Dictionary"
	}
	if d := h.SHA256(p); I.FontHashes[d] {
		return &F{Severity: crit, Category: cat, Title: "PolinRider loader (hash match): " + name, Path: p,
			Details:     "SHA-256 " + d + " matches a confirmed PolinRider font-disguised loader.",
			Remediation: "Delete " + p + ". Search the repo for what references it (tasks.json, package.json scripts).",
			Meta:        findings.Meta{Quarantine: true, Evidence: []string{"SHA-256 " + d[:16] + "... is a confirmed PolinRider loader"}}}
	}
	verdict, detail := h.AssetVerdict(p, I.Marker)
	switch verdict {
	case "code":
		ev := append([]string{fmt.Sprintf("%s extension but no %s magic bytes; content is %s", ext, ext[1:], detail)},
			h.Evidence(h.ReadText(p, 2<<20), I, 6)...)
		return &F{Severity: crit, Category: cat, Title: kind + " file contains code: " + name, Path: p,
			Details:     fmt.Sprintf("Has a %s extension but the content is %s, not %s data.", ext, detail, ext[1:]),
			Remediation: fmt.Sprintf("Delete %s and find what loads it (grep -r '%s' .vscode package.json).", p, name),
			Meta:        findings.Meta{Quarantine: true, Evidence: ev}}
	case "text":
		sev := warn
		if I.IsFontName(name) {
			sev = high
		}
		return &F{Severity: sev, Category: cat, Title: kind + " file is not binary: " + name, Path: p,
			Details:     fmt.Sprintf("Has a %s extension but the content is %s.", ext, detail),
			Remediation: "Run: file " + p + "  then open it in a text editor and check what it contains."}
	case "unknown":
		if I.IsFontName(name) {
			return &F{Severity: warn, Category: cat, Title: "Unverifiable font with PolinRider filename: " + name, Path: p,
				Details: "Name matches the campaign loader but header is inconclusive.", Remediation: "Run: file " + p}
		}
	}
	return nil
}

func (r *Repo) CheckDisguisedAssets(repo string) []*F {
	var out []*F
	sub := &Repo{Root: repo, UI: r.UI, I: r.I, Deep: r.Deep, Exclude: r.Exclude}
	sub.walkDirs(func(dir string, ents []fs.DirEntry) bool {
		for _, e := range ents {
			if e.IsDir() || !isAssetExt(strings.ToLower(filepath.Ext(e.Name()))) {
				continue
			}
			r.FilesChecked++
			if f := r.assetFinding(filepath.Join(dir, e.Name())); f != nil {
				out = append(out, f)
			}
		}
		return true
	})
	return out
}

func git(timeout time.Duration, repo string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...).Output()
	return string(out)
}

func (r *Repo) CheckGitHistory(repo string) []*F {
	var out []*F
	reflog := strings.ToLower(git(15*time.Second, repo, "reflog", "--all", "-40"))
	amend := strings.Count(reflog, "amend")
	force := strings.Count(reflog, "forced-update") + strings.Count(reflog, "force")
	if amend > 2 || force > 0 {
		out = append(out, &F{Severity: warn, Category: "git_tampering",
			Title: fmt.Sprintf("Suspicious reflog in %s (%d amends, %d force refs)", filepath.Base(repo), amend, force),
			Path:  filepath.Join(repo, ".git"), Details: "PolinRider amends commits in place and force-pushes.",
			Remediation: "git -C " + repo + " reflog --all -40   # look for commits you didn't make"})
	}
	var sus []string
	for _, line := range strings.Split(strings.TrimSpace(git(15*time.Second, repo, "log", "-30", "--format=%H|%at|%ct|%s")), "\n") {
		p := strings.SplitN(line, "|", 4)
		if len(p) < 4 {
			continue
		}
		at, e1 := strconv.ParseInt(p[1], 10, 64)
		ct, e2 := strconv.ParseInt(p[2], 10, 64)
		if e1 != nil || e2 != nil || len(p[0]) < 10 {
			continue
		}
		if ct < at-86400*7 {
			sus = append(sus, fmt.Sprintf("%s committer date %s is before author date %s", p[0][:10],
				time.Unix(ct, 0).UTC().Format("2006-01-02"), time.Unix(at, 0).UTC().Format("2006-01-02")))
		}
	}
	if len(sus) > 0 {
		d := strings.Join(sus[:min(5, len(sus))], "\n")
		if len(sus) > 5 {
			d += "\n..."
		}
		out = append(out, &F{Severity: high, Category: "forged_timestamp", Title: "Backdated commits in " + filepath.Base(repo),
			Path: filepath.Join(repo, ".git"), Details: d + "\nPolinRider sets GIT_COMMITTER_DATE to hide when the backdoor was really pushed.",
			Remediation: "git -C " + repo + " log --format='%h %ad %cd %s' --date=iso   # compare author vs committer dates"})
	}
	return out
}

func (r *Repo) CheckHistoryPayloads(repo string) []*F {
	log := git(60*time.Second, repo, "log", "--all", "-n", "1000", "--text", "-E", "-G", r.I.HistoryPayloadRegex,
		"--format=%h|%ad|%s", "--date=short")
	var commits [][]string
	for _, l := range strings.Split(strings.TrimSpace(log), "\n") {
		if p := strings.SplitN(l, "|", 3); len(p) == 3 {
			commits = append(commits, p)
		}
	}
	if len(commits) == 0 {
		return nil
	}
	var lines []string
	for i, c := range commits {
		if i >= 10 {
			lines = append(lines, "...")
			break
		}
		lines = append(lines, c[0]+" "+c[1]+" "+h.Trunc(c[2], 60))
	}
	return []*F{{Severity: warn, Category: "history_payload",
		Title: fmt.Sprintf("%d commit(s) in %s history touch PolinRider payload code", len(commits), filepath.Base(repo)),
		Path:  filepath.Join(repo, ".git"),
		Details: strings.Join(lines, "\n") +
			"\nCheck each one: commit messages are often decoys that add the loader rather than remove it.",
		Remediation: "git -C " + repo + " show --stat <commit>   # then audit every branch that contains it"}}
}

var (
	fsmonRe  = regexp.MustCompile(`(?m)^\s*fsmonitor\s*=\s*(.+)$`)
	fsmonBad = regexp.MustCompile(`(?i)node|\.js|\.woff|curl|wget|powershell`)
)

func (r *Repo) CheckGitHooks(repo string) []*F {
	var out []*F
	hooks := filepath.Join(repo, ".git", "hooks")
	ents, _ := os.ReadDir(hooks)
	for _, e := range ents {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		p := filepath.Join(hooks, e.Name())
		c := h.ReadText(p, 1<<20)
		bad := r.I.LoaderExt.MatchString(c) || r.I.HasMarker(c)
		for _, x := range r.I.MaliciousHosts {
			bad = bad || strings.Contains(c, x)
		}
		if bad {
			out = append(out, &F{Severity: crit, Category: "git_hook", Title: "Malicious git hook: " + e.Name(), Path: p,
				Details: h.Trunc(c, 200), Remediation: "Delete " + p,
				Meta: findings.Meta{Quarantine: true, Evidence: h.Evidence(c, r.I, 6)}})
		}
	}
	gcfg := filepath.Join(repo, ".git", "config")
	if m := fsmonRe.FindStringSubmatch(h.ReadText(gcfg, 1<<20)); m != nil && fsmonBad.MatchString(m[1]) {
		out = append(out, &F{Severity: crit, Category: "git_hook", Title: "core.fsmonitor runs a script on every git command",
			Path: gcfg, Details: h.Trunc(m[0], 200), Remediation: "git -C " + repo + " config --unset core.fsmonitor"})
	}
	return out
}

var lifecycleRe = regexp.MustCompile(`(?i)node\s+-e|curl|wget|\.woff2?|\.dict|bash\s+-c|powershell|\.bat|atob\(|eval\(|vercel\.app`)

func (r *Repo) CheckPackageJSON(repo string) []*F {
	pj := filepath.Join(repo, "package.json")
	b := h.ReadBytes(pj, 5<<20)
	if b == nil {
		return nil
	}
	r.FilesChecked++
	var data struct {
		Dependencies, DevDependencies, OptionalDependencies, PeerDependencies map[string]any
		Scripts                                                               map[string]any
	}
	if json.Unmarshal(b, &data) != nil {
		return nil
	}
	deps := map[string]string{}
	for _, m := range []map[string]any{data.Dependencies, data.DevDependencies, data.OptionalDependencies, data.PeerDependencies} {
		for k, v := range m {
			deps[k] = fmt.Sprint(v)
		}
	}
	var out []*F
	for name, bad := range r.I.CompromisedNPM {
		ver, ok := deps[name]
		if !ok {
			continue
		}
		hit := false
		for _, v := range bad {
			hit = hit || v == "*" || strings.Contains(ver, v)
		}
		sev := high
		if hit {
			sev = crit
		}
		out = append(out, &F{Severity: sev, Category: "compromised_package", Title: "Compromised npm package: " + name + "@" + ver,
			Path: pj, Details: "Known-bad versions: " + strings.Join(bad, ", "),
			Remediation: "Remove " + name + " or pin to a clean version; rm -rf node_modules; check lockfile."})
	}
	for _, hook := range []string{"preinstall", "install", "postinstall", "prepare", "prepublish"} {
		body := ""
		if v, ok := data.Scripts[hook]; ok {
			body = fmt.Sprint(v)
		}
		if body != "" && lifecycleRe.MatchString(body) {
			out = append(out, &F{Severity: high, Category: "lifecycle_script", Title: "Suspicious " + hook + " script", Path: pj,
				Details: hook + ": " + h.Trunc(body, 120), Remediation: "Review scripts." + hook + " in " + pj + "; install with --ignore-scripts until verified."})
		}
	}
	return out
}

func (r *Repo) CheckLockfiles(repo string) []*F {
	var out []*F
	for _, lock := range []string{"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"} {
		p := filepath.Join(repo, lock)
		content := h.ReadText(p, 50<<20)
		if content == "" {
			continue
		}
		for name, bad := range r.I.CompromisedNPM {
			if !strings.Contains(content, name) {
				continue
			}
			short := name[strings.LastIndex(name, "/")+1:]
			for _, v := range bad {
				if v == "*" || strings.Contains(content, name+"@"+v) || strings.Contains(content, `"`+name+`": "`+v+`"`) ||
					strings.Contains(content, "/"+name+"/"+v) || strings.Contains(content, name+"/-/"+short+"-"+v+".tgz") {
					shown := v
					if v == "*" {
						shown = "any"
					}
					out = append(out, &F{Severity: crit, Category: "compromised_package",
						Title: "Compromised package pinned in " + lock + ": " + name + "@" + shown, Path: p,
						Details:     "Lockfile resolves a known-poisoned release.",
						Remediation: "Delete node_modules and " + lock + "; remove " + name + " or pin clean; reinstall with --ignore-scripts."})
					break
				}
			}
		}
	}
	return out
}

func (r *Repo) CheckGoMod(repo string) []*F {
	var out []*F
	for _, n := range []string{"go.mod", "go.sum"} {
		p := filepath.Join(repo, n)
		content := h.ReadText(p, 20<<20)
		for _, m := range r.I.CompromisedGo {
			if content != "" && strings.Contains(content, m) {
				out = append(out, &F{Severity: crit, Category: "compromised_package", Title: "Compromised Go module in " + n + ": " + m,
					Path: p, Details: "proxy.golang.org caches these permanently; the poisoned tag is still served.",
					Remediation: "Drop " + m + "; go clean -modcache; audit the vendored fa-solid-400.woff2."})
			}
		}
	}
	return out
}

func (r *Repo) CheckComposer(repo string) []*F {
	out := r.checkComposerVersions(repo)
	for _, n := range []string{"composer.json", "composer.lock"} {
		p := filepath.Join(repo, n)
		content := h.ReadText(p, 20<<20)
		for _, pkg := range r.I.CompromisedPackagist {
			if content != "" && strings.Contains(content, pkg) {
				out = append(out, &F{Severity: crit, Category: "compromised_package", Title: "Compromised Packagist package in " + n + ": " + pkg,
					Path: p, Details: "Shares C2 23.27.202.27 with PolinRider infrastructure.",
					Remediation: "Remove " + pkg + "; composer clear-cache; rotate any secrets the project holds."})
			}
		}
	}
	return out
}

// checkComposerVersions handles packages compromised only in some versions or
// branches: CRITICAL when composer.lock resolves one of them, HIGH when the
// package is present in another version (or only in composer.json).
func (r *Repo) checkComposerVersions(repo string) []*F {
	if len(r.I.CompromisedPackagistVersions) == 0 {
		return nil
	}
	installed := map[string]string{}
	lockPath := filepath.Join(repo, "composer.lock")
	if b := h.ReadBytes(lockPath, 20<<20); b != nil {
		var lock struct {
			Packages    []struct{ Name, Version string } `json:"packages"`
			PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
		}
		if json.Unmarshal(b, &lock) == nil {
			for _, p := range append(lock.Packages, lock.PackagesDev...) {
				installed[strings.ToLower(p.Name)] = p.Version
			}
		}
	}
	required := map[string]string{}
	jsonPath := filepath.Join(repo, "composer.json")
	if b := h.ReadBytes(jsonPath, 5<<20); b != nil {
		var cj struct {
			Require    map[string]string `json:"require"`
			RequireDev map[string]string `json:"require-dev"`
		}
		if json.Unmarshal(b, &cj) == nil {
			for _, m := range []map[string]string{cj.Require, cj.RequireDev} {
				for k, v := range m {
					required[strings.ToLower(k)] = v
				}
			}
		}
	}
	var out []*F
	for pkg, bad := range r.I.CompromisedPackagistVersions {
		key := strings.ToLower(pkg)
		ver, inLock := installed[key]
		constraint, inJSON := required[key]
		if !inLock && !inJSON {
			continue
		}
		path, shown := jsonPath, constraint
		if inLock {
			path, shown = lockPath, ver
		}
		hit := false
		for _, v := range bad {
			hit = hit || strings.EqualFold(shown, v) || (!inLock && strings.Contains(constraint, v))
		}
		sev, title := high, "Package with compromised branches: "+pkg+" "+shown
		if hit {
			sev, title = crit, "Compromised Packagist package: "+pkg+" "+shown
		}
		out = append(out, &F{Severity: sev, Category: "compromised_package", Title: title, Path: path,
			Details:     "Poisoned versions/branches: " + strings.Join(bad, ", "),
			Remediation: "Pin " + pkg + " to a clean stable release, composer clear-cache, reinstall; rotate secrets if a poisoned branch was installed."})
	}
	return out
}

func (r *Repo) CheckEnvFiles(repo string) []*F {
	var out []*F
	for _, n := range []string{".env", ".env.local", ".env.production", ".env.development", ".env.staging"} {
		p := filepath.Join(repo, n)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			out = append(out, &F{Severity: warn, Category: "credential_exposure", Title: "Secrets file present in infected repo: " + n,
				Path: p, Details: "The payload reads process.env; every value here should be treated as leaked.",
				Remediation: "Rotate every secret in " + p + "."})
		}
	}
	return out
}

// ── orchestration ────────────────────────────────────────────────────────────

// ScanFile scans a single file (guard quick path / real-time / pre-commit).
func (r *Repo) ScanFile(fp string) []*F {
	st, err := os.Stat(fp)
	if err != nil || st.IsDir() {
		return nil
	}
	name, parent := filepath.Base(fp), filepath.Base(filepath.Dir(fp))
	switch {
	case name == "tasks.json" && parent == ".vscode":
		return r.CheckVSCodeTasks(filepath.Dir(filepath.Dir(fp)))
	case name == "settings.json" && parent == ".vscode":
		return r.CheckVSCodeSettings(filepath.Dir(filepath.Dir(fp)))
	case r.I.IsPropagation(name):
		return r.CheckPropagation(filepath.Dir(fp))
	case isAssetExt(strings.ToLower(filepath.Ext(fp))):
		if f := r.assetFinding(fp); f != nil && f.Severity == crit {
			return []*F{f}
		}
		return nil
	}
	out := r.CheckSignatures(fp)
	if r.I.IsConfig(name) {
		out = append(out, r.CheckSizeAndLines(fp)...)
	} else {
		out = append(out, r.CheckEntryHook(fp)...)
	}
	return findings.Dedup(out)
}

func (r *Repo) ScanRepo(repo string, isGit bool) []*F {
	r.UI.Progress("Scanning " + repo)
	var f []*F
	done := map[string]bool{}
	for _, n := range r.I.ConfigFiles {
		fp := filepath.Join(repo, n)
		if st, err := os.Stat(fp); err == nil && !st.IsDir() {
			done[fp] = true
			f = append(f, r.CheckSignatures(fp)...)
			f = append(f, r.CheckSizeAndLines(fp)...)
		}
	}
	for _, n := range r.I.EntryFiles {
		fp := filepath.Join(repo, filepath.FromSlash(n))
		if st, err := os.Stat(fp); err == nil && !st.IsDir() {
			done[fp] = true
			f = append(f, r.CheckEntryHook(fp)...)
			f = append(f, r.CheckSignatures(fp)...)
		}
	}
	if r.JSAll {
		sub := &Repo{Root: repo, UI: r.UI, I: r.I, Deep: r.Deep, Exclude: r.Exclude}
		sub.walkDirs(func(dir string, ents []fs.DirEntry) bool {
			for _, e := range ents {
				p := filepath.Join(dir, e.Name())
				if e.IsDir() || done[p] || !h.ScriptExt[strings.ToLower(filepath.Ext(e.Name()))] {
					continue
				}
				if info, err := e.Info(); err != nil || info.Size() > 8<<20 {
					continue
				}
				f = append(f, r.CheckSignatures(p)...)
			}
			return true
		})
	}
	f = append(f, r.CheckPropagation(repo)...)
	f = append(f, r.CheckVSCodeTasks(repo)...)
	f = append(f, r.CheckVSCodeSettings(repo)...)
	f = append(f, r.CheckDisguisedAssets(repo)...)
	f = append(f, r.CheckPackageJSON(repo)...)
	f = append(f, r.CheckLockfiles(repo)...)
	f = append(f, r.CheckGoMod(repo)...)
	f = append(f, r.CheckComposer(repo)...)
	if isGit {
		f = append(f, r.CheckGitHooks(repo)...)
		f = append(f, r.CheckGitHistory(repo)...)
		f = append(f, r.CheckHistoryPayloads(repo)...)
	}
	if findings.AnyAtLeast(f, high) {
		f = append(f, r.CheckEnvFiles(repo)...)
	}
	return findings.Dedup(f)
}

// ScanAll scans every repo/project under Root.  Pass nil to discover.
func (r *Repo) ScanAll(repos, projects []string) ([]*F, int, int) {
	if repos == nil && projects == nil {
		repos, projects = r.Discover()
	}
	total := len(repos) + len(projects)
	if total == 0 {
		r.UI.Info("No repositories or projects under " + r.Root)
		return nil, 0, 0
	}
	r.UI.Progress(fmt.Sprintf("Found %d git repos + %d non-git projects", len(repos), len(projects)))
	var all []*F
	infected := 0
	scan := func(p string, isGit bool) {
		rf := r.ScanRepo(p, isGit)
		switch {
		case findings.AnyAtLeast(rf, high):
			infected++
			r.UI.Err("[INFECTED] " + p)
			for _, x := range rf {
				r.UI.Finding(x)
			}
		case len(rf) > 0 && r.Verbose:
			r.UI.Warn("[REVIEW] " + p)
			for _, x := range rf {
				r.UI.Finding(x)
			}
		case r.Verbose:
			r.UI.OK("Clean: " + p)
		}
		all = append(all, rf...)
	}
	for _, p := range repos {
		scan(p, true)
	}
	for _, p := range projects {
		scan(p, false)
	}
	return all, total, infected
}
