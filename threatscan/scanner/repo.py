"""Repository / project scanner (read-only)."""

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from ..findings import Finding, Severity
from ..helpers import ASSET_MAGIC, FONT_EXTENSIONS, TEXT_ASSET_EXTENSIONS, asset_verdict, read_text, sha256_of, skip_dir


class RepoScanner:
    def __init__(self, scan_dir: Path, ui, iocs, js_all=False, verbose=False, exclude=None):
        self.scan_dir = scan_dir.resolve()
        self.ui = ui
        self.iocs = iocs
        self.js_all = js_all
        self.verbose = verbose
        self.exclude = [str(Path(e).expanduser()) for e in (exclude or [])]
        self.files_checked = 0

    def _excluded(self, p: Path) -> bool:
        s = str(p)
        return any(s.startswith(e) for e in self.exclude)

    # ── Discovery ────────────────────────────────────────────────────────────
    def find_repos(self) -> List[Path]:
        repos = []
        for root, dirs, files in os.walk(self.scan_dir):
            if self._excluded(Path(root)):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if not skip_dir(d) or d == ".git"]
            if ".git" in dirs or ".git" in files:
                repos.append(Path(root))
                dirs[:] = [d for d in dirs if d != ".git"]
        return repos

    def find_non_git_projects(self) -> List[Path]:
        projects = []
        for root, dirs, files in os.walk(self.scan_dir):
            if self._excluded(Path(root)):
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if not skip_dir(d)]
            if ".git" in os.listdir(root) if os.path.isdir(root) else False:
                dirs[:] = []
                continue
            if "package.json" in files or "go.mod" in files or "composer.json" in files:
                projects.append(Path(root))
                dirs[:] = []
        return projects

    # ── File-level checks ────────────────────────────────────────────────────
    def check_signatures(self, fp: Path) -> List[Finding]:
        out = []
        content = read_text(fp)
        if not content:
            return out
        self.files_checked += 1
        I = self.iocs

        for sig in I.literal_signatures:
            if sig in content:
                out.append(Finding(Severity.CRITICAL, "config_injection",
                    f"PolinRider signature in {fp.name}", str(fp),
                    f"Literal: {sig[:70]}",
                    f"Remove everything after the legitimate config in:\n  {fp}\n"
                    f"  Look for global['!'], global['_V'], _$_1e42, MDy(, or Cot%3t=shtP.",
                    meta={"cleanable": True}))
                break

        if not out and I.marker_regex.search(content):
            out.append(Finding(Severity.CRITICAL, "config_injection",
                f"PolinRider marker regex in {fp.name}", str(fp),
                "Generalised campaign marker matched (covers all A#- / 8-stN rotations).",
                f"Inspect and strip the obfuscated block from:\n  {fp}",
                meta={"cleanable": True}))

        for key in I.xor_keys:
            if key in content:
                out.append(Finding(Severity.CRITICAL, "xor_key",
                    f"PolinRider XOR key in {fp.name}", str(fp),
                    f"Key: {key}",
                    f"This file contains the payload decryption key. Delete or clean:\n  {fp}",
                    meta={"cleanable": True}))
                break

        # RPC hostnames alone are NOT an indicator (wallet SDKs use them). Fire on a
        # known dead-drop wallet, or an RPC host co-located with a campaign marker.
        hosts = [h for h in I.blockchain_rpc_hosts if h in content]
        wallets = [w for w in I.wallets if w.lower() in content.lower()]
        if wallets or (hosts and I.has_marker(content)):
            out.append(Finding(Severity.CRITICAL, "blockchain_c2",
                f"Blockchain dead-drop indicators in {fp.name}", str(fp),
                f"RPC hosts: {', '.join(hosts) or '-'}\nWallets: {', '.join(wallets) or '-'}",
                f"File references PolinRider dead-drop wallets/RPCs. Clean or delete:\n  {fp}"))

        c2paths = [p for p in I.c2_url_paths if p in content]
        ips = [ip for ip in I.malicious_ips if ip in content]
        c2hosts = [h for h in I.malicious_hosts if h in content]
        if ips or c2hosts or (c2paths and ("http" in content)):
            out.append(Finding(Severity.CRITICAL, "c2_reference",
                f"C2 reference in {fp.name}", str(fp),
                f"IPs: {', '.join(ips) or '-'}\nHosts: {', '.join(c2hosts) or '-'}\nPaths: {', '.join(c2paths) or '-'}",
                f"Hard-coded C2 infrastructure. Clean or delete:\n  {fp}"))

        tg = [t for t in I.telegram_indicators if t in content]
        if tg:
            out.append(Finding(Severity.CRITICAL, "telegram_exfil",
                f"Telegram exfiltration bot in {fp.name}", str(fp),
                f"Indicator: {tg[0]}", f"OmniStealer exfil channel. Delete:\n  {fp}"))
        return out

    def check_size_and_lines(self, fp: Path) -> List[Finding]:
        out = []
        try:
            size = fp.stat().st_size
        except Exception:
            return out
        if size > 4096:
            out.append(Finding(Severity.WARNING, "file_anomaly",
                f"{fp.name} is large ({size} bytes)", str(fp),
                "Framework config files are normally <1 KB. PolinRider appends 5-80 KB payloads.",
                f"Inspect {fp}; strip anything after the real export."))
        content = read_text(fp)
        for i, line in enumerate(content.split("\n"), 1):
            if len(line) > 400:
                trailing = re.search(r"\s{40,}\S", line)
                out.append(Finding(Severity.HIGH if trailing else Severity.WARNING, "file_anomaly",
                    f"{fp.name} line {i} is {len(line)} chars" + (" with hidden payload after whitespace" if trailing else ""),
                    str(fp), "PolinRider hides its payload after ~280 spaces on the export line.",
                    f"Open {fp}, go to line {i}, scroll right, delete the trailing code."))
                break
        return out

    def check_entry_hook(self, fp: Path) -> List[Finding]:
        content = read_text(fp)
        if re.search(r"atob\s*\(\s*process\.env", content) or re.search(r"eval\s*\(\s*atob", content):
            return [Finding(Severity.CRITICAL, "entry_hook",
                f"Malicious entry hook in {fp.name}", str(fp),
                "atob(process.env...)/eval(atob...) decodes a base64 URL from env and evals the response.",
                f"Remove the injected async IIFE from:\n  {fp}", meta={"cleanable": True})]
        return []

    # ── Repo-level checks ────────────────────────────────────────────────────
    def check_propagation_scripts(self, repo: Path) -> List[Finding]:
        out = []
        I = self.iocs
        for name in I.propagation_scripts:
            p = repo / name
            if p.exists():
                out.append(Finding(Severity.CRITICAL, "propagation_script",
                    f"Propagation script: {name}", str(p),
                    "Rewrites git history with forged GIT_COMMITTER_DATE and force-pushes.",
                    f"Delete {p}. Then audit every branch this repo pushed to.",
                    meta={"quarantine": True}))
        gi = repo / ".gitignore"
        if gi.is_file():
            content = read_text(gi)
            for name in I.propagation_scripts:
                if re.search(rf"^\s*{re.escape(name)}\s*$", content, re.M):
                    out.append(Finding(Severity.HIGH, "gitignore_tampering",
                        f".gitignore hides {name}", str(gi),
                        "PolinRider adds its orchestrator to .gitignore so it never shows in git status.",
                        f"Remove '{name}' from {gi}."))
            for name in I.gitignore_iocs if (repo / ".git").exists() else []:
                if re.search(rf"^\s*/?{re.escape(name)}\s*$", content, re.M):
                    out.append(Finding(Severity.HIGH, "gitignore_tampering",
                        f".gitignore hides {name}", str(gi),
                        "PolinRider ignores its own artefacts (and .gitignore itself) to hide the tampering.",
                        f"Remove '{name}' from {gi}, then run: git status --ignored"))
        return out

    def check_vscode_tasks(self, repo: Path) -> List[Finding]:
        out = []
        tasks = repo / ".vscode" / "tasks.json"
        if not tasks.is_file():
            return out
        content = read_text(tasks)
        I = self.iocs
        if "folderOpen" in content:
            sev = Severity.CRITICAL
            details = "runOptions.runOn=folderOpen executes the moment the folder opens in VS Code/Cursor/GitHub Desktop.\n"
            loader = I.loader_ext_regex.search(content)
            c2host = any(h in content for h in I.malicious_hosts)
            if loader or c2host or any(k in content for k in I.tasks_json_loader_keywords):
                details += "Task body references a loader/font/shell/C2 host: this is the PolinRider stage-1 entry point."
                meta = {"quarantine": True}
            else:
                details += "No obvious loader in the task body, but folderOpen autorun is itself the PolinRider signature."
                sev = Severity.HIGH
                meta = {}
            out.append(Finding(sev, "vscode_autorun",
                "VS Code folderOpen autorun task", str(tasks), details,
                f"Delete {tasks} unless you wrote it.\n  Run: threatscan harden   (sets task.allowAutomaticTasks=off).",
                meta=meta))
        elif any(h in content for h in I.malicious_hosts):
            out.append(Finding(Severity.CRITICAL, "vscode_autorun",
                "VS Code task references PolinRider C2 host", str(tasks),
                "tasks.json downloads from a known stage-1 host.", f"Delete {tasks}.",
                meta={"quarantine": True}))
        return out

    def check_vscode_settings(self, repo: Path) -> List[Finding]:
        settings = repo / ".vscode" / "settings.json"
        if not settings.is_file():
            return []
        content = read_text(settings)
        if not re.search(r'"task\.allowAutomaticTasks"\s*:\s*(true|"on")', content):
            return []
        extras = [k for k in ('"terminal.integrated.hideOnStartup"', '"runOn": "folderOpen"', '"debug.openDebug"')
                  if k in content]
        return [Finding(Severity.HIGH, "vscode_autorun",
            "VS Code settings force automatic tasks on", str(settings),
            "task.allowAutomaticTasks suppresses the 'allow automatic tasks?' prompt, so a folderOpen "
            "task runs silently." + (f"\nAlso sets: {', '.join(extras)}" if extras else ""),
            f"Remove task.allowAutomaticTasks from {settings} unless you added it.")]

    def check_disguised_assets(self, repo: Path) -> List[Finding]:
        """Font/image/dict files whose content is not what the extension claims."""
        out = []
        I = self.iocs
        exts = set(ASSET_MAGIC) | TEXT_ASSET_EXTENSIONS
        for root, dirs, files in os.walk(repo):
            dirs[:] = [d for d in dirs if not skip_dir(d)]
            for fn in files:
                p = Path(root) / fn
                ext = p.suffix.lower()
                if ext not in exts:
                    continue
                self.files_checked += 1
                is_font = ext in FONT_EXTENSIONS
                category = "fake_font_loader" if is_font else "disguised_payload"
                kind = "Font" if is_font else ("Dictionary" if ext in TEXT_ASSET_EXTENSIONS else "Image")
                digest = sha256_of(p)
                if digest in I.fake_font_sha256:
                    out.append(Finding(Severity.CRITICAL, category,
                        f"PolinRider loader (hash match): {fn}", str(p),
                        f"SHA-256 {digest} matches a confirmed PolinRider font-disguised loader.",
                        f"Delete {p}. Search the repo for what references it (tasks.json, package.json scripts).",
                        meta={"quarantine": True}))
                    continue
                verdict, detail = asset_verdict(p, I.marker_regex)
                if verdict == "code":
                    out.append(Finding(Severity.CRITICAL, category,
                        f"{kind} file contains code: {fn}", str(p),
                        f"Has a {ext} extension but the content is {detail}, not {ext[1:]} data.",
                        f"Delete {p} and find what loads it (grep -r '{fn}' .vscode package.json).",
                        meta={"quarantine": True}))
                elif verdict == "text":
                    out.append(Finding(Severity.HIGH if fn in I.fake_font_names else Severity.WARNING, category,
                        f"{kind} file is not binary: {fn}", str(p),
                        f"Has a {ext} extension but the content is {detail}.",
                        f"Run: file {p}  then open it in a text editor and check what it contains."))
                elif verdict == "unknown" and fn in I.fake_font_names:
                    out.append(Finding(Severity.WARNING, category,
                        f"Unverifiable font with PolinRider filename: {fn}", str(p),
                        "Name matches the campaign loader but header is inconclusive.",
                        f"Run: file {p}  it should say 'Web Open Font Format'."))
        return out

    def check_git_history(self, repo: Path) -> List[Finding]:
        out = []
        git = ["git", "-C", str(repo)]
        try:
            reflog = subprocess.run(git + ["reflog", "--all", "-40"],
                                    capture_output=True, text=True, timeout=15).stdout.lower()
        except Exception:
            return out
        amend = reflog.count("amend")
        force = reflog.count("forced-update") + reflog.count("force")
        if amend > 2 or force > 0:
            out.append(Finding(Severity.WARNING, "git_tampering",
                f"Suspicious reflog in {repo.name} ({amend} amends, {force} force refs)",
                str(repo / ".git"), "PolinRider amends commits in place and force-pushes.",
                f"git -C {repo} reflog --all -40   # look for commits you didn't make"))
        try:
            log = subprocess.run(git + ["log", "-30", "--format=%H|%at|%ct|%an|%cn|%s"],
                                 capture_output=True, text=True, timeout=15).stdout
        except Exception:
            log = ""
        suspicious = []
        for line in log.strip().split("\n"):
            parts = line.split("|", 5)
            if len(parts) < 6:
                continue
            h, at, ct, an, cn, subj = parts
            try:
                at, ct = int(at), int(ct)
            except ValueError:
                continue
            if ct < at - 86400 * 7:
                suspicious.append(f"{h[:10]} committer date {datetime.fromtimestamp(ct, timezone.utc):%Y-%m-%d} is before author date {datetime.fromtimestamp(at, timezone.utc):%Y-%m-%d}")
        if suspicious:
            out.append(Finding(Severity.HIGH, "forged_timestamp",
                f"Backdated commits in {repo.name}", str(repo / ".git"),
                "\n".join(suspicious[:5]) + ("\n..." if len(suspicious) > 5 else "") +
                "\nPolinRider sets GIT_COMMITTER_DATE to hide when the backdoor was really pushed.",
                f"git -C {repo} log --format='%h %ad %cd %s' --date=iso   # compare author vs committer dates"))
        return out

    def check_history_payloads(self, repo: Path) -> List[Finding]:
        try:
            log = subprocess.run(
                ["git", "-C", str(repo), "log", "--all", "-n", "1000", "--text", "-E",
                 "-G", self.iocs.history_payload_regex, "--format=%h|%ad|%s", "--date=short"],
                capture_output=True, text=True, timeout=60).stdout
        except Exception:
            return []
        commits = [line.split("|", 2) for line in log.strip().split("\n") if line.count("|") >= 2]
        if not commits:
            return []
        listing = "\n".join(f"{h} {d} {s[:60]}" for h, d, s in commits[:10])
        return [Finding(Severity.WARNING, "history_payload",
            f"{len(commits)} commit(s) in {repo.name} history touch PolinRider payload code", str(repo / ".git"),
            listing + ("\n..." if len(commits) > 10 else "") +
            "\nCheck each one: commit messages are often decoys that add the loader rather than remove it.",
            f"git -C {repo} show --stat <commit>   # then audit every branch that contains it")]

    def check_git_hooks_and_config(self, repo: Path) -> List[Finding]:
        """Hooks or core.fsmonitor that run node on a non-JS file (GitSpawn-style)."""
        out = []
        hooks = repo / ".git" / "hooks"
        if hooks.is_dir():
            for h in hooks.iterdir():
                if h.suffix == ".sample" or not h.is_file():
                    continue
                c = read_text(h, limit_bytes=1024 * 1024)
                if self.iocs.loader_ext_regex.search(c) or self.iocs.has_marker(c) or \
                        any(host in c for host in self.iocs.malicious_hosts):
                    out.append(Finding(Severity.CRITICAL, "git_hook",
                        f"Malicious git hook: {h.name}", str(h), c[:200],
                        f"Delete {h}", meta={"quarantine": True}))
        gcfg = repo / ".git" / "config"
        if gcfg.is_file():
            c = read_text(gcfg)
            m = re.search(r"^\s*fsmonitor\s*=\s*(.+)$", c, re.M)
            if m and re.search(r"node|\.js|\.woff|curl|wget|powershell", m.group(1), re.I):
                out.append(Finding(Severity.CRITICAL, "git_hook",
                    "core.fsmonitor runs a script on every git command", str(gcfg), m.group(0)[:200],
                    f"git -C {repo} config --unset core.fsmonitor"))
        return out

    def check_package_json(self, repo: Path) -> List[Finding]:
        out = []
        pj = repo / "package.json"
        if not pj.is_file():
            return out
        self.files_checked += 1
        try:
            data = json.loads(read_text(pj) or "{}")
        except Exception:
            return out
        deps = {}
        for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps.update(data.get(k, {}) or {})
        for name, bad_versions in self.iocs.compromised_npm.items():
            if name in deps:
                ver = str(deps[name])
                hit = "*" in bad_versions or any(v in ver for v in bad_versions)
                out.append(Finding(Severity.CRITICAL if hit else Severity.HIGH, "compromised_package",
                    f"Compromised npm package: {name}@{ver}", str(pj),
                    f"Known-bad versions: {', '.join(bad_versions)}",
                    f"Remove {name} or pin to a clean version; rm -rf node_modules; check lockfile."))
        scripts = data.get("scripts", {}) or {}
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish"):
            body = str(scripts.get(hook, ""))
            if not body:
                continue
            if re.search(r"node\s+-e|curl|wget|\.woff2?|\.dict|bash\s+-c|powershell|\.bat|atob\(|eval\(|vercel\.app", body, re.I):
                out.append(Finding(Severity.HIGH, "lifecycle_script",
                    f"Suspicious {hook} script", str(pj), f"{hook}: {body[:120]}",
                    f"Review scripts.{hook} in {pj}; install with --ignore-scripts until verified."))
        return out

    def check_lockfiles(self, repo: Path) -> List[Finding]:
        out = []
        for lock in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"):
            p = repo / lock
            if not p.is_file():
                continue
            content = read_text(p)
            for name, bad_versions in self.iocs.compromised_npm.items():
                if name not in content:
                    continue
                short = name.split("/")[-1]
                for v in bad_versions:
                    if v == "*" or f"{name}@{v}" in content or f'"{name}": "{v}"' in content \
                            or f"/{name}/{v}" in content or f"{name}/-/{short}-{v}.tgz" in content:
                        out.append(Finding(Severity.CRITICAL, "compromised_package",
                            f"Compromised package pinned in {lock}: {name}@{v if v != '*' else 'any'}",
                            str(p), "Lockfile resolves a known-poisoned release.",
                            f"Delete node_modules and {lock}; remove {name} or pin clean; reinstall with --ignore-scripts."))
                        break
        return out

    def check_go_mod(self, repo: Path) -> List[Finding]:
        out = []
        for name in ("go.mod", "go.sum"):
            p = repo / name
            if not p.is_file():
                continue
            content = read_text(p)
            for mod in self.iocs.compromised_go:
                if mod in content:
                    out.append(Finding(Severity.CRITICAL, "compromised_package",
                        f"Compromised Go module in {name}: {mod}", str(p),
                        "proxy.golang.org caches these permanently; the poisoned tag is still served.",
                        f"Drop {mod}; go clean -modcache; audit the vendored fa-solid-400.woff2."))
        return out

    def check_composer(self, repo: Path) -> List[Finding]:
        out = []
        for name in ("composer.json", "composer.lock"):
            p = repo / name
            if not p.is_file():
                continue
            content = read_text(p)
            for pkg in self.iocs.compromised_packagist:
                if pkg in content:
                    out.append(Finding(Severity.CRITICAL, "compromised_package",
                        f"Compromised Packagist package in {name}: {pkg}", str(p),
                        "Shares C2 23.27.202.27 with PolinRider infrastructure.",
                        f"Remove {pkg}; composer clear-cache; rotate any secrets the project holds."))
        return out

    def check_env_files(self, repo: Path) -> List[Finding]:
        out = []
        for name in (".env", ".env.local", ".env.production", ".env.development", ".env.staging"):
            p = repo / name
            if p.is_file():
                out.append(Finding(Severity.WARNING, "credential_exposure",
                    f"Secrets file present in infected repo: {name}", str(p),
                    "The payload reads process.env; every value here should be treated as leaked.",
                    f"Rotate every secret in {p}."))
        return out

    # ── Orchestration ────────────────────────────────────────────────────────
    def scan_file(self, fp: Path) -> List[Finding]:
        """Scan one tracked file (used by the guard's quick pass)."""
        f: List[Finding] = []
        if not fp.is_file():
            return f
        name = fp.name
        if name == "tasks.json" and fp.parent.name == ".vscode":
            return self.check_vscode_tasks(fp.parent.parent)
        if name == "settings.json" and fp.parent.name == ".vscode":
            return self.check_vscode_settings(fp.parent.parent)
        if name in self.iocs.propagation_scripts:
            return self.check_propagation_scripts(fp.parent)
        if fp.suffix.lower() in ASSET_MAGIC or fp.suffix.lower() in TEXT_ASSET_EXTENSIONS:
            digest = sha256_of(fp)
            if digest in self.iocs.fake_font_sha256:
                return [Finding(Severity.CRITICAL, "fake_font_loader", f"PolinRider loader (hash match): {name}",
                                str(fp), f"SHA-256 {digest}", f"Delete {fp}", meta={"quarantine": True})]
            verdict, detail = asset_verdict(fp, self.iocs.marker_regex)
            if verdict == "code":
                return [Finding(Severity.CRITICAL, "fake_font_loader", f"Font/asset file contains code: {name}",
                                str(fp), detail, f"Delete {fp}", meta={"quarantine": True})]
            return f
        f += self.check_signatures(fp)
        if name in self.iocs.config_files:
            f += self.check_size_and_lines(fp)
        else:
            f += self.check_entry_hook(fp)
        return f

    def scan_repo(self, repo: Path, is_git=True) -> List[Finding]:
        f: List[Finding] = []
        self.ui.progress(f"Scanning {repo}")
        I = self.iocs
        for name in I.config_files:
            fp = repo / name
            if fp.is_file():
                f += self.check_signatures(fp)
                f += self.check_size_and_lines(fp)
        for name in I.entry_files:
            fp = repo / name
            if fp.is_file():
                f += self.check_entry_hook(fp)
                f += self.check_signatures(fp)
        if self.js_all:
            for root, dirs, files in os.walk(repo):
                dirs[:] = [d for d in dirs if not skip_dir(d)]
                for fn in files:
                    if fn.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
                        f += self.check_signatures(Path(root) / fn)
        f += self.check_propagation_scripts(repo)
        f += self.check_vscode_tasks(repo)
        f += self.check_vscode_settings(repo)
        f += self.check_disguised_assets(repo)
        f += self.check_package_json(repo)
        f += self.check_lockfiles(repo)
        f += self.check_go_mod(repo)
        f += self.check_composer(repo)
        if is_git:
            f += self.check_git_hooks_and_config(repo)
            f += self.check_git_history(repo)
            f += self.check_history_payloads(repo)
        if any(x.severity >= Severity.HIGH for x in f):
            f += self.check_env_files(repo)
        # De-duplicate identical findings (a file can be reached by two checks).
        seen, uniq = set(), []
        for x in f:
            if x.key not in seen:
                seen.add(x.key)
                uniq.append(x)
        return uniq

    def scan_all(self) -> Tuple[List[Finding], int, int]:
        findings: List[Finding] = []
        repos = self.find_repos()
        projects = [p for p in self.find_non_git_projects() if p not in repos]
        total = len(repos) + len(projects)
        if not total:
            self.ui.info(f"No repositories or projects under {self.scan_dir}")
            return findings, 0, 0
        self.ui.progress(f"Found {len(repos)} git repos + {len(projects)} non-git projects")
        infected = 0
        for repo, is_git in [(r, True) for r in repos] + [(p, False) for p in projects]:
            rf = self.scan_repo(repo, is_git=is_git)
            if any(x.severity >= Severity.HIGH for x in rf):
                infected += 1
                self.ui.err(f"[INFECTED] {repo}")
                for x in rf:
                    self.ui.finding(x)
            elif rf and self.verbose:
                self.ui.warn(f"[REVIEW] {repo}")
                for x in rf:
                    self.ui.finding(x)
            elif self.verbose:
                self.ui.ok(f"Clean: {repo}")
            findings += rf
        return findings, total, infected

    def tracked_files(self, repos: List[Path]) -> List[Path]:
        """Files the guard re-checks cheaply on mtime change."""
        out = []
        I = self.iocs
        for repo in repos:
            for name in list(I.config_files) + list(I.entry_files) + list(I.propagation_scripts):
                out.append(repo / name)
            out.append(repo / ".vscode" / "tasks.json")
            out.append(repo / ".vscode" / "settings.json")
            for sub in ("public/fonts", "public/font", "static/fonts", "assets/fonts", "src/assets/fonts", "fonts"):
                for fn in I.fake_font_names:
                    out.append(repo / sub / fn)
        return out
