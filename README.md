# ThreatScan

**Blockchain C2 Config-Injection Malware Detector**

Cross-platform (Linux / macOS / Windows) scanner that detects the Lazarus Group "Contagious Interview" malware family — obfuscated payloads hidden in JS/TS config files, propagation scripts, stolen credential exfiltration, and blockchain-based command & control.

## What It Detects

| Indicator | Description |
|-----------|-------------|
| `global['!']='4-1928'` | Campaign marker in config files |
| `global['_V']='A4-1928'` | Variant campaign marker |
| `_$_1e42` | Obfuscation variable family |
| Hidden payloads | Malicious code after ~280 spaces on config lines |
| Propagation scripts | `temp_auto_push.bat`, `config.bat`, etc. |
| `.gitignore` tampering | Entries hiding `.bat` propagation scripts |
| File size anomalies | Config files >1KB (normal: ~80-300 bytes) |
| `atob(process.env...)` | Entry-file hooks stealing environment variables |
| Fake font files | Non-font files with font extensions in `public/` |
| Git reflog evidence | Amend/force-push history consistent with campaign |
| Active C2 connections | Network connections to known malicious IPs |

## Local Usage

```bash
# Scan home directory
python3 threat_scanner.py

# Scan specific directory
python3 threat_scanner.py ~/projects

# Verbose output
python3 threat_scanner.py --verbose ~/projects

# Scan ALL .js/.ts files (not just known configs)
python3 threat_scanner.py --js-all ~/projects

# Skip GitHub audit
python3 threat_scanner.py --no-github ~/projects
```

## CI/CD Integration (GitHub Actions)

Add this one file to any repo to enable automatic malware scanning on every push:

**`.github/workflows/malware-scan.yml`:**
```yaml
name: Malware Scan
on: [push, pull_request]
jobs:
  scan:
    uses: FaheemRafiq/threatscan/.github/workflows/malware-scan.yml@main
```

That's it. No scanner code in your repo — it downloads the latest scanner from this central repo on every run.

### What Happens on Detection

1. **Commit status** set to `failure` (visible in GitHub UI)
2. **Commit comment** posted with full scan report and remediation steps
3. **Workflow fails** (can be made a required status check to block merges)

### Branch Protection (Recommended)

Make ThreatScan a required check to prevent merging infected code:

```
Repo Settings → Branches → Branch protection rules → Edit
  ☑ Require status checks to pass
  → Add "threatscan" as required check
```

## Scanner Modules

| Module | Local | CI |
|--------|:-----:|:--:|
| Repo config file scanning | Yes | Yes |
| Malware signature detection | Yes | Yes |
| File size / long-line anomalies | Yes | Yes |
| Propagation script detection | Yes | Yes |
| `.gitignore` tampering | Yes | Yes |
| Fake font detection | Yes | Yes |
| Git reflog analysis | Yes | No |
| System process checks | Yes | No |
| Network connection checks | Yes | No |
| Shell startup file checks | Yes | No |
| SSH key permission checks | Yes | No |
| GitHub repo audit | Yes | No |

## Known Malicious IPs

Block these in your firewall:

```
166.88.54.158    198.105.127.210    23.27.202.27
154.91.0.103     136.0.9.8          166.88.4.2
23.27.120.142    202.155.8.173      166.88.134.82
188.43.33.249
```

## Attribution

Based on analysis of the Lazarus Group (DPRK) "Contagious Interview" campaign, active since 2023. Targets developers via fake job interviews on Upwork, LinkedIn, and Freelancer. Primary goals: cryptocurrency wallet theft, credential harvesting, and source code exfiltration.

## License

MIT
