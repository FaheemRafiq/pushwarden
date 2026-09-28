<!-- threatscan:allow-signatures -->
# Lazarus "Contagious Interview" - Complete IoC List

## Wallet Addresses (Blockchain C2 Dead-Drop)

| Wallet | Purpose |
|--------|---------|
| `0xa322E5f3...` | Primary dead-drop wallet (malware scans for transactions to this) |
| `global['i'] = "A10-*23650"` | Campaign identifier embedded in wallet lookup |

## Network Indicators

### C2 Server IPs (Block Immediately)

```
166.88.54.158
198.105.127.210
23.27.202.27
154.91.0.103
136.0.9.8
166.88.4.2
23.27.120.142
202.155.8.173
166.88.134.82
188.43.33.249
```

### Ethereum RPC Endpoints Used by Malware

```
https://ethereum-rpc.publicnode.com
https://rpc.ankr.com/eth
https://eth.drpc.org
https://1rpc.io/eth
```

### C2 Communication Patterns

- HTTP POST to port 443/80
- Header: `Sec-V: <version>` (e.g., `A10-*23650`)
- Header: `X-Payload: <data>`
- Header: `Content-Encoding: gzip` / `x-gzip` / `br`
- User-Agent: Chrome on Windows 10/11
- XOR-encrypted payloads (key derived from Sec-V header)

## File Indicators

### Infected Config Files (check size and content)

| File | Normal Size | Infected Size | What to Look For |
|------|-------------|---------------|------------------|
| `postcss.config.js` | ~200B | >1024B | Payload hidden after ~280 spaces |
| `tailwind.config.js` | ~300B | >1024B | Same technique |
| `eslint.config.js` | ~400B | >1024B | Same technique |
| `next.config.js` | ~200B | >1024B | Same technique |
| `vite.config.js` | ~300B | >1024B | Same technique |
| `webpack.config.js` | ~500B | >2000B | Same technique |
| `babel.config.js` | ~100B | >1024B | Same technique |

### Propagation Scripts (delete immediately)

```
temp_auto_push.bat
temp_interactive_push.bat
config.bat
auto_push.bat
```

### .gitignore Tampering

Look for entries hiding `.bat` files:
```
temp_auto_push.bat
temp_interactive_push.bat
```

## Code Signatures

### Literal Strings (exact matches - definitive detection)

```
("rmcej%otb%",2857687)
global['!']='8-270-2';var $_1e42=
global['!']='4-1928'
global['_V']='A4-1928'
global['!']='10-83-10'
global['!']='A10-010'
global['!']='A10-2340'
```

### Regex Patterns (heuristic detection)

```
global['!']='[A-Z0-9-]{4,}'
global['_V']='[A-Z0-9-]{4,}'
\$_1e42
global\['r'\]=require
atob\(process\.env
eval\(atob
```

### Obfuscation Patterns

- IIFE array rotation (`(function(arr, target){...})(array, rotation)`)
- Hex-encoded function names (`_0x4963`, `_0xb40cd9`)
- `parseInt` with hex math for array shuffling
- String array with 150+ entries returned by `_0x240a()`

## Global Variables (Runtime Indicators)

The malware injects these into the Node.js global scope:

```
global['_V']   = campaign version (from global['i'])
global['_H']   = C2 host URL (http://<ip>:443)
global['_H2']  = fallback C2 host
global['_t_u'] = C2 update endpoint
global['_t_s'] = C2 status endpoint
global['_H2']  = second C2 host
global['r']    = require (reference hijack)
global['m']    = module (reference hijack)
global['i']    = campaign ID ("A10-*23650")
```

## Process Indicators

Malicious process command lines:

```
node -e ...global['!']
node -e ...$_1e42
node -e ...eval(atob
python3 -c ...eval(`/`base64`/`exec(`
font-updater
font_updater
.cache/font/
/tmp/.<single-letter>
```

## Shell RC Injection

Check `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile` for:

```
curl|wget piped to bash/sh/python
eval(base64
eval(atob
python -c import socket
node -e require('child_process')
global['!
```

## Persistence Mechanisms

### Cron Jobs
- Entries containing: `font`, `cache`, `temp`, `/tmp`, `curl`, `wget`, `eval`, `base64`, `node`

### Launch Agents (macOS) / Startup (Windows)
- `.plist` or `.job` files in `~/Library/LaunchAgents/` containing `curl`, `wget`, `eval`, `base64`, `node -e`, `font-updater`

### Windows Scheduled Tasks
- Tasks containing: `font`, `cache`, `update`, `temp`, `.tmp`

## Fake Font Files

Font files under `public/`, `static/`, `assets/` that fail magic byte validation:

| Extension | Expected Magic Bytes | Malware Indicator |
|-----------|---------------------|-------------------|
| `.woff` | `wOFF` | Contains `<!html`, `node`, `eval` |
| `.woff2` | `wOF2` | Contains `<!html`, `node`, `eval` |
| `.ttf` | `\x00\x01\x00\x00` | Contains `<!html`, `node`, `eval` |
| `.otf` | `OTTO` | Contains `<!html`, `node`, `eval` |

## Git Indicators

- Commits with messages: "add copy code button", "update config", "fix build", "update postcss", "add postcss config", "update tailwind config", "update dependencies", "update package.json", "update next.config", "update eslint config", "chore: update", "style: update", "fix: update"
- Repos with >2 amended commits
- Force-push evidence in reflog
- Recent pushes within 24 hours

## Credential Targets

The malware reads ALL `process.env` variables. High-value targets:

- `ETH_RPC_URL` - Ethereum RPC endpoint
- `GITHUB_TOKEN` / `GH_TOKEN` - GitHub PATs
- `NPM_TOKEN` - npm publishing tokens
- `AWS_*` - AWS credentials
- `PRIVATE_KEY` / `SECRET_KEY` - Any crypto keys
- `.env` files in project root
- SSH private keys in `~/.ssh/`

## Shell Script IoC (polinrider-scanner.sh v2.0)

```bash
# Add to firewall blocklist:
iptables -A OUTPUT -d 166.88.54.158 -j DROP
iptables -A OUTPUT -d 198.105.127.210 -j DROP
iptables -A OUTPUT -d 23.27.202.27 -j DROP
iptables -A OUTPUT -d 154.91.0.103 -j DROP
iptables -A OUTPUT -d 136.0.9.8 -j DROP
iptables -A OUTPUT -d 166.88.4.2 -j DROP
iptables -A OUTPUT -d 23.27.120.142 -j DROP
iptables -A OUTPUT -d 202.155.8.173 -j DROP
iptables -A OUTPUT -d 166.88.134.82 -j DROP
iptables -A OUTPUT -d 188.43.33.249 -j DROP
```
