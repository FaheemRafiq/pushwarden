#!/usr/bin/env python3
"""
Lazarus C2 Implant Deobfuscator & Static Analyzer
Campaign: Contagious Interview (Blockchain C2 dead-drop)

Usage:
    python3 deobfuscate.py <malware.js>
    python3 deobfuscate.py <malware.js> --output readable.js
    python3 deobfuscate.py <malware.js> --iocs-only
"""

import re
import sys
import json
import hashlib
from pathlib import Path


def extract_string_array(js_code):
    match = re.search(r"function _0x240a\(\)\{const _\w+=(\[.*?\]);", js_code, re.DOTALL)
    if not match:
        return None
    raw = match.group(1)
    strings = []
    i = 0
    while i < len(raw):
        if raw[i] == "'":
            j = i + 1
            while j < len(raw):
                if raw[j] == '\\' and j + 1 < len(raw):
                    j += 2
                    continue
                if raw[j] == "'":
                    break
                j += 1
            s = raw[i+1:j]
            s = s.replace("\\x27", "'").replace("\\x20", " ").replace("\\x22", '"')
            strings.append(s)
            i = j + 1
        else:
            i += 1
    return strings


def compute_offset(js_code):
    m = re.search(r"function _0x4963\(_0xfccef8.*?return _0x5dde51;\}", js_code, re.DOTALL)
    if not m:
        return 0
    block = m.group(0)
    nums = re.findall(r"0x([0-9a-f]+)", block)
    if len(nums) >= 3:
        a = int(nums[0], 16)
        b = int(nums[1], 16)
        c = int(nums[2], 16)
        return a - b + c
    return 0


def resolve_lookup(arr, index_val, offset=0):
    idx = index_val - offset
    if 0 <= idx < len(arr):
        return arr[idx]
    return f"<OOB:{index_val}>"


def try_deobfuscate(js_code, arr, offset):
    count = 0
    def repl(m):
        nonlocal count
        try:
            idx = int(m.group(1), 16)
            val = resolve_lookup(arr, idx, offset)
            count += 1
            return json.dumps(val)
        except:
            return m.group(0)
    result = re.sub(r"_0x[0-9a-f]+\(0x([0-9a-f]+)\)", repl, js_code)
    return result, count


def find_best_rotation(strings, js_code, offset):
    best_rot = 0
    best_count = 0
    best_arr = strings

    for rot in range(len(strings)):
        test_arr = strings[rot:] + strings[:rot]
        _, count = try_deobfuscate(js_code, test_arr, offset)
        if count > best_count:
            best_count = count
            best_rot = rot
            best_arr = test_arr

    return best_arr, best_rot, best_count


def extract_iocs(text):
    iocs = {
        "wallets": [],
        "urls": [],
        "domains": [],
        "ips": [],
        "global_vars": [],
        "modules": [],
        "c2_indicators": [],
    }

    seen = set()
    for m in re.finditer(r"0x[a-fA-F0-9]{40}", text):
        w = m.group(0).lower()
        if w not in seen:
            seen.add(w)
            iocs["wallets"].append(m.group(0))

    seen = set()
    for m in re.finditer(r"https?://[^\s\"'<>\\]+", text):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            iocs["urls"].append(u)

    seen = set()
    for m in re.finditer(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)", text):
        d = m.group(1)
        if d not in seen and not d.startswith("0x") and len(d) > 5:
            seen.add(d)
            iocs["domains"].append(d)

    seen = set()
    for m in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text):
        ip = m.group(1)
        if ip not in seen:
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                seen.add(ip)
                iocs["ips"].append(ip)

    seen = set()
    for m in re.finditer(r"global\[.([\w_]+).\]?\s*=", text):
        v = m.group(1)
        if v not in seen:
            seen.add(v)
            iocs["global_vars"].append(v)

    seen = set()
    for m in re.finditer(r"require\(([\w.'\"]+)\)", text):
        mod = m.group(1).strip("'\"")
        if mod not in seen:
            seen.add(mod)
            iocs["modules"].append(mod)

    c2_checks = [
        ("eval(", "Code evaluation (stage-2 loader)"),
        ("atob(", "Base64 decoding"),
        ("child_process", "Child process module"),
        ("spawn", "Process spawning"),
        ("process.env", "Environment variable access"),
        ("Sec-V", "Custom C2 version header"),
        ("zlib", "Data compression/decompression"),
        ("unref", "Background persistence (fire-and-forget)"),
        ("detached", "Detached process (persistence)"),
        ("eth_blockNumber", "Ethereum block scanning"),
        ("eth_getTransactionByHash", "Ethereum transaction inspection"),
        ("x-payload", "C2 payload transfer header"),
        ("content-encoding", "Compressed C2 responses"),
        ("User-Agent", "HTTP fingerprint spoofing"),
    ]
    for pattern, desc in c2_checks:
        if pattern.lower() in text.lower():
            iocs["c2_indicators"].append(desc)

    return iocs


def generate_report(js_code, arr, iocs, offset, best_rot):
    lines = []
    lines.append("=" * 70)
    lines.append("LAZARUS C2 IMPLANT - STATIC ANALYSIS REPORT")
    lines.append("Campaign: Contagious Interview")
    lines.append("Type: Blockchain-based C2 dead-drop implant")
    lines.append("=" * 70)

    lines.append(f"\nFile SHA256: {hashlib.sha256(js_code.encode()).hexdigest()}")
    lines.append(f"File size: {len(js_code)} bytes")
    lines.append(f"String array: {len(arr)} entries")
    lines.append(f"Array rotation: {best_rot}")
    lines.append(f"Lookup offset: {offset}")

    lines.append("\n--- DEOBFUSCATED STRING TABLE (first 50) ---")
    rotated = arr[best_rot:] + arr[:best_rot]
    for i, s in enumerate(rotated[:50]):
        safe = s.replace('\n', '\\n').replace('\r', '\\r')
        lines.append(f"  [{i:3d}] = \"{safe}\"")
    if len(arr) > 50:
        lines.append(f"  ... ({len(arr) - 50} more)")

    lines.append("\n--- WALLET ADDRESSES (C2 dead-drop target) ---")
    for w in iocs["wallets"]:
        lines.append(f"  {w}")

    lines.append("\n--- URLs ---")
    for u in iocs["urls"]:
        lines.append(f"  {u}")

    lines.append("\n--- DOMAINS ---")
    for d in iocs["domains"]:
        lines.append(f"  {d}")

    lines.append("\n--- IP ADDRESSES ---")
    for ip in iocs["ips"]:
        lines.append(f"  {ip}")

    lines.append("\n--- GLOBAL VARIABLES (injected into runtime) ---")
    for v in iocs["global_vars"]:
        lines.append(f"  global['{v}']")

    lines.append("\n--- NODE.JS MODULES ---")
    for m in iocs["modules"]:
        lines.append(f"  require('{m}')")

    lines.append("\n--- C2 INDICATORS ---")
    for c in iocs["c2_indicators"]:
        lines.append(f"  * {c}")

    lines.append("\n" + "=" * 70)
    lines.append("ATTACK CHAIN RECONSTRUCTION")
    lines.append("=" * 70)
    lines.append("""
  STAGE 0: INFECTION
    Developer runs npm install on a compromised package
    (fake job interview lure: "Contagious Interview" campaign)

  STAGE 1: INITIAL LOADER (in config file)
    File: postcss.config.js / tailwind.config.js / eslint.config.js etc.
    Technique: Payload hidden after ~280 trailing spaces on export line
    Trigger: require() during build/dev server startup
    Code: atob(process.env.SECRET_KEY) -> fetch(url) -> eval(response)

  STAGE 2: C2 IMPLANT (THIS SAMPLE)
    2a. BLOCKCHAIN DEAD-DROP SCANNING
        - Connects to Ethereum RPC nodes (drpc.org, blastapi.io, publicnode)
        - Scans last 1000 blocks for transactions to target wallet
        - Target wallet: 0xa322E5f3... (see wallet addresses above)
        - Extracts C2 server IP from transaction value field
        - Uses binary search + linear scan for efficiency

    2b. C2 COMMUNICATION
        - HTTP requests to extracted IP on port 443
        - Custom header: Sec-V = campaign version (A10-*23650)
        - XOR cipher for response decryption
        - Supports gzip, deflate, brotli decompression
        - User-Agent: Chrome/Edge on Windows 10/11

    2c. PAYLOAD EXECUTION
        - Receives JavaScript code from C2
        - eval() in current process
        - Simultaneously spawns detached node -e process
        - Detached: true, stdio: ignore, windowsHide: true

    2d. CREDENTIAL THEFT
        - Reads ALL process.env variables
        - Targets: ETH_RPC_URL, GitHub PATs, API keys
        - Exfiltrates via C2 channel

    2e. PERSISTENCE
        - Global variable injection: _V, _H, _H2, _t_u, _t_s, _H2
        - Detached background processes
        - .bat script drops (temp_auto_push.bat, config.bat)

    2f. PROPAGATION
        - Auto-pushes infected files to victim's GitHub repos
        - Uses stolen PATs for authentication
        - Amends commits to hide infection
        - Force-pushes to overwrite clean history
        - Commit messages: innocuous ("update config", "fix build")

  STAGE 3: LATERAL MOVEMENT
    - Stolen credentials used to infect other repos
    - Supply chain spread via npm packages""")

    lines.append("\n" + "=" * 70)
    lines.append("DETECTION SIGNATURES")
    lines.append("=" * 70)
    lines.append("""
  LITERAL STRINGS:
    ("rmcej%otb%",2857687)
    global['!']='8-270-2';var $_1e42=
    global['!']='4-1928'
    global['_V']='A4-1928'
    global['!']='10-83-10'
    global['!']='A10-010'
    global['!']='A10-2340'

  REGEX PATTERNS:
    global['!']='[A-Z0-9-]{4,}'
    global['_V']='[A-Z0-9-]{4,}'
    $_1e42
    global['r']=require
    atob(process.env
    eval(atob

  NETWORK IoCs (C2 IPs):
    166.88.54.158    198.105.127.210
    23.27.202.27     154.91.0.103
    136.0.9.8        166.88.4.2
    23.27.120.142    202.155.8.173
    166.88.134.82    188.43.33.249

  FILE INDICATORS:
    - .bat files: temp_auto_push.bat, config.bat, auto_push.bat
    - Config files >1024 bytes (normal: ~200 bytes)
    - Lines >300 chars in config files (payload hidden after spaces)
    - Font files with invalid magic bytes""")

    lines.append("\n" + "=" * 70)
    lines.append("BLOCKCHAIN C2 ARCHITECTURE")
    lines.append("=" * 70)
    lines.append("""
  The malware uses Ethereum as a dead-drop for C2 addresses:

  1. Attacker sends ETH transaction to known wallet
  2. Transaction 'value' field encodes C2 server IP
  3. Malware scans recent blocks (1000 block window)
  4. Finds matching transaction, extracts IP
  5. Connects to new C2 server for commands

  Benefits for attacker:
  - No hardcoded C2 IPs in malware sample
  - C2 can be changed by sending new transaction
  - Transactions are immutable and public
  - Difficult to takedown (blockchain is decentralized)

  RPC Endpoints Used:
    - {URL}https://eth-mainnet.g.alchemy.com...
    - https://ethereum-rpc.publicnode.com
    - https://rpc.ankr.com/eth
    - https://eth.drpc.org
    - https://1rpc.io/eth""")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <malware.js> [--output readable.js] [--iocs-only]")
        sys.exit(1)

    sample_path = sys.argv[1]
    output_file = None
    iocs_only = "--iocs-only" in sys.argv

    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]

    js_code = Path(sample_path).read_text(errors="replace")
    print(f"[*] Loaded: {sample_path} ({len(js_code)} bytes)")

    print("[*] Extracting string array...")
    strings = extract_string_array(js_code)
    if not strings:
        print("  Failed to extract string array")
        sys.exit(1)
    print(f"  Found {len(strings)} strings")

    print("[*] Computing lookup offset...")
    offset = compute_offset(js_code)
    print(f"  Offset: {offset}")

    print("[*] Finding correct array rotation...")
    arr, best_rot, best_count = find_best_rotation(strings, js_code, offset)
    print(f"  Best rotation: {best_rot} ({best_count} resolved calls)")

    print("[*] Deobfuscating...")
    deobfuscated, total = try_deobfuscate(js_code, arr, offset)
    print(f"  Resolved {total} function calls")

    print("[*] Extracting IOCs...")
    iocs = extract_iocs(deobfuscated)

    report = generate_report(js_code, arr, iocs, offset, best_rot)

    if iocs_only:
        ioc_json = {
            "wallets": iocs["wallets"],
            "urls": iocs["urls"],
            "domains": iocs["domains"],
            "ips": iocs["ips"],
            "global_vars": iocs["global_vars"],
            "modules": iocs["modules"],
            "c2_indicators": iocs["c2_indicators"],
            "sha256": hashlib.sha256(js_code.encode()).hexdigest(),
            "file_size": len(js_code),
        }
        print(json.dumps(ioc_json, indent=2))
    else:
        print("\n" + report)

    if output_file:
        Path(output_file).write_text(deobfuscated)
        print(f"\n[*] Deobfuscated output: {output_file}")

    report_path = Path(sample_path).with_name("analysis-report.txt")
    report_path.write_text(report)
    print(f"[*] Report saved: {report_path}")

    ioc_path = Path(sample_path).with_suffix(".iocs.json")
    ioc_data = {
        "wallets": iocs["wallets"],
        "urls": iocs["urls"],
        "domains": iocs["domains"],
        "ips": iocs["ips"],
        "global_vars": iocs["global_vars"],
        "modules": iocs["modules"],
        "c2_indicators": iocs["c2_indicators"],
        "sha256": hashlib.sha256(js_code.encode()).hexdigest(),
    }
    ioc_path.write_text(json.dumps(ioc_data, indent=2))
    print(f"[*] IOCs saved: {ioc_path}")


if __name__ == "__main__":
    main()
