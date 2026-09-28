<!-- threatscan:allow-signatures -->
# PolinRider / Contagious Interview: indicator research, September 2026

Research date: 2026-09-28. Baseline: ThreatScan indicator file `threatscan/iocs.json` version `2026.09.28`
and program version 0.1.1.

> **Applied 2026-09-28** in indicator file `2026.09.28.1` and program 0.2.0: everything in the
> [proposal](#proposed-iocsjson-additions) except the generic `/api/ipcheck` and `/api/ip-check/` paths
> (ThreatScan pairs any C2 path with any `http` string, so they would flag ordinary IP-lookup code; the
> exact `*.vercel.app` hosts cover that infrastructure instead). `visanduma/nova-two-factor` uses the new
> version-aware key `compromised_packagist_versions` (CRITICAL on the four `dev-*` branches, HIGH on other
> versions). `@common-stack/generate-plugin` uses the version prefix `9.0.2-alpha.` because package versions
> are matched by substring. Code changes 1-3 are implemented with regression tests; change 4 (Go module
> cache in `--deep`) is not, because the cache holds thousands of modules and needs its own design.
> A scan of the author's `~/Coding` gave identical results before and after (no new false positives).

**Status labels** used throughout:

- **NEW**: not in `iocs.json` 2026.09.28 (checked by string search of the file, not by assumption).
- **KNOWN**: already in `iocs.json`.
- **GAP**: listed in `iocs.json` or covered by a pattern, but a test shows ThreatScan does not detect it.

Every indicator below was confirmed by at least three independent verification passes against its source
(see [Method](#method)). Claims that failed verification are listed separately in
[Rejected claims](#rejected-claims-do-not-add) and must not be added without a primary source.

---

## Summary

1. **Detection gap (fix first).** Two current marker forms are not detected at all:
   `global.i = 'A8'` (fake-font variant, deployed 2026-09-03 and 2026-09-25) and `global.i = 'A9-0204-3'`
   (NullReceiver variant, active 2026-09-04 to 09-15). A test repository with either marker in
   `postcss.config.mjs`, behind 300 spaces of padding, produced no CRITICAL, HIGH or WARNING finding. The
   existing pattern `global(?:\.i|\[['"]i['"]\])\s*=\s*['"]A\d+-\*?\d+['"]` requires exactly `A<n>-<n>` and misses
   both. See [Detection gaps](#detection-gaps-found-by-testing).
2. **New since September 2026:** two fake-font loaders deployed side by side (`fa-solid-500.woff2` with
   `global.i='A8'`, `fa-solid-900.woff2` with `global['!']='9-10094'`); the Packagist package
   `visanduma/nova-two-factor` compromised on four `dev-*` branches, with a **new PHP execution path**
   (`index.php` running obfuscated JavaScript through `shell_exec`); the npm package
   `@dforge-core/dforge-mcp@0.2.21`, published with **valid npm provenance** during an account takeover; and
   the NullReceiver Ethereum dead drop resolving to `193.247.144.38` (already KNOWN) with the marker
   `helloipbot!!` (NEW).
3. **Older but missing from ThreatScan:** 9 Packagist packages (July 2026), `@common-stack/generate-plugin`
   (May-June 2026), 16 typosquatted npm names, 8 C2 IPs and 7 staging URLs from the wider Contagious
   Interview npm waves (October 2025 onward).
4. **Not usable yet:** more than 80 Go modules show compromise traces (about 61 confirmed malicious
   versions), but no source publishes their module paths. Detection for Go must stay content-based.
5. **Not covered by any verified source:** PyPI, crates.io, VS Code / Open VSX extensions, and new host
   persistence (systemd, LaunchAgents, Run keys). See [Open questions](#open-questions).

---

## Detection gaps found by testing

Tested with ThreatScan 0.1.1 (`threatscan scan --ci --no-system`) on a throw-away git repository whose
`postcss.config.mjs` was `export default { plugins: {} };` + 300 spaces + the marker + a dummy IIFE.

| Marker in `postcss.config.mjs` | Result | Status |
|---|---|---|
| `global.i = 'A8';` | nothing reported | **GAP** |
| `global.i='A9-0204-3';` | nothing reported | **GAP** |
| `global.i='A10-2340';` | CRITICAL | KNOWN |
| `global['!']='9-10094';` | CRITICAL (generic marker regex) | KNOWN |
| `global['_V']='8-1144';` | CRITICAL (generic marker regex) | KNOWN |

Real payloads usually also contain decoder or XOR-key signatures that ThreatScan does catch, so the gap
matters most for new variants whose body differs. Two further observations from the same test:

- The whitespace-padding heuristic did not fire on these short files: padding plus code after the closing
  export was not reported on its own.
- Suggested pattern replacing the current `global.i` regex:
  `global(?:\.i|\[['"]i['"]\])\s*=\s*['"]A\d+(?:-\*?\d+)*['"]`
  (matches `A8`, `A9-0204-3`, `A10-2340`, `A10-*23650`).

---

## Markers, obfuscation and XOR keys

| Indicator | Detail | First seen | Status | Source |
|---|---|---|---|---|
| `rmcej%otb%` | original variant marker; shuffle seed `2857687`; decoder `_$_1e42`; globals `global['!']`, `global['r']`, `global['m']` | 2026-03-08 | KNOWN | [1], [3], [4] |
| `Cot%3t=shtP` | rotated variant (made to evade the public `rmcej_otb_payload` YARA rule); decoder `MDy`; globals `global['_V']='8-XXX'`, `global['r']`, `global['m']` | 2026-04-10 | KNOWN | [1], [3], [4] |
| Shuffle seeds `2667686`, `1111436`, `3896884` | cheap extra literals (`2857687` is already present) | Mar-Apr 2026 | **NEW** | [1], [3] |
| XOR keys `2[gWfGj;<:-93Z^C`, `m6:tTh^D)cBz?NM]` | shared by both variants and by the `@common-stack` compromise | 2026 | KNOWN | [1], [3], [4] |
| `global.i = 'A8'` | build marker in the `fa-solid-500.woff2` loader | 2026-09-03 | **GAP** | [2] |
| `global['!']='9-10094'` | build marker in the `fa-solid-900.woff2` loader | 2026-09-25 | KNOWN (regex) | [2] |
| Build-marker lineage in `eslint.config.mjs` | `9-2078`, `8-1259`, then `8-1586`, `8-1144`, then `9-10094`; `A8-n*` variants also exist | Apr-Sep 2026 | KNOWN (regex) | [2] |
| `global.i = 'A9-0204-3'` | campaign tag in the NullReceiver `postcss.config.mjs` payload | 2026-09-04 | **GAP** | [6] |
| `helloipbot!!` (hex `68656c6c6f6970626f742121`) | ASCII marker embedded in the dead-drop transaction recipient | 2026-08 | **NEW** | [6] |

## Fake-font loaders

| File | Marker | Size | Seen | Status | Source |
|---|---|---|---|---|---|
| `fa-solid-500.woff2` | `global.i = 'A8'` | 32,320 bytes | deployed 2026-09-03, redeployed 2026-09-25 | name KNOWN, marker **GAP** | [2] |
| `fa-solid-900.woff2` | `global['!']='9-10094'` | 37,567 bytes | pushed to three Binary-Mindz repos, 2026-09-25 01:30:28-01:38:11 UTC | KNOWN | [2] |
| `fa-solid-400.woff2` | (5,533 characters) | | 2026-04-25; `public/fonts/fa-solid-400.woff2` in 141 repos | KNOWN | [1], [2] |

The loaders are placed under `public/`, `public/fonts/`, `static/` or `assets/`. Detection rule already in
ThreatScan and still correct: any font file whose bytes are JavaScript rather than a font header. SHA-256s of
the September 2026 fonts were not published.

## Injected config and entry files

Counts of infected files (OpenSourceMalware tracker). All file names below are already in ThreatScan's
`config_files` / `entry_files` lists (**KNOWN**).

| File | Repos (Apr 2026) | Repos (Jul 2026) |
|---|---|---|
| `postcss.config.mjs` | ~960 | 1,135 |
| `tailwind.config.js` | ~210 | 213 |
| `eslint.config.mjs` | ~150 | |
| `postcss.config.js` | ~40 | |
| `next.config.mjs`, `App.js` | ~30 each | |
| `vite.config.js` / `.mjs` | ~20 | |
| `webpack.config.js` | ~15 | |
| `vue.config.js` | ~10 | |

By July 2026 the campaign had hit 2,417 repositories: 93.9 % config-file injection, 5.9 % fake font,
0.2 % both. Sources: [1], [3], [4].

**NEW execution vector (PHP):** in the Visanduma compromise, `index.php` runs the obfuscated JavaScript
through PHP `shell_exec` [5]. Suggested rule: flag `.php` files that contain `shell_exec` together with
`node -e` or a long obfuscated JavaScript string.

## Propagation and history tampering

Already detected by ThreatScan (**KNOWN**); confirmed unchanged:

- `temp_auto_push.bat` (101 repos): runs `git log -1`, sets the Windows clock to the original commit time,
  `git commit --amend --no-verify`, restores the clock, then `git push -uf origin <branch> --no-verify` [1].
- Repeated force-pushes rewrite history: the Visanduma org has been force-pushed since mid-June 2026 [5];
  commit `79bdb26` (3 May) on the Xpos587 account was force-pushed on 2026-06-23 [7].
- Go and Composer packages are compromised as soon as the backing GitHub repository is: repository write
  access is publishing access [7].

---

## Compromised packages

### npm

| Package | Versions | Date | Status | Source |
|---|---|---|---|---|
| `@dforge-core/dforge-mcp` | `0.2.21` (malicious, latest for 35 m 38 s), `0.2.20` (failed attempt, also flag); `0.2.22` is clean | 2026-09-09 | **NEW** | [6] |
| `@common-stack/generate-plugin` | `9.0.2-alpha.21`, `9.0.2-alpha.22` confirmed; 13 compromised versions in total, the rest unpublished, so flag `9.0.2-alpha.*` | 2026-05 to 06-04 | **NEW** | [4] |
| `epxreso`, `epxresso`, `epxressoo`, `dotevn`, `boby_parser`, `ethrs.js`, `ethres.js`, `we3.js`, `wb3.js`, `hardhat-deploy-notifier`, `hardhat-deploy-notification`, `metamask-api`, `vaildator`, `truffel`, `ganacche`, `foudry` | any (typosquats) | 2025-07 to 2025-10 | **NEW** | [8] |

Notes:

- `@dforge-core/dforge-mcp@0.2.21` was published through GitHub Actions OIDC trusted publishing with a valid
  npm provenance statement and Sigstore attestation, during a 105-minute takeover of the maintainer account.
  **Provenance checks do not protect against this.** CloudSEK names the loader GHAPPIER and does not
  attribute it to DPRK, so treat it as PolinRider-adjacent. Hashes are in the [hash table](#file-hashes).
- The 16 typosquats come from Socket's count of 338 malicious npm packages in the wider Contagious Interview
  campaign (more than 50,000 downloads, 180+ personas; 25 still live on 2025-10-10). They are BeaverTail /
  HexEval / XORIndex era and some may be inactive, but installed copies are still dangerous.

### Packagist (Composer)

| Package | Versions | Date | Status | Source |
|---|---|---|---|---|
| `visanduma/nova-two-factor` (>700,000 downloads) | branches `dev-nova4support`, `dev-main`, `dev-using-inertia`, `dev-nova5`; no malicious stable release known as of 2026-09-17 | 2026-06 to 09 | **NEW** | [5] |
| `thiio/kubernetes-php-sdk`, `arsl/optima-class`, `olc/olc-php`, `sevenspan/laravel-whatsapp`, `adxio/twig-hmvc`, `sevenspan/code-generator`, `lambda-platform/moqup`, `sevenspan/laravel-chat`, `plusinfolab/logstation` | not published: verify installed files, not version numbers | 2026-07-08 | **NEW** | [7] |
| `roberts/leads` | | 2026-07 | KNOWN | [7] |

The Visanduma intrusion came through the compromised GitHub account `lahirulhr` (LaHiRu). Poisoned files:
`tailwind.config.js` (five obfuscated variants), `.vscode/tasks.json` with `runOn: folderOpen`, `index.php`
(PHP `shell_exec`) and fake `.woff2` fonts [5].

### Go modules

More than 80 Go modules show compromise traces, about 61 of them confirmed distinct malicious module
versions [7]. ThreatScan lists 16. No source publishes the module paths, so these cannot be added by name.
Recommendation: keep detection content-based and extend the repository scan to the Go module cache
(`$GOPATH/pkg/mod`) and `vendor/` directories when `--deep` is used.

### PyPI, crates.io, VS Code / Open VSX extensions

No verified PolinRider or Contagious Interview indicators were found for these ecosystems in this research
pass. This is a gap in the research, not evidence that they are clean.

---

## Network indicators

### C2 IP addresses

| IP | Context | Active | Status | Source |
|---|---|---|---|---|
| `193.247.144.38` | NullReceiver C2 (decoded from the dead drop; 70 transactions) | 2026-09-04 to 09-15 | KNOWN | [6] |
| `166.88.134.62` | earlier NullReceiver C2 | 2026-08 | KNOWN | [6] |
| `166.88.73.46` | earlier NullReceiver C2 | 2026-08-30 to 09-03 | **NEW** | [6] |
| `135.181.123.177`, `138.201.50.5`, `144.172.105.235`, `144.172.112.106`, `146.70.253.107`, `23.127.202.249`, `23.227.202.244` | Contagious Interview npm wave C2s | 2025 | **NEW** | [8] |

### Hosts and URLs

All **NEW**, all from the Contagious Interview npm waves [8]. Defanged here; plain values are in the
[proposal](#proposed-iocsjson-additions).

| URL |
|---|
| `fashdefi[.]store:6168/defy/v7` |
| `0927[.]vercel[.]app/api/ipcheck` |
| `ip-check-server[.]vercel[.]app/api/ip-check/208` |
| `process-log[.]vercel[.]app/api/ipcheck` |
| `process-log-update[.]vercel[.]app/api/ipcheck` |
| `log-server-lovat[.]vercel[.]app/api/ipcheck/703` |
| `api[.]npoint[.]io/b964566497d98298d32c` |

Generic pattern worth adding: a `*.vercel.app` host followed by `/api/ipcheck` or `/api/ip-check`.
`api.npoint.io` is a legitimate JSON-bin service: match the full path, never the bare host.

### Blockchain dead drops

| Indicator | Detail | Status | Source |
|---|---|---|---|
| Ethereum wallet `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a` | NullReceiver watched wallet. Built at runtime as `('0xa322E5f3D311D3080e6f0121063e9aDC2490Ef' + '1a').toLowerCase()` to defeat string search; the 38-character prefix is also in `iocs.json` | KNOWN | [6] |
| Recipient `0xc1f79026c1f7902668656c6c6f6970626f742121` | encodes C2 `193.247.144.38` and the marker `helloipbot!!` | **NEW** (the address itself) | [6] |
| TRON `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP`, `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG`; Aptos `0xbe0374...811e`, `0x3f0e57...dce3` | dead-drop wallets | KNOWN | [1], [7] |
| RPC resolvers `ethereum-rpc.publicnode.com`, `eth.drpc.org`, `1rpc.io/eth` | legitimate services used to read the dead drop | KNOWN | [6] |
| RPC resolvers `eth-mainnet.public.blastapi.io`, `eth.blockscout.com/api?module=account&action=txlist&address=` | as above | **NEW** | [6] |
| Environment variable `ETH_RPC_URL` | overrides the RPC endpoint | **NEW** | [6] |

RPC hosts are legitimate public infrastructure: alert when they appear next to a marker, never block them.
The NullReceiver payload starts its next stage with `spawn('node', ['-e', ...], {detached: true})` [6].

---

## File hashes

All **NEW** (SHA-256).

| SHA-256 | File | Source |
|---|---|---|
| `7d47c430e6e404dc2fa8b4837678d1cbdb4d0aeacec9b405655cab79d54a2ad9` | `tailwind.config.js` (Visanduma variant) | [5] |
| `b7ede935d4979146b55f12b9eec7c83b61962b478f5dc9b8db251e539ec2abd3` | `tailwind.config.js` (Visanduma variant) | [5] |
| `ccb187dc9de0cc7477c9817ae53365d273e121407c0305f863e2ab67c35d6395` | `tailwind.config.js` (Visanduma variant) | [5] |
| `139ea03dcddf4aa810d55740be3cf6c92ce7a9f3cbcbbb35440e25b769a87683` | `tailwind.config.js` (Visanduma variant) | [5] |
| `515a53291d25d229e1f9fa72e66407e1cfd7e77c91478400b24d5185af68531a` | `tailwind.config.js` (Visanduma variant) | [5] |
| `f2c8234c00b1f5b0b135534bf51207dc0239647890b73531996d60c90cf9e866` | `skills/indexe.cjs` in `@dforge-core/dforge-mcp@0.2.21` | [6] |
| `a85c6955ad689aa89eaae8c8b30723935274f069aed044489cfd922b46bcf2f7` | `package.json` of `@dforge-core/dforge-mcp@0.2.21` | [6] |
| `e9045b27557e5019fe44a1d5ae4b77714faa65fef883127ca7db85b7970afab4` | npm tarball of `@dforge-core/dforge-mcp@0.2.21` | [6] |

ThreatScan's `fake_font_sha256` list only matches font files. These hashes are config files, a loader and a
tarball, so they need a general "known malicious file hash" list (see the proposal).

---

## Proposed `iocs.json` additions

For review before merging. Keys marked *(new key)* need a small scanner change; everything else fits an
existing key and reaches every installed copy within 24 hours once pushed to `main`.

```json
{
  "marker_regexes (replace the global.i pattern)": [
    "global(?:\\.i|\\[['\"]i['\"]\\])\\s*=\\s*['\"]A\\d+(?:-\\*?\\d+)*['\"]"
  ],
  "literal_signatures (add)": [
    "helloipbot!!",
    "68656c6c6f6970626f742121",
    "0xc1f79026c1f7902668656c6c6f6970626f742121"
  ],
  "malicious_ips (add)": [
    "166.88.73.46", "135.181.123.177", "138.201.50.5", "144.172.105.235",
    "144.172.112.106", "146.70.253.107", "23.127.202.249", "23.227.202.244"
  ],
  "malicious_hosts (add)": [
    "fashdefi.store", "0927.vercel.app", "ip-check-server.vercel.app", "process-log.vercel.app",
    "process-log-update.vercel.app", "log-server-lovat.vercel.app"
  ],
  "c2_url_paths (add)": [
    "/defy/v7", "/api/ipcheck", "/api/ip-check/", "/b964566497d98298d32c"
  ],
  "blockchain_rpc_hosts (add, alert only)": [
    "eth-mainnet.public.blastapi.io", "eth.blockscout.com"
  ],
  "compromised_npm (add)": {
    "@dforge-core/dforge-mcp": ["0.2.20", "0.2.21"],
    "@common-stack/generate-plugin": ["9.0.2-alpha.*"],
    "epxreso": ["*"], "epxresso": ["*"], "epxressoo": ["*"], "dotevn": ["*"], "boby_parser": ["*"],
    "ethrs.js": ["*"], "ethres.js": ["*"], "we3.js": ["*"], "wb3.js": ["*"],
    "hardhat-deploy-notifier": ["*"], "hardhat-deploy-notification": ["*"], "metamask-api": ["*"],
    "vaildator": ["*"], "truffel": ["*"], "ganacche": ["*"], "foudry": ["*"]
  },
  "compromised_packagist (add)": [
    "visanduma/nova-two-factor", "thiio/kubernetes-php-sdk", "arsl/optima-class", "olc/olc-php",
    "sevenspan/laravel-whatsapp", "adxio/twig-hmvc", "sevenspan/code-generator", "lambda-platform/moqup",
    "sevenspan/laravel-chat", "plusinfolab/logstation"
  ],
  "malicious_file_sha256 (new key)": [
    "7d47c430e6e404dc2fa8b4837678d1cbdb4d0aeacec9b405655cab79d54a2ad9",
    "b7ede935d4979146b55f12b9eec7c83b61962b478f5dc9b8db251e539ec2abd3",
    "ccb187dc9de0cc7477c9817ae53365d273e121407c0305f863e2ab67c35d6395",
    "139ea03dcddf4aa810d55740be3cf6c92ce7a9f3cbcbbb35440e25b769a87683",
    "515a53291d25d229e1f9fa72e66407e1cfd7e77c91478400b24d5185af68531a",
    "f2c8234c00b1f5b0b135534bf51207dc0239647890b73531996d60c90cf9e866",
    "a85c6955ad689aa89eaae8c8b30723935274f069aed044489cfd922b46bcf2f7",
    "e9045b27557e5019fe44a1d5ae4b77714faa65fef883127ca7db85b7970afab4"
  ]
}
```

Before merging, check against the scanner code:

- How `compromised_npm` versions are matched (exact list, `*`, or a prefix such as `9.0.2-alpha.*`).
- Whether the Packagist check reads `composer.lock` branch versions such as `dev-main`, since the Visanduma
  compromise has no bad stable release.
- Name-only package matches (the typosquats, the Packagist packages without versions) will also flag clean
  versions; report them as HIGH, not CRITICAL, unless the file content also matches.

Scanner changes suggested by this research (code, not data):

1. Widen the `global.i` marker regex (above) and add a regression test with `A8` and `A9-0204-3`.
2. Flag `.php` files containing `shell_exec` together with `node -e` or a long obfuscated string.
3. Add `malicious_file_sha256` and check it for config, entry and package files.
4. In `--deep` mode, include `$GOPATH/pkg/mod` and `vendor/` so compromised Go modules are found by content.

---

## Rejected claims (do not add)

These appeared in sources but failed three-vote verification: the source did not support the exact value,
or the value was misquoted. They may be real; add them only after checking a primary source by hand.

| Claim | Vote | Source |
|---|---|---|
| Tailwind typosquats `tailwind-animationbased`, `tailwindcss-typography-style@0.8.2`, `tailwindcss-style-modify@0.8.3`, `tailwindcss-animate-style@1.2.5` | 0-3 | [1] |
| `fa-solid-500` variant uses new XOR keys `q4FZkxX{!h`, `Sr3=@`, `y-p_>d$0B&@^1aQk`, C2 paths `:443/0x/cls`, `:443/0x/ls`, and headers `Sec-V` / `X-Payload-B64` | 0-3 | [2] |
| `.gitignore` hides `temp_interactive_push.bat` and `branch_structure.json`; loader run as `node ./prisma/generated/prisma/internal/public/fonts/fa-solid-900.woff2` | 1-2 | [2] |
| Template UUID `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9` in injected code | 0-3 | [3] |
| GHAPPIER loader `indexe.cjs` details: header string, stage hosts `primevector-app924560.vercel.app`, `brightlaunch-ext75642.vercel.app`, socket C2 `193.26.115.131:15152`, loader hashes for tags g1028/g0115/g213515 | 0-3 | [6] |
| GHAPPIER host artefacts: `$TMPDIR/.git-checker`, `$TMPDIR/vscode-ext.lock`, `~/.config/tokenlinux.sh`, `%APPDATA%\token.cmd`, `~/.npm/.vscode/parser.js`, `%APPDATA%\VSCODE\loader.js` | 1-2 | [6] |

Note: several of these values (`q4FZkxX{!h`, `Sr3=@`, `temp_interactive_push.bat`, `branch_structure.json`,
`/0x/cls`, `Sec-V`, `X-Payload-B64`, the UUID `e9b53a7c-...`) are **already in `iocs.json`** from earlier work. This research could not
re-confirm them against the cited pages; they were not removed, and nothing here says they are wrong.

---

## Open questions

- Which Go module paths and versions make up the ~61 confirmed malicious modules, and which overlap the 16
  in ThreatScan?
- The 11 unpublished `@common-stack/generate-plugin` versions, and the malicious commits or tags of the July
  2026 Packagist packages.
- SHA-256s of the September 2026 `fa-solid-500.woff2` and `fa-solid-900.woff2` loaders, and whether the `A8`
  variant uses its own XOR keys, C2 paths or wallet.
- PolinRider or Contagious Interview activity in PyPI, crates.io and VS Code / Open VSX extensions since
  September 2026.
- Host persistence dropped by the current stages (systemd user units, LaunchAgents, Run keys, scheduled
  tasks), InvisibleFerret / OtterCookie variants, and Telegram bot tokens. No verified source in this pass.

---

## Method

Deep-research workflow run on 2026-09-28: 5 search angles (primary tracker, vendor package research,
news and threat intel, technical artefacts, blockchain and C2 infrastructure), 17 sources fetched,
83 claims extracted, 25 verified by three independent adversarial checks (two refutations remove a claim),
19 confirmed, 6 rejected, merged into 11 findings. "NEW" and "KNOWN" were then re-checked by searching
`threatscan/iocs.json` directly, and the two marker gaps by scanning test repositories with ThreatScan 0.1.1.

Source concentration: much of the PolinRider-specific detail comes from one tracker (OpenSourceMalware),
which also named the campaign. Items from a single source are marked medium confidence in the workflow
output; the three-vote check confirms the source says it, not that the source is right.

## Sources

| # | Source | Date | Type |
|---|---|---|---|
| [1] | [OpenSourceMalware/PolinRider tracker](https://github.com/OpenSourceMalware/PolinRider) | ongoing (README counts as of Apr 2026) | primary |
| [2] | [OpenSourceMalware: PolinRider is A/B testing its way past your detections](https://opensourcemalware.com/blog/polinrider-is-a-b-testing-its-way-past-your-detections) | 2026-09-26 | primary |
| [3] | [OpenSourceMalware: PolinRider blast radius grows](https://opensourcemalware.com/blog/polinrider-blast-radius-grows) | 2026-07-15 | primary |
| [4] | [Sonatype: hijacked npm package attempts to deliver PolinRider-linked RAT](https://www.sonatype.com/blog/hijacked-npm-package-attempts-to-deliver-polinrider-linked-rat) | 2026-06 | primary |
| [5] | [Socket: PolinRider spreads through compromised GitHub accounts and Packagist](https://socket.dev/blog/polinrider-github-packagist) | 2026-09-17 | primary |
| [6] | [CloudSEK: GHAPPIER malware loader npm supply-chain attack](https://www.cloudsek.com/blog/ghappier-malware-loader-npm-supply-chain-attack) (IOC tables corroborated by gbhackers, cybersecuritynews and Infosecurity Magazine; NullReceiver by The Hacker News and OpenSourceMalware) | 2026-09-21 | primary |
| [7] | [OpenSourceMalware: PolinRider jumps the fence](https://opensourcemalware.com/blog/polinrider-jumps-the-fence) | 2026-07-08 | primary |
| [8] | [Socket: North Korea's Contagious Interview campaign, 338 malicious npm packages](https://socket.dev/blog/north-korea-contagious-interview-campaign-338-malicious-npm-packages) | 2025-10-10 | primary |

Also fetched, no additional verified indicators: The Hacker News (2026-04, 2026-07, 2026-09), Panther
("Inside DPRK's npm malware factory"), SafeDep (Astro config blockchain C2), securityonline.info,
radar.offseq.com, meSingh/polinrider-cleaner PR #32, michaelyali/michaelyali issue #1.
