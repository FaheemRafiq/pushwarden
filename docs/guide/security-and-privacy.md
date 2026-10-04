---
title: Security and privacy
description: "The trust model of PushWarden: what runs with which privileges, how tokens and updates are protected, and exactly what data can leave the machine."
---
# Security and privacy

A security tool runs on machines that may already be compromised and handles sensitive material. This page states what PushWarden does and does not do, so you can decide whether to trust it.

## Privileges

| Part | Runs as | Notes |
|---|---|---|
| Every command and the background guard | your user | installs per user; no administrator password |
| The C2 block and its boot-time job | root or SYSTEM | installed once, with your consent, through the system's own elevation dialog |

The privileged job never reads files under your home folder to decide what to block. It uses a root-owned copy of the indicators, refreshed only from the project repository, and a root-owned copy of the program. A process running as you therefore cannot make the job edit the hosts file or firewall. See [Blocking C2 servers](network-block.md).

## Data that leaves the machine

Nothing leaves the machine unless you opt in.

| Connection | Content | Default |
|---|---|---|
| Indicator download | an HTTPS GET of `iocs.json` from the project repository | on; `ioc_update=false` turns it off |
| Program update | HTTPS GETs of the release list, checksums, signature and binary from GitHub | on; `auto_update=false` turns it off |
| `github-clean` | GitHub API calls and git over HTTPS with your token | only when you run it |
| Webhook alerts | each alert with host name, paths and reasons | off until `webhook_url` is set |
| Daily digest | counts only | off until `feedback_url` is set |
| Central event upload | redacted journal events | off until `upload_url` is set |

There is no built-in telemetry endpoint. No URL for the digest or the upload is compiled into the program.

Before turning the digest or the upload on you can see exactly what would be sent:

```sh
pushwarden feedback --digest
pushwarden feedback --preview
```

See [Team reporting](team-reporting.md) for the contents and the redaction rules.

## Redaction

The feedback bundle and the central upload remove what identifies the person or opens their accounts: the home folder becomes `~`, the user name and host name are removed, and token-shaped strings, private keys, credentials in URLs and secret-keyed values are masked. On the upload path this cannot be turned off.

## Token handling in `github-clean`

- The token is read from `--token`, standard input, an environment variable or the `gh` CLI.
- It is handed to git through an askpass helper built into the program and an environment variable of the child process.
- It is never written to disk, into a remote URL, into the JSON report, into the progress file or into kept clones.
- Git's error output is scrubbed of the token before it is shown.
- While git runs, stored credential helpers, hooks and `core.fsmonitor` are disabled, so a malicious global git configuration cannot run code or send the token elsewhere.

Use a fine-grained token limited to the repositories being cleaned, and rotate it afterwards.

## What the guided screens read to sign in

`pushwarden ui` looks for GitHub logins that already exist on the machine. It reads the `GITHUB_TOKEN` and `GH_TOKEN` variables, asks `gh` for the tokens of its logged-in accounts, reads the host names in `~/.ssh/config`, and runs `ssh -T` once per GitHub host to learn which account the key belongs to. It never reads SSH key files, and no token is written to disk. To mark local clones it reads the remote addresses in the `.git/config` of the repositories under your project folders; nothing in those repositories is run. See [Guided screens](guided-screens.md).

## Update integrity

- Release checksums are signed with the project's ed25519 key. The public key is built into the program.
- A downloaded release must pass the signature check and the SHA-256 check before it replaces the running program.
- A release that does not start cleanly is rolled back and never retried.
- Indicator files are validated before use and cannot contain code: they are data only.

The install script verifies the SHA-256 of the download against `checksums.txt`. It does not check the signature; the program checks it on every self-update.

## Handling of malicious files

- Detection reads files; it never executes them.
- A file is copied to quarantine before it is changed or removed, so every action can be undone.
- Quarantine is a folder under your data directory with user-only permissions. Files in it are inert copies.
- Automatic action requires strong evidence. Heuristic findings are reported only.
- A process is killed only on a strict marker that legitimate tools never use.

## The central upload key

The key that every machine holds for the central upload is an insert-only key. The provided SQL enables row level security with a single insert policy, so the key cannot read, change or delete rows, and the triage views are closed to it. Extracting the key from a machine allows adding junk rows and nothing more. See [Team reporting](team-reporting.md).

## Local files and permissions

The data directory and the files in it are created with user-only permissions (`0700` for directories, `0600` for files). `config.json` can contain a webhook URL and an upload key; treat it like any other credentials file.

## What PushWarden does not do

- It does not collect analytics or usage statistics.
- It does not upload file contents. The central upload carries only the matched text and evidence lines of a finding, redacted.
- It does not rewrite git history or force-push.
- It does not need or request administrator rights except for the C2 block.
- It does not protect against malware families other than the one it targets. It complements a general antivirus; it does not replace one.

## Reporting a vulnerability

Open an issue at <https://github.com/FaheemRafiq/pushwarden/issues>. For anything that should not be public, contact the maintainer through the GitHub profile first.

## Source

The source code can be read at <https://github.com/FaheemRafiq/pushwarden>.
