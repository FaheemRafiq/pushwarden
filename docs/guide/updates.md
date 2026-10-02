---
title: Updates
description: "How ThreatScan keeps its indicators and itself up to date: daily indicator refresh, signed program updates, rollback, channels and how to turn updates off."
---
# Updates

Two things are updated, on separate schedules: the indicators (what to look for) and the program.

## Indicator updates

Most new malware variants are covered by adding an indicator, without a new release.

- Every 24 hours (`ioc_update_interval`) the guard downloads `iocs.json` from the project repository's `main` branch.
- The file is parsed and validated before it replaces the previous copy: every regular expression must compile, and every IP address and hash must be well formed.
- A file whose version is not newer is ignored.
- If the download fails, the previous copy stays in use. The program always has an embedded copy as a fallback.

```sh
threatscan update-iocs              # download now
threatscan update-iocs --url URL    # from a mirror or a fork
```

A running guard picks a new file up at its next definitions check. Restart the service to use it immediately.

| Setting | Default | Effect |
|---|---|---|
| `ioc_update` | `true` | download indicators at all |
| `ioc_update_interval` | `86400` | seconds between downloads |
| `ioc_update_url` | empty | alternative indicator URL |

## Program updates

Every 6 hours (`update_interval`) the guard checks GitHub for a newer release.

```sh
threatscan update --check     # is a newer release available?
threatscan update             # update now
```

### Verification

A release is verified before it replaces the program:

1. `checksums.txt` is downloaded with its signature, `checksums.txt.sig`.
2. The signature is checked against the project's ed25519 public key, which is built into the program.
3. The downloaded binary's SHA-256 must match the entry in `checksums.txt`.

A release that fails any step is refused and recorded as an error in the journal.

### Rollback

The previous binary is kept beside the new one. After an update the guard restarts and must write a heartbeat with the new version. If the new version does not start cleanly, the previous binary is restored, and that release is never retried. Once the new version has confirmed itself, the old binary is deleted.

### Channels

| `update_channel` | Considers |
|---|---|
| `stable` (default) | full releases only |
| `beta` | pre-releases too |

### Settings

| Setting | Default | Effect |
|---|---|---|
| `auto_update` | `true` | update the program automatically |
| `update_channel` | `stable` | `stable` or `beta` |
| `update_interval` | `21600` | seconds between update checks |
| `update_api_url` | empty | alternative release API, for mirrors |

To turn automatic updates off:

```sh
threatscan config --set auto_update=false
```

## The firewall block updates separately

The privileged job that keeps the [C2 block](network-block.md) refreshes its own root-owned copy of the indicators once a day, from the project repository only.

## What is recorded

Every indicator and program update, and every refused or rolled-back update, is written to the journal with kind `update` or `error`.

```sh
threatscan history --all --kind update
```

## Versions

```sh
threatscan version
```

Release builds print the release number; development builds end in `-dev`. `threatscan status` shows the program version and the indicator version.

## How releases are made

A release is cut by pushing a tag `vX.Y.Z`; a hyphen, as in `v0.2.0-rc1`, makes a pre-release. The release workflow builds every asset, installs it on Windows, macOS and Linux until the guard reports alive, and only then publishes with a signed `checksums.txt`. Installed copies pick the release up within 6 hours.
