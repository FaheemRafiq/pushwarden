---
title: Hardening
description: "Preventive settings PushWarden applies to VS Code-family editors and npm so that opening a malicious project does not run code."
---
# Hardening

Hardening closes the door the malware uses to start. PolinRider's first stage usually runs through a VS Code task that executes when a folder is opened, or through a package lifecycle script. Both can be turned off.

`pushwarden install` applies the editor hardening automatically. Run `pushwarden harden` to apply it without installing the guard, or to add the opt-in settings.

```sh
pushwarden harden [options]
```

| Option | Effect |
|---|---|
| (none) | harden every VS Code-family editor found |
| `--npm-ignore-scripts` | set `ignore-scripts=true` in `~/.npmrc`, so installs never run lifecycle scripts |
| `--undo-npm` | remove that setting again |
| `--pre-commit REPO` | install a pre-commit hook in `REPO` that runs `pushwarden check-staged`. Repeatable |
| `--dry-run` | show what would change |

## Editor settings

These four settings are written into each editor's user `settings.json`:

```json
"task.allowAutomaticTasks": "off",
"security.workspace.trust.enabled": true,
"security.workspace.trust.startupPrompt": "always",
"security.workspace.trust.untrustedFiles": "prompt"
```

| Setting | Why |
|---|---|
| `task.allowAutomaticTasks: off` | A task with `runOn: folderOpen` no longer starts by itself. This is the campaign's main entry point |
| Workspace trust on, prompt always | A newly opened folder starts in restricted mode until you trust it |

Editors covered: VS Code, VS Code Insiders, VSCodium, Cursor, Windsurf and Positron, on all three platforms.

The file is edited in place: comments, trailing commas and your other settings are preserved. A backup of the previous file is written next to it as `settings.json.pushwarden-<timestamp>.bak`; the newest two backups are kept.

`pushwarden status` lists each editor with its current `task.allowAutomaticTasks` value. The guard also reports a project that tries to force automatic tasks back on.

## npm lifecycle scripts

```sh
pushwarden harden --npm-ignore-scripts
```

This sets `ignore-scripts=true` in `~/.npmrc`. Package `preinstall`, `install` and `postinstall` scripts then never run during `npm install`, which blocks compromised packages from executing code at install time.

Some packages need their install script to build native code. For those, run the script deliberately, or undo the setting:

```sh
pushwarden harden --undo-npm
```

pnpm version 10 and later already ignores lifecycle scripts by default.

## Pre-commit hook

```sh
pushwarden harden --pre-commit ~/code/repo1
for r in ~/code/*/; do pushwarden harden --pre-commit "$r"; done
```

The hook runs `pushwarden check-staged`, which scans the files staged for commit and refuses the commit if any carries a PolinRider indicator at HIGH or above. This stops an infected machine from committing the malware into a clean repository.

An existing hook is kept as `pre-commit.pre-pushwarden`.

## Hardening is kept on uninstall

`pushwarden uninstall` leaves the editor settings in place, because they are a safe default for any developer machine.
