---
title: Cleaning GitHub repositories
description: "How threatscan github-clean removes PolinRider from every branch of every GitHub repository you can push to, with dry run, resume, token handling and exit codes."
---
# Cleaning GitHub repositories

PolinRider steals a token, rewrites your repositories and force-pushes its backdoor to every branch it can reach. `threatscan github-clean` undoes that at the same scale: it removes the malware from every branch of every repository your token can push to.

```sh
threatscan github-clean [options]
```

## Prefer screens to commands?

`threatscan ui` does the same work on guided screens: sign in, tick the repositories, check them, review what was found, then fix and push after you confirm. On Windows open **ThreatScan** from the Start menu; on macOS open **ThreatScan** from `~/Applications` (the first time, macOS asks whether it may control Terminal: allow it). Progress is shared with `github-clean`, so you can stop in one and continue in the other.

## What it does for each repository

1. Clones it once as a bare clone.
2. Checks out each branch in its own worktree.
3. Runs the repository scanner.
4. Fixes what it finds, with the same reversible protector as `scan --fix`: strips payloads appended to config files, deletes whole-file threats (fake fonts, malicious `.vscode/tasks.json`, propagation scripts) and removes the `.gitignore` entries that hide them.
5. Makes one commit per infected branch and pushes it with an explicit refspec.

**History is never rewritten and nothing is force-pushed.** A push the remote refuses (protected branch, archived repository, missing permission) is reported, not forced.

## Dry run is the default

Without `--apply` nothing is committed or pushed. The output says what would change on each branch.

```sh
threatscan github-clean                    # dry run over everything
threatscan github-clean --apply            # fix and push every infected branch
```

A dry run in a terminal that finds infected branches ends with a question, for example *Fix and push these 12 branches in 4 repositories now?* Answer `y` and the fixes are committed and pushed in the same run. `--no-ask` and `--ci` suppress the question.

## Options

| Option | Effect |
|---|---|
| `--apply` | commit and push the fixes |
| `--token PAT` | the GitHub token. Also read from `GITHUB_TOKEN`, then `GH_TOKEN`, then the `gh` CLI login |
| `--token-stdin` | read the token from standard input, for secret managers and CI |
| `--list` | print the repositories the token can push to and exit |
| `--select` | list the reachable repositories with numbers and pick which to clean and in which order |
| `--repo owner/name` | only this repository. Repeatable; run in the order given |
| `--owner NAME` | only repositories under this user or organisation. Repeatable |
| `--branch GLOB` | only branches matching this glob, for example `release/*`. Repeatable. Default: all |
| `--include-forks` | also clean forks (skipped by default) |
| `--include-archived` | also clean archived repositories. GitHub rejects pushes to them until they are unarchived |
| `--author "Name <email>"` | identity for the fix commits. Default: your git config, then `ThreatScan <threatscan@users.noreply.github.com>` |
| `--keep-clones DIR` | keep the clones under `DIR` for inspection instead of deleting them |
| `--json FILE` | write the full result to `FILE` |
| `--api URL` | GitHub Enterprise API base. Default `https://api.github.com` |
| `--ci` | no colour, no interactive prompts |
| `--no-ask` | after a dry run, do not offer to fix what was found |
| `--progress` | show what earlier runs already verified and exit. Needs no token and no network |
| `--fresh` | forget the progress of earlier runs, delete the kept copies and check every branch again |

## The token

Create a **fine-grained personal access token** with *Repository permissions, Contents: Read and write* on the repositories you want cleaned. A classic token needs the `repo` scope.

How the token is handled:

- It is passed to git through an askpass helper built into the program and an environment variable.
- It is never written to disk, into a remote URL, into the report or into the progress file.
- Stored git credential helpers, git hooks and `core.fsmonitor` are disabled while git runs, so a malicious git configuration cannot run code or redirect credentials.

Rotate the token after the clean-up.

## Selecting repositories

```sh
threatscan github-clean --list
threatscan github-clean --select --apply
threatscan github-clean --repo me/api --repo me/web --apply
threatscan github-clean --owner my-org --branch main --branch 'release/*' --apply
```

`--select` prints a numbered list. Type `3`, `1,4,2`, `5-9` or `all`. The order you type is the order the repositories are processed, so put the important one first.

## Progress is remembered

Every branch that is finished (clean, fixed and pushed, or flagged for manual review) is recorded right away, together with the commit it was verified at.

If a run is interrupted with Ctrl-C, hangs, or the machine goes to sleep, run the same command again:

- Branches whose tip is still the verified commit are skipped.
- A repository where nothing moved is not even cloned; one quick remote query confirms it.
- The summary counts what this run did and what earlier runs did.

A branch is checked again when:

- its tip commit changes, because the attacker can push again
- ThreatScan or its indicators are updated, because a newer version may find more

Dry-run findings, refused pushes and errors are never recorded as done.

```sh
threatscan github-clean --progress     # what is already verified, per repository
threatscan github-clean --fresh        # forget it and check everything
```

The reason progress is tied to the commit and not to the branch name: the attacker force-pushes with a stolen token, so "this branch was cleaned yesterday" proves nothing about today.

## From dry run to fix without doing the work twice

| After a dry run, `--apply` ... | |
|---|---|
| branches found clean | are skipped, as long as their tip has not moved |
| repositories where every branch was clean | are not cloned |
| repositories with infected branches | are not cloned again: the dry run's copy is kept and only new commits are fetched |
| the infected branches | are scanned once more, then fixed, committed and pushed |

The second scan of an infected branch is deliberate. The fix is made from the files as they are on the branch at that moment, so nothing stale is ever pushed.

A kept copy is a bare repository with no checked-out files and no token. It is deleted as soon as its repository has nothing left to fix, after 3 days without use (`clone_keep_days`), when the copies together pass 2 GB (`clone_keep_mb`), or by `--fresh`. A repository larger than that limit is not kept at all.

## Per-branch status

| Status | Meaning |
|---|---|
| `clean` | nothing to do |
| `clean, unchanged since verified ...` or `fixed earlier ...` | taken from an earlier run. In the JSON: `"resumed": true` |
| `infected` | dry run: this branch needs fixes |
| `pushed` | fixed and pushed; the short commit hash is shown |
| `push-failed` | fixed locally, the remote refused the push. The error is shown |
| `manual` | HIGH or CRITICAL findings ThreatScan does not fix automatically. Review them |
| `error` | clone, worktree, commit or scan failure |

Repository-wide findings about commits in history that touch payload code are listed under `history`. They are informational; removing them would need a force-push.

## The fix commit

Each infected branch gets one normal commit on top, titled `security: remove PolinRider malware`. The message lists every file with the threat name and what was done, and states that history was not rewritten.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | everything clean, or fixed and pushed |
| `1` | infected branches remain: dry run, refused pushes or errors |
| `2` | no token, bad token, or an API failure |

## JSON output

`--json FILE` writes the version, the user, whether it was an apply run, the start time, and for each repository its branches with status, findings, fixed files, commit, the verified commit (`sha`) and whether the result was resumed.

## Afterwards

1. Rotate the token you used and every secret those repositories or their CI could read.
2. Check *Settings, Applications* and *Deploy keys* on GitHub for anything you did not add.
3. Tell collaborators to `git pull`.
4. Quarantined originals are in `threatscan history`.

## Recipes

Organisation-wide clean-up after a compromise:

```sh
threatscan github-clean --owner my-org --list
threatscan github-clean --owner my-org --json dryrun.json     # review dryrun.json
threatscan github-clean --owner my-org --apply --json applied.json
```

In CI or with a secret manager:

```sh
GITHUB_TOKEN=... threatscan github-clean --ci --apply --json clean.json
op read op://Vault/GitHub/token | threatscan github-clean --token-stdin --apply
```

GitHub Enterprise:

```sh
threatscan github-clean --api https://github.example.com/api/v3 --owner my-org
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `push-failed` | The branch is protected, the repository is archived, or the token lacks write access. Allow the push temporarily, or open a pull request from a clean branch, then run again with `--repo owner/name --apply` |
| `push-failed` with a non-fast-forward error | Someone pushed between clone and push. Run again |
| No token found | Pass `--token`, export `GITHUB_TOKEN`, or run `gh auth login` |
| A repository is missing from `--list` | Forks and archived repositories are hidden unless `--include-forks` or `--include-archived` is given; a fine-grained token must list the repository |
