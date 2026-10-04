---
title: Guided screens
description: "pushwarden ui: the easy way to check and clean your GitHub repositories. Guided screens walk you through it, from the Start menu on Windows or the Applications folder on macOS."
---
# Guided screens

`pushwarden ui` does the work of [github-clean](github-clean.md) on screens you move through with the keyboard: sign in, tick the repositories, check them, read what was found, then fix and push after you confirm. There are no commands to remember.

## Opening it

| System | How |
|---|---|
| Windows | Open **PushWarden** from the Start menu. The installer puts it there |
| macOS | Open **PushWarden** from the `Applications` folder in your home folder (`~/Applications`), or find it with Spotlight. The first time, macOS asks whether PushWarden may control Terminal: allow it |
| Linux | Run `pushwarden ui` in a terminal |

On every system `pushwarden ui` in a terminal does the same. The shortcuts open a terminal window for you. Git must be installed; the screens tell you if it is not.

## The steps

### 1. Sign in

PushWarden looks for accounts you are already signed in to on this computer:

- **Tokens:** `GITHUB_TOKEN` and `GH_TOKEN`, and every account logged in to the GitHub command-line tool (`gh`).
- **Git over SSH:** every SSH host in `~/.ssh/config` that leads to `github.com`, and `github.com` itself. Each is tried once (`ssh -T`), and GitHub's answer names the account. A key that needs a passphrase which is not in your SSH agent is skipped, because nothing is ever asked.

What happens next depends on how many it finds:

- **One account:** it is used and you go straight to the next step.
- **Several:** you choose one from a list. The last row, *Use another token*, lets you paste a token instead.
- **None:** the screen explains how to create a token and shows a field to paste it into.

```
  Which account's repositories do you want to check?

  > me                 gh login
    me-at-work         SSH (github-work)
    Use another token  paste it on the next screen
```

In the token field, what you paste is shown as `*`. The token is used for this run only and is never written to disk. A fine-grained token needs *Contents: Read and write* on the repositories to clean; a classic token needs the `repo` scope. See [the token section](github-clean.md#the-token).

When the same account is found both as a token and over SSH, the token is listed: it can see every repository, SSH cannot (see [SSH accounts](#ssh-accounts)).

### 2. Choose the repositories

The repositories of the account are listed with a checkbox each. **Nothing is ticked to begin with**: you choose what is checked.

```
  Choose the repositories to check   0 of 3 selected
  2 verified by earlier runs, 1 not checked yet.

  > [ ] me/app   private      fixed · 3 branches · 3 Oct 14:15
    [ ] me/lib   local clone  clean · 1 branch · 2 Oct 23:00
    [ ] me/site               not checked yet

  On this computer: ~/code/lib
```

Each row shows what is known about the repository:

- **Tags:** `private`, `fork`, `archived`, and `local clone` when the repository is also cloned on this computer. For the highlighted row the folder of that clone is shown under the list.
- **Earlier result:** what earlier runs verified, with the number of branches and when: `clean`, `fixed` (PushWarden pushed a fix), `needs review`, or `not checked yet`. A repository that was verified is not downloaded again unless a branch has moved since.

| Key | Action |
|---|---|
| Up, Down | move |
| Space | tick or untick the repository |
| `a`, `n` | tick all, or none, of the repositories shown |
| `u` | tick the repositories no earlier run has checked |
| `l` | tick the repositories that are cloned on this computer |
| `/` | type to filter the list by name; Enter keeps the filter, Esc clears it |
| `f`, `r` | show or hide forks and archived repositories. They are hidden until you show them |
| `+` | SSH accounts only: add a repository by typing `owner/name` |
| `s` | switch to another account |
| Enter | check the ticked repositories |
| `q` | quit |

### 3. Check

Each repository is downloaded and every branch is scanned. **Nothing is changed in this step.**

```
  Checking 4 repositories. Nothing is changed.

  ████████████░░░░░░░░░░░░  2/4   50%  1:12
  Branches so far: 6 clean · 1 infected · 0 need review · 0 failed

  + me/app   3 clean
  ! me/lib   1 INFECTED
  / me/site  2 branches done   > me/site @ main
  . me/api   waiting
```

The bar counts finished repositories; the line under it counts branches as they finish. A large repository with many branches takes the longest, because it is downloaded in full. Press `q` to stop; what is finished is remembered.

### 4. Review

The report opens with the totals, then lists every infected branch and the files that would be fixed.

```
  Check finished

  ┌────────────────┐┌─────────┐┌────────────┐┌───────────────┐┌──────────┐
  │       2        ││    1    ││     2      ││       0       ││    0     │
  │  repositories  ││  clean  ││  infected  ││  need review  ││  failed  │
  └────────────────┘└─────────┘└────────────┘└───────────────┘└──────────┘

  ! me/app @ main  INFECTED, 5 files would be fixed
      - postcss.config.mjs: payload stripped
      - temp_auto_push.bat: deleted
      - .gitignore: entries removed
      - .vscode/tasks.json: deleted
      - public/fonts/fa-solid-900.woff2: deleted

  Press Enter to fix and push 2 branches in 1 repository.
  Nothing has been changed so far.
```

If nothing is infected the report says so and Enter closes the program. Press `b` to go back to the repository list and check more of the same account, or `q` to leave without changing anything.

### 5. Fix and push

Enter asks once more, and only `y` goes ahead. Each infected branch then gets one normal commit, "security: remove PolinRider malware", which is pushed to GitHub. History is not rewritten and nothing is force-pushed. The original files are kept in quarantine on your computer.

The final report shows what was pushed and what to do next: rotate the token and every secret those repositories or their CI could read, review *Settings, Applications* and *Deploy keys* on GitHub, and ask collaborators to `git pull`.

A push that GitHub refuses, for example to a protected branch, is reported and not forced. See [Per-branch status](github-clean.md#per-branch-status).

## More than one GitHub account

A personal and a work account are cleaned one after the other. Clean the first, then press `s` on the repository list or on the final report to return to the list of accounts, and choose the next. The header always shows which account is signed in and how, and each account's fixes are pushed as that account.

To make a second account appear in the list, any of these works:

- **It already has an SSH key set up for git.** Then it is listed without you doing anything.
- **Log it in to `gh`.** Run `gh auth login` again for the other account; `gh` keeps several accounts side by side and PushWarden lists them all.
- **Paste a token.** Choose *Use another token*. An accepted token stays in the list until you close the program, so you can switch back without pasting it again. It is not saved.

A fine-grained token for repositories that belong to an organisation may need that organisation's approval before it can push. Progress is remembered per repository, so the accounts do not disturb each other's resume state.

## SSH accounts

An SSH account uses the key git already has, so there is nothing to paste. The trade-off: **SSH can download and push a repository that is named, but it cannot ask GitHub for the list of your repositories.** PushWarden therefore builds the list from what it can find:

1. **Clones on this computer** whose remote goes through that SSH host, for example `git@github-work:my-org/api.git`. The folders searched are the ones the guard watches (`scan_roots`, or the usual project folders under your home folder).
2. **The account's public repositories**, which GitHub lists without a token.
3. **Names you type.** Press `+` and enter `owner/name`.

A private repository that is not cloned on this computer does not appear unless you add it. The malware pushes to every repository a stolen token could reach, so for a complete clean-up use a token account, or add the missing repositories by name.

Downloads and pushes go through `git@HOST:owner/name.git` with your own SSH command and settings. PushWarden reads the host names from `~/.ssh/config`; it never reads key files.

## Stopping and continuing

`q` or Ctrl+C during a check or a fix stops cleanly: the branch in progress is abandoned, everything already finished is saved, and the next run skips what is verified and unchanged. The progress is shared with `github-clean`, so you can stop on the screens and continue with the command, or the other way round. `pushwarden ui --fresh` forgets the progress and checks everything again.

## Options

| Option | Effect |
|---|---|
| `--api URL` | GitHub API base URL, for GitHub Enterprise |
| `--fresh` | forget the progress of earlier runs and check every branch again |
| `--pause` | if the screens cannot start, wait for Enter before closing. The shortcuts use this so a message stays readable |

The screens always check first and ask before fixing. For scripts, CI, choosing branches or owners, a commit author or JSON output, use [github-clean](github-clean.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | everything checked is clean, or was fixed and pushed |
| `1` | infected branches remain, a push was refused or a repository failed |
| `2` | no interactive terminal, or git is not installed |
