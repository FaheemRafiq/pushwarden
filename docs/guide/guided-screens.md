---
title: Guided screens
description: "pushwarden ui: check and clean your GitHub repositories on guided screens instead of command-line options, from the Start menu on Windows or the Applications folder on macOS."
---
# Guided screens

`pushwarden ui` does the work of [github-clean](github-clean.md) on screens you move through with the keyboard: sign in, tick the repositories, check them, read what was found, then fix and push after you confirm. It is made for people who would rather not type commands and options.

## Opening it

| System | How |
|---|---|
| Windows | Open **PushWarden** from the Start menu. The installer puts it there |
| macOS | Open **PushWarden** from the `Applications` folder in your home folder (`~/Applications`), or find it with Spotlight. The first time, macOS asks whether PushWarden may control Terminal: allow it |
| Linux | Run `pushwarden ui` in a terminal |

On every system `pushwarden ui` in a terminal does the same. The shortcuts open a terminal window for you. Git must be installed; the screens tell you if it is not.

## The steps

### 1. Sign in

PushWarden looks for accounts you are already signed in to on this computer: the tokens in `GITHUB_TOKEN` and `GH_TOKEN`, and every account logged in to the GitHub command-line tool (`gh`).

- **One account found:** it is used and you go straight to the next step.
- **Several found:** you choose one from a list. The last row, *Use another token*, lets you paste a token instead.
- **None found:** the screen explains how to create a token and shows a field to paste it into.

```
  Which account's repositories do you want to check?

  > me                 gh login
    me-at-work         gh login
    Use another token  paste it on the next screen
```

In the token field, what you paste is shown as `*`. The token is used for this run only and is never written to disk. A fine-grained token needs *Contents: Read and write* on the repositories to clean; a classic token needs the `repo` scope. See [the token section](github-clean.md#the-token).

### 2. Choose the repositories

Every repository the token can push to is listed with a checkbox, all ticked to begin with.

```
  Choose the repositories to check   2 of 3 selected

  > [x] me/app       private
    [x] me/lib
    [ ] me/old-fork  fork
```

| Key | Action |
|---|---|
| Up, Down | move |
| Space | tick or untick the repository |
| `a`, `n` | tick all, or none, of the repositories shown |
| `/` | type to filter the list by name; Enter keeps the filter, Esc clears it |
| `f`, `r` | show or hide forks and archived repositories. They are hidden, and not ticked, until you show them |
| `s` | switch to another account |
| Enter | check the ticked repositories |
| `q` | quit |

### 3. Check

Each repository is downloaded and every branch is scanned. **Nothing is changed in this step.** The list shows the result per repository as it finishes. Press `q` to stop; what is finished is remembered.

### 4. Review

The report lists every infected branch and the files that would be fixed.

```
  Check finished

  Repositories:               2
  Branches clean:             1
  Branches infected:          2

  ! me/app @ main  INFECTED, 5 files would be fixed
      - postcss.config.mjs: payload stripped
      - temp_auto_push.bat: deleted
      - .gitignore: entries removed
      - .vscode/tasks.json: deleted
      - public/fonts/fa-solid-900.woff2: deleted

  Press Enter to fix and push 2 branches in 1 repository.
  Nothing has been changed so far.
```

If nothing is infected the report says so and Enter closes the program. Press `q` to leave without changing anything.

### 5. Fix and push

Enter asks once more, and only `y` goes ahead. Each infected branch then gets one normal commit, "security: remove PolinRider malware", which is pushed to GitHub. History is not rewritten and nothing is force-pushed. The original files are kept in quarantine on your computer.

The final report shows what was pushed and what to do next: rotate the token and every secret those repositories or their CI could read, review *Settings, Applications* and *Deploy keys* on GitHub, and ask collaborators to `git pull`.

A push that GitHub refuses, for example to a protected branch, is reported and not forced. See [Per-branch status](github-clean.md#per-branch-status).

## More than one GitHub account

A personal and a work account are cleaned one after the other. Clean the first, then press `s` on the repository list or on the final report to return to the list of accounts, and choose the next. The header always shows which account is signed in, and each account's fixes are pushed with that account's own token.

To make a second account appear in the list, do one of these:

- **Log it in to `gh`.** Run `gh auth login` again for the other account; `gh` keeps several accounts side by side and PushWarden lists them all.
- **Paste a token.** Choose *Use another token*. An accepted token stays in the list until you close the program, so you can switch back without pasting it again. It is not saved.

SSH keys and host names from your SSH configuration play no part: PushWarden downloads and pushes over HTTPS with the token. A fine-grained token for repositories that belong to an organisation may need that organisation's approval before it can push.

Progress is remembered per repository, so the accounts do not disturb each other's resume state.

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
