# shell-guard

A Claude Code mod that refuses shell commands which wipe your home folder, the project, a disk, a protected branch or a database, and saves your uncommitted work to a git ref before commands that would destroy it.

```
shell-guard blocked: rm -rf ~/shell-guard-smoke-nonexistent

Error: shell-guard blocked this command: the target ~/shell-guard-smoke-nonexistent is outside the
project (~/proj); recursive or forced deletes are allowed only inside the project and temp folders.
If the user really wants this, ask them to run it themselves.

snapshot saved: refs/shell-guard/20261006-120304-567

> /shell-guard
shell-guard is on. 1 snapshot in ~/proj, newest first.
Restoring overwrites the same files in the working tree; files created since stay.

1. 2026-10-06 14:03  git reset --hard HEAD~1
   see:      git diff --stat refs/shell-guard/20261006-120304-567^1 refs/shell-guard/20261006-120304-567
   restore:  git checkout refs/shell-guard/20261006-120304-567 -- .
   one file: git checkout refs/shell-guard/20261006-120304-567 -- <path>
```

## Why

Claude Code runs a destructive command now and then, and `/rewind` does not undo what Bash did:

- Reddit: [Claude deleted my home folder](https://www.reddit.com/r/ClaudeAI/comments/1pgxckk/).
- Reddit: [Claude Code deleted the whole project](https://www.reddit.com/r/ClaudeCode/comments/1t7ggbu/).
- Reddit: [a 202 GB archive wiped despite "don't delete data"](https://www.reddit.com/r/ClaudeCode/comments/1sbpfdl/).
- Hacker News: [an agent dropped a production database](https://news.ycombinator.com/item?id=47278720).

Guards already exist, for example [dcg](https://github.com/Dicklesworthstone/destructive_command_guard) and [cc-safety-net](https://github.com/kenryu42/cc-safety-net). shell-guard differs in two ways:

- **It knows where the project is.** `rm -rf dist` inside the project runs; `rm -rf ~/anything`, `rm -rf ..`, `rm -rf *` at the project root and `cd ~ && rm -rf *` are refused. Paths are resolved against the working directory, `cd` included.
- **It snapshots before it lets work go.** `git reset --hard`, `git checkout -- .`, `git clean -fd`, `git stash drop` and `rm -r` inside the project still run, but first the whole working tree, untracked files included, is committed to `refs/shell-guard/<time>`. `/shell-guard` prints the commands that bring it back.

## What it does

| Command | What happens |
|---|---|
| `rm -r`/`-f` of `/`, `~`, `$HOME`, `/*`, the project root, `*` or `.` at the root, anything outside the project | Refused |
| `git push --force` / `-f` / `--force-with-lease` / `+ref` to a protected branch, `git push --mirror`, deleting a protected branch | Refused |
| `dd of=/dev/…`, `> /dev/sdb`, `mkfs*`, `shred`, `wipefs`, `diskutil erase*` | Refused |
| `chmod -R` / `chown -R` outside the project, `find / … -delete`, `find … -exec rm` outside the project | Refused |
| `terraform destroy`, `kubectl delete` of namespaces or `--all`, `docker system prune --volumes`, `docker volume rm/prune`, `docker compose down -v` | Refused |
| `DROP DATABASE`, `DROP SCHEMA`, `DROP TABLE`, `TRUNCATE` through `psql -c`, `mysql -e`, `sqlite3`, or a heredoc; `redis-cli FLUSHALL` | Refused |
| `git reset --hard`, `git checkout -- <path>`, `git checkout .`, `git restore` (not `--staged` alone), `git clean -f`, `git switch --discard-changes`, `git stash drop/clear`, `rm -r` and `find -delete` inside the project | Snapshot, then run |
| `rm -rf node_modules dist`, `rm file.txt`, `git push --force` to a feature branch, `git reset --soft`, `docker compose down`, `kubectl delete pod x`, `rm -rf /tmp/x` | Run |

The parser splits a command on `&&`, `||`, `;`, `|`, `&`, newlines and parentheses, and looks inside `bash -c`/`sh -c`, `eval`, `$(…)`, backticks, `xargs` and shell heredocs. It strips `sudo`, `env`, `nice`, `timeout` and `VAR=value` prefixes. Quotes are respected: `grep "rm -rf /"` and `echo 'git push --force'` run.

A refusal shows a toast and tells the model what to do instead. A snapshot shows `snapshot saved: refs/shell-guard/…`.

## Install

You need Claude Code with mods (function hooks); tested on 2.1.285 and 2.1.291. Mods are in early access: if the CLI says hooks modules are not turned on, start it as `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude`.

From the marketplace in this repo:

```
/plugin marketplace add Jvrd97/claude-shell-guard
/plugin install shell-guard@shell-guard
```

Or straight from disk, for one session:

```bash
git clone https://github.com/Jvrd97/claude-shell-guard.git
claude --plugin-dir ./claude-shell-guard
```

`/shell-guard off` turns the guard off for the session and `/shell-guard on` turns it back on. Only a person can turn it off: the command refuses a run that did not come from the prompt, the bridge or the SDK host.

## Settings

Change them in `/config` under the plugin, or in `settings.json` under `pluginConfigs`:

| Field | Default | Meaning |
|---|---|---|
| `mode` | `deny` | `deny` refuses a dangerous command. `ask` sends it to the permission dialog with the reason instead |
| `protectedBranches` | `main,master` | Branches that may not be force-pushed, deleted on the remote or deleted with `git branch -D` |
| `snapshots` | `true` | Snapshot uncommitted work before commands that destroy it |
| `extraDeny` | empty | Regular expressions, one per line, matched against each command of a Bash call with prefixes like `sudo` stripped, for example `^npm publish` |

`ask` hands the decision to your permission mode. In `bypassPermissions`, `auto` or a headless run, that mode may let the command through without asking you, which is why `deny` is the default.

## How it works

- `tool.call` on Bash classifies the command. A dangerous command is answered with a deny, so it never runs. In `ask` mode, `tool.check` turns the same verdict into an `ask`.
- The project root is the session's root (`$.session.root()`), where Claude Code started or `/cd` moved it. Recursive or forced deletes are allowed beneath it and beneath `/tmp`, `/private/tmp`, `/var/tmp` and `$TMPDIR`.
- A snapshot runs in the repo of the command's working directory: `git status --porcelain` first (a clean tree is skipped silently, as is a folder outside git), then `git add -A` into a temporary index at `.git/shell-guard-index` (a copy of the real one, deleted afterwards), `git write-tree`, `git commit-tree` with `HEAD` as parent and `git update-ref refs/shell-guard/<time>`. The real index, `HEAD` and your branches are not touched. `git stash drop/clear` also adds every stash as a parent, so a dropped stash can be stored back.
- The newest 100 snapshots per repo are kept; older refs are deleted.
- If a snapshot fails, the command is refused rather than run unprotected.
- The mod writes nothing outside your repos' `.git` folders and sends nothing anywhere.

What it cannot do:

- It reads the command text, not what a script does. `./cleanup.sh`, `make clean`, `python -c "shutil.rmtree(...)"` and `ssh host 'rm -rf /'` run unchecked.
- It does not follow symbolic links. A link inside the project that points outside it counts as inside.
- A target built from a variable it cannot resolve (`rm -rf "$DIR"`, a loop variable) is refused; the model is told to repeat the command with a literal path. `$HOME`, `$PWD` and `$(pwd)` are resolved.
- `xargs rm -rf` with no targets of its own is treated as a delete inside the project, because the paths arrive on stdin.
- Snapshots respect `.gitignore`: `git clean -fdx` deletes ignored files (an `.env`, local databases) that no snapshot holds.
- It does not catch SQL piped from another command (`echo "DROP TABLE x" | psql`), only `-c`/`-e`, sqlite3 arguments and heredocs.
- False positives it accepts: `DROP TABLE` against a throwaway local database, `rm -f` of a single file outside the project, any `shred`.

## Develop

Inside Claude Code run `/plugin-types .claude/types` once: it writes the API types `tsc` reads. Then:

```bash
tsc -p .
claude plugin validate .claude-plugin/plugin.json
claude plugin test .
```

## По-русски

Мод не даёт Claude Code выполнить команды, которые стирают домашнюю папку, весь проект, диск, защищённую ветку или базу данных. Модель получает отказ с объяснением, что сделать вместо этого.

Мод знает границы проекта: `rm -rf dist` внутри проекта пройдёт, `rm -rf ~/что-угодно` и `rm -rf *` в корне — нет.

Перед `git reset --hard`, `git clean -f`, `git checkout -- .` и `rm -r` внутри проекта мод сохраняет все незакоммиченные файлы, включая неотслеживаемые, в ref `refs/shell-guard/<время>`. `/rewind` такие изменения не откатывает, а `/shell-guard` печатает готовые команды восстановления.

## License

MIT
