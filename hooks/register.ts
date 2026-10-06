import { atom, read, update } from 'claude-code'
import type { CommandRunInput, EngineInterface, ProcessRunResult, Register } from 'claude-code'

import type { ShellGuardMode } from '../types'
import {
  classify,
  DEFAULT_PROTECTED,
  formatSnapshots,
  MAX_SNAPSHOTS,
  parseBranches,
  parsePatterns,
  parseSnapshots,
  SNAPSHOT_FORMAT,
  SNAPSHOT_PREFIX,
  snapshotMessage,
  snapshotRef,
  type Context,
  type Verdict,
} from './logic'
import { tildify } from './paths'

const COMMAND = 'shell-guard'
const DENY_TOAST_MS = 8_000
const SNAPSHOT_TOAST_MS = 6_000
/** `git add -A` hashes every changed file; a big repo needs more than the default 30 s. */
const GIT_TIMEOUT_MS = 120_000
const SYSTEM_TEMP_DIRS = ['/tmp', '/private/tmp', '/var/tmp', '/private/var/tmp']
/** Who may turn the guard off: a person, never the model or another agent. */
const HUMAN_ORIGINS = new Set(['composer', 'bridge', 'sdk'])
const TEMP_INDEX = 'shell-guard-index'
const GIT_ENV: Record<string, string> = {
  GIT_OPTIONAL_LOCKS: '0',
  GIT_AUTHOR_NAME: 'shell-guard',
  GIT_AUTHOR_EMAIL: 'shell-guard@localhost',
  GIT_COMMITTER_NAME: 'shell-guard',
  GIT_COMMITTER_EMAIL: 'shell-guard@localhost',
}

const isOff = atom({ plugin: 'shell-guard', key: 'isOff' } as const, false)

type Settings = {
  mode: ShellGuardMode
  protectedBranches: string[]
  hasSnapshots: boolean
  extraDeny: RegExp[]
  invalidPatterns: string[]
}

type Run = { ok: true; out: string } | { ok: false; error: string }

/** Runs git and never rejects: a missing folder or binary comes back as an error. */
async function runGit($: EngineInterface, args: readonly string[], cwd: string, env: Record<string, string> = {}): Promise<Run> {
  let result: ProcessRunResult

  try {
    result = await $.process.run(['git', ...args], { cwd, env: { ...GIT_ENV, ...env }, timeoutMs: GIT_TIMEOUT_MS })
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }

  return result.exitCode === 0 ? { ok: true, out: result.stdout.trim() } : { ok: false, error: result.stderr.trim() || `git ${args[0] ?? ''} exited ${result.exitCode}` }
}

async function contextOf($: EngineInterface, command: string, settings: Settings): Promise<Context> {
  const cwd = await $.session.cwd()
  const root = await $.session.root()
  const home = (await $.env.get('HOME')) ?? ''
  const tmp = await $.env.get('TMPDIR')
  const branch = /\bpush\b/.test(command) ? await runGit($, ['rev-parse', '--abbrev-ref', 'HEAD'], cwd) : null
  const tempDirs = tmp === undefined || tmp === '' ? SYSTEM_TEMP_DIRS : [...SYSTEM_TEMP_DIRS, tmp.replace(/\/+$/, '')]

  return {
    cwd,
    root,
    home,
    tempDirs,
    branch: branch !== null && branch.ok && branch.out !== 'HEAD' ? branch.out : null,
    protectedBranches: settings.protectedBranches,
    extraDeny: settings.extraDeny,
  }
}

type Saved = { kind: 'saved'; ref: string } | { kind: 'skipped' } | { kind: 'failed'; error: string }

/** Drops the oldest snapshots past MAX_SNAPSHOTS. */
async function prune($: EngineInterface, top: string): Promise<void> {
  const listed = await runGit($, ['for-each-ref', '--sort=-refname', '--format=%(refname)', SNAPSHOT_PREFIX], top)

  if (!listed.ok) {
    return
  }

  for (const ref of listed.out.split('\n').slice(MAX_SNAPSHOTS)) {
    await runGit($, ['update-ref', '-d', ref], top)
  }
}

/**
 * Commits the working tree, untracked files included, to a ref of its own
 * without touching the real index, HEAD or any branch.
 */
async function snapshot($: EngineInterface, dir: string, command: string, withStashes: boolean): Promise<Saved> {
  const found = await runGit($, ['rev-parse', '--show-toplevel', '--absolute-git-dir'], dir)

  if (!found.ok) {
    return { kind: 'skipped' }
  }

  const [top = dir, gitDir = `${dir}/.git`] = found.out.split('\n')
  const stashList = withStashes ? await runGit($, ['stash', 'list', '--format=%H'], top) : null
  const stashes = stashList !== null && stashList.ok ? stashList.out.split('\n').filter(sha => sha !== '') : []
  const status = await runGit($, ['status', '--porcelain'], top)

  if (!status.ok) {
    return { kind: 'failed', error: status.error }
  }

  if (status.out === '' && stashes.length === 0) {
    return { kind: 'skipped' }
  }

  const index = `${gitDir}/${TEMP_INDEX}`
  const withIndex = { GIT_INDEX_FILE: index }
  // Starting from a copy of the real index lets `git add` reuse its stat cache instead of hashing every file.
  await $.process.run(['cp', `${gitDir}/index`, index]).catch(() => undefined)

  try {
    const added = await runGit($, ['add', '-A'], top, withIndex)

    if (!added.ok) {
      return { kind: 'failed', error: added.error }
    }

    const tree = await runGit($, ['write-tree'], top, withIndex)

    if (!tree.ok) {
      return { kind: 'failed', error: tree.error }
    }

    const head = await runGit($, ['rev-parse', '--verify', '--quiet', 'HEAD'], top)
    const parents = [...(head.ok ? [head.out] : []), ...stashes].flatMap(sha => ['-p', sha])
    const commit = await runGit($, ['commit-tree', tree.out, ...parents, '-m', snapshotMessage(command, stashes)], top)

    if (!commit.ok) {
      return { kind: 'failed', error: commit.error }
    }

    const ref = snapshotRef(await $.clock.now())
    const stored = await runGit($, ['update-ref', '-m', 'shell-guard snapshot', ref, commit.out], top)

    if (!stored.ok) {
      return { kind: 'failed', error: stored.error }
    }

    await prune($, top)

    return { kind: 'saved', ref }
  } finally {
    await $.process.run(['rm', '-f', index]).catch(() => undefined)
  }
}

async function refuse($: EngineInterface, verdict: Extract<Verdict, { kind: 'deny' }>): Promise<{ deny: string }> {
  $.ui.toast(`shell-guard blocked: ${verdict.summary}`, { timeoutMs: DENY_TOAST_MS })

  return { deny: verdict.reason }
}

/** The tool.call decision: null lets the call run. */
async function guard($: EngineInterface, command: string, settings: Settings): Promise<{ deny: string } | null> {
  if (await read($, isOff)) {
    return null
  }

  const verdict = classify(command, await contextOf($, command, settings))

  if (verdict.kind === 'deny') {
    return settings.mode === 'deny' ? refuse($, verdict) : null
  }

  if (verdict.kind !== 'snapshot' || !settings.hasSnapshots) {
    return null
  }

  for (const dir of verdict.dirs) {
    const saved = await snapshot($, dir, command, verdict.withStashes)

    if (saved.kind === 'saved') {
      $.ui.toast(`snapshot saved: ${saved.ref}`, { timeoutMs: SNAPSHOT_TOAST_MS })
    }

    if (saved.kind === 'failed') {
      return refuse($, {
        kind: 'deny',
        summary: verdict.summary,
        reason: `shell-guard could not snapshot the uncommitted work this command would destroy (${saved.error}). Commit or stash the work first, then run it again.`,
      })
    }
  }

  return null
}

/** The tool.check decision in ask mode: a command the guard would refuse goes to the permission dialog. */
async function askVerdict($: EngineInterface, input: unknown, settings: Settings): Promise<string | null> {
  const command = typeof input === 'object' && input !== null && 'command' in input ? input.command : undefined

  if (typeof command !== 'string' || (await read($, isOff))) {
    return null
  }

  const verdict = classify(command, await contextOf($, command, settings))

  return verdict.kind === 'deny' ? verdict.reason.replace('shell-guard blocked this command: ', 'shell-guard: ') : null
}

async function runCommand($: EngineInterface, e: CommandRunInput): Promise<{ text: string }> {
  const arg = e.args.trim().toLowerCase()

  if (arg === 'off' || arg === 'on') {
    if (arg === 'off' && !HUMAN_ORIGINS.has(e.origin.kind)) {
      return { text: 'shell-guard: only the user can turn the guard off, by typing /shell-guard off.' }
    }

    await update($, isOff, () => arg === 'off')
    $.ui.toast(`shell-guard ${arg} for this session`)

    return { text: arg === 'off' ? 'shell-guard is off until /shell-guard on or the end of the session.' : 'shell-guard is on.' }
  }

  if (arg !== '') {
    return { text: 'Usage: /shell-guard (list snapshots), /shell-guard off, /shell-guard on' }
  }

  const cwd = await $.session.cwd()
  const home = (await $.env.get('HOME')) ?? ''
  const isOn = !(await read($, isOff))
  const top = await runGit($, ['rev-parse', '--show-toplevel'], cwd)

  if (!top.ok) {
    return { text: `shell-guard is ${isOn ? 'on' : 'off'}. ${tildify(cwd, home)} is not a git repository, so it has no snapshots.` }
  }

  const listed = await runGit($, ['for-each-ref', '--sort=-refname', `--format=${SNAPSHOT_FORMAT}`, SNAPSHOT_PREFIX], top.out)

  return { text: formatSnapshots(listed.ok ? parseSnapshots(listed.out) : [], tildify(top.out, home), isOn) }
}

const settingsOf = (options: Readonly<Record<string, unknown>>): Settings => {
  const branches = parseBranches(String(options.protectedBranches ?? DEFAULT_PROTECTED.join(',')))
  const { patterns, invalid } = parsePatterns(String(options.extraDeny ?? ''))

  return {
    mode: options.mode === 'ask' ? 'ask' : 'deny',
    protectedBranches: branches.length === 0 ? DEFAULT_PROTECTED : branches,
    hasSnapshots: options.snapshots !== false,
    extraDeny: patterns,
    invalidPatterns: invalid,
  }
}

export const register: Register = (on, options) => {
  const settings = settingsOf(options)

  on('session.start', async ($, e, next) => {
    await $.command.register({ name: COMMAND, description: 'List shell-guard snapshots with restore commands; off / on for this session', argumentHint: '[off|on]' })

    if (settings.invalidPatterns.length > 0) {
      $.ui.toast(`shell-guard: ignored invalid extraDeny pattern ${settings.invalidPatterns.join(', ')}`, { timeoutMs: DENY_TOAST_MS })
    }

    return next(e)
  })

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const refused = await guard($, e.command, settings)

    return refused ?? next(e)
  })

  on('tool.check', { tool: 'Bash' }, async ($, e, next) => {
    if (settings.mode !== 'ask') {
      return next(e)
    }

    const reason = await askVerdict($, e.input, settings)

    return reason === null ? next(e) : { decision: 'ask', reason }
  })

  on('command.run', { command: COMMAND }, async ($, e) => runCommand($, e))
}
