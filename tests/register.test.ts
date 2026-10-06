import type { CommandRunInput, ProcessRunResult, PromptOrigin, SessionStartInput } from 'claude-code'
import { describe, expect, mock, test } from 'claude-code/testing'

const HOME = '/home/me'
const ROOT = '/home/me/proj'
const GIT_DIR = `${ROOT}/.git`
const NOW = Date.parse('2026-10-06T12:03:04.567Z')
const SESSION: SessionStartInput = { surface: 'terminal', isInteractive: true, cwd: ROOT }

type Repo = {
  isRepo: boolean
  status: string
  branch: string
  stashes: string[]
  failsAdd: boolean
  refs: string
}

type World = {
  repo: Repo
  /** Every host command the plugin ran, as one line each; env noted when it set GIT_INDEX_FILE. */
  ran: string[]
  toasts: string[]
  /** Commands that reached the tool beneath the plugin. */
  executed: string[]
}

const ok = (stdout = ''): ProcessRunResult => ({ exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false })
const fail = (stderr: string): ProcessRunResult => ({ exitCode: 128, stdout: '', stderr, isStdoutTruncated: false, isStderrTruncated: false })

/** A fake git good enough for the commands the guard runs. */
const gitAnswer = (repo: Repo, args: readonly string[]): ProcessRunResult => {
  if (!repo.isRepo) {
    return fail('fatal: not a git repository')
  }

  const [sub, ...rest] = args

  switch (sub) {
    case 'rev-parse':
      if (rest.includes('--abbrev-ref')) {
        return ok(`${repo.branch}\n`)
      }

      if (rest.includes('--verify')) {
        return ok('h1\n')
      }

      return ok(rest.includes('--absolute-git-dir') ? `${ROOT}\n${GIT_DIR}\n` : `${ROOT}\n`)
    case 'status':
      return ok(repo.status)
    case 'stash':
      return ok(repo.stashes.join('\n'))
    case 'add':
      return repo.failsAdd ? fail('fatal: Unable to create index.lock') : ok()
    case 'write-tree':
      return ok('t1\n')
    case 'commit-tree':
      return ok('c1\n')
    case 'for-each-ref':
      return ok(rest.some(arg => arg === '--format=%(refname)') ? '' : repo.refs)
    default:
      return ok()
  }
}

type TestOn = Parameters<Extract<Parameters<typeof test>[1], (...args: never[]) => unknown>>[1]

const world = (on: TestOn, repo: Partial<Repo> = {}): World => {
  const state: World = {
    repo: { isRepo: true, status: ' M src/app.ts\n?? notes.md\n', branch: 'feature/login', stashes: [], failsAdd: false, refs: '', ...repo },
    ran: [],
    toasts: [],
    executed: [],
  }

  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('session.cwd', () => ({ value: ROOT }))
  on('session.root', () => ({ value: ROOT }))
  on('env.get', ($, e) => ({ value: e.name === 'HOME' ? HOME : undefined }))
  on('command.register', ($, e) => ({ value: { command: e.name } }))
  on('ui.toast', ($, e) => {
    state.toasts.push(e.text)

    return { value: undefined }
  })
  on('process.run', ($, e) => {
    const withIndex = e.init?.env?.GIT_INDEX_FILE === undefined ? '' : ' [temp index]'
    state.ran.push(`${e.argv.join(' ')}${withIndex}`)
    const [bin, ...args] = e.argv

    return { value: bin === 'git' ? gitAnswer(state.repo, args) : ok() }
  })
  on('tool.call', ($, e) => {
    state.executed.push(e.tool === 'Bash' ? e.command : e.tool)

    return { result: 'ok', text: 'ok' }
  })
  on('tool.check', () => ({ decision: 'allow' }))

  return state
}

const run = (command: string, origin: PromptOrigin = { kind: 'composer' }): CommandRunInput => ({
  command: 'shell-guard',
  args: command,
  origin,
  presentation: { isFullscreen: true, columns: 140 },
})

describe('shell-guard blocks', () => {
  test('rm -rf of a folder in home outside the project is refused with a reason and a toast', async ($, on) => {
    const state = world(on)
    await $.session.start(SESSION)

    const result = await $.tool.call({ tool: 'Bash', command: 'rm -rf ~/shell-guard-smoke-nonexistent' })

    expect(result.deny ?? '').toContain('outside the project')
    expect(state.executed).toEqual([])
    expect(state.toasts).toEqual(['shell-guard blocked: rm -rf ~/shell-guard-smoke-nonexistent'])
  })

  test('a force push to main is refused, to a feature branch it runs', async ($, on) => {
    const state = world(on, { branch: 'main' })
    await $.session.start(SESSION)

    const onMain = await $.tool.call({ tool: 'Bash', command: 'git push --force' })

    expect(onMain.deny ?? '').toContain('protected branch main')

    state.repo.branch = 'feature/login'
    await $.tool.call({ tool: 'Bash', command: 'git push --force' })

    expect(state.executed).toEqual(['git push --force'])
  })

  test('everyday commands run untouched and start no git', async ($, on) => {
    const state = world(on)
    await $.session.start(SESSION)

    for (const command of ['ls -la', 'npm test', 'git status', 'docker compose down', 'grep "rm -rf /" README.md']) {
      await $.tool.call({ tool: 'Bash', command })
    }

    expect(state.executed.length).toBe(5)
    expect(state.ran).toEqual([])
    expect(state.toasts).toEqual([])
  })

  test('protectedBranches from settings replaces main and master', { options: { protectedBranches: 'release' } }, async ($, on) => {
    const state = world(on, { branch: 'main' })
    await $.session.start(SESSION)

    await $.tool.call({ tool: 'Bash', command: 'git push --force' })
    const toRelease = await $.tool.call({ tool: 'Bash', command: 'git push -f origin release' })

    expect(state.executed).toEqual(['git push --force'])
    expect(toRelease.deny).toBeDefined()
  })

  test('extraDeny refuses matching commands and reports a broken pattern once', { options: { extraDeny: '^npm publish\n(broken' } }, async ($, on) => {
    const state = world(on)
    await $.session.start(SESSION)

    const result = await $.tool.call({ tool: 'Bash', command: 'npm publish' })

    expect(result.deny ?? '').toContain('extraDeny')
    expect(state.toasts[0]).toBe('shell-guard: ignored invalid extraDeny pattern (broken')
  })
})

describe('shell-guard snapshots', () => {
  test('git reset --hard in a dirty repo saves a snapshot with untracked files, then runs', async ($, on) => {
    const state = world(on)
    mock.clock(on, { now: NOW })
    await $.session.start(SESSION)

    await $.tool.call({ tool: 'Bash', command: 'git reset --hard HEAD~1' })

    expect(state.ran).toEqual([
      'git rev-parse --show-toplevel --absolute-git-dir',
      'git status --porcelain',
      `cp ${GIT_DIR}/index ${GIT_DIR}/shell-guard-index`,
      'git add -A [temp index]',
      'git write-tree [temp index]',
      'git rev-parse --verify --quiet HEAD',
      'git commit-tree t1 -p h1 -m shell-guard: git reset --hard HEAD~1\n\ngit reset --hard HEAD~1',
      'git update-ref -m shell-guard snapshot refs/shell-guard/20261006-120304-567 c1',
      'git for-each-ref --sort=-refname --format=%(refname) refs/shell-guard',
      `rm -f ${GIT_DIR}/shell-guard-index`,
    ])
    expect(state.toasts).toEqual(['snapshot saved: refs/shell-guard/20261006-120304-567'])
    expect(state.executed).toEqual(['git reset --hard HEAD~1'])
  })

  test('a clean tree is skipped silently', async ($, on) => {
    const state = world(on, { status: '' })
    await $.session.start(SESSION)

    await $.tool.call({ tool: 'Bash', command: 'rm -rf node_modules dist' })

    expect(state.ran.some(line => line.startsWith('git commit-tree'))).toBe(false)
    expect(state.toasts).toEqual([])
    expect(state.executed).toEqual(['rm -rf node_modules dist'])
  })

  test('outside a git repo the command just runs', async ($, on) => {
    const state = world(on, { isRepo: false })
    await $.session.start(SESSION)

    await $.tool.call({ tool: 'Bash', command: 'git clean -fd' })

    expect(state.toasts).toEqual([])
    expect(state.executed).toEqual(['git clean -fd'])
  })

  test('git stash clear on a clean tree still keeps the stashes as parents', async ($, on) => {
    const state = world(on, { status: '', stashes: ['s1', 's2'] })
    mock.clock(on, { now: NOW })
    await $.session.start(SESSION)

    await $.tool.call({ tool: 'Bash', command: 'git stash clear' })

    expect(state.ran.find(line => line.startsWith('git commit-tree'))).toContain('-p h1 -p s1 -p s2')
    expect(state.toasts).toEqual(['snapshot saved: refs/shell-guard/20261006-120304-567'])
  })

  test('a snapshot that fails refuses the command instead of losing the work', async ($, on) => {
    const state = world(on, { failsAdd: true })
    await $.session.start(SESSION)

    const result = await $.tool.call({ tool: 'Bash', command: 'git checkout -- .' })

    expect(result.deny ?? '').toContain('could not snapshot')
    expect(state.executed).toEqual([])
    expect(state.ran.at(-1)).toBe(`rm -f ${GIT_DIR}/shell-guard-index`)
  })

  test('snapshots: false lets the command run without git', { options: { snapshots: false } }, async ($, on) => {
    const state = world(on)
    await $.session.start(SESSION)

    await $.tool.call({ tool: 'Bash', command: 'git reset --hard' })

    expect(state.ran).toEqual([])
    expect(state.executed).toEqual(['git reset --hard'])
  })
})

describe('/shell-guard', () => {
  test('lists snapshots newest first with restore commands', async ($, on) => {
    world(on, { refs: 'refs/shell-guard/20261006-120304-567\u001f2026-10-06 12:03:04 +0200\u001fh1\u001fshell-guard: git reset --hard\n\ngit reset --hard\n\u001e' })
    await $.session.start(SESSION)

    const answer = await $.command.run(run(''))

    expect(answer.text ?? '').toContain('1 snapshot in ~/proj')
    expect(answer.text ?? '').toContain('2026-10-06 12:03  git reset --hard')
    expect(answer.text ?? '').toContain('restore:  git checkout refs/shell-guard/20261006-120304-567 -- .')
  })

  test('off lets everything through for the session, on brings the guard back', async ($, on) => {
    const state = world(on)
    await $.session.start(SESSION)

    expect((await $.command.run(run('off'))).text).toContain('off until /shell-guard on')
    await $.tool.call({ tool: 'Bash', command: 'rm -rf ~/scratch' })

    await $.command.run(run('on'))
    const again = await $.tool.call({ tool: 'Bash', command: 'rm -rf ~/scratch' })

    expect(state.executed).toEqual(['rm -rf ~/scratch'])
    expect(again.deny).toBeDefined()
  })

  test('only a person can turn it off', async ($, on) => {
    world(on)
    await $.session.start(SESSION)

    const answer = await $.command.run(run('off', { kind: 'unclassified' }))
    const result = await $.tool.call({ tool: 'Bash', command: 'rm -rf /' })

    expect(answer.text).toContain('only the user')
    expect(result.deny).toBeDefined()
  })
})

describe('ask mode', () => {
  test('a dangerous command goes to the permission dialog with the reason', { options: { mode: 'ask' } }, async ($, on) => {
    world(on)
    await $.session.start(SESSION)

    const verdict = await $.tool.check({ tool: 'Bash', input: { command: 'rm -rf ~' } })

    expect(verdict.decision).toBe('ask')
    expect(verdict.reason ?? '').toContain('home folder')
    expect((await $.tool.check({ tool: 'Bash', input: { command: 'ls' } })).decision).toBe('allow')
  })

  test('tool.call no longer refuses it on its own', { options: { mode: 'ask' } }, async ($, on) => {
    const state = world(on)
    await $.session.start(SESSION)

    await $.tool.call({ tool: 'Bash', command: 'rm -rf ~/scratch' })

    expect(state.executed).toEqual(['rm -rf ~/scratch'])
  })

  test('in deny mode tool.check is left to the engine', async ($, on) => {
    world(on)
    await $.session.start(SESSION)

    expect((await $.tool.check({ tool: 'Bash', input: { command: 'rm -rf ~' } })).decision).toBe('allow')
  })
})
