import { basename, isBelow, isWithin, join, normalize, tildify } from './paths'
import { parse, type Segment, type Word } from './shell'

/** What the guard knows about where a command runs. */
export type Context = {
  /** The session's working directory, absolute. */
  cwd: string
  /** The project root: deletes are allowed beneath it, never of it. */
  root: string
  home: string
  /** Folders whose contents may be deleted freely (`/tmp`, `$TMPDIR`). */
  tempDirs: readonly string[]
  /** The branch checked out in `cwd`, or null when unknown. */
  branch: string | null
  protectedBranches: readonly string[]
  extraDeny: readonly RegExp[]
}

export type Verdict =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string; summary: string }
  /** Runs after a snapshot of each repo in `dirs`; `withStashes` keeps stash entries too. */
  | { kind: 'snapshot'; dirs: string[]; withStashes: boolean; summary: string }

const ALLOW: Verdict = { kind: 'allow' }
/** Nesting of `bash -c`, `eval` and `$(...)` the guard follows before it gives up and refuses. */
const MAX_DEPTH = 6
const SUMMARY_LENGTH = 80
const TAIL = 'If the user really wants this, ask them to run it themselves.'

export const DEFAULT_PROTECTED = ['main', 'master']

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish'])
const SQL_CLIENTS = new Set(['psql', 'mysql', 'mariadb', 'sqlite3'])
const DESTRUCTIVE_SQL = /\b(drop\s+(database|schema|table)|truncate)\b/i
const SAFE_DEVICE = /^\/dev\/(null|zero|stdin|stdout|stderr|tty|u?random|fd\/\d+)$/
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/
const GLOB = /[*?[]/
const VARIABLE = /\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g
const SHELL_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '}', 'time'])
const DISKUTIL_ERASE = /^(erase|zero|secureerase|partitiondisk|reformat|randomdisk)/i
const NAMESPACE_KINDS = new Set(['ns', 'namespace', 'namespaces'])

/** Options of prefix commands that take a value, by command. */
const PREFIX_VALUE_OPTIONS: Readonly<Record<string, ReadonlySet<string>>> = {
  sudo: new Set(['-u', '-g', '-h', '-p', '-C', '-r', '-t', '-U', '-D', '-R', '-T']),
  doas: new Set(['-u', '-C']),
  env: new Set(['-u', '-C', '-S', '--unset', '--chdir']),
  nice: new Set(['-n']),
  timeout: new Set(['-s', '-k', '--signal', '--kill-after']),
  exec: new Set(['-a']),
  ionice: new Set(['-c', '-n', '-p']),
  stdbuf: new Set([]),
  nohup: new Set([]),
  command: new Set([]),
  builtin: new Set([]),
}
const XARGS_VALUE_OPTIONS = new Set(['-n', '-I', '-L', '-P', '-d', '-E', '-s', '-a', '-i', '-l'])

type Place =
  | { kind: 'system' }
  | { kind: 'home'; path: string }
  | { kind: 'project'; path: string }
  | { kind: 'contains-project'; path: string }
  | { kind: 'inside'; path: string }
  | { kind: 'temp'; path: string }
  | { kind: 'outside'; path: string }
  | { kind: 'unknown'; text: string }

/** Where the walk stands: `cwd` null after a `cd` the guard could not follow. */
type Walk = { cwd: string | null; depth: number; snapshotDirs: string[]; withStashes: boolean; summary: string }

const summarize = (text: string): string => {
  const line = text.replace(/\s+/g, ' ').trim()

  return line.length > SUMMARY_LENGTH ? `${line.slice(0, SUMMARY_LENGTH - 1)}…` : line
}

const deny = (reason: string, segment: readonly string[]): Verdict => ({
  kind: 'deny',
  reason: `shell-guard blocked this command: ${reason} ${TAIL}`,
  summary: summarize(segment.join(' ')),
})

const isFlag = (word: string): boolean => word.startsWith('-') && word !== '-'

/** True when a short-flag cluster (`-rf`) or a long flag spells one of `letters` or `longs`. */
const hasFlag = (args: readonly string[], letters: string, longs: readonly string[]): boolean =>
  args.some(arg => {
    if (arg.startsWith('--')) {
      return longs.some(long => arg === long || arg.startsWith(`${long}=`))
    }

    return arg.startsWith('-') && !arg.startsWith('--') && [...arg.slice(1)].some(ch => letters.includes(ch))
  })

const positionals = (args: readonly string[], valueOptions: ReadonlySet<string> = new Set()): string[] => {
  const found: string[] = []
  let i = 0

  while (i < args.length) {
    const arg = args[i] ?? ''

    if (arg === '--') {
      found.push(...args.slice(i + 1))
      break
    }

    if (isFlag(arg)) {
      i += valueOptions.has(arg) ? 2 : 1
      continue
    }

    found.push(arg)
    i += 1
  }

  return found
}

/**
 * Strips what runs a command without being it: `VAR=x`, `sudo`, `env`,
 * `nice`, `timeout 5` and their options. Returns the command's own words.
 */
const stripPrefixes = (words: readonly Word[]): Word[] => {
  let i = 0

  while (i < words.length) {
    const text = words[i]?.text ?? ''

    if (ASSIGNMENT.test(text) || SHELL_KEYWORDS.has(text)) {
      i += 1
      continue
    }

    const options = PREFIX_VALUE_OPTIONS[basename(text)]

    if (options === undefined) {
      break
    }

    const name = basename(text)
    i += 1

    while (i < words.length) {
      const arg = words[i]?.text ?? ''

      if (arg === '--') {
        i += 1
        break
      }

      if (isFlag(arg)) {
        i += options.has(arg) ? 2 : 1
        continue
      }

      if (name === 'env' && ASSIGNMENT.test(arg)) {
        i += 1
        continue
      }

      if (name === 'timeout') {
        i += 1
      }

      break
    }
  }

  return words.slice(i)
}

/** Expands `~`, `$HOME`, `$PWD` and `$(pwd)`; anything else unresolved stays as `$`. */
const expand = (word: Word, cwd: string | null, ctx: Context): string => {
  let text = word.text

  if (word.isTildeLive && ctx.home !== '' && (text === '~' || text.startsWith('~/'))) {
    text = ctx.home + text.slice(1)
  }

  return text.replace(VARIABLE, (match, name: string) => {
    if (name === 'HOME' && ctx.home !== '') {
      return ctx.home
    }

    if (name === 'PWD' && cwd !== null) {
      return cwd
    }

    return match
  })
}

/** Where an absolute path sits relative to the project, home and temp folders. */
export const placeOfPath = (path: string, ctx: Context): Place => {
  if (path === '/') {
    return { kind: 'system' }
  }

  if (isWithin(ctx.home, path)) {
    return { kind: 'home', path }
  }

  if (path === ctx.root) {
    return { kind: 'project', path }
  }

  if (isWithin(ctx.root, path)) {
    return { kind: 'contains-project', path }
  }

  if (isBelow(path, ctx.root)) {
    return { kind: 'inside', path }
  }

  if (ctx.tempDirs.some(dir => isBelow(path, dir))) {
    return { kind: 'temp', path }
  }

  return { kind: 'outside', path }
}

/**
 * Where a delete target lands. A last component of `*`, `.*` or a variable
 * covers its whole folder, so `rm -rf *` at the root is the root.
 */
export const placeOf = (word: Word, cwd: string | null, ctx: Context): Place => {
  const text = expand(word, cwd, ctx)

  if (word.isTildeLive && text.startsWith('~')) {
    return { kind: 'unknown', text: word.text }
  }

  if (text.startsWith('$') || text.startsWith('`')) {
    return { kind: 'unknown', text: word.text }
  }

  if (!text.startsWith('/') && cwd === null) {
    return { kind: 'unknown', text: word.text }
  }

  const absolute = text.startsWith('/') ? text : `${cwd ?? '/'}/${text}`
  const parts = absolute.split('/')
  const wild = parts.findIndex(part => GLOB.test(part) || part.includes('$'))

  if (wild === -1) {
    return placeOfPath(normalize(absolute), ctx)
  }

  const folder = normalize(parts.slice(0, wild).join('/') || '/')
  const part = parts[wild] ?? ''
  const coversFolder = part === '*' || part === '.*' || part.startsWith('$') || /^\{.*\}$/.test(part)

  return placeOfPath(coversFolder ? folder : join(folder, 'x'), ctx)
}

const describePlace = (place: Place, ctx: Context): string => {
  switch (place.kind) {
    case 'system':
      return 'the target is / (the whole filesystem).'
    case 'home':
      return place.path === ctx.home
        ? 'the target is your home folder.'
        : `the target ${place.path} contains your home folder.`
    case 'project':
      return `the target is the project root (${tildify(ctx.root, ctx.home)}). Delete specific folders instead, for example rm -rf dist.`
    case 'contains-project':
      return `the target ${tildify(place.path, ctx.home)} contains the whole project.`
    case 'outside':
    case 'inside':
    case 'temp':
      return `the target ${tildify(place.path, ctx.home)} is outside the project (${tildify(ctx.root, ctx.home)}); recursive or forced deletes are allowed only inside the project and temp folders.`
    case 'unknown':
      return `the target ${place.text} depends on a variable, a substitution or another user's home that shell-guard cannot resolve. Repeat the command with a literal path.`
  }
}

const addSnapshot = (walk: Walk, dir: string | null, ctx: Context, words: readonly string[]): void => {
  const where = dir ?? ctx.cwd

  if (!walk.snapshotDirs.includes(where)) {
    walk.snapshotDirs.push(where)
  }

  if (walk.summary === '') {
    walk.summary = summarize(words.join(' '))
  }
}

const rm = (args: readonly Word[], walk: Walk, ctx: Context, words: readonly string[], isFed: boolean): Verdict | null => {
  const flags: string[] = []
  const targets: Word[] = []
  let isLiteral = false

  for (const arg of args) {
    if (!isLiteral && arg.text === '--') {
      isLiteral = true
    } else if (!isLiteral && isFlag(arg.text)) {
      flags.push(arg.text)
    } else {
      targets.push(arg)
    }
  }

  if (flags.includes('--no-preserve-root')) {
    return deny('--no-preserve-root removes the last safety net against deleting /.', words)
  }

  const isRecursive = hasFlag(flags, 'rR', ['--recursive'])
  const isForced = hasFlag(flags, 'f', ['--force'])

  if (!isRecursive && !isForced) {
    return null
  }

  if (targets.length === 0 && isFed && isRecursive) {
    addSnapshot(walk, walk.cwd, ctx, words)
  }

  for (const target of targets) {
    const place = placeOf(target, walk.cwd, ctx)

    if (place.kind === 'temp') {
      continue
    }

    if (place.kind === 'inside') {
      if (isRecursive) {
        addSnapshot(walk, walk.cwd, ctx, words)
      }

      continue
    }

    return deny(describePlace(place, ctx), words)
  }

  return null
}

const FIND_FILTERS = new Set([
  '-name', '-iname', '-path', '-ipath', '-wholename', '-iwholename', '-regex', '-iregex', '-type', '-mtime', '-mmin',
  '-atime', '-amin', '-ctime', '-cmin', '-newer', '-size', '-user', '-group', '-empty', '-perm', '-lname', '-inum', '-links',
])
const FIND_EXEC = new Set(['-exec', '-execdir', '-ok', '-okdir'])
const FIND_DELETERS = new Set(['rm', 'shred', 'unlink'])

const find = (args: readonly Word[], walk: Walk, ctx: Context, words: readonly string[]): Verdict | null => {
  const texts = args.map(arg => arg.text)
  const firstExpression = texts.findIndex(text => text.startsWith('-') || text === '(' || text === '!')
  const isDestructive =
    texts.includes('-delete') ||
    texts.some((text, i) => FIND_EXEC.has(text) && FIND_DELETERS.has(basename(texts[i + 1] ?? '')))

  if (!isDestructive) {
    return null
  }

  const starts = (firstExpression === -1 ? args : args.slice(0, firstExpression)).filter(arg => !['-H', '-L', '-P'].includes(arg.text))
  const hasFilter = texts.some(text => FIND_FILTERS.has(text))

  for (const start of starts.length === 0 ? [{ text: '.', isTildeLive: false }] : starts) {
    const place = placeOf(start, walk.cwd, ctx)

    if (place.kind === 'temp') {
      continue
    }

    if (place.kind === 'inside' || (place.kind === 'project' && hasFilter)) {
      addSnapshot(walk, walk.cwd, ctx, words)
      continue
    }

    return deny(`find with -delete: ${describePlace(place, ctx)}`, words)
  }

  return null
}

/** `chmod -R` / `chown -R` outside the project changes system or other people's files. */
const recursiveOwnership = (cmd: string, args: readonly Word[], walk: Walk, ctx: Context, words: readonly string[]): Verdict | null => {
  const texts = args.map(arg => arg.text)

  if (!hasFlag(texts, 'R', ['--recursive'])) {
    return null
  }

  const operands = args.filter(arg => !isFlag(arg.text))
  const hasReference = texts.some(text => text.startsWith('--reference'))
  const targets = hasReference ? operands : operands.slice(1)

  for (const target of targets) {
    const place = placeOf(target, walk.cwd, ctx)

    if (place.kind === 'inside' || place.kind === 'project' || place.kind === 'temp') {
      continue
    }

    return deny(`${cmd} -R ${describePlace(place, ctx)}`, words)
  }

  return null
}

type Refspec = { isForced: boolean; isDelete: boolean; branch: string | null }

const refspecOf = (spec: string, current: string | null): Refspec => {
  const isForced = spec.startsWith('+')
  const body = isForced ? spec.slice(1) : spec
  const colon = body.indexOf(':')
  const src = colon === -1 ? body : body.slice(0, colon)
  const dst = colon === -1 ? body : body.slice(colon + 1)
  const name = (dst === 'HEAD' ? current : dst)?.replace(/^refs\/heads\//, '') ?? null

  return { isForced, isDelete: colon !== -1 && src === '', branch: name }
}

const PUSH_VALUE_OPTIONS = new Set(['-o', '--push-option', '--repo', '--receive-pack', '--exec'])

const gitPush = (args: readonly string[], branch: string | null, ctx: Context, words: readonly string[]): Verdict | null => {
  if (args.includes('--mirror')) {
    return deny('git push --mirror overwrites and deletes every ref on the remote.', words)
  }

  const isForced = hasFlag(args, 'f', ['--force', '--force-with-lease', '--force-if-includes'])
  const isDelete = hasFlag(args, 'd', ['--delete'])
  const isAll = args.includes('--all') || args.includes('--branches')
  const specs = positionals(args, PUSH_VALUE_OPTIONS).slice(1).map(spec => refspecOf(spec, branch))
  const pushed = specs.length === 0 && !isAll ? [{ isForced: false, isDelete: false, branch }] : specs
  const isProtected = (name: string | null): boolean => name !== null && ctx.protectedBranches.includes(name)
  const listed = ctx.protectedBranches.join(', ')

  if (isForced && isAll) {
    return deny(`a forced push of all branches includes the protected ones (${listed}). Force-push one feature branch by name.`, words)
  }

  for (const spec of pushed) {
    const forced = isForced || spec.isForced

    if ((isDelete || spec.isDelete) && isProtected(spec.branch)) {
      return deny(`deleting the protected branch ${spec.branch ?? ''} on the remote.`, words)
    }

    if (forced && spec.branch === null) {
      return deny('a forced push whose branch shell-guard cannot tell. Name the branch: git push --force-with-lease origin <feature-branch>.', words)
    }

    if (forced && isProtected(spec.branch)) {
      return deny(`force-pushing to the protected branch ${spec.branch ?? ''} rewrites shared history. Push a feature branch, or push without --force.`, words)
    }
  }

  return null
}

const GIT_VALUE_OPTIONS = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env'])

const git = (args: readonly Word[], walk: Walk, ctx: Context, words: readonly string[]): Verdict | null => {
  let dir = walk.cwd
  let i = 0

  while (i < args.length && isFlag(args[i]?.text ?? '')) {
    const option = args[i]?.text ?? ''

    if (option === '-C') {
      const target = args[i + 1]
      dir = target === undefined || dir === null ? null : join(dir, expand(target, dir, ctx))
    }

    i += GIT_VALUE_OPTIONS.has(option) ? 2 : 1
  }

  const sub = args[i]?.text
  const rest = args.slice(i + 1).map(arg => arg.text)
  const snapshot = (): null => {
    addSnapshot(walk, dir, ctx, words)

    return null
  }

  switch (sub) {
    case 'push':
      return gitPush(rest, dir === ctx.cwd ? ctx.branch : null, ctx, words)
    case 'branch': {
      const isForceDelete = hasFlag(rest, 'D', []) || (hasFlag(rest, 'd', ['--delete']) && hasFlag(rest, 'f', ['--force']))
      const victim = positionals(rest).find(name => ctx.protectedBranches.includes(name))

      return isForceDelete && victim !== undefined ? deny(`git branch -D deletes the protected branch ${victim}.`, words) : null
    }
    case 'reset':
      return rest.includes('--hard') ? snapshot() : null
    case 'checkout':
      return rest.includes('--') || rest.includes('.') || hasFlag(rest, 'f', ['--force']) ? snapshot() : null
    case 'switch':
      return hasFlag(rest, 'f', ['--force', '--discard-changes']) ? snapshot() : null
    case 'restore': {
      const isStagedOnly = hasFlag(rest, 'S', ['--staged']) && !hasFlag(rest, 'W', ['--worktree'])

      return isStagedOnly ? null : snapshot()
    }
    case 'clean':
      return hasFlag(rest, 'f', ['--force']) && !hasFlag(rest, 'n', ['--dry-run']) ? snapshot() : null
    case 'stash':
      if (rest[0] === 'drop' || rest[0] === 'clear') {
        walk.withStashes = true

        return snapshot()
      }

      return null
    default:
      return null
  }
}

const kubectl = (args: readonly string[], words: readonly string[]): Verdict | null => {
  const at = args.indexOf('delete')

  if (at === -1) {
    return null
  }

  const rest = args.slice(at + 1)

  if (rest.some(arg => arg === '--all' || arg === '--all-namespaces' || arg === '-A')) {
    return deny('kubectl delete --all removes every resource of that kind.', words)
  }

  const kinds = positionals(rest, new Set(['-n', '--namespace', '--context', '-l', '--selector', '-f', '--filename', '-o', '--output', '--field-selector']))
  const hitsNamespace = kinds.some((kind, i) =>
    kind.split(',').some(part => {
      const type = part.split('/')[0] ?? ''

      return NAMESPACE_KINDS.has(type) && (i === 0 || part.includes('/'))
    }),
  )

  return hitsNamespace ? deny('kubectl delete namespace removes everything in it.', words) : null
}

const DOCKER_VALUE_OPTIONS = new Set(['--context', '-H', '--host', '-c', '--config', '-f', '--file', '-p', '--project-name', '--log-level', '--env-file', '--profile'])

const docker = (cmd: string, args: readonly string[], words: readonly string[]): Verdict | null => {
  const subs = positionals(args, DOCKER_VALUE_OPTIONS)
  const [first, second] = cmd === 'docker-compose' ? ['compose', subs[0]] : [subs[0], subs[1]]

  if (first === 'system' && second === 'prune' && args.includes('--volumes')) {
    return deny('docker system prune --volumes deletes every unused volume, and volumes hold databases.', words)
  }

  if (first === 'volume' && (second === 'rm' || second === 'remove' || second === 'prune')) {
    return deny(`docker volume ${second} deletes volume data, which no snapshot can bring back.`, words)
  }

  const isCompose = first === 'compose' && subs.includes('down')

  if (isCompose && hasFlag(args, 'v', ['--volumes'])) {
    return deny('docker compose down -v deletes the project\'s volumes. Use docker compose down without -v.', words)
  }

  return null
}

const SQL_VALUE_FLAGS: Readonly<Record<string, readonly string[]>> = {
  psql: ['-c', '--command'],
  mysql: ['-e', '--execute'],
  mariadb: ['-e', '--execute'],
  sqlite3: ['-cmd'],
}

const sqlTexts = (cmd: string, args: readonly string[], stdin: string | undefined): string[] => {
  const flags = SQL_VALUE_FLAGS[cmd] ?? []
  const texts: string[] = stdin === undefined ? [] : [stdin]

  args.forEach((arg, i) => {
    for (const flag of flags) {
      if (arg === flag) {
        texts.push(args[i + 1] ?? '')
      } else if (arg.startsWith(`${flag}=`)) {
        texts.push(arg.slice(flag.length + 1))
      } else if (flag.length === 2 && arg.startsWith(flag) && !arg.startsWith('--')) {
        texts.push(arg.slice(2))
      }
    }
  })

  if (cmd === 'sqlite3') {
    texts.push(...positionals(args, new Set(['-cmd', '-separator', '-newline', '-nullvalue', '-init'])).slice(1))
  }

  return texts
}

/** The command `xargs` runs: its words after xargs' own options. */
const xargsCommand = (args: readonly Word[]): Word[] => {
  let i = 0

  while (i < args.length && isFlag(args[i]?.text ?? '')) {
    i += XARGS_VALUE_OPTIONS.has(args[i]?.text ?? '') ? 2 : 1
  }

  return args.slice(i)
}

/** Classifies one simple command; null lets the walk go on. */
const segmentVerdict = (segment: Segment, walk: Walk, ctx: Context, isFed: boolean): Verdict | null => {
  for (const target of segment.redirects) {
    if (target.startsWith('/dev/') && !SAFE_DEVICE.test(target)) {
      return deny(`writing to the device ${target} overwrites the disk.`, segment.words.map(word => word.text))
    }
  }

  const own = stripPrefixes(segment.words)
  const words = own.map(word => word.text)
  const cmd = basename(words[0] ?? '')
  const args = own.slice(1)
  const texts = words.slice(1)

  for (const pattern of ctx.extraDeny) {
    if (words.length > 0 && pattern.test(words.join(' '))) {
      return deny(`it matches the extraDeny rule ${pattern.source}.`, words)
    }
  }

  switch (cmd) {
    case '':
      return null
    case 'cd':
    case 'pushd': {
      const target = args.find(arg => !isFlag(arg.text))

      if (target === undefined) {
        walk.cwd = ctx.home
      } else {
        const text = expand(target, walk.cwd, ctx)
        walk.cwd = text.includes('$') || text === '-' || (walk.cwd === null && !text.startsWith('/')) ? null : join(walk.cwd ?? '/', text)
      }

      return null
    }
    case 'rm':
      return rm(args, walk, ctx, words, isFed)
    case 'find':
      return find(args, walk, ctx, words)
    case 'xargs': {
      const inner = xargsCommand(args)

      return inner.length === 0 ? null : segmentVerdict({ words: inner, redirects: [] }, walk, ctx, true)
    }
    case 'git':
      return git(args, walk, ctx, words)
    case 'eval':
      return nested(texts.join(' '), walk, ctx)
    case 'dd':
      return texts.some(arg => arg.startsWith('of=/dev/') && !SAFE_DEVICE.test(arg.slice(3)))
        ? deny('dd onto a device overwrites the disk.', words)
        : null
    case 'shred':
      return deny('shred destroys files beyond recovery.', words)
    case 'wipefs':
    case 'newfs':
      return deny(`${cmd} erases a filesystem.`, words)
    case 'diskutil':
      return DISKUTIL_ERASE.test(texts[0] ?? '') ? deny(`diskutil ${texts[0] ?? ''} erases a disk.`, words) : null
    case 'chmod':
    case 'chown':
    case 'chgrp':
      return recursiveOwnership(cmd, args, walk, ctx, words)
    case 'terraform':
    case 'tofu':
    case 'terragrunt': {
      const sub = texts.find(arg => !isFlag(arg))
      const isDestroy = sub === 'destroy' || (sub === 'apply' && texts.includes('-destroy'))

      return isDestroy ? deny(`${cmd} destroy deletes real infrastructure.`, words) : null
    }
    case 'kubectl':
    case 'oc':
      return kubectl(texts, words)
    case 'docker':
    case 'podman':
    case 'docker-compose':
      return docker(cmd, texts, words)
    case 'redis-cli':
      return texts.some(arg => /^flush(all|db)$/i.test(arg)) ? deny('FLUSHALL / FLUSHDB empties the Redis database.', words) : null
    default:
      break
  }

  if (cmd.startsWith('mkfs')) {
    return deny(`${cmd} formats a disk.`, words)
  }

  if (SQL_CLIENTS.has(cmd)) {
    const hit = sqlTexts(cmd, texts, segment.stdin).find(sql => DESTRUCTIVE_SQL.test(sql))

    return hit === undefined ? null : deny(`it runs ${summarize(hit)} against a database; DROP and TRUNCATE cannot be undone.`, words)
  }

  if (SHELLS.has(cmd)) {
    const at = texts.findIndex(arg => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(arg))

    if (at !== -1) {
      return nested(texts[at + 1] ?? '', walk, ctx)
    }

    if (segment.stdin !== undefined && positionals(texts).length === 0) {
      return nested(segment.stdin, walk, ctx)
    }
  }

  return null
}

/** Classifies a script nested in this one (`bash -c`, `eval`, `$(...)`). */
const nested = (script: string, walk: Walk, ctx: Context): Verdict | null => {
  if (walk.depth >= MAX_DEPTH) {
    return deny('the command nests shells too deeply to check.', [script])
  }

  walk.depth += 1
  const verdict = walkScript(script, walk, ctx)
  walk.depth -= 1

  return verdict
}

const walkScript = (script: string, walk: Walk, ctx: Context): Verdict | null => {
  const { segments, subs } = parse(script)

  for (const sub of subs) {
    const verdict = nested(sub, walk, ctx)

    if (verdict !== null) {
      return verdict
    }
  }

  for (const segment of segments) {
    const verdict = segmentVerdict(segment, walk, ctx, false)

    if (verdict !== null) {
      return verdict
    }
  }

  return null
}

/**
 * The guard's decision for one Bash command: refuse it, snapshot the repo
 * first, or let it run.
 */
export const classify = (command: string, ctx: Context): Verdict => {
  const walk: Walk = { cwd: ctx.cwd, depth: 0, snapshotDirs: [], withStashes: false, summary: '' }
  const verdict = walkScript(command, walk, ctx)

  if (verdict !== null) {
    return verdict
  }

  if (walk.snapshotDirs.length > 0) {
    return { kind: 'snapshot', dirs: walk.snapshotDirs, withStashes: walk.withStashes, summary: walk.summary }
  }

  return ALLOW
}

/** Splits the protected-branches setting: comma or space separated. */
export const parseBranches = (text: string): string[] =>
  text
    .split(/[,\s]+/)
    .map(name => name.trim())
    .filter(name => name !== '')

export type ParsedPatterns = { patterns: RegExp[]; invalid: string[] }

/** One regular expression per line; a line that does not compile is reported, not used. */
export const parsePatterns = (text: string): ParsedPatterns => {
  const patterns: RegExp[] = []
  const invalid: string[] = []

  for (const line of text.split('\n').map(item => item.trim()).filter(item => item !== '')) {
    try {
      patterns.push(new RegExp(line))
    } catch {
      invalid.push(line)
    }
  }

  return { patterns, invalid }
}

export const SNAPSHOT_PREFIX = 'refs/shell-guard'
/** Snapshots kept per repo; older ones are pruned so the refs do not pile up. */
export const MAX_SNAPSHOTS = 100
const FIELD = '\u001f'
const RECORD = '\u001e'
const STASH_LINE = 'stashes: '
const TIME_LENGTH = 16

/** `refs/shell-guard/20261006-120000-123`: sortable, unique per millisecond, legal in a ref name. */
export const snapshotRef = (now: number): string => {
  const iso = new Date(now).toISOString()
  const stamp = `${iso.slice(0, 10).replace(/-/g, '')}-${iso.slice(11, 19).replace(/:/g, '')}-${iso.slice(20, 23)}`

  return `${SNAPSHOT_PREFIX}/${stamp}`
}

/** The snapshot commit's message: the command as its subject, kept stashes listed in the body. */
export const snapshotMessage = (command: string, stashes: readonly string[]): string => {
  const lines = [`shell-guard: ${summarize(command)}`, '', command.trim()]

  if (stashes.length > 0) {
    lines.push('', `${STASH_LINE}${stashes.join(' ')}`)
  }

  return lines.join('\n')
}

/** The `git for-each-ref` format `parseSnapshots` reads. */
export const SNAPSHOT_FORMAT = `%(refname)%1f%(creatordate:iso)%1f%(parent)%1f%(contents)%1e`

export type Snapshot = { ref: string; time: string; command: string; hasHead: boolean; stashes: string[] }

export const parseSnapshots = (stdout: string): Snapshot[] =>
  stdout
    .split(RECORD)
    .map(record => record.replace(/^\n/, ''))
    .filter(record => record.trim() !== '')
    .map(record => {
      const [ref = '', time = '', parents = '', contents = ''] = record.split(FIELD)
      const [subject = ''] = contents.split('\n')
      const stashLine = contents.split('\n').find(line => line.startsWith(STASH_LINE))
      const stashes = stashLine === undefined ? [] : stashLine.slice(STASH_LINE.length).split(' ').filter(sha => sha !== '')
      const parentCount = parents.split(' ').filter(sha => sha !== '').length

      return {
        ref,
        time: time.slice(0, TIME_LENGTH),
        command: subject.replace(/^shell-guard: /, ''),
        hasHead: parentCount > stashes.length,
        stashes,
      }
    })

/** What `/shell-guard` prints: each snapshot with the exact commands that bring it back. */
export const formatSnapshots = (snapshots: readonly Snapshot[], repo: string, isOn: boolean): string => {
  const state = isOn ? 'on' : 'off for this session (/shell-guard on turns it back on)'

  if (snapshots.length === 0) {
    return `shell-guard is ${state}. No snapshots in ${repo} yet.`
  }

  const lines = [
    `shell-guard is ${state}. ${snapshots.length} snapshot${snapshots.length === 1 ? '' : 's'} in ${repo}, newest first.`,
    'Restoring overwrites the same files in the working tree; files created since stay.',
  ]

  snapshots.forEach((snapshot, i) => {
    const see = snapshot.hasHead ? `git diff --stat ${snapshot.ref}^1 ${snapshot.ref}` : `git show --stat ${snapshot.ref}`

    lines.push(
      '',
      `${i + 1}. ${snapshot.time}  ${snapshot.command}`,
      `   see:      ${see}`,
      `   restore:  git checkout ${snapshot.ref} -- .`,
      `   one file: git checkout ${snapshot.ref} -- <path>`,
      ...snapshot.stashes.map(sha => `   stash:    git stash store -m "restored by shell-guard" ${sha}`),
    )
  })

  return lines.join('\n')
}
