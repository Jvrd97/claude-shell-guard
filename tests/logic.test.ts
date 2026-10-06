import { describe, expect, test } from 'claude-code/testing'

import {
  classify,
  formatSnapshots,
  parseBranches,
  parsePatterns,
  parseSnapshots,
  placeOf,
  snapshotMessage,
  snapshotRef,
  type Context,
} from '../hooks/logic'
import { parse } from '../hooks/shell'

const HOME = '/home/me'
const ROOT = '/home/me/proj'

const CTX: Context = {
  cwd: ROOT,
  root: ROOT,
  home: HOME,
  tempDirs: ['/tmp', '/private/tmp'],
  branch: 'feature/login',
  protectedBranches: ['main', 'master'],
  extraDeny: [],
}

type Case = { command: string; kind: 'allow' | 'deny' | 'snapshot'; ctx?: Partial<Context> }

const SAFE: Case[] = [
  { command: 'ls -la', kind: 'allow' },
  { command: 'rm file.txt', kind: 'allow' },
  { command: 'rm -f file.txt', kind: 'allow' },
  { command: 'rm notes.txt ~/Desktop/old.txt', kind: 'allow' },
  { command: 'grep "rm -rf /" src', kind: 'allow' },
  { command: "echo 'git push --force'", kind: 'allow' },
  { command: 'git commit -m "rm -rf ~ is bad; git push -f origin main"', kind: 'allow' },
  { command: 'git reset --soft HEAD~1', kind: 'allow' },
  { command: 'git reset HEAD file.ts', kind: 'allow' },
  { command: 'git push', kind: 'allow' },
  { command: 'git push -u origin feature/login', kind: 'allow' },
  { command: 'git push --force', kind: 'allow' },
  { command: 'git push -f origin feature/login', kind: 'allow' },
  { command: 'git push --force-with-lease origin HEAD', kind: 'allow' },
  { command: 'git push origin main', kind: 'allow' },
  { command: 'git checkout -b feature/new', kind: 'allow' },
  { command: 'git checkout main', kind: 'allow' },
  { command: 'git restore --staged src/a.ts', kind: 'allow' },
  { command: 'git clean -n', kind: 'allow' },
  { command: 'git stash pop', kind: 'allow' },
  { command: 'git branch -D feature/old', kind: 'allow' },
  { command: 'git branch -M main', kind: 'allow' },
  { command: 'docker compose down', kind: 'allow' },
  { command: 'docker system prune -af', kind: 'allow' },
  { command: 'docker volume ls', kind: 'allow' },
  { command: 'docker run -v /data:/data postgres', kind: 'allow' },
  { command: 'kubectl delete pod web-1', kind: 'allow' },
  { command: 'kubectl delete pod web-1 -n ns', kind: 'allow' },
  { command: 'terraform plan', kind: 'allow' },
  { command: 'rm -rf /tmp/build-cache', kind: 'allow' },
  { command: 'rm -rf /private/tmp/claude-501/scratch', kind: 'allow' },
  { command: 'find . -name "*.log"', kind: 'allow' },
  { command: 'cat <<EOF\nrm -rf /\nEOF', kind: 'allow' },
  { command: 'psql -c "SELECT * FROM users"', kind: 'allow' },
  { command: 'dd if=/dev/zero of=./disk.img bs=1m count=1', kind: 'allow' },
  { command: 'npm test 2>/dev/null && echo ok > /dev/null', kind: 'allow' },
  { command: 'chmod -R 755 ./scripts', kind: 'allow' },
  { command: 'chmod 600 ~/.ssh/id_ed25519', kind: 'allow' },
  { command: 'git log --format=%H | xargs echo', kind: 'allow' },
  { command: 'sudo apt-get install -y ripgrep', kind: 'allow' },
]

const SNAPSHOT: Case[] = [
  { command: 'rm -rf node_modules dist build .next', kind: 'snapshot' },
  { command: 'rm -r src/old', kind: 'snapshot' },
  { command: 'git reset --hard HEAD~1', kind: 'snapshot' },
  { command: 'git checkout -- src/app.ts', kind: 'snapshot' },
  { command: 'git checkout .', kind: 'snapshot' },
  { command: 'git restore src/app.ts', kind: 'snapshot' },
  { command: 'git clean -fdx', kind: 'snapshot' },
  { command: 'git stash drop', kind: 'snapshot' },
  { command: 'git stash clear', kind: 'snapshot' },
  { command: 'git switch --discard-changes main', kind: 'snapshot' },
  { command: 'cd src && rm -rf *', kind: 'snapshot' },
  { command: 'find . -name "*.pyc" -delete', kind: 'snapshot' },
  { command: 'find . -type d -name __pycache__ | xargs rm -rf', kind: 'snapshot' },
  { command: 'rm -rf "$(pwd)/build"', kind: 'snapshot' },
]

const DANGEROUS: Case[] = [
  { command: 'rm -rf ~', kind: 'deny' },
  { command: 'rm -rf ~/', kind: 'deny' },
  { command: 'rm -rf $HOME', kind: 'deny' },
  { command: 'rm -rf "${HOME}"/*', kind: 'deny' },
  { command: 'rm -rf /', kind: 'deny' },
  { command: 'rm -rf /*', kind: 'deny' },
  { command: 'sudo rm -rf --no-preserve-root /', kind: 'deny' },
  { command: 'rm -rf ..', kind: 'deny' },
  { command: 'rm -rf *', kind: 'deny' },
  { command: 'rm -rf .', kind: 'deny' },
  { command: 'rm -fr ./', kind: 'deny' },
  { command: `rm -rf ${ROOT}`, kind: 'deny' },
  { command: 'rm -rf ~/shell-guard-smoke-nonexistent', kind: 'deny' },
  { command: 'rm -rf /Volumes/archive/2024', kind: 'deny' },
  { command: 'rm -f /etc/hosts', kind: 'deny' },
  { command: 'cd .. && rm -rf proj', kind: 'deny' },
  { command: 'cd ~ && rm -rf *', kind: 'deny' },
  { command: 'rm -rf ~other/data', kind: 'deny' },
  { command: 'ls && rm -rf "$BUILD_DIR"', kind: 'deny' },
  { command: 'bash -c "rm -rf ~"', kind: 'deny' },
  { command: "sh -lc 'cd / && rm -rf *'", kind: 'deny' },
  { command: 'echo "$(rm -rf ~)"', kind: 'deny' },
  { command: 'eval "rm -rf /"', kind: 'deny' },
  { command: 'env FOO=1 nice -n 5 rm -rf /', kind: 'deny' },
  { command: 'find . -type f | xargs rm -rf ~', kind: 'deny' },
  { command: 'git push --force', kind: 'deny', ctx: { branch: 'main' } },
  { command: 'git push --force', kind: 'deny', ctx: { branch: null } },
  { command: 'git push -f origin main', kind: 'deny' },
  { command: 'git push origin +master', kind: 'deny' },
  { command: 'git push --force-with-lease origin HEAD:main', kind: 'deny' },
  { command: 'git push --force origin refs/heads/main', kind: 'deny' },
  { command: 'git push --force --all', kind: 'deny' },
  { command: 'git push --mirror', kind: 'deny' },
  { command: 'git push origin --delete main', kind: 'deny' },
  { command: 'git push origin :master', kind: 'deny' },
  { command: 'git branch -D main', kind: 'deny' },
  { command: 'git push -f origin release', kind: 'deny', ctx: { protectedBranches: ['release'] } },
  { command: 'dd if=/dev/zero of=/dev/disk2 bs=1m', kind: 'deny' },
  { command: 'cat image.iso > /dev/sdb', kind: 'deny' },
  { command: 'mkfs.ext4 /dev/sdb1', kind: 'deny' },
  { command: 'diskutil eraseDisk APFS Empty disk4', kind: 'deny' },
  { command: 'shred -u secrets.txt', kind: 'deny' },
  { command: 'chmod -R 777 /', kind: 'deny' },
  { command: 'sudo chown -R me ~/', kind: 'deny' },
  { command: 'find / -name "*.log" -delete', kind: 'deny' },
  { command: 'find ~ -exec rm -rf {} +', kind: 'deny' },
  { command: 'find . -delete', kind: 'deny' },
  { command: 'terraform destroy -auto-approve', kind: 'deny' },
  { command: 'terraform -chdir=infra apply -destroy', kind: 'deny' },
  { command: 'kubectl delete namespace prod', kind: 'deny' },
  { command: 'kubectl delete ns/prod', kind: 'deny' },
  { command: 'kubectl delete pods --all', kind: 'deny' },
  { command: 'docker system prune -a --volumes', kind: 'deny' },
  { command: 'docker volume rm pgdata', kind: 'deny' },
  { command: 'docker volume prune -f', kind: 'deny' },
  { command: 'docker compose -f prod.yml down -v', kind: 'deny' },
  { command: 'psql -h db -U app -c "DROP DATABASE prod"', kind: 'deny' },
  { command: 'psql --command="drop schema public cascade"', kind: 'deny' },
  { command: "mysql -u root -e 'TRUNCATE users'", kind: 'deny' },
  { command: 'sqlite3 app.db "drop table users"', kind: 'deny' },
  { command: 'psql app <<SQL\nDROP TABLE users;\nSQL', kind: 'deny' },
  { command: 'redis-cli -h cache FLUSHALL', kind: 'deny' },
]

describe('classify: the command table', () => {
  for (const { command, kind, ctx } of [...SAFE, ...SNAPSHOT, ...DANGEROUS]) {
    test(`${kind}: ${command.replace(/\n/g, '\\n')}`, () => {
      expect(classify(command, { ...CTX, ...ctx }).kind).toBe(kind)
    })
  }

  test('the table holds at least 40 cases of each side', () => {
    expect(SAFE.length + SNAPSHOT.length).toBeGreaterThan(40)
    expect(DANGEROUS.length).toBeGreaterThan(40)
  })
})

describe('classify: details', () => {
  test('a deny says what is wrong and what to do instead', () => {
    const verdict = classify('rm -rf ~', CTX)

    expect(verdict.kind).toBe('deny')

    if (verdict.kind === 'deny') {
      expect(verdict.reason).toContain('home folder')
      expect(verdict.reason).toContain('ask them to run it themselves')
      expect(verdict.summary).toBe('rm -rf ~')
    }
  })

  test('the project root deny suggests deleting a folder inside it', () => {
    const verdict = classify('rm -rf *', CTX)

    expect(verdict.kind === 'deny' && verdict.reason.includes('rm -rf dist')).toBe(true)
  })

  test('git -C points the snapshot at the other repo', () => {
    const verdict = classify('git -C packages/web reset --hard', CTX)

    expect(verdict).toEqual({ kind: 'snapshot', dirs: [`${ROOT}/packages/web`], withStashes: false, summary: 'git -C packages/web reset --hard' })
  })

  test('a stash drop keeps the stashes in the snapshot', () => {
    const verdict = classify('git stash drop stash@{0}', CTX)

    expect(verdict.kind === 'snapshot' && verdict.withStashes).toBe(true)
  })

  test('a cd before the delete moves the snapshot with it', () => {
    const verdict = classify('cd packages/api && git reset --hard', CTX)

    expect(verdict.kind === 'snapshot' ? verdict.dirs : []).toEqual([`${ROOT}/packages/api`])
  })

  test('working in a subfolder, * covers only that folder', () => {
    expect(classify('rm -rf *', { ...CTX, cwd: `${ROOT}/build` }).kind).toBe('snapshot')
  })

  test('a project in a temp folder is still a project', () => {
    const ctx = { ...CTX, root: '/tmp/x1', cwd: '/tmp/x1' }

    expect(classify('rm -rf dist', ctx).kind).toBe('snapshot')
    expect(classify('rm -rf .', ctx).kind).toBe('deny')
    expect(classify('rm -rf /tmp', ctx).kind).toBe('deny')
  })

  test('extraDeny patterns refuse a matching command and leave the rest', () => {
    const ctx = { ...CTX, extraDeny: [/^npm publish/] }

    expect(classify('npm publish --access public', ctx).kind).toBe('deny')
    expect(classify('sudo npm publish', ctx).kind).toBe('deny')
    expect(classify('echo "npm publish"', ctx).kind).toBe('allow')
  })

  test('shells nested past the limit are refused rather than trusted', () => {
    let command = 'ls'

    for (let i = 0; i < 8; i += 1) {
      command = `bash -c ${JSON.stringify(command)}`
    }

    expect(classify(command, CTX).kind).toBe('deny')
  })
})

describe('parse', () => {
  test('quotes hide operators and keep words whole', () => {
    const { segments } = parse(`grep "a && b" file; echo 'x | y' | wc -l`)

    expect(segments.map(segment => segment.words.map(word => word.text))).toEqual([
      ['grep', 'a && b', 'file'],
      ['echo', 'x | y'],
      ['wc', '-l'],
    ])
  })

  test('redirections are not arguments', () => {
    const [segment] = parse('rm -rf build 2>/dev/null >log.txt').segments

    expect(segment?.words.map(word => word.text)).toEqual(['rm', '-rf', 'build'])
    expect(segment?.redirects).toEqual(['/dev/null', 'log.txt'])
  })

  test('command substitutions come back as their own scripts', () => {
    expect(parse('echo "today $(date +%F)" `whoami`').subs).toEqual(['date +%F', 'whoami'])
  })

  test('a heredoc body is stdin, not commands', () => {
    const { segments } = parse("cat <<'EOF' > out.txt\nrm -rf /\nEOF\necho done")

    expect(segments.map(segment => segment.words[0]?.text)).toEqual(['cat', 'echo'])
    expect(segments[0]?.stdin).toBe('rm -rf /')
  })

  test('only an unquoted leading tilde expands', () => {
    const [segment] = parse(`rm ~/a "~/b" x~`).segments

    expect(segment?.words.map(word => word.isTildeLive)).toEqual([false, true, false, false])
  })
})

describe('placeOf', () => {
  const word = (text: string) => ({ text, isTildeLive: text.startsWith('~') })

  test('relative paths resolve against the working directory', () => {
    expect(placeOf(word('src/../dist'), ROOT, CTX).kind).toBe('inside')
    expect(placeOf(word('../other'), ROOT, CTX).kind).toBe('outside')
    expect(placeOf(word('../..'), ROOT, CTX).kind).toBe('home')

    const deep = { ...CTX, root: `${HOME}/code/proj`, cwd: `${HOME}/code/proj` }

    expect(placeOf(word('..'), deep.cwd, deep).kind).toBe('contains-project')
  })

  test('a variable in the middle of a path is judged by the folder before it', () => {
    expect(placeOf(word('dist/$NAME'), ROOT, CTX).kind).toBe('inside')
    expect(placeOf(word('~/$NAME'), ROOT, CTX).kind).toBe('home')
  })

  test('a narrow glob is a child of its folder, a bare one is the folder', () => {
    expect(placeOf(word('*.log'), ROOT, CTX).kind).toBe('inside')
    expect(placeOf(word('.*'), ROOT, CTX).kind).toBe('project')
  })
})

describe('settings', () => {
  test('protected branches split on commas and spaces', () => {
    expect(parseBranches(' main, master  release ')).toEqual(['main', 'master', 'release'])
  })

  test('extraDeny keeps valid patterns and reports broken ones', () => {
    const { patterns, invalid } = parsePatterns('^npm publish\n(unclosed\n\n')

    expect(patterns.map(pattern => pattern.source)).toEqual(['^npm publish'])
    expect(invalid).toEqual(['(unclosed'])
  })
})

describe('snapshots', () => {
  test('a ref name sorts by time and is legal for git', () => {
    expect(snapshotRef(Date.parse('2026-10-06T12:03:04.567Z'))).toBe('refs/shell-guard/20261006-120304-567')
  })

  test('the message carries the command and the stashes it keeps', () => {
    expect(snapshotMessage('git stash clear', ['abc', 'def'])).toBe('shell-guard: git stash clear\n\ngit stash clear\n\nstashes: abc def')
  })

  test('the listing reads for-each-ref output and prints restore commands', () => {
    const out = [
      'refs/shell-guard/20261006-120304-567\u001f2026-10-06 12:03:04 +0200\u001fh1 s1\u001fshell-guard: git stash clear\n\ngit stash clear\n\nstashes: s1\n\u001e',
      '\nrefs/shell-guard/20261006-110000-000\u001f2026-10-06 11:00:00 +0200\u001fh1\u001fshell-guard: git reset --hard\n\ngit reset --hard\n\u001e',
    ].join('')
    const snapshots = parseSnapshots(out)

    expect(snapshots).toEqual([
      { ref: 'refs/shell-guard/20261006-120304-567', time: '2026-10-06 12:03', command: 'git stash clear', hasHead: true, stashes: ['s1'] },
      { ref: 'refs/shell-guard/20261006-110000-000', time: '2026-10-06 11:00', command: 'git reset --hard', hasHead: true, stashes: [] },
    ])

    const text = formatSnapshots(snapshots, '~/proj', true)

    expect(text).toContain('2 snapshots in ~/proj, newest first')
    expect(text).toContain('git checkout refs/shell-guard/20261006-110000-000 -- .')
    expect(text).toContain('git diff --stat refs/shell-guard/20261006-120304-567^1 refs/shell-guard/20261006-120304-567')
    expect(text).toContain('git stash store -m "restored by shell-guard" s1')
  })

  test('an empty listing says so', () => {
    expect(formatSnapshots([], '~/proj', false)).toContain('No snapshots in ~/proj yet')
  })
})
