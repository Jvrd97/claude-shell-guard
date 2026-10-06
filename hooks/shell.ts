/**
 * A small shell lexer: enough of POSIX sh to split a command line into the
 * simple commands it runs, with quotes respected. It does not run anything
 * and does not expand anything; expansions stay in the word text for the
 * classifier to judge.
 */

export type Word = {
  /** The word with quotes removed; `$VAR`, globs and `~` kept as written. */
  text: string
  /** True when the word begins with an unquoted `~`, so the shell expands it. */
  isTildeLive: boolean
}

export type Segment = {
  words: Word[]
  /** Targets of `>`, `>>`, `&>` and the like. */
  redirects: string[]
  /** A heredoc's body or a here-string, what the command reads on stdin. */
  stdin?: string
}

export type Parsed = {
  segments: Segment[]
  /** Inner text of `$(...)`, backticks and `<(...)`: commands of their own. */
  subs: string[]
}

const BREAKS = new Set([';', '&', '|', '\n', '(', ')'])
const WORD_END = new Set([' ', '\t', ';', '&', '|', '\n', '(', ')', '<', '>'])
const DOUBLE_QUOTE_ESCAPES = new Set(['$', '`', '"', '\\', '\n'])
const FD_PREFIX = /^\d+$/

type Heredoc = { delimiter: string; stripsTabs: boolean; segment: Segment }

/** Index just past the `)` closing the paren opened right before `start`. */
const closeParen = (text: string, start: number): number => {
  let depth = 1
  let i = start
  let quote: '"' | "'" | null = null

  while (i < text.length) {
    const ch = text[i]

    if (quote === "'") {
      if (ch === "'") {
        quote = null
      }
    } else if (ch === '\\') {
      i += 1
    } else if (quote === '"') {
      if (ch === '"') {
        quote = null
      }
    } else if (ch === "'" || ch === '"') {
      quote = ch
    } else if (ch === '(') {
      depth += 1
    } else if (ch === ')') {
      depth -= 1

      if (depth === 0) {
        return i + 1
      }
    }

    i += 1
  }

  return text.length
}

/** Index just past the backtick closing the one right before `start`. */
const closeBacktick = (text: string, start: number): number => {
  let i = start

  while (i < text.length) {
    if (text[i] === '\\') {
      i += 2
      continue
    }

    if (text[i] === '`') {
      return i + 1
    }

    i += 1
  }

  return text.length
}

/** Reads the heredoc bodies queued on a line, starting after its newline. */
const readHeredocs = (text: string, start: number, pending: readonly Heredoc[]): number => {
  let i = start

  for (const doc of pending) {
    const lines: string[] = []

    while (i < text.length) {
      const end = text.indexOf('\n', i)
      const lineEnd = end === -1 ? text.length : end
      const raw = text.slice(i, lineEnd)
      const line = doc.stripsTabs ? raw.replace(/^\t+/, '') : raw
      i = end === -1 ? text.length : end + 1

      if (line === doc.delimiter) {
        break
      }

      lines.push(line)
    }

    const body = lines.join('\n')
    doc.segment.stdin = doc.segment.stdin === undefined ? body : `${doc.segment.stdin}\n${body}`
  }

  return i
}

/**
 * Splits a command line into simple commands (on `&&`, `||`, `;`, `|`, `&`,
 * newlines and parentheses) and collects the command substitutions inside it.
 */
export const parse = (text: string): Parsed => {
  const segments: Segment[] = []
  const subs: string[] = []
  let segment: Segment = { words: [], redirects: [] }
  let word = ''
  let hasWord = false
  let isTildeLive = false
  let isRedirectTarget = false
  let isHereString = false
  let heredocNext: { stripsTabs: boolean } | null = null
  let pending: Heredoc[] = []
  let i = 0

  const endWord = (): void => {
    if (!hasWord) {
      return
    }

    if (heredocNext !== null) {
      pending.push({ delimiter: word, stripsTabs: heredocNext.stripsTabs, segment })
      heredocNext = null
    } else if (isHereString) {
      segment.stdin = word
      isHereString = false
    } else if (isRedirectTarget) {
      segment.redirects.push(word)
      isRedirectTarget = false
    } else {
      segment.words.push({ text: word, isTildeLive })
    }

    word = ''
    hasWord = false
    isTildeLive = false
  }

  const endSegment = (): void => {
    endWord()

    if (segment.words.length > 0 || segment.redirects.length > 0 || segment.stdin !== undefined) {
      segments.push(segment)
    }

    segment = { words: [], redirects: [] }
  }

  const substitution = (from: number, to: number, closeLength: number): void => {
    const inner = text.slice(from, to - closeLength)
    subs.push(inner)
    word += inner.trim() === 'pwd' ? '$PWD' : '$(…)'
    hasWord = true
  }

  while (i < text.length) {
    const ch = text[i] ?? ''

    if (ch === '\\') {
      const nextCh = text[i + 1]

      if (nextCh === '\n') {
        i += 2
        continue
      }

      word += nextCh ?? ''
      hasWord = true
      i += 2
      continue
    }

    if (ch === "'") {
      const end = text.indexOf("'", i + 1)
      const close = end === -1 ? text.length : end
      word += text.slice(i + 1, close)
      hasWord = true
      i = close + 1
      continue
    }

    if (ch === '"') {
      i += 1

      while (i < text.length && text[i] !== '"') {
        const inner = text[i] ?? ''

        if (inner === '\\' && DOUBLE_QUOTE_ESCAPES.has(text[i + 1] ?? '')) {
          word += text[i + 1] === '\n' ? '' : text[i + 1]
          i += 2
          continue
        }

        if (inner === '$' && text[i + 1] === '(') {
          const end = closeParen(text, i + 2)
          substitution(i + 2, end, 1)
          i = end
          continue
        }

        if (inner === '`') {
          const end = closeBacktick(text, i + 1)
          substitution(i + 1, end, 1)
          i = end
          continue
        }

        word += inner
        i += 1
      }

      hasWord = true
      i += 1
      continue
    }

    if (ch === '$' && text[i + 1] === "'") {
      const end = text.indexOf("'", i + 2)
      const close = end === -1 ? text.length : end
      word += text.slice(i + 2, close)
      hasWord = true
      i = close + 1
      continue
    }

    if (ch === '$' && text[i + 1] === '(') {
      const end = closeParen(text, i + 2)
      substitution(i + 2, end, 1)
      i = end
      continue
    }

    if (ch === '`') {
      const end = closeBacktick(text, i + 1)
      substitution(i + 1, end, 1)
      i = end
      continue
    }

    if ((ch === '<' || ch === '>') && text[i + 1] === '(') {
      endWord()
      const end = closeParen(text, i + 2)
      subs.push(text.slice(i + 2, end - 1))
      i = end
      continue
    }

    if (ch === '#' && !hasWord) {
      const end = text.indexOf('\n', i)
      i = end === -1 ? text.length : end
      continue
    }

    if (ch === '<' && text[i + 1] === '<') {
      if (FD_PREFIX.test(word)) {
        word = ''
        hasWord = false
      }

      endWord()

      if (text[i + 2] === '<') {
        isHereString = true
        i += 3
      } else {
        const stripsTabs = text[i + 2] === '-'
        heredocNext = { stripsTabs }
        i += stripsTabs ? 3 : 2
      }

      continue
    }

    if (ch === '<' || ch === '>' || (ch === '&' && text[i + 1] === '>')) {
      if (FD_PREFIX.test(word)) {
        word = ''
        hasWord = false
      }

      endWord()
      i += 1

      while (i < text.length && ['>', '&', '|', '<'].includes(text[i] ?? '')) {
        i += 1
      }

      isRedirectTarget = true
      continue
    }

    if (BREAKS.has(ch)) {
      endSegment()

      if (ch === '\n' && pending.length > 0) {
        i = readHeredocs(text, i + 1, pending)
        pending = []
        continue
      }

      i += 1
      continue
    }

    if (WORD_END.has(ch)) {
      endWord()
      i += 1
      continue
    }

    if (ch === '~' && !hasWord) {
      isTildeLive = true
    }

    word += ch
    hasWord = true
    i += 1
  }

  endSegment()

  return { segments, subs }
}
