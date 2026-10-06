/**
 * Path arithmetic without Node: hooks modules have no `path` module.
 * Every path here is absolute and POSIX.
 */

/** Resolves `.` and `..` and repeated slashes; `..` above `/` stays at `/`. */
export const normalize = (path: string): string => {
  const parts: string[] = []

  for (const part of path.split('/')) {
    if (part === '' || part === '.') {
      continue
    }

    if (part === '..') {
      parts.pop()
      continue
    }

    parts.push(part)
  }

  return `/${parts.join('/')}`
}

export const join = (base: string, rest: string): string =>
  rest.startsWith('/') ? normalize(rest) : normalize(`${base}/${rest}`)

/** True when `inner` is `outer` or lies beneath it. */
export const isWithin = (inner: string, outer: string): boolean =>
  outer === '/' || inner === outer || inner.startsWith(`${outer}/`)

/** True when `inner` lies strictly beneath `outer`. */
export const isBelow = (inner: string, outer: string): boolean => inner !== outer && isWithin(inner, outer)

export const basename = (path: string): string => {
  const trimmed = path.replace(/\/+$/, '')
  const slash = trimmed.lastIndexOf('/')

  return slash === -1 ? trimmed : trimmed.slice(slash + 1)
}

/** Shows a path under the home folder as `~/...`, as people write it. */
export const tildify = (path: string, home: string): string =>
  home !== '/' && isWithin(path, home) ? `~${path.slice(home.length)}` : path
