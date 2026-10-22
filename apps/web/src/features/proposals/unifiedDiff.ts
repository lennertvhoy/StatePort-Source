/**
 * Minimal, total parser for the unified diffs StatePort computes for a file
 * proposal (`git diff --cached --binary`, agent-sandbox.md §4). Plain
 * `---`/`+++` diffs without a `diff --git` header parse too. The parser never
 * throws: text it does not recognise is kept as a `meta` line so nothing in
 * the exact patch is hidden from review.
 */
import type { FileChangeKind, ProposedFileChange } from '@/client/proposals'

export type PatchLineKind = 'context' | 'add' | 'del' | 'meta'

export interface PatchLine {
  kind: PatchLineKind
  text: string
  oldNumber: number | null
  newNumber: number | null
}

export interface PatchHunk {
  header: string
  lines: PatchLine[]
}

export interface PatchFile {
  path: string
  oldPath: string | null
  change: FileChangeKind
  binary: boolean
  additions: number
  deletions: number
  hunks: PatchHunk[]
  /** Header lines (index, mode, similarity) kept verbatim. */
  meta: string[]
}

const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/
const NO_NEWLINE_MARKER = '\\'

function stripPrefix(path: string): string {
  const trimmed = path.replace(/\t.*$/, '')
  if (trimmed === '/dev/null') return trimmed
  return trimmed.replace(/^[ab]\//, '')
}

function gitHeaderPaths(line: string): { oldPath: string; newPath: string } | null {
  const match = /^diff --git a\/(.+) b\/(.+)$/.exec(line)
  return match ? { oldPath: match[1], newPath: match[2] } : null
}

function newFile(path: string): PatchFile {
  return { path, oldPath: null, change: 'modified', binary: false, additions: 0, deletions: 0, hunks: [], meta: [] }
}

interface ParserState {
  files: PatchFile[]
  file: PatchFile | null
  /** The file opened by `diff --git` whose `---`/`+++` lines may still follow. */
  headerFile: PatchFile | null
  hunk: PatchHunk | null
  oldLine: number
  newLine: number
  oldRemaining: number
  newRemaining: number
  fromPath: string | null
}

function startFile(state: ParserState, path: string): PatchFile {
  const created = newFile(path)
  state.files.push(created)
  state.file = created
  state.hunk = null
  return created
}

/** A line inside a hunk whose header counts are not yet exhausted. */
function readHunkLine(state: ParserState, hunk: PatchHunk, file: PatchFile, line: string): void {
  if (line.startsWith('+')) {
    hunk.lines.push({ kind: 'add', text: line.slice(1), oldNumber: null, newNumber: state.newLine++ })
    file.additions += 1
    state.newRemaining -= 1
  } else if (line.startsWith('-')) {
    hunk.lines.push({ kind: 'del', text: line.slice(1), oldNumber: state.oldLine++, newNumber: null })
    file.deletions += 1
    state.oldRemaining -= 1
  } else if (line.startsWith(' ') || line === '') {
    hunk.lines.push({ kind: 'context', text: line.slice(1), oldNumber: state.oldLine++, newNumber: state.newLine++ })
    state.oldRemaining -= 1
    state.newRemaining -= 1
  } else {
    // "\ No newline at end of file" and anything unexpected stay visible.
    hunk.lines.push({ kind: 'meta', text: line, oldNumber: null, newNumber: null })
  }
}

function readFileMeta(file: PatchFile, line: string): void {
  if (line.startsWith('new file mode')) file.change = 'added'
  else if (line.startsWith('deleted file mode')) file.change = 'deleted'
  else if (line.startsWith('rename from ')) {
    file.change = 'renamed'
    file.oldPath = line.slice('rename from '.length)
  } else if (line.startsWith('rename to ')) {
    file.change = 'renamed'
    file.path = line.slice('rename to '.length)
  } else if (line.startsWith('Binary files ') || line === 'GIT binary patch') {
    file.binary = true
  }
  file.meta.push(line)
}

export function parseUnifiedDiff(patch: string): PatchFile[] {
  const state: ParserState = {
    files: [],
    file: null,
    headerFile: null,
    hunk: null,
    oldLine: 0,
    newLine: 0,
    oldRemaining: 0,
    newRemaining: 0,
    fromPath: null,
  }
  const lines = patch.replace(/\r\n/g, '\n').split('\n')
  // A trailing newline yields one empty final element that is not a line.
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()

  for (const line of lines) {
    // Inside a hunk the header's line counts decide what a line is, so a
    // removed line that itself starts with "--" is never read as a header.
    if (state.hunk && state.file && (state.oldRemaining > 0 || state.newRemaining > 0)) {
      readHunkLine(state, state.hunk, state.file, line)
      continue
    }
    if (line.startsWith(NO_NEWLINE_MARKER) && state.hunk) {
      state.hunk.lines.push({ kind: 'meta', text: line, oldNumber: null, newNumber: null })
      continue
    }

    const git = gitHeaderPaths(line)
    if (git) {
      const created = startFile(state, git.newPath)
      if (git.oldPath !== git.newPath) {
        created.oldPath = git.oldPath
        created.change = 'renamed'
      }
      state.headerFile = created
      state.fromPath = null
      continue
    }

    if (line.startsWith('--- ')) {
      state.fromPath = stripPrefix(line.slice(4))
      continue
    }

    if (line.startsWith('+++ ') && state.fromPath !== null) {
      const fromPath = state.fromPath
      const toPath = stripPrefix(line.slice(4))
      const current = state.headerFile ?? startFile(state, toPath === '/dev/null' ? fromPath : toPath)
      if (fromPath === '/dev/null') current.change = 'added'
      else if (toPath === '/dev/null') {
        current.change = 'deleted'
        current.path = fromPath
      } else if (fromPath !== toPath) {
        current.change = 'renamed'
        current.oldPath = fromPath
        current.path = toPath
      }
      state.fromPath = null
      state.headerFile = null
      continue
    }

    const header = HUNK_HEADER.exec(line)
    if (header && state.file) {
      state.oldLine = Number(header[1])
      state.newLine = Number(header[3])
      state.oldRemaining = header[2] === undefined ? 1 : Number(header[2])
      state.newRemaining = header[4] === undefined ? 1 : Number(header[4])
      const opened: PatchHunk = { header: line, lines: [] }
      state.file.hunks.push(opened)
      state.hunk = opened
      state.headerFile = null
      continue
    }

    // Preamble before the first file header is not part of any file.
    if (state.file) readFileMeta(state.file, line)
  }
  return state.files
}

/** Prefer the proposal's declared file list; fill counts from the parsed patch. */
export function mergeFileList(declared: ProposedFileChange[], parsed: PatchFile[]): ProposedFileChange[] {
  if (declared.length === 0) {
    return parsed.map((file) => ({
      path: file.path,
      oldPath: file.oldPath,
      change: file.change,
      additions: file.binary ? null : file.additions,
      deletions: file.binary ? null : file.deletions,
      binary: file.binary,
    }))
  }
  return declared.map((entry) => {
    const match = parsed.find((file) => file.path === entry.path)
    return {
      ...entry,
      additions: entry.additions ?? (match && !match.binary ? match.additions : null),
      deletions: entry.deletions ?? (match && !match.binary ? match.deletions : null),
      binary: entry.binary || Boolean(match?.binary),
    }
  })
}

/** Rendered rows of one file's diff (hunk headers count as a row). */
export function patchLineCount(file: PatchFile): number {
  return file.hunks.reduce((total, hunk) => total + hunk.lines.length + 1, 0)
}
