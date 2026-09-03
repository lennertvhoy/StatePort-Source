/**
 * Language detection by file extension (files.md): CodeMirror language
 * support from the installed @codemirror/lang-* packages. Nix is provided
 * through a compact StreamLanguage tokenizer (the installed legacy-modes
 * build ships no nix mode, so the grammar lives here — still the standard
 * StreamLanguage mechanism the design calls for).
 * Unknown extensions fall back to plain text (no language extension).
 */
import { css } from '@codemirror/lang-css'
import { html } from '@codemirror/lang-html'
import { javascript } from '@codemirror/lang-javascript'
import { json } from '@codemirror/lang-json'
import { markdown } from '@codemirror/lang-markdown'
import { python } from '@codemirror/lang-python'
import { yaml } from '@codemirror/lang-yaml'
import { LanguageSupport, StreamLanguage } from '@codemirror/language'
import type { StreamParser } from '@codemirror/language'

export function fileExtension(path: string): string {
  const name = path.split('/').pop() ?? path
  const dot = name.lastIndexOf('.')
  if (dot <= 0) return ''
  return name.slice(dot + 1).toLowerCase()
}

// ── Nix (StreamLanguage tokenizer) ───────────────────────────────────────────

const NIX_KEYWORDS = new Set(['let', 'in', 'with', 'rec', 'inherit', 'if', 'then', 'else', 'assert'])

interface NixState {
  /** 'double' inside "…", 'indented' inside ''…'', null otherwise. */
  string: 'double' | 'indented' | null
  blockComment: boolean
  /** Interpolation depth inside a string (${ … }). */
  interpolation: number
}

const nixParser: StreamParser<NixState> = {
  name: 'nix',
  startState: () => ({ string: null, blockComment: false, interpolation: 0 }),
  copyState: (s) => ({ ...s }),
  token(stream, state) {
    if (state.blockComment) {
      if (stream.match(/^.*?\*\//)) state.blockComment = false
      else stream.skipToEnd()
      return 'comment'
    }
    if (state.string) {
      if (stream.match(/^\\./)) return 'string'
      if (state.interpolation > 0) {
        // Inside ${ … }: lex as normal nix until the closing brace.
        if (stream.eat('{')) state.interpolation += 1
        else if (stream.eat('}')) state.interpolation -= 1
        else return nixToken(stream, state)
        return state.interpolation === 0 ? 'meta' : 'operator'
      }
      if (state.string === 'double' && stream.eat('"')) {
        state.string = null
        return 'string'
      }
      if (state.string === 'indented' && stream.match("''")) {
        state.string = null
        return 'string'
      }
      if (stream.match(/^\$\{/)) {
        state.interpolation = 1
        return 'meta'
      }
      stream.next()
      return 'string'
    }
    return nixToken(stream, state)
  },
  languageData: {
    commentTokens: { line: '#', block: { open: '/*', close: '*/' } },
    closeBrackets: { brackets: ['(', '[', '{', '"'] },
  },
}

function nixToken(stream: Parameters<StreamParser<NixState>['token']>[0], state: NixState): string | null {
  if (stream.eatSpace()) return null
  if (stream.match('/*')) {
    state.blockComment = true
    return 'comment'
  }
  if (stream.peek() === '#') {
    stream.skipToEnd()
    return 'comment'
  }
  if (stream.eat('"')) {
    state.string = 'double'
    return 'string'
  }
  if (stream.match("''")) {
    state.string = 'indented'
    return 'string'
  }
  if (stream.match(/^\d+(\.\d+)?/)) return 'number'
  if (stream.match(/^(true|false|null)\b/)) return 'atom'
  if (stream.match(/^<[A-Za-z0-9._+/~-]+>/)) return 'labelName' // <nixpkgs> paths
  if (stream.match(/^[A-Za-z_][A-Za-z0-9_'-]*/)) {
    const word = stream.current()
    if (NIX_KEYWORDS.has(word)) return 'keyword'
    if (stream.match(/^\s*=[^=]/, false) || stream.match(/^\s*\./, false)) return 'propertyName'
    return 'variableName'
  }
  if (stream.match(/^(==|!=|<=|>=|&&|\|\||->|\/\/|\+\+|[=<>!+\-*/&|?@])/)) return 'operator'
  stream.next()
  return null
}

const nixLanguage = () => new LanguageSupport(StreamLanguage.define(nixParser))

// ── Extension map ────────────────────────────────────────────────────────────

interface LanguageDef {
  name: string
  support: () => LanguageSupport
}

const LANGUAGES: Record<string, LanguageDef> = {
  nix: { name: 'Nix', support: nixLanguage },
  json: { name: 'JSON', support: () => json() },
  md: { name: 'Markdown', support: () => markdown() },
  markdown: { name: 'Markdown', support: () => markdown() },
  js: { name: 'JavaScript', support: () => javascript() },
  jsx: { name: 'JavaScript (JSX)', support: () => javascript({ jsx: true }) },
  mjs: { name: 'JavaScript', support: () => javascript() },
  cjs: { name: 'JavaScript', support: () => javascript() },
  ts: { name: 'TypeScript', support: () => javascript({ typescript: true }) },
  tsx: { name: 'TypeScript (TSX)', support: () => javascript({ jsx: true, typescript: true }) },
  yaml: { name: 'YAML', support: () => yaml() },
  yml: { name: 'YAML', support: () => yaml() },
  py: { name: 'Python', support: () => python() },
  html: { name: 'HTML', support: () => html() },
  htm: { name: 'HTML', support: () => html() },
  css: { name: 'CSS', support: () => css() },
}

/** Display name for the status strip. */
export function languageNameFor(path: string): string {
  return LANGUAGES[fileExtension(path)]?.name ?? 'Plain text'
}

/** CodeMirror language extension for a path (empty array = plain text). */
export function languageSupportFor(path: string): LanguageSupport[] {
  const def = LANGUAGES[fileExtension(path)]
  return def ? [def.support()] : []
}
