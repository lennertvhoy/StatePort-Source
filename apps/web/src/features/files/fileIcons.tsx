/**
 * Curated file-type glyph map (design.md §8, §11): extension → lucide icon.
 * One muted tint (`--text-secondary`); identity comes from the name, not
 * color coding. Directories use Folder/FolderOpen; unknown files FileText.
 */
import {
  FileArchive,
  FileCode2,
  FileCog,
  FileImage,
  FileJson2,
  FileTerminal,
  FileText,
  FileType,
  Folder,
  FolderOpen,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { createElement } from 'react'

import { fileExtension } from './language'

const EXTENSION_ICONS: Record<string, LucideIcon> = {
  nix: FileCode2,
  json: FileJson2,
  md: FileText,
  markdown: FileText,
  txt: FileText,
  js: FileCode2,
  jsx: FileCode2,
  ts: FileCode2,
  tsx: FileCode2,
  mjs: FileCode2,
  cjs: FileCode2,
  yaml: FileCog,
  yml: FileCog,
  toml: FileCog,
  ini: FileCog,
  conf: FileCog,
  py: FileCode2,
  html: FileCode2,
  htm: FileCode2,
  css: FileType,
  scss: FileType,
  sh: FileTerminal,
  bash: FileTerminal,
  zsh: FileTerminal,
  png: FileImage,
  jpg: FileImage,
  jpeg: FileImage,
  gif: FileImage,
  svg: FileImage,
  webp: FileImage,
  zip: FileArchive,
  tar: FileArchive,
  gz: FileArchive,
  lock: FileCog,
}

function fileIconFor(path: string): LucideIcon {
  return EXTENSION_ICONS[fileExtension(path)] ?? FileText
}

export interface FileGlyphProps {
  path: string
  kind: 'file' | 'directory'
  expanded?: boolean
  className?: string
}

/** The canonical tree/tab glyph for a file node. */
export function FileGlyph({ path, kind, expanded, className = 'size-4' }: FileGlyphProps) {
  // createElement keeps this a dynamic lookup, not a render-created component.
  return createElement(kind === 'directory' ? (expanded ? FolderOpen : Folder) : fileIconFor(path), {
    className,
    'aria-hidden': true,
  })
}
