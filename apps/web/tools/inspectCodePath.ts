/**
 * Vite plugin that stamps `code-path="<file>:<line>:<column>"` onto every JSX
 * element of `.tsx` / `.jsx` modules, so a reviewer can map a DOM node of the
 * dev/demo surface back to its source location. It is never loaded for
 * production builds (see vite.config.ts).
 *
 * Behaviour deliberately matches the former `plugin-inspect-react-code`
 * devDependency (`inspectAttr`): the path is relative to the working directory,
 * the line is 1-based, the column is 1-based, `React.*` elements are skipped,
 * and the attribute is inserted straight after the tag name.
 *
 * The idea derives from @namnode/vite-plugin-inspect-react (MIT):
 *
 *   MIT License
 *
 *   Copyright (c) 2024 Nam Nguyen
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a
 *   copy of this software and associated documentation files (the "Software"),
 *   to deal in the Software without restriction, including without limitation
 *   the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *   and/or sell copies of the Software, and to permit persons to whom the
 *   Software is furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *   DEALINGS IN THE SOFTWARE.
 *
 * This file is an independent in-repository implementation on the TypeScript
 * compiler API (already a direct devDependency); no third-party code is copied.
 */
import path from 'node:path'

import ts from 'typescript'
import type { Plugin } from 'vite'

type JsxElementNode = ts.JsxElement | ts.JsxSelfClosingElement

function openingNode(node: JsxElementNode): ts.JsxOpeningLikeElement {
  return ts.isJsxElement(node) ? node.openingElement : node
}

function isReactNamespace(tagName: ts.JsxTagNameExpression): boolean {
  return (
    ts.isPropertyAccessExpression(tagName) &&
    ts.isIdentifier(tagName.expression) &&
    tagName.expression.text === 'React'
  )
}

/** Returns `code` with a `code-path` attribute on each JSX element, or undefined. */
export function stampCodePaths(
  code: string,
  id: string,
  root: string = process.cwd(),
): string | undefined {
  const file = id.split('?', 1)[0] ?? id
  const source = ts.createSourceFile(
    file,
    code,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ false,
    file.endsWith('.jsx') ? ts.ScriptKind.JSX : ts.ScriptKind.TSX,
  )
  const relative = path.relative(root, path.resolve(file))
  const insertions: Array<{ at: number; text: string }> = []

  const visit = (node: ts.Node): void => {
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      const opening = openingNode(node)
      if (!isReactNamespace(opening.tagName)) {
        const { line, character } = source.getLineAndCharacterOfPosition(
          node.getStart(source),
        )
        insertions.push({
          // NodeArray.end excludes the closing `>` of explicit type arguments.
          at: opening.typeArguments
            ? code.indexOf('>', opening.typeArguments.end) + 1
            : opening.tagName.end,
          text: ` code-path="${relative}:${line + 1}:${character + 1}"`,
        })
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)

  if (insertions.length === 0) return undefined
  insertions.sort((a, b) => a.at - b.at)
  let output = ''
  let cursor = 0
  for (const { at, text } of insertions) {
    output += code.slice(cursor, at) + text
    cursor = at
  }
  return output + code.slice(cursor)
}

export function inspectCodePath(): Plugin {
  return {
    name: 'stateport-inspect-code-path',
    enforce: 'pre',
    transform(code, id) {
      const file = id.split('?', 1)[0] ?? id
      if (!file.endsWith('.tsx') && !file.endsWith('.jsx')) return undefined
      const stamped = stampCodePaths(code, id)
      // Attribute insertion is column-shifting only; an empty mapping tells
      // Rollup the original mapping is kept rather than warning.
      return stamped === undefined
        ? undefined
        : { code: stamped, map: { mappings: '' } }
    },
  }
}
