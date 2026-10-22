import assert from 'node:assert/strict'
import test from 'node:test'

import { stampCodePaths } from '../tools/inspectCodePath.ts'

const ROOT = '/repo/apps/web'
const stamp = (code, id = `${ROOT}/src/A.tsx`) => stampCodePaths(code, id, ROOT)

test('stamps host, component and self-closing elements with 1-based line:column', () => {
  const out = stamp('const a = (\n  <div>\n    <Foo x={1} />\n  </div>\n)\n')
  assert.equal(
    out,
    'const a = (\n  <div code-path="src/A.tsx:2:3">\n    <Foo code-path="src/A.tsx:3:5" x={1} />\n  </div>\n)\n',
  )
})

test('skips React.* elements, fragments and modules without JSX', () => {
  assert.equal(stamp('const a = <React.Fragment><>x</></React.Fragment>'), undefined)
  assert.equal(stamp('export const n = 1'), undefined)
})

test('keeps member tags and generic type arguments intact', () => {
  const out = stamp('const a = <Ns.Item<string> v="x" />')
  assert.equal(out, 'const a = <Ns.Item<string> code-path="src/A.tsx:1:11" v="x" />')
})

test('ignores a Vite query suffix when resolving the path', () => {
  assert.match(stamp('const a = <i />', `${ROOT}/src/B.tsx?t=1`), /code-path="src\/B\.tsx:1:11"/)
})
