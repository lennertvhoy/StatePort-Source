/** True only for the two Markdown extensions supported by the Files preview. */
export function isMarkdownPath(path: string): boolean {
  return /\.(?:md|markdown)$/i.test(path)
}
