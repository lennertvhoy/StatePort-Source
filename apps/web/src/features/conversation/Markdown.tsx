/**
 * Markdown — sanitized assistant-message rendering (conversation.md).
 * react-markdown + remark-gfm + rehype-sanitize; raw HTML is never rendered.
 * Code blocks sit on --bg-sunken with a language tag + copy affordance.
 */
import { memo } from 'react'
import type { ReactNode } from 'react'
import ReactMarkdown from 'react-markdown'
import rehypeSanitize from 'rehype-sanitize'
import remarkGfm from 'remark-gfm'

import { CopyButton } from '@/components'
import { cn } from '@/lib/utils'

import { safeMarkdownUrl } from './markdownLinks'

function extractText(node: ReactNode): string {
  if (typeof node === 'string') return node
  if (Array.isArray(node)) return node.map(extractText).join('')
  if (node && typeof node === 'object' && 'props' in node) {
    return extractText((node as { props: { children?: ReactNode } }).props.children)
  }
  return ''
}

/** Block code: sunken well, mono, language tag + copy. */
function PreBlock({ children }: { children?: ReactNode }) {
  const codeEl = Array.isArray(children) ? children[0] : children
  const className =
    codeEl && typeof codeEl === 'object' && 'props' in codeEl
      ? String((codeEl as { props: { className?: string } }).props.className ?? '')
      : ''
  const language = /language-(\w+)/.exec(className)?.[1] ?? ''
  const text = extractText(children).replace(/\n$/, '')
  return (
    <div className="group/code relative my-2 overflow-hidden rounded-sm border border-border bg-sunken">
      <div className="flex h-7 items-center justify-between border-b border-border px-2.5">
        <span className="font-mono text-xs text-foreground-tertiary">{language || 'code'}</span>
        <CopyButton text={text} label="Copy code" className="opacity-0 transition-opacity duration-instant focus-visible:opacity-100 group-hover/code:opacity-100" />
      </div>
      <pre className="overflow-x-auto p-2.5 font-mono text-code text-foreground">{children}</pre>
    </div>
  )
}

export const Markdown = memo(function Markdown({
  content,
  className,
  variant = 'conversation',
}: {
  content: string
  className?: string
  /** Conversation contains headings; document previews preserve their outline. */
  variant?: 'conversation' | 'document'
}) {
  return (
    <div className={cn('markdown-body text-sm text-foreground', className)} data-testid="markdown">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeSanitize]}
        urlTransform={safeMarkdownUrl}
        components={{
          pre: ({ children }) => <PreBlock>{children}</PreBlock>,
          code: ({ className: codeClass, children, ...props }) => {
            // Block code renders inside our PreBlock; inline code gets a subtle chip.
            const isBlock = /language-/.test(codeClass ?? '')
            if (isBlock) {
              return (
                <code className={codeClass} {...props}>
                  {children}
                </code>
              )
            }
            return (
              <code className="rounded-xs bg-surface-2 px-1 py-0.5 font-mono text-[0.92em] text-foreground" {...props}>
                {children}
              </code>
            )
          },
          a: ({ children, href }) => {
            const safeHref = href ? safeMarkdownUrl(href) : ''
            return safeHref ? (
              <a href={safeHref} target="_blank" rel="noreferrer noopener" className="text-accent underline underline-offset-2">
                {children}
              </a>
            ) : (
              <span>{children}</span>
            )
          },
          p: ({ children }) => <p className="my-2 leading-relaxed first:mt-0 last:mb-0">{children}</p>,
          ul: ({ children }) => <ul className="my-2 list-disc pl-5 leading-relaxed">{children}</ul>,
          ol: ({ children }) => <ol className="my-2 list-decimal pl-5 leading-relaxed">{children}</ol>,
          li: ({ children }) => <li className="my-0.5">{children}</li>,
          blockquote: ({ children }) => (
            <blockquote className="my-2 border-l-2 border-border-strong pl-3 text-foreground-secondary">{children}</blockquote>
          ),
          h1: ({ children }) =>
            variant === 'document' ? (
              <h1 className="mb-1 mt-3 text-xl font-semibold first:mt-0">{children}</h1>
            ) : (
              <h3 className="mb-1 mt-3 text-md font-semibold first:mt-0">{children}</h3>
            ),
          h2: ({ children }) =>
            variant === 'document' ? (
              <h2 className="mb-1 mt-3 text-lg font-semibold first:mt-0">{children}</h2>
            ) : (
              <h3 className="mb-1 mt-3 text-md font-semibold first:mt-0">{children}</h3>
            ),
          h3: ({ children }) =>
            variant === 'document' ? (
              <h3 className="mb-1 mt-3 text-md font-semibold first:mt-0">{children}</h3>
            ) : (
              <h4 className="mb-1 mt-3 text-sm font-semibold first:mt-0">{children}</h4>
            ),
          h4: ({ children }) =>
            variant === 'document' ? (
              <h4 className="mb-1 mt-2 text-sm font-semibold first:mt-0">{children}</h4>
            ) : (
              <h5 className="mb-1 mt-2 text-sm font-semibold first:mt-0">{children}</h5>
            ),
          table: ({ children }) => (
            <div className="my-2 overflow-x-auto rounded-sm border border-border">
              <table className="w-full border-collapse text-sm">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="border-b border-border bg-surface-2 px-2.5 py-1.5 text-left font-medium">{children}</th>
          ),
          td: ({ children }) => <td className="border-b border-border px-2.5 py-1.5 last:border-b-0">{children}</td>,
          hr: () => <hr className="my-3 border-border" />,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  )
})
