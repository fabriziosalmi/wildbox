'use client'

/**
 * A tool's output, shown as it came: objects as key/value tables, arrays as
 * lists, scalars as text. Nothing is named, renamed or added, so every tool's
 * output reads the same way and a field the tool did not return is simply
 * not there.
 *
 * Every value is rendered as React text, never as HTML, and a URL in the
 * output is plain text, not a link: tool output describes targets that may be
 * hostile.
 */
import { useState } from 'react'
import { Check, Copy, Download } from 'lucide-react'
import { Button } from '@/components/ui/button'

/** Nested deeper than this, a value is shown as JSON text. */
const MAX_DEPTH = 6
/** Items shown per array; the rest are in the raw JSON. */
const MAX_ITEMS = 200

type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

function Scalar({ value }: { value: null | boolean | number | string }) {
  if (value === null) return <span className="text-muted-foreground">null</span>
  if (typeof value === 'string') {
    if (value === '') return <span className="text-muted-foreground">(empty string)</span>
    return <span className="whitespace-pre-wrap break-all">{value}</span>
  }
  return <span className="font-mono">{String(value)}</span>
}

function More({ hidden }: { hidden: number }) {
  if (hidden <= 0) return null
  return <p className="text-xs text-muted-foreground">{hidden} more in the raw JSON</p>
}

export function ValueView({ value, depth = 0 }: { value: unknown; depth?: number }) {
  const v = value as Json
  if (v === null || typeof v !== 'object') {
    if (v === undefined) return <span className="text-muted-foreground">undefined</span>
    return <Scalar value={v} />
  }
  if (depth >= MAX_DEPTH) {
    return (
      <pre className="whitespace-pre-wrap break-all font-mono text-xs">
        {JSON.stringify(v, null, 2)}
      </pre>
    )
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="text-muted-foreground">(empty list)</span>
    const shown = v.slice(0, MAX_ITEMS)
    const allScalars = shown.every(item => item === null || typeof item !== 'object')
    return (
      <div className="space-y-1">
        {allScalars ? (
          <ul className="list-inside list-disc space-y-0.5">
            {shown.map((item, i) => (
              <li key={i}>
                <ValueView value={item} depth={depth + 1} />
              </li>
            ))}
          </ul>
        ) : (
          <ol className="space-y-2">
            {shown.map((item, i) => (
              <li key={i} className="rounded border border-border p-2">
                <p className="mb-1 text-xs text-muted-foreground">#{i + 1}</p>
                <ValueView value={item} depth={depth + 1} />
              </li>
            ))}
          </ol>
        )}
        <More hidden={v.length - shown.length} />
      </div>
    )
  }
  const keys = Object.keys(v)
  if (keys.length === 0) return <span className="text-muted-foreground">(empty object)</span>
  return (
    <table className="w-full border-collapse text-sm">
      <tbody>
        {keys.map(key => (
          <tr key={key} className="border-b border-border align-top last:border-b-0">
            <th
              scope="row"
              className="w-1/4 whitespace-nowrap py-1 pr-3 text-left font-mono text-xs font-medium text-muted-foreground"
            >
              {key}
            </th>
            <td className="py-1" data-key={key}>
              <ValueView value={v[key]} depth={depth + 1} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** Copies text, and says so; says so too when the browser refuses. */
export function CopyButton({
  text,
  label,
  testId,
}: {
  text: string
  label: string
  testId?: string
}) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setState('copied')
    } catch {
      setState('failed')
    }
    setTimeout(() => setState('idle'), 2000)
  }
  return (
    <Button type="button" variant="outline" size="sm" onClick={copy} data-testid={testId}>
      {state === 'copied' ? <Check className="mr-1 h-3 w-3" /> : <Copy className="mr-1 h-3 w-3" />}
      {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}
    </Button>
  )
}

/** Saves a value as a .json file. */
export function DownloadJsonButton({ value, filename }: { value: unknown; filename: string }) {
  const download = () => {
    const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <Button type="button" variant="outline" size="sm" onClick={download}>
      <Download className="mr-1 h-3 w-3" />
      Download JSON
    </Button>
  )
}

/** The value as indented JSON, collapsed until opened. */
export function RawJson({ value, open = false }: { value: unknown; open?: boolean }) {
  return (
    <details open={open} className="rounded border border-border">
      <summary className="cursor-pointer select-none px-3 py-2 text-sm font-medium">
        Raw JSON
      </summary>
      <pre
        data-testid="result-raw"
        className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-all border-t border-border bg-muted/50 p-3 font-mono text-xs"
      >
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  )
}
