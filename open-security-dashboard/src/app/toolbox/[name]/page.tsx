'use client'

import Link from 'next/link'
import { useParams } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, ArrowLeft } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { MainLayout } from '@/components/main-layout'
import { ToolRunner } from '@/components/toolbox/tool-runner'
import type { ApiError } from '@/lib/api-client'
import { getToolInfo, type ToolInfo } from '@/lib/tools-api'

function safeDecode(segment: string): string {
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

/**
 * One tool: its description, a form generated from its input schema, and the
 * run (#585). Replaces the tools service's standalone page, removed in #581.
 */
export default function ToolPage() {
  const params = useParams<{ name: string }>()
  const name = safeDecode(params.name)

  const info = useQuery<ToolInfo, ApiError>({
    queryKey: ['tool-info', name],
    queryFn: () => getToolInfo(name),
    // A tool that does not exist will not start existing on a retry.
    retry: (count, error) => error.status !== 404 && count < 2,
    refetchOnWindowFocus: false,
  })

  return (
    <MainLayout>
      <div className="space-y-6">
        <Button asChild variant="ghost" size="sm" className="-ml-2">
          <Link href="/toolbox">
            <ArrowLeft className="mr-1 h-4 w-4" />
            Toolbox
          </Link>
        </Button>

        {info.isLoading && (
          <div className="space-y-3" aria-busy="true">
            <div className="h-8 w-1/3 animate-pulse rounded bg-muted" />
            <div className="h-4 w-2/3 animate-pulse rounded bg-muted" />
            <div className="h-64 animate-pulse rounded bg-muted" />
          </div>
        )}

        {info.isError && (
          <Card role="alert" data-testid="tool-info-error">
            <CardContent className="py-8 text-center">
              <AlertCircle className="mx-auto mb-4 h-12 w-12 text-red-500" />
              <h1 className="mb-2 text-lg font-semibold">
                {info.error.status === 404 ? `No tool named "${name}"` : 'Failed to load the tool'}
              </h1>
              <p className="mb-4 text-muted-foreground">{info.error.message}</p>
              {info.error.status !== 404 && (
                <Button variant="outline" onClick={() => info.refetch()} disabled={info.isFetching}>
                  Try Again
                </Button>
              )}
            </CardContent>
          </Card>
        )}

        {info.data && (
          <>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-3xl font-bold" data-testid="tool-title">
                  {info.data.display_name || info.data.name}
                </h1>
                {info.data.category && <Badge variant="secondary">{info.data.category}</Badge>}
                {info.data.version && <Badge variant="outline">v{info.data.version}</Badge>}
              </div>
              {info.data.description && (
                <p className="mt-1 text-muted-foreground">{info.data.description}</p>
              )}
              <p className="mt-1 text-xs text-muted-foreground">
                <code>{info.data.name}</code>
                {info.data.author && <> &middot; by {info.data.author}</>}
              </p>
            </div>
            <ToolRunner key={info.data.name} tool={info.data} />
          </>
        )}
      </div>
    </MainLayout>
  )
}
