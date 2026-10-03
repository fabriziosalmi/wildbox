'use client'

import Link from 'next/link'
import { Activity, Book, ChevronRight, Info, Loader2 } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useResponderPlaybooks } from '@/hooks/use-responder-playbooks'

/*
 * Everything on this page comes from the responder's playbook list. The page
 * used to show run statistics too -- 45 runs, 2 running, 87% success and three
 * recent runs -- which were constants: the responder has no endpoint that
 * lists or counts runs, so there is nothing real to show there.
 */
export default function ResponsePage() {
  const { playbooks, total, isLoading, error, refetch } = useResponderPlaybooks()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Response & Automation</h1>
          <p className="text-muted-foreground">
            Incident response playbooks and automated security workflows
          </p>
        </div>
        <Button onClick={() => refetch()} variant="outline" size="sm">
          Refresh
        </Button>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Playbooks: the responder's answer, or why there is none */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Book className="h-5 w-5 text-blue-600" />
              Playbooks
            </CardTitle>
            <CardDescription>Automated response workflows the responder has loaded</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between text-sm">
              <span>Available playbooks</span>
              <span className="text-2xl font-bold" data-testid="response-playbook-count">
                {isLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : error ? (
                  'Unavailable'
                ) : (
                  total
                )}
              </span>
            </div>

            {error ? (
              <p className="text-sm text-muted-foreground">
                The responder could not be reached: {error.message}
              </p>
            ) : (
              playbooks.length > 0 && (
                <ul className="space-y-1 text-sm" data-testid="response-playbook-list">
                  {playbooks.map(playbook => (
                    <li
                      key={playbook.playbook_id}
                      className="flex items-center justify-between gap-2"
                      data-playbook-id={playbook.playbook_id}
                    >
                      <span className="truncate">{playbook.name}</span>
                      <Badge variant="outline" className="shrink-0">
                        {playbook.steps_count} steps
                      </Badge>
                    </li>
                  ))}
                </ul>
              )
            )}

            <Link href="/response/playbooks">
              <Button className="w-full">
                Manage Playbooks
                <ChevronRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>

        {/* Runs: no counts, because the responder reports none */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-green-600" />
              Runs
            </CardTitle>
            <CardDescription>Status of the playbook runs started here</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div
              className="flex items-start gap-3 rounded-md border p-3 text-sm"
              data-testid="response-run-stats-unavailable"
            >
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-blue-600" />
              <p>
                Run statistics are not available: the responder does not list or count runs, so
                there are no totals, success rates or recent runs to show.
              </p>
            </div>
            <Link href="/response/runs">
              <Button className="w-full" variant="outline">
                View Runs
                <ChevronRight className="ml-2 h-4 w-4" />
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
