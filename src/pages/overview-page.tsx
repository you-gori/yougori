import { lazy, Suspense, useCallback, useMemo, useState } from "react"
import { EnvironmentGraph } from "@/components/environment-graph"
import { usePlatform } from "@/context/platform-context"
import { WorkspaceFooter } from "@/components/workspace-footer"
import { PageHeader, PillButton } from "@/components/prompx"
import { useWorkspaceActions } from "@/components/use-workspace-actions"

const loadConnectionDialog = () => import("@/components/dialogs/connection-dialog")
const ConnectionDialog = lazy(async () => ({ default: (await loadConnectionDialog()).ConnectionDialog }))

export function OverviewPage({ onOpenEnvironment, onSelectEnvironment, vaultError }: {
  onOpenEnvironment(environmentId: string): void
  onSelectEnvironment(environmentId: string): void
  vaultError?: string | null
}) {
  const { state } = usePlatform()
  const { create, openModel } = useWorkspaceActions()
  const [graphErrorContainer, setGraphErrorContainer] = useState<HTMLDivElement | null>(null)
  const [connectionOpen, setConnectionOpen] = useState(false)
  const [connectionMounted, setConnectionMounted] = useState(false)
  const [connectionSourceId, setConnectionSourceId] = useState<string | undefined>()
  const [connectionTargetId, setConnectionTargetId] = useState<string | undefined>()
  const environments = useMemo(() => [...(state?.environments ?? []).filter(environment => environment.id !== state?.cliEnvironmentId)].sort((a, b) => new Date(b.lastOpenedAt ?? b.createdAt).getTime() - new Date(a.lastOpenedAt ?? a.createdAt).getTime()), [state?.environments, state?.cliEnvironmentId])
  const runningCount = environments.filter((environment) => environment.status === "running").length

  const openConnection = useCallback((sourceId?: string, targetId?: string) => {
    void loadConnectionDialog()
    setConnectionMounted(true)
    setConnectionSourceId(sourceId)
    setConnectionTargetId(targetId)
    setConnectionOpen(true)
  }, [])

  if (!state) return null

  return (
    <div className="workspace-overview flex flex-col">
      <PageHeader
        title="My computer."
        lead="Private environments on this computer, each with its own files, network and ports."
        actions={<>
          <PillButton tone="dark" data-tour="new-environment" onClick={create}>Add sandbox</PillButton>
          <PillButton tone="light" data-instruction="model-trigger" onClick={openModel}>Run a local model</PillButton>
        </>}
      />
      <div className="relative">
      <div className="absolute inset-x-0 bottom-full flex h-8 items-center empty:hidden sm:h-10 [&>*]:w-full" ref={setGraphErrorContainer} />

      </div>

      <section aria-label="Environments workspace">
        <EnvironmentGraph connections={state.connections} environments={environments} errorContainer={graphErrorContainer} onConnect={openConnection} onOpen={onOpenEnvironment} onSelect={onSelectEnvironment} vaultError={vaultError} footer={() =>
          <WorkspaceFooter
            status={<span className="workspace-footer-running" title={`${runningCount} running · ${environments.length - runningCount} not running`}><i aria-hidden="true" data-active={runningCount > 0} /><strong>{runningCount}</strong> running<span className="sr-only"> · {environments.length - runningCount} not running</span></span>}
          />
        } />
      </section>

      {connectionMounted ? (
        <Suspense fallback={null}>
          <ConnectionDialog initialSourceId={connectionSourceId} initialTargetId={connectionTargetId} onOpenChange={setConnectionOpen} open={connectionOpen} />
        </Suspense>
      ) : null}
    </div>
  )
}
