import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react"
import { EnvironmentGraph } from "@/components/environment-graph"
import { usePlatform } from "@/context/platform-context"
import { WorkspaceFooter } from "@/components/workspace-footer"
import { PageHeader, PillButton } from "@/components/prompx"
import { useWorkspaceActions } from "@/components/use-workspace-actions"
import { useSandboxVms } from "@/components/sandbox-vm/sandbox-vm-context"
import { sandboxVmEnvironments } from "@/components/sandbox-vm/sandbox-vm-environments"
import { Dialog, DialogPopup, DialogTitle, DialogDescription, DialogPanel } from "@/components/ui/dialog"
import { SandboxVmPanel } from "@/components/sandbox-vm/sandbox-vm-panel"
import { SandboxConfiguration } from "@/components/sandbox-configuration"
import { useSetupBuilder } from "@/components/setups/builder-context"

const loadConnectionDialog = () => import("@/components/dialogs/connection-dialog")
const ConnectionDialog = lazy(async () => ({ default: (await loadConnectionDialog()).ConnectionDialog }))

export function OverviewPage({ onOpenEnvironment, onSelectEnvironment, vaultError }: {
  onOpenEnvironment(environmentId: string): void
  onSelectEnvironment(environmentId: string): void
  vaultError?: string | null
}) {
  const { state } = usePlatform()
  const builder = useSetupBuilder()
  const vmFeed = useSandboxVms()
  const sandboxVms = useMemo(() => sandboxVmEnvironments(vmFeed.status), [vmFeed.status])
  const [selectedVm, setSelectedVm] = useState<string | null>(null)
  const [configureIds, setConfigureIds] = useState<string[]>([])
  useEffect(() => {
    const show = (event: Event) => { const id = (event as CustomEvent<unknown>).detail; if (typeof id === "string") setSelectedVm(id) }
    window.addEventListener("yougori-open-sandbox-vm", show)
    return () => window.removeEventListener("yougori-open-sandbox-vm", show)
  }, [])
  const { create, openModel } = useWorkspaceActions()
  const [graphErrorContainer, setGraphErrorContainer] = useState<HTMLDivElement | null>(null)
  const [connectionOpen, setConnectionOpen] = useState(false)
  const [connectionMounted, setConnectionMounted] = useState(false)
  const [connectionSourceId, setConnectionSourceId] = useState<string | undefined>()
  const [connectionTargetId, setConnectionTargetId] = useState<string | undefined>()
  const environments = useMemo(() => [...(state?.environments ?? []).filter(environment => environment.id !== state?.cliEnvironmentId)].sort((a, b) => new Date(b.lastOpenedAt ?? b.createdAt).getTime() - new Date(a.lastOpenedAt ?? a.createdAt).getTime()), [state?.environments, state?.cliEnvironmentId])
  const runningCount = [...environments, ...sandboxVms].filter((environment) => environment.status === "running").length
  const totalCount = environments.length + sandboxVms.length

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
          <PillButton tone="dark" data-tour="new-environment" onClick={create}>New environment</PillButton>
          <PillButton tone="light" data-instruction="model-trigger" onClick={openModel}>Run a local model</PillButton>
        </>}
      />
      <div className="relative">
      <div className="absolute inset-x-0 bottom-full flex h-8 items-center empty:hidden sm:h-10 [&>*]:w-full" ref={setGraphErrorContainer} />

      </div>

      <section aria-label="Environments workspace">
        <EnvironmentGraph onCreateTemplate={ids => builder.open({ mode: "create", entry: "environments", environments: ids })} sandboxVms={sandboxVms} onOpenSandboxVm={setSelectedVm} onConfigureSelection={setConfigureIds} connections={state.connections} environments={environments} errorContainer={graphErrorContainer} onConnect={openConnection} onOpen={onOpenEnvironment} onSelect={onSelectEnvironment} vaultError={vaultError} footer={() =>
          <WorkspaceFooter
            status={<span className="workspace-footer-running" title={`${runningCount} running · ${totalCount - runningCount} not running`}><i aria-hidden="true" data-active={runningCount > 0} /><strong>{runningCount}</strong> running<span className="sr-only"> · {totalCount - runningCount} not running</span></span>}
          />
        } />
      </section>

      {vmFeed.error ? <p role="status" className="mt-2 text-xs text-muted-foreground">{vmFeed.error} <button type="button" className="underline" onClick={() => void vmFeed.refresh()}>Retry</button></p> : null}
      <Dialog open={selectedVm !== null} onOpenChange={open => { if (!open) setSelectedVm(null) }}>
        <DialogPopup className="max-w-4xl">
          <DialogTitle>Sandbox VM</DialogTitle>
          <DialogDescription>{selectedVm}</DialogDescription>
          <DialogPanel>{selectedVm ? <SandboxVmPanel key={selectedVm} sandbox={selectedVm} /> : null}</DialogPanel>
        </DialogPopup>
      </Dialog>
      {configureIds.length ? <SandboxConfiguration environments={[...environments, ...sandboxVms].filter(environment => configureIds.includes(environment.id))} onClose={() => setConfigureIds([])} onConfigureEnvironment={onSelectEnvironment} onOpenEnvironment={onOpenEnvironment} /> : null}

      {connectionMounted ? (
        <Suspense fallback={null}>
          <ConnectionDialog initialSourceId={connectionSourceId} initialTargetId={connectionTargetId} onOpenChange={setConnectionOpen} open={connectionOpen} />
        </Suspense>
      ) : null}
    </div>
  )
}
