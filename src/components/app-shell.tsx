import { RemoteAccessStatus } from "@/components/remote-access-status"
import { useEffect, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { startFirstLaunchInstructions } from "@/lib/instructions-tour"
import "@/components/dashboard-actions.css"
import { PreferencesDialog } from "@/components/dialogs/preferences-dialog"
import { ReleaseUpdateNotice } from "@/components/release-update"
import { EnvironmentDownloadStatus } from "@/components/environment-download-status"
import { PersonalVault } from "@/components/personal-vault"
import { ModelWorkspace } from "@/components/model-workspace"
import { NetworkPanel } from "@/components/network-panel"
import yougoriLogo from "../../Yoo-app.png"
import { WindowControls } from "@/components/shared/window-controls"
import "@/components/workspace-design.css"


function Brand() {
  return (
    <div data-tauri-drag-region aria-label="Yougori" className="flex select-none items-center gap-3 [&>*]:pointer-events-none">
      <span className="flex size-9 shrink-0 items-center justify-center overflow-hidden">
        <img src={yougoriLogo} alt="" draggable={false} className="size-full scale-[1.07] object-contain" />
      </span>
      <span className="startup-brand workspace-brand-text">Yougori</span>
    </div>
  )
}

export function AppShell({ onCreate, children, vaultError }: {
  onCreate(): void
  children: ReactNode
  vaultError?: string | null
}) {
  useEffect(() => { startFirstLaunchInstructions() }, [])
  return (
    <div className="workspace-app isolate min-h-screen bg-background text-foreground">
      <header data-tauri-drag-region className="workspace-header sticky top-0 z-20 border-b bg-background">
        <div data-tauri-drag-region className="mx-auto flex min-h-16 w-full flex-wrap items-center gap-x-4 gap-y-3 px-5 py-3">
          <Brand />
          <div data-tauri-drag-region className="min-w-0 flex-1 self-stretch" aria-hidden="true" />
          <div className="dashboard-actions ml-auto flex flex-wrap items-center justify-end gap-2" role="group" aria-label="Dashboard actions">
            <RemoteAccessStatus />
            <EnvironmentDownloadStatus />
            <div className="dashboard-action-group">
              <PersonalVault startupError={vaultError} />
              <ModelWorkspace />
              <NetworkPanel />
              <PreferencesDialog />
            </div>
            <Button data-tour="new-environment" aria-label="New environment" title="New environment" className="dashboard-action dashboard-action-primary" onClick={onCreate} size="sm" type="button">
              <span>New environment</span>
            </Button>
            <WindowControls />
          </div>
        </div>
      </header>
      <main className="workspace-main mx-auto min-h-[calc(100vh-64px)] w-full min-w-0 px-5 py-8 sm:px-6 sm:py-10">
        <ReleaseUpdateNotice />
        {children}
      </main>

    </div>
  )
}
