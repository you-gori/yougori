import { PillButton } from "@/components/prompx"
import { RemoteAccessStatus } from "@/components/remote-access-status"
import { PreferencesDialog } from "@/components/dialogs/preferences-dialog"
import { useEffect, type ReactNode } from "react"
import { startFirstLaunchInstructions } from "@/lib/instructions-tour"
import "@/components/dashboard-actions.css"
import { ReleaseUpdateNotice } from "@/components/release-update"
import { EnvironmentDownloadStatus } from "@/components/environment-download-status"
import yougoriLogo from "../../Yoo-app.png"
import { WindowControls } from "@/components/shared/window-controls"
import "@/components/workspace-design.css"
import "@/components/prompx.css"
import "@/components/setups/setups.css"

export type AppPage = "sandboxes" | "hub" | "setups"

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

export function AppShell({ onOpenHub, children }: {
  onOpenHub(): void
  children: ReactNode
}) {
  useEffect(() => { startFirstLaunchInstructions() }, [])
  return (
    <div className="workspace-app app-frame isolate bg-background text-foreground">
      <div className="app-main">
        <header data-tauri-drag-region className="workspace-header app-topbar">
          <div data-tauri-drag-region className="flex w-full flex-wrap items-center gap-x-4 gap-y-3 px-6">
            <Brand />
            <div className="dashboard-actions ml-auto flex flex-wrap items-center justify-end gap-2" role="group" aria-label="Dashboard actions">
              <PillButton tone="dark" onClick={onOpenHub} aria-haspopup="dialog">Hub</PillButton>
              <RemoteAccessStatus />
              <EnvironmentDownloadStatus />
              <PreferencesDialog />
              <WindowControls />
            </div>
          </div>
        </header>
        <main className="workspace-main workspace-home w-full min-w-0 px-6 pt-1">
          <ReleaseUpdateNotice />

          {children}
        </main>
      </div>
    </div>
  )
}
