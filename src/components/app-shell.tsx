import { RemoteAccessStatus } from "@/components/remote-access-status"
import { PreferencesDialog } from "@/components/dialogs/preferences-dialog"
import { useEffect, useMemo, type ReactNode } from "react"
import { startFirstLaunchInstructions } from "@/lib/instructions-tour"
import "@/components/dashboard-actions.css"
import { ReleaseUpdateNotice } from "@/components/release-update"
import { EnvironmentDownloadStatus } from "@/components/environment-download-status"
import yougoriLogo from "../../Yoo-app.png"
import { WindowControls } from "@/components/shared/window-controls"
import { usePlatform } from "@/context/platform-context"
import { useWorkspaceActions } from "@/components/use-workspace-actions"
import { useAccessApprovalNotices, useAccessStatus } from "@/components/use-access-status"
import { GRID_NAME, gridRealms, gridsHint, type GridRealm } from "@/lib/grid-realm"
import { NavIcon } from "@/components/app-nav-icons"
import type { GridFocus } from "@/lib/grid-link"
import "@/components/workspace-design.css"
import "@/components/prompx.css"
import "@/components/grids.css"

export type AppPage = "sandboxes" | "grids" | "hub"

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

/** One line under each name, so its state reads at a glance. The grids' own lines are the ones
 *  they have always had, built once in `@/lib/grid-realm` and read here and by the Grids area. */
function useSectionHints(): { sandboxes: string; grids: string; realms: GridRealm[] } {
  const { state } = usePlatform()
  const { grid, workers, desks } = useWorkspaceActions()
  const sandboxes = (state?.environments ?? []).filter(environment => environment.id !== state?.cliEnvironmentId)
  const running = sandboxes.filter(environment => environment.status === "running").length
  const { status: access } = useAccessStatus(15_000)
  useAccessApprovalNotices(access)
  const thisComputer = state?.host.hostname?.trim() || "this computer"
  const realms = useMemo(
    () => gridRealms({ grid, desks, access, workers, thisComputer }),
    [grid, desks, access, workers, thisComputer],
  )
  return {
    sandboxes: sandboxes.length ? `${running} running · ${sandboxes.length} in all` : "None yet",
    grids: gridsHint(realms),
    realms,
  }
}

export function AppShell({ page, focus, onNavigate, children }: {
  page: AppPage
  focus: GridFocus
  onNavigate(page: AppPage, focus?: GridFocus): void
  children: ReactNode
}) {
  useEffect(() => { startFirstLaunchInstructions() }, [])
  const hints = useSectionHints()
  return (
    <div className="workspace-app app-frame isolate bg-background text-foreground">
      <aside className="app-sidebar">
        <div data-tauri-drag-region className="app-sidebar-brand"><Brand /></div>
        <nav className="app-nav" aria-label="Sections">
          <button
            type="button"
            className="app-nav-item"
            aria-label="My computer"
            aria-describedby="app-nav-hint-sandboxes"
            aria-current={page === "sandboxes" ? "page" : undefined}
            onClick={() => onNavigate("sandboxes")}
          >
            <NavIcon name="computer" />
            <span className="app-nav-label">My computer</span>
            <span className="app-nav-hint" id="app-nav-hint-sandboxes">{hints.sandboxes}</span>
          </button>
          <button
            type="button"
            className="app-nav-item"
            aria-label="Grids"
            aria-describedby="app-nav-hint-grids"
            aria-current={page === "grids" && !focus ? "page" : undefined}
            onClick={() => onNavigate("grids", null)}
          >
            <NavIcon name="grids" />
            <span className="app-nav-label">Grids</span>
            <span className="app-nav-hint" id="app-nav-hint-grids">{hints.grids}</span>
          </button>
          {/* Each grid keeps its own name under Grids, and its own line, so the way people
              already reach them is the way they still reach them. */}
          {hints.realms.map(realm => (
            <button
              key={realm.key}
              type="button"
              className="app-nav-item app-nav-sub"
              aria-label={GRID_NAME[realm.key]}
              aria-describedby={`app-nav-hint-${realm.key}`}
              aria-current={page === "grids" && focus?.grid === realm.key ? "true" : undefined}
              onClick={() => onNavigate("grids", { kind: "page", grid: realm.key })}
            >
              <NavIcon name={realm.key} />
              <span className="app-nav-label">{GRID_NAME[realm.key]}</span>
              <span className="app-nav-hint" id={`app-nav-hint-${realm.key}`}>{realm.hint}</span>
            </button>
          ))}
          <button
            type="button"
            className="app-nav-item"
            aria-label="Hub"
            aria-describedby="app-nav-hint-hub"
            aria-current={page === "hub" ? "page" : undefined}
            onClick={() => onNavigate("hub")}
          >
            <NavIcon name="hub" />
            <span className="app-nav-label">Hub</span>
            <span className="app-nav-hint" id="app-nav-hint-hub">Templates and tools</span>
          </button>
        </nav>
      </aside>
      <div className="app-main">
        <header data-tauri-drag-region className="workspace-header app-topbar">
          <div data-tauri-drag-region className="flex w-full flex-wrap items-center gap-x-4 gap-y-3 px-6">
            <div data-tauri-drag-region className="min-w-0 flex-1 self-stretch" aria-hidden="true" />
            <div className="dashboard-actions ml-auto flex flex-wrap items-center justify-end gap-2" role="group" aria-label="Dashboard actions">
              <RemoteAccessStatus />
              <EnvironmentDownloadStatus />
              <PreferencesDialog />
              <WindowControls />
            </div>
          </div>
        </header>
        <main className="workspace-main w-full min-w-0 px-6 pt-1">
          <ReleaseUpdateNotice />
          {children}
        </main>
      </div>
    </div>
  )
}
