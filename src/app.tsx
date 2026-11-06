import { lazy, Suspense, useCallback, useEffect, useState } from "react"
import { AppCloseDialog } from "@/components/app-close-dialog"
import { SandboxVmProvider } from "@/components/sandbox-vm/sandbox-vm-provider"
import { WorkspacePage } from "@/pages/workspace-page"
import { HostAccessRequests } from "@/components/sandbox-vm/host-access-requests"
import { AppShell, type AppPage } from "@/components/app-shell"
import { WorkspaceActionsProvider } from "@/components/workspace-actions"
import { LoadingScreen } from "@/components/shared/loading-screen"
import { AnchoredToastProvider, toastManager, ToastProvider } from "@/components/ui/toast"
import { PlatformProvider, usePlatform } from "@/context/platform-context"
import { platformApi } from "@/api/platform-api"
import { useVaultStartup } from "@/components/use-vault-startup"
import { environmentIdFromSearch } from "@/lib/environment-window"
import { appLocationFromSearch } from "@/components/setups/setup-link"
import { SetupBuilderProvider } from "@/components/setups/setup-builder-provider"
import type { DetailTab } from "@/components/setups/setup-detail"
import type { EnvironmentKind } from "@/types/platform"
import { prepareTourWindow, stopInstructions, tourWindowFailed, useInstructionsTour } from "@/lib/instructions-tour"
import { resolveAppearance } from "@/lib/appearance"

const loadCreateEnvironmentDialog = () => import("@/components/dialogs/create-environment-dialog")
const loadEnvironmentDetailSheet = () => import("@/components/environment-detail-sheet")
const loadGuestDesktop = () => import("@/components/guest-desktop")

const CreateEnvironmentDialog = lazy(async () => ({ default: (await loadCreateEnvironmentDialog()).CreateEnvironmentDialog }))
const EnvironmentDetailSheet = lazy(async () => ({ default: (await loadEnvironmentDetailSheet()).EnvironmentDetailSheet }))
const GuestDesktop = lazy(async () => ({ default: (await loadGuestDesktop()).GuestDesktop }))
const GuestWorkspace = lazy(async () => ({ default: (await import("@/components/guest-workspace")).GuestWorkspace }))
const InstructionsTour = lazy(() => import("@/components/instructions-tour"))

function ThemeSync() {
  const { state } = usePlatform()
  const preference = state?.settings.theme ?? "system"
  const background = state?.settings.customThemeColors?.background
  const surface = state?.settings.customThemeColors?.surface
  const accent = state?.settings.customThemeColors?.accent
  const detail = state?.settings.customThemeColors?.detail

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)")
    const root = document.documentElement
    const colors = background && surface && accent && detail ? { background, surface, accent, detail } : null
    const appearance = resolveAppearance(preference, colors)
    const apply = () => {
      const dark = appearance?.dark ?? (preference === "dark" || (preference === "system" && media.matches))
      root.classList.toggle("dark", dark)
      root.dataset.yougoriTheme = appearance ? preference : dark ? "dark" : "light"
      if (appearance) {
        root.dataset.yougoriPalette = "true"
        for (const [name, value] of Object.entries(appearance.tokens)) root.style.setProperty(name, value)
      } else {
        delete root.dataset.yougoriPalette
      }
      root.style.colorScheme = dark ? "dark" : "light"
      document.querySelector('meta[name="theme-color"]')?.setAttribute("content", appearance?.background ?? (dark ? "#0e0f11" : "#ffffff"))
    }
    apply()
    media.addEventListener("change", apply)
    return () => {
      media.removeEventListener("change", apply)
      if (appearance) for (const name of Object.keys(appearance.tokens)) root.style.removeProperty(name)
      delete root.dataset.yougoriPalette
    }
  }, [preference, background, surface, accent, detail])
  return null
}

function Workspace() {
  const tour = useInstructionsTour()
  const { state, loading, error, openEnvironmentWindow } = usePlatform()
  // Links open discovery or setup details in a popup over the same computer workspace.
  const [linked] = useState(() => appLocationFromSearch(window.location.search))
  const [page, setPage] = useState<AppPage>(linked.page)
  const [highlight, setHighlight] = useState<string | null>(linked.setupId)
  const [highlightTab, setHighlightTab] = useState<DetailTab | undefined>(undefined)
  const navigate = useCallback((next: AppPage) => {
    setPage(next)
    setHighlight(null)
  }, [])
  const showSetups = useCallback((setupId: string | null, tab?: DetailTab) => {
    setPage("setups")
    setHighlight(setupId)
    setHighlightTab(tab)
  }, [])
  const [createOpen, setCreateOpen] = useState(false)
  const [createMounted, setCreateMounted] = useState(false)
  const [createKind, setCreateKind] = useState<EnvironmentKind | undefined>()
  const [detailMounted, setDetailMounted] = useState(false)
  const [detailEnvironmentId, setDetailEnvironmentId] = useState<string | null>(null)
  const [guestEnvironmentId, setGuestEnvironmentId] = useState<string | null>(null)

  const platformReady = !loading && Boolean(state)
  const vaultStartup = useVaultStartup(platformReady)

  const openEnvironment = useCallback((environmentId: string) => {
    const selected = state?.environments.find((item) => item.id === environmentId)
    if (!selected || selected.provider === "nativeSandbox" || selected.kind === "computerBranch") return
    prepareTourWindow(environmentId)
    void (async () => {
      try {
        const openedNativeWindow = await openEnvironmentWindow(environmentId)
        setDetailEnvironmentId(null)
        if (!openedNativeWindow && !("__TAURI_INTERNALS__" in window)) {
          void loadGuestDesktop()
          setGuestEnvironmentId(environmentId)
        }
      } catch (reason) {
        tourWindowFailed(environmentId)
        toastManager.add({
          title: "Couldn’t open environment window",
          description: reason instanceof Error ? reason.message : String(reason),
          type: "error",
        })
      }
    })()
  }, [openEnvironmentWindow, state?.environments])
  const environment = guestEnvironmentId ? state?.environments.find((item) => item.id === guestEnvironmentId) : undefined
  const openCreate = useCallback((kind?: EnvironmentKind) => {
    // Hand off from the old guided container exercise to the current VM creation flow.
    stopInstructions()
    void loadCreateEnvironmentDialog()
    setCreateMounted(true)
    setCreateKind(kind)
    setCreateOpen(true)
  }, [])
  const createSandbox = useCallback(() => openCreate(), [openCreate])
  const selectEnvironment = useCallback((environmentId: string) => {
    void loadEnvironmentDetailSheet()
    setDetailMounted(true)
    setDetailEnvironmentId(environmentId)
  }, [])
  const changeDetailOpen = useCallback((open: boolean) => {
    if (!open) setDetailEnvironmentId(null)
  }, [])

  // The tour walks through the sandbox page, so it is shown while the tour runs.
  const shown: AppPage = tour?.active ? "sandboxes" : page
  if (loading || !state) return <LoadingScreen error={error} onRetry={() => window.location.reload()} />
  if (!vaultStartup.ready) return <><ThemeSync /><LoadingScreen message="Starting your Personal Vault…" error={vaultStartup.error} onRetry={vaultStartup.retry} onContinue={vaultStartup.error ? vaultStartup.continueWithoutVault : undefined} /></>

  return (
    <>
      <ThemeSync />
      <AppCloseDialog />
      <HostAccessRequests />
      <Suspense fallback={<LoadingScreen message="Loading your environments…" onRetry={() => window.location.reload()} />}>
        <SandboxVmProvider>
        <WorkspaceActionsProvider onCreate={createSandbox}>
          <SetupBuilderProvider initial={linked.builder} onShowSetups={showSetups}>
            <AppShell onOpenHub={() => navigate("hub")}>
              <WorkspacePage page={shown} onClosePopup={() => navigate("sandboxes")} highlight={highlight} highlightTab={highlightTab}
                onOpenEnvironment={openEnvironment} onSelectEnvironment={selectEnvironment} vaultError={vaultStartup.error} />
            </AppShell>
          </SetupBuilderProvider>
        </WorkspaceActionsProvider>
        </SandboxVmProvider>
      </Suspense>
      {createMounted ? (
        <Suspense fallback={null}>
          <CreateEnvironmentDialog initialKind={createKind} onOpenChange={setCreateOpen} open={createOpen} />
        </Suspense>
      ) : null}
      {detailMounted ? (
        <Suspense fallback={null}>
          <EnvironmentDetailSheet environmentId={detailEnvironmentId} onOpenEnvironment={openEnvironment} onOpenChange={changeDetailOpen} />
        </Suspense>
      ) : null}
      {environment ? (
        <Suspense fallback={null}>
          <GuestDesktop environment={environment} onClose={() => setGuestEnvironmentId(null)} />
        </Suspense>
      ) : null}
      {tour?.active ? <Suspense fallback={null}><InstructionsTour onCreate={() => openCreate("container")} /></Suspense> : null}
    </>
  )
}

function EnvironmentWindow({ environmentId }: { environmentId: string }) {
  const tour = useInstructionsTour()
  const { state, loading, error } = usePlatform()
  const environment = state?.environments.find((item) => item.id === environmentId)

  useEffect(() => {
    document.title = environment ? `${environment.name} — Yougori` : "Environment — Yougori"
  }, [environment])

  if (loading || !state) return <LoadingScreen error={error} onRetry={() => window.location.reload()} />

  return (
    <Suspense fallback={<LoadingScreen message="Opening your environment…" onRetry={() => window.location.reload()} />}>
      <GuestWorkspace initialEnvironmentId={environmentId} initialAppSessionId={new URLSearchParams(window.location.search).get("guestApp")?.match(/^app-[a-zA-Z0-9-]{1,76}$/)?.[0]} onClose={() => { void platformApi.closeEnvironmentWindow().catch(() => undefined) }} />
      {tour?.active ? <InstructionsTour environmentId={environmentId} /> : null}
    </Suspense>
  )
}

export function App() {
  const environmentId = environmentIdFromSearch(window.location.search)
  return (
    <ToastProvider>
      <AnchoredToastProvider>
        <PlatformProvider pollHostMetrics={!environmentId}>
          {environmentId ? <><ThemeSync /><EnvironmentWindow environmentId={environmentId} /></> : <Workspace />}
        </PlatformProvider>
      </AnchoredToastProvider>
    </ToastProvider>
  )
}
