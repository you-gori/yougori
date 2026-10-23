import { lazy, Suspense, useCallback, useEffect, useState } from "react"
import { AppCloseDialog } from "@/components/app-close-dialog"
import { AppShell, type AppPage } from "@/components/app-shell"
import { WorkspaceActionsProvider } from "@/components/workspace-actions"
import { LoadingScreen } from "@/components/shared/loading-screen"
import { AnchoredToastProvider, toastManager, ToastProvider } from "@/components/ui/toast"
import { PlatformProvider, usePlatform } from "@/context/platform-context"
import { platformApi } from "@/api/platform-api"
import { useVaultStartup } from "@/components/use-vault-startup"
import { environmentIdFromSearch } from "@/lib/environment-window"
import { gridFocusFromSearch, type GridFocus } from "@/lib/grid-link"
import type { EnvironmentKind } from "@/types/platform"
import { prepareTourWindow, tourWindowFailed, useInstructionsTour } from "@/lib/instructions-tour"
import { resolveAppearance } from "@/lib/appearance"

const loadCreateEnvironmentDialog = () => import("@/components/dialogs/create-environment-dialog")
const loadEnvironmentDetailSheet = () => import("@/components/environment-detail-sheet")
const loadGuestDesktop = () => import("@/components/guest-desktop")
const loadOverviewPage = () => import("@/pages/overview-page")

const CreateEnvironmentDialog = lazy(async () => ({ default: (await loadCreateEnvironmentDialog()).CreateEnvironmentDialog }))
const EnvironmentDetailSheet = lazy(async () => ({ default: (await loadEnvironmentDetailSheet()).EnvironmentDetailSheet }))
const GuestDesktop = lazy(async () => ({ default: (await loadGuestDesktop()).GuestDesktop }))
const GuestWorkspace = lazy(async () => ({ default: (await import("@/components/guest-workspace")).GuestWorkspace }))
const OverviewPage = lazy(async () => ({ default: (await loadOverviewPage()).OverviewPage }))
const GridsPage = lazy(async () => ({ default: (await import("@/pages/grids-page")).GridsPage }))
const HubPage = lazy(async () => ({ default: (await import("@/pages/hub-page")).HubPage }))
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
  // An address may name a grid, in its own word, and the four older spellings still work.
  const [focus, setFocus] = useState<GridFocus>(() => gridFocusFromSearch(window.location.search))
  const [page, setPage] = useState<AppPage>(() => gridFocusFromSearch(window.location.search) ? "grids" : "sandboxes")
  const navigate = useCallback((next: AppPage, where?: GridFocus) => {
    setPage(next)
    if (next === "grids") setFocus(where ?? null)
    else setFocus(null)
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
      <Suspense fallback={<LoadingScreen message="Loading your environments…" onRetry={() => window.location.reload()} />}>
        <WorkspaceActionsProvider onCreate={createSandbox}>
          <AppShell page={shown} focus={shown === "grids" ? focus : null} onNavigate={navigate}>
            {shown === "grids" ? <GridsPage focus={focus} onFocus={setFocus} /> : shown === "hub" ? <HubPage /> : (
              <OverviewPage
                onOpenEnvironment={openEnvironment}
                onSelectEnvironment={selectEnvironment}
                vaultError={vaultStartup.error}
              />
            )}
          </AppShell>
        </WorkspaceActionsProvider>
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
