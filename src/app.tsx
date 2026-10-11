import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react"
import { AppCloseDialog } from "@/components/app-close-dialog"
import { AppShell } from "@/components/app-shell"
import { LoadingScreen } from "@/components/shared/loading-screen"
import { AnchoredToastProvider, toastManager, ToastProvider } from "@/components/ui/toast"
import { PlatformProvider, usePlatform } from "@/context/platform-context"
import { platformApi } from "@/api/platform-api"
import { startHostCli } from "@/api/host-terminal-api"
import { useVaultStartup } from "@/components/use-vault-startup"
import { environmentIdFromSearch } from "@/lib/environment-window"
import type { EnvironmentKind } from "@/types/platform"
import { prepareTourWindow, tourWindowFailed, useInstructionsTour } from "@/lib/instructions-tour"
import { resolveAppearance } from "@/lib/appearance"

// Startup keeps waiting after this; it only offers to open the app without the CLI.
const CLI_STARTUP_NOTICE_MS = 20_000

const loadCreateEnvironmentDialog = () => import("@/components/dialogs/create-environment-dialog")
const loadEnvironmentDetailSheet = () => import("@/components/environment-detail-sheet")
const loadGuestDesktop = () => import("@/components/guest-desktop")
const loadOverviewPage = () => import("@/pages/overview-page")

const CreateEnvironmentDialog = lazy(async () => ({ default: (await loadCreateEnvironmentDialog()).CreateEnvironmentDialog }))
const EnvironmentDetailSheet = lazy(async () => ({ default: (await loadEnvironmentDetailSheet()).EnvironmentDetailSheet }))
const GuestDesktop = lazy(async () => ({ default: (await loadGuestDesktop()).GuestDesktop }))
const GuestWorkspace = lazy(async () => ({ default: (await import("@/components/guest-workspace")).GuestWorkspace }))
const OverviewPage = lazy(async () => ({ default: (await loadOverviewPage()).OverviewPage }))
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
      document.querySelector('meta[name="theme-color"]')?.setAttribute("content", appearance?.background ?? (dark ? "#0e0f10" : "#f7f7f6"))
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
  const [createOpen, setCreateOpen] = useState(false)
  const [createMounted, setCreateMounted] = useState(false)
  const [createKind, setCreateKind] = useState<EnvironmentKind | undefined>()
  const [detailMounted, setDetailMounted] = useState(false)
  const [detailEnvironmentId, setDetailEnvironmentId] = useState<string | null>(null)
  const [guestEnvironmentId, setGuestEnvironmentId] = useState<string | null>(null)

  const [cliReady, setCliReady] = useState(false)
  const [cliError, setCliError] = useState<string | null>(null)
  const [cliSkipped, setCliSkipped] = useState(false)
  const [cliAttempt, setCliAttempt] = useState(0)
  const cliStartup = useRef<Promise<void> | null>(null)
  const platformReady = !loading && Boolean(state)
  const vaultStartup = useVaultStartup(platformReady)
  useEffect(() => {
    if (!platformReady) return
    let active = true
    // startHostCli shares one pending start and forgets failures, so a retry never duplicates it.
    cliStartup.current ??= startHostCli()
    const slow = setTimeout(() => {
      if (active) setCliError(current => current ?? "The CLI is taking longer than expected to start.")
    }, CLI_STARTUP_NOTICE_MS)
    void cliStartup.current.then(() => {
      if (active) { setCliError(null); setCliReady(true) }
    }).catch(reason => {
      if (active) setCliError(`Could not start the CLI: ${reason instanceof Error ? reason.message : String(reason)}`)
    }).finally(() => clearTimeout(slow))
    return () => { active = false; clearTimeout(slow) }
  }, [platformReady, cliAttempt])
  const retryCli = useCallback(() => { cliStartup.current = null; setCliError(null); setCliAttempt(value => value + 1) }, [])
  const continueWithoutCli = useCallback(() => {
    if (cliError) toastManager.add({ title: "The CLI didn’t start", description: `${cliError} Open the CLI view to try again.`, type: "error" })
    setCliSkipped(true)
  }, [cliError])

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
  const selectEnvironment = useCallback((environmentId: string) => {
    void loadEnvironmentDetailSheet()
    setDetailMounted(true)
    setDetailEnvironmentId(environmentId)
  }, [])
  const changeDetailOpen = useCallback((open: boolean) => {
    if (!open) setDetailEnvironmentId(null)
  }, [])

  if (loading || !state) return <LoadingScreen error={error} onRetry={() => window.location.reload()} />
  if (!cliReady && !cliSkipped) return <><ThemeSync /><LoadingScreen message="Starting the CLI…" error={cliError} onRetry={retryCli} onContinue={cliError ? continueWithoutCli : undefined} continueKind="cli" /></>
  if (!vaultStartup.ready) return <><ThemeSync /><LoadingScreen message="Starting your Personal Vault…" error={vaultStartup.error} onRetry={vaultStartup.retry} onContinue={vaultStartup.error ? vaultStartup.continueWithoutVault : undefined} /></>

  return (
    <>
      <ThemeSync />
      <AppCloseDialog />
      <Suspense fallback={<LoadingScreen message="Loading your environments…" onRetry={() => window.location.reload()} />}>
        <AppShell onCreate={() => openCreate()} vaultError={vaultStartup.error}>
          <OverviewPage
            onOpenEnvironment={openEnvironment}
            onSelectEnvironment={selectEnvironment}
          />
        </AppShell>
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
