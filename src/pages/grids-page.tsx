import { lazy, Suspense, useCallback, useMemo, useState } from "react"
import { PageHeader, PillButton } from "@/components/prompx"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import { LoadingScreen } from "@/components/shared/loading-screen"
import { useWorkspaceActions } from "@/components/use-workspace-actions"
import { useAccessStatus } from "@/components/use-access-status"
import { usePlatform } from "@/context/platform-context"
import { GridCreateWizard, type GridCreation } from "@/components/grid-create-wizard"
import { GridRealmView } from "@/components/grid-realm-view"
import { GridRollout } from "@/components/grid-rollout"
import { DeleteGrid } from "@/components/grid-deletion"
import { deletableGrid } from "@/lib/grid-deletion-plan"
import type { GridRun } from "@/components/grid-swarm"
import { grids } from "@/api/grids"
import { CAPABILITY_LEAD, capabilitiesSentence } from "@/lib/grid-capability"
import { brandedName, readGridBrand } from "@/lib/grid-brand"
import { gridRealms, GRID_NAME, type GridRealm } from "@/lib/grid-realm"
import type { GridFocus, GridKey } from "@/lib/grid-link"
import type { GridBlueprint } from "@/lib/grid-blueprint"
import { rememberResearch, researchSentence } from "@/lib/research-authorisation"
import type { Reach } from "@/api/grids/types"
import "@/components/neo-grid.css"
import "@/components/grids.css"

const NeoGridPage = lazy(async () => ({ default: (await import("@/pages/neocloud-page")).NeoGridPage }))
const SwarmMiningPage = lazy(async () => ({ default: (await import("@/pages/swarm-mining-page")).SwarmMiningPage }))
const DesksPage = lazy(async () => ({ default: (await import("@/pages/desks-page")).DesksPage }))
const AccessPage = lazy(async () => ({ default: (await import("@/pages/access-page")).AccessPage }))

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

const reachOf = (blueprint: GridBlueprint): Reach =>
  blueprint.reach.kind === "quick" ? "quick"
    : blueprint.reach.kind === "domain" ? { domain: blueprint.reach.hostname.trim() }
    : "network"

/** One area for every grid on this computer.
 *
 *  The four products are still four hubs, so each of them keeps its own page and this area opens
 *  it unchanged. What is new is that they are one list, with one way to read a grid's state and
 *  one way to create one, and that nothing is offered for a grid that cannot do it.
 */
export function GridsPage({ focus, onFocus }: { focus: GridFocus; onFocus(focus: GridFocus): void }) {
  const { state } = usePlatform()
  const { grid, workers, desks, refreshGrid, refreshDesks, refreshSwarm } = useWorkspaceActions()
  const { status: access, refresh: refreshAccess } = useAccessStatus(15_000)
  const [busy, setBusy] = useState("")
  const [creating, setCreating] = useState(false)
  const thisComputer = state?.host.hostname?.trim() || "this computer"
  const realms = useMemo(
    () => gridRealms({ grid, desks, access, workers, thisComputer }),
    [grid, desks, access, workers, thisComputer],
  )

  const refresh = useCallback(async () => {
    await Promise.all([refreshGrid(), refreshDesks(), refreshSwarm(), refreshAccess()])
  }, [refreshGrid, refreshDesks, refreshSwarm, refreshAccess])

  const run: GridRun = async (job, work, done) => {
    if (busy) return false
    setBusy(job)
    try {
      const result = await work() as { warning?: string | null } | undefined
      if (done) toastManager.add({ title: done, description: result?.warning ?? undefined, type: result?.warning ? "warning" : "success" })
      return true
    } catch (reason) {
      toastManager.add({ title: `${job} did not finish`, description: message(reason), type: "error" })
      return false
    } finally {
      setBusy("")
      await refresh()
    }
  }

  const done = useCallback((said?: string) => {
    if (said) toastManager.add({ title: said, type: "success" })
    void refresh()
  }, [refresh])

  /** Creating a grid, after its dry run and after every sentence on it was agreed to. */
  const create = useCallback(async ({ blueprint, password, accepted }: GridCreation) => {
    const name = blueprint.name.trim()
    const address = blueprint.address.trim()
    const reach = reachOf(blueprint)
    setBusy("Creating the grid")
    try {
      if (blueprint.capabilities.includes("research")) {
        // Nothing is started here. Research runs as its own worker, which Swarm Mining's own
        // page sets up, so the authorised answers are kept and handed to that setup rather than
        // asked for a second time or quietly dropped when this closes.
        rememberResearch(blueprint.research)
        toastManager.add({
          title: "Swarm Mining has what you authorised",
          description: `${researchSentence(blueprint.research)} Make a worker there and it starts with this.`,
          type: "success",
        })
        onFocus({ kind: "page", grid: "research" })
        return
      }
      // Each purpose is still served by its own hub, so a grid for two things starts two of
      // them. If the second one refuses, the first is already running and the sentence says so
      // rather than leaving somebody to find out.
      const started: string[] = []
      const start = async <T,>(what: string, work: () => Promise<T>): Promise<T> => {
        try {
          const value = await work()
          started.push(what)
          return value
        } catch (reason) {
          throw new Error(started.length
            ? `${name} is already ${started.join(" and ")}, but ${what} did not start: ${message(reason)}`
            : message(reason))
        }
      }
      if (blueprint.capabilities.includes("models")) {
        await start("serving models", () => grids.models.host(name, address, password, reach))
        // The summary named one model plan, so the grid is left with that plan in it rather
        // than with a promise somebody has to go and keep themselves.
        const model = blueprint.models.model.trim()
        if (model) {
          await start(`ordering ${model}`, () => grids.models.addPlan({
            model,
            quant: blueprint.models.quant.trim() || null,
            target: blueprint.models.scope === "computers"
              ? { kind: "hosts", hosts: blueprint.models.computers }
              : { kind: blueprint.models.scope, percent: blueprint.models.percent },
          }))
        }
      }
      if (blueprint.capabilities.includes("workspaces")) {
        const hosted = await start("hosting desks", () => grids.workspaces.host(name, address, password, reach))
        // This computer joined its own grid as it was made, so the share the summary named is
        // set on it here. A grid committed whole is set on the Sandbox Grid's own page, which
        // is why the summary no longer says this screen does it.
        const me = hosted.member?.deviceId
        if (me && blueprint.workspaces.commitment === "share") {
          await start("giving this computer's share to the grid", () => grids.workspaces.setOffer(me, { ...blueprint.workspaces.share, idleOnly: false }))
        }
      }
      if (blueprint.capabilities.includes("credentials")) {
        const administrator = (blueprint.administrators[0] ?? "admin").trim()
        await start("brokering credentials", () => grids.credentials.host(name, address, { username: administrator, name: administrator, password }, reach))
      }
      toastManager.add({
        title: `${name} is running on this computer`,
        description: accepted.length ? `You agreed to ${accepted.length} ${accepted.length === 1 ? "thing" : "things"} about it.` : undefined,
        type: "success",
      })
      const first = blueprint.capabilities[0]
      if (first) onFocus({ kind: "status", grid: first === "models" ? "models" : first === "workspaces" ? "workspaces" : "credentials" })
    } finally {
      setBusy("")
      await refresh()
    }
  }, [onFocus, refresh])

  if (focus?.kind === "page") {
    return <Suspense fallback={<LoadingScreen message="Opening this grid…" onRetry={() => window.location.reload()} />}>
      {focus.grid === "models" ? <NeoGridPage />
        : focus.grid === "workspaces" ? <DesksPage />
        : focus.grid === "credentials" ? <AccessPage />
        : <SwarmMiningPage />}
    </Suspense>
  }

  const shown = focus?.kind === "status" ? realms.find(realm => realm.key === focus.grid) ?? null : null
  return <section className="app-page" aria-label="Grids workspace" aria-busy={Boolean(busy)}>
    <PageHeader
      title="Grids."
      lead="Every grid your company runs on its own computers: models it serves, desks it builds, credentials its agents use and the research it authorises. Each one keeps its own key, its own people and its own record of what happened."
      actions={<>
        {shown ? <PillButton tone="light" onClick={() => onFocus(null)}>All grids</PillButton> : null}
        <PillButton tone="dark" title="Asks what the grid is for first, then only the questions that belong to it." onClick={() => setCreating(true)}>Create a grid</PillButton>
      </>}
    />
    <div className="app-page-body">
      {busy ? <p role="status" className="grid-muted">{busy}…</p> : null}
      {shown
        ? <GridRealmView realm={shown} run={run} done={done} onOpenPage={() => onFocus({ kind: "page", grid: shown.key })} />
        : <>
          <GridList realms={realms} onFocus={onFocus} run={run} />
          <GridRollout />
        </>}
    </div>
    <GridCreateWizard
      open={creating}
      onOpenChange={setCreating}
      me={access?.me?.person.username ?? desks?.desk?.username ?? "admin"}
      facts={{
        computer: thisComputer,
        computers: realms.flatMap(realm => realm.hosts.map(host => host.name)).filter((name, at, all) => all.indexOf(name) === at),
        alreadyHere: realms.filter(realm => realm.present && realm.role === "host").flatMap(realm => realm.capabilities),
      }}
      onCreate={create}
      suggestedAddress={() => grids.models.suggestedAddress()}
    />
  </section>
}

/** Every grid as a card: the ones on this computer first, then the ones it could run. */
function GridList({ realms, onFocus, run }: { realms: GridRealm[]; onFocus(focus: GridFocus): void; run: GridRun }) {
  const here = realms.filter(realm => realm.present)
  const rest = realms.filter(realm => !realm.present)
  return <section aria-label="Grids on this computer" className="grids-section">
    <header className="grids-head">
      <h2 className="grids-heading">On this computer <span>{here.length ? `${here.length} of ${realms.length} set up` : "none set up yet"}</span></h2>
      {here.length ? null : <p className="grids-lead">Create a grid and it is asked what it is for before anything else.</p>}
    </header>
    <div className="grids-cards">
      {[...here, ...rest].map(realm => <GridCard key={realm.key} realm={realm} onFocus={onFocus} run={run} />)}
    </div>
  </section>
}

/** One grid. A grid that is here shows how it is doing; one that is not says what it would be for. */
function GridCard({ realm, onFocus, run }: { realm: GridRealm; onFocus(focus: GridFocus): void; run: GridRun }) {
  const open = (kind: "status" | "page") => onFocus({ kind, grid: realm.key as GridKey })
  const deletion = realm.present ? deletableGrid(realm) : null
  const [only, ...others] = realm.capabilities
  const kind = capabilitiesSentence(realm.capabilities)
  const name = realm.present ? brandedName(realm.name, readGridBrand(realm.key)) : GRID_NAME[realm.key]
  return <article className="grids-card" aria-label={name} data-absent={realm.present ? undefined : ""}>
    <p className="grids-card-kind">{kind.charAt(0).toUpperCase() + kind.slice(1)}</p>
    <h3 className="grids-card-name">{name}</h3>
    {realm.present
      ? <p className="grids-card-state">
        <i aria-hidden="true" className="grid-dot" data-online={realm.lifecycle === "open" || undefined} />
        <span>{realm.hint}</span>
      </p>
      : <>
        {only && !others.length ? <p className="grids-card-lead">{CAPABILITY_LEAD[only]}</p> : null}
        <p className="grids-card-state">{realm.state}</p>
      </>}
    <div className="grids-card-actions">
      {realm.present ? <Button size="xs" onClick={() => open("status")}>Status</Button> : null}
      <Button size="xs" variant={realm.present ? "ghost" : "outline"} onClick={() => open("page")}>Open {GRID_NAME[realm.key]}</Button>
      {deletion ? <DeleteGrid closing={realm.closing} run={run} what={deletion.what} remove={deletion.remove} restore={deletion.restore} /> : null}
    </div>
  </article>
}
