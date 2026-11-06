import { lazy, Suspense, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react"
import { SetupBuilderContext } from "./builder-context"
import { WorkspaceActionsContext } from "@/components/use-workspace-actions"
import type { BuilderIntent } from "./setup-intent"
import type { DetailTab } from "./setup-detail"

const TemplateBuilder = lazy(async () => ({ default: (await import("./template-builder")).TemplateBuilder }))
const VmTemplateCreator = lazy(async () => ({ default: (await import("./vm-template-creator")).VmTemplateCreator }))

/** Holds the one template builder. Whatever opened it gets focus back when it closes. */
export function SetupBuilderProvider({ children, initial = null, onShowSetups }: {
  children: ReactNode
  /** A builder an address asked for, open from the start. */
  initial?: BuilderIntent | null
  onShowSetups?(setupId: string | null, tab?: DetailTab): void
}) {
  const workspaceActions = useContext(WorkspaceActionsContext)
  const [intent, setIntent] = useState<BuilderIntent | null>(initial)
  const [round, setRound] = useState(0)
  const opener = useRef<HTMLElement | null>(null)
  const open = useCallback((next: BuilderIntent) => {
    opener.current = document.activeElement instanceof HTMLElement && document.activeElement !== document.body ? document.activeElement : null
    setIntent(next)
    setRound(value => value + 1)
  }, [])
  const close = useCallback(() => {
    setIntent(null)
    const back = opener.current
    requestAnimationFrame(() => { if (back?.isConnected) back.focus() })
  }, [])
  const controls = useMemo(() => ({ open }), [open])
  return <SetupBuilderContext.Provider value={controls}>
    {children}
    {intent ? <Suspense fallback={null}>
      {intent.mode === "create" ? <VmTemplateCreator key={round} selected={intent.environments} open onClose={close}
        onCreateVm={workspaceActions ? () => { setIntent(null); workspaceActions.create() } : undefined} />
        : <TemplateBuilder key={round} intent={intent} open onClose={close} onShowSetups={onShowSetups} returnFocus={opener} />}
    </Suspense> : null}
  </SetupBuilderContext.Provider>
}

/** Gives its children a builder: the app's one, or a builder of their own when there is none. */
export function SetupBuilderScope({ children }: { children: ReactNode }) {
  const outer = useContext(SetupBuilderContext)
  return outer ? <>{children}</> : <SetupBuilderProvider>{children}</SetupBuilderProvider>
}
