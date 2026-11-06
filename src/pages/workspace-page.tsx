import { lazy, Suspense } from "react"
import type { AppPage } from "@/components/app-shell"
import type { DetailTab } from "@/components/setups/setup-detail"
import { Dialog, DialogPopup, DialogTitle, DialogDescription, DialogPanel, DialogHeader } from "@/components/ui/dialog"
import { OverviewPage } from "./overview-page"
const HubPage = lazy(async () => ({ default: (await import("./hub-page")).HubPage }))
const SetupDetail = lazy(async () => ({ default: (await import("@/components/setups/setup-detail")).SetupDetailView }))

export function WorkspacePage({ page, onClosePopup, highlight, highlightTab, ...overview }: {
  page: AppPage
  onClosePopup(): void
  highlight: string | null
  highlightTab?: DetailTab
  onOpenEnvironment(id: string): void
  onSelectEnvironment(id: string): void
  vaultError?: string | null
}) {
  return <>
    <OverviewPage {...overview} />
    <Dialog open={page === "hub"} onOpenChange={open => { if (!open) onClosePopup() }}>
      <DialogPopup className="workspace-popup">
        <DialogTitle className="sr-only">Hub</DialogTitle>
        <DialogDescription className="sr-only">Explore, run and publish templates and tools.</DialogDescription>
        <DialogPanel><Suspense fallback={<p role="status">Loading Hub…</p>}>{page === "hub" ? <HubPage /> : null}</Suspense></DialogPanel>
      </DialogPopup>
    </Dialog>
    <Dialog open={page === "setups"} onOpenChange={open => { if (!open) onClosePopup() }}>
      <DialogPopup className="workspace-popup">
        <DialogHeader>
          <DialogTitle>Setup configuration</DialogTitle>
          <DialogDescription>Manage the configuration of your sandboxes.</DialogDescription>
        </DialogHeader>
        <DialogPanel><Suspense fallback={<p role="status">Loading configuration…</p>}>
          {page === "setups" && highlight ? <SetupDetail setupId={highlight} initialTab={highlightTab} onBack={onClosePopup} /> : <p>Select one or more sandboxes in My computer, then choose Configure.</p>}
        </Suspense></DialogPanel>
      </DialogPopup>
    </Dialog>
  </>
}
