import { useEffect, useRef, useState } from "react"
import { sandboxVmApi, visibleText } from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"
import { Dialog, DialogDescription, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { HostAccessBox } from "./host-access-box"

/** Requests reach the owner even when the VM panel is closed or another page is open.
 * Nothing is approved by receiving a request, closing the dialog or dismissing it. */
export function HostAccessRequests() {
  const [pending, setPending] = useState<{ sandbox: string; requests: string[] }[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const seen = useRef(new Set<string>())
  useEffect(() => {
    if (!("__TAURI_INTERNALS__" in window)) return
    let active = true
    let reading = false
    async function refresh() {
      if (reading) return
      reading = true
      try {
        const status = await sandboxVmApi.status()
        const rows = await Promise.all(status.sandboxes.filter(vm => vm.phase === "ready").map(async vm => {
          const view = await sandboxVmApi.hostAccess(vm.sandbox)
          return { sandbox: vm.sandbox, requests: view.requests.filter(r => r.state === "pending").map(r => r.id) }
        }))
        if (!active) return
        const asking = rows.filter(row => row.requests.length)
        setPending(asking)
        const first = asking.find(row => row.requests.some(id => !seen.current.has(id)))
        seen.current = new Set(asking.flatMap(row => row.requests))
        if (first) setSelected(previous => previous ?? first.sandbox)
      } catch { /* No VM service/older installed engine: no invented request or approval. */ }
      finally { reading = false }
    }
    void refresh()
    const timer = setInterval(() => void refresh(), 3000)
    return () => { active = false; clearInterval(timer) }
  }, [])
  return <>
    {pending.length ? <div className="fixed bottom-4 right-4 z-40 flex flex-wrap gap-2 rounded-lg border bg-popover p-3 shadow-lg" aria-label="VM file-access requests">
      {pending.map(row => <Button key={row.sandbox} size="sm" onClick={() => setSelected(row.sandbox)}>
        Review {row.requests.length} file request{row.requests.length === 1 ? "" : "s"} · {visibleText(row.sandbox)}
      </Button>)}
    </div> : null}
    <Dialog open={selected !== null} onOpenChange={open => { if (!open) setSelected(null) }}>
      <DialogPopup>
        <DialogHeader>
          <DialogTitle>VM requests access to your computer</DialogTitle>
          <DialogDescription>{selected ? visibleText(selected) : ""}. Choose the path permissions below. Closing this window grants nothing.</DialogDescription>
        </DialogHeader>
        <DialogPanel>{selected ? <HostAccessBox key={selected} sandbox={selected} /> : null}</DialogPanel>
      </DialogPopup>
    </Dialog>
  </>
}
