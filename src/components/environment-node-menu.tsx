import { cloneElement, useEffect, useRef, useState, type MouseEvent, type ReactElement, type ReactNode } from "react"
import { ContextMenu } from "@base-ui/react/context-menu"
import { EnvironmentDownloadDialog } from "@/components/dialogs/environment-download-dialog"
import { usePlatform } from "@/context/platform-context"
import type { Environment } from "@/types/platform"
import { MenuItem, MenuPopup } from "@/components/ui/menu"
import { Button } from "@/components/ui/button"
import { AlertDialog, AlertDialogPopup, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter } from "@/components/ui/alert-dialog"

// `asChild` puts the menu on the child element itself, e.g. a table row that cannot be wrapped in a div.
export function EnvironmentNodeMenu({ environment, disabled, asChild, children }: { environment: Environment; disabled?: boolean; asChild?: boolean; children: ReactNode }) {
  const { deleteEnvironment, environmentActions } = usePlatform()
  const [confirm, setConfirm] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [download, setDownload] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const pending = useRef(false)
  const nativeMenu = "__TAURI_INTERNALS__" in window && /Win/i.test(navigator.platform)
  const busy = deleting || Boolean(environmentActions[environment.id]) || environment.status === "provisioning"
  useEffect(() => {
    const requestDelete = (event: Event) => {
      if (!disabled && !busy && (event as CustomEvent<string>).detail === environment.id) {
        setConfirm(true)
      }
    }
    window.addEventListener("yougori-delete-node", requestDelete)
    const requestDownload = (event: Event) => {
      if (!disabled && !busy && (event as CustomEvent<string>).detail === environment.id) setDownload(true)
    }
    window.addEventListener("yougori-download-node", requestDownload)
    return () => { window.removeEventListener("yougori-delete-node", requestDelete); window.removeEventListener("yougori-download-node", requestDownload) }
  }, [disabled, busy, environment.id])
  const remove = async () => {
    if (pending.current || busy) return
    pending.current = true
    setDeleting(true)
    setConfirm(false)
    try { await deleteEnvironment(environment.id) }
    catch { /* The platform reports failures through a non-blocking notification. */ }
    finally { pending.current = false; setDeleting(false) }
  }
  const markContext = () => { document.documentElement.dataset.yougoriNodeContext = busy ? "" : environment.id }
  if (disabled) return children
  return <>
    {nativeMenu ? asChild ? cloneElement(children as ReactElement<{ onContextMenu?(event: MouseEvent): void }>, { onContextMenu: markContext }) : <div onContextMenu={markContext}>{children}</div> : <ContextMenu.Root open={menuOpen} onOpenChange={setMenuOpen}>
      {asChild ? <ContextMenu.Trigger render={children as ReactElement<Record<string, unknown>>} /> : <ContextMenu.Trigger>{children}</ContextMenu.Trigger>}
      {menuOpen && <MenuPopup align="start" finalFocus={confirm ? false : undefined} className="nodrag nopan" onPointerDown={event => event.stopPropagation()}>
        <MenuItem disabled={busy} onClick={() => { setMenuOpen(false); setDownload(true) }}>Create a download link</MenuItem>
        <MenuItem variant="destructive" disabled={busy} onClick={() => { setMenuOpen(false); setConfirm(true) }}>Delete node</MenuItem>
      </MenuPopup>}
    </ContextMenu.Root>}
    {download && <EnvironmentDownloadDialog environment={environment} onClose={() => setDownload(false)} />}
    <AlertDialog open={confirm} onOpenChange={value => { if (!pending.current) setConfirm(value) }}>
      <AlertDialogPopup className="nodrag nopan" onPointerDown={event => event.stopPropagation()}>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete {environment.name}?</AlertDialogTitle>
          <AlertDialogDescription>{environment.kind === "cloud"
            ? "This removes the node and its Yougori connections. The remote server and its data are not deleted."
            : "This removes the environment with its local data, snapshots and connection permissions, and cannot be undone. Your original installer files, exported backups and shared PC files are kept."}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <Button variant="outline" disabled={deleting} onClick={() => setConfirm(false)}>Cancel</Button>
          <Button variant="destructive" disabled={busy} loading={deleting} onClick={() => void remove()}>Delete node</Button>
        </AlertDialogFooter>
      </AlertDialogPopup>
    </AlertDialog>
  </>
}
