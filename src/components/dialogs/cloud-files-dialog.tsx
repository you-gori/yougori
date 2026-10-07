import { useEffect, useRef, useState } from "react"
import { usePlatform } from "@/context/platform-context"
import type { Environment } from "@/types/platform"
import { customOciImage, defaultOciImage, ociImages } from "@/data/oci-images"
import { OciImagePicker } from "@/components/dialogs/oci-image-picker"
import { ConfigurationHelp } from "@/components/configuration-help"
import { Button } from "@/components/ui/button"
import { Field, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { driveLabel, storageDrives } from "@/lib/storage-drives"

export function CloudFilesDialog({ environment, onClose }: { environment: Environment; onClose(): void }) {
  const { state, duplicateEnvironment, refreshPlatform } = usePlatform()
  const [saved] = useState(() => Object.values(state?.duplicationJobs ?? {}).find(job => job.request.environmentId === environment.id && job.request.localFiles && job.status !== "complete"))
  const [operationId] = useState(() => saved?.request.operationId ?? crypto.randomUUID())
  const [name, setName] = useState(saved?.request.name ?? `${environment.name.slice(0, 65)} copy`)
  const [image, setImage] = useState(saved?.request.localFiles?.image ?? defaultOciImage.value)
  const [selectedImage, setSelectedImage] = useState(() => ociImages.find(item => item.value === image) ?? customOciImage)
  const [paths, setPaths] = useState(saved?.request.localFiles?.paths.join("\n") ?? "~")
  const [storageGb, setStorageGb] = useState(String(saved?.request.localFiles?.storageGb ?? 20))
  const [drive, setDrive] = useState(saved?.request.storageDrive ?? "")
  const [reviewed, setReviewed] = useState(saved?.request.reviewed ?? false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const guard = useRef(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  useEffect(() => {
    if (!busy) return
    const timer = window.setInterval(() => void refreshPlatform().catch(() => undefined), 2000)
    return () => window.clearInterval(timer)
  }, [busy, refreshPlatform])
  const job = state?.duplicationJobs?.[operationId]
  const frozen = Boolean(job || saved)
  const sourcePaths = paths.split(/\r?\n/).filter(path => path.trim().length > 0)
  const capacity = Number(storageGb)
  const valid = name.trim().length > 0 && Boolean(image.trim()) && sourcePaths.length > 0 && Number.isInteger(capacity) && capacity >= 6 && capacity <= 16380
  const edit = (change: () => void) => { change(); setReviewed(false) }
  const submit = async () => {
    if (guard.current || !valid || !reviewed) return
    guard.current = true; setBusy(true); setError("")
    try {
      await duplicateEnvironment(saved?.request ?? job?.request ?? {
        operationId, environmentId: environment.id, name, destination: "local", source: null, target: null,
        targetBucket: "", storageDrive: drive || null, reviewed,
        localFiles: { image: image.trim(), paths: sourcePaths, storageGb: capacity },
      })
      if (alive.current) onClose()
    } catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { guard.current = false; if (alive.current) setBusy(false) }
  }
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogPopup className="w-[min(56rem,calc(100vw-2rem))] max-w-none">
      <DialogHeader><DialogTitle>Duplicate environment</DialogTitle><DialogDescription>{environment.name} → Local files</DialogDescription></DialogHeader>
      <form className="contents" onSubmit={event => { event.preventDefault(); void submit() }}>
        <DialogPanel className="space-y-4">
          <fieldset disabled={busy || frozen} className="grid gap-4 sm:grid-cols-2">
            <label className="space-y-1 text-xs">Name<Input maxLength={80} value={name} onChange={event => edit(() => setName(event.target.value))} required /></label>
            <Field name="localImage" className="min-w-0 space-y-1 text-xs"><FieldLabel>Local container image</FieldLabel><OciImagePicker disabled={busy || frozen} value={selectedImage} onChange={option => edit(() => { setSelectedImage(option); setImage(option.value === customOciImage.value ? "" : option.value) })} />
              {selectedImage.value === customOciImage.value ? <Input aria-label="Custom local image" placeholder="registry/image:tag" value={image} onChange={event => edit(() => setImage(event.target.value))} required /> : null}
            </Field>
            <label className="space-y-1 text-xs">Storage drive<select aria-label="Storage drive" className="block h-9 w-full rounded-md border bg-background px-2" value={drive} onChange={event => edit(() => setDrive(event.target.value))}><option value="">Default drive</option>{state ? storageDrives(state.host).filter(item => item.path).map(item => <option key={item.path} value={item.path} disabled={item.readOnly}>{driveLabel(item.path)} · {item.freeGb.toFixed(1)} GB free</option>) : null}</select></label>
            <label className="space-y-1 text-xs">Local storage (GB)<Input type="number" min={6} max={16380} step={1} value={storageGb} onChange={event => edit(() => setStorageGb(event.target.value))} required /></label>
            <label className="space-y-1 text-xs sm:col-span-2"><span className="flex items-center gap-1">Cloud files and folders<ConfigurationHelp label="Cloud folder copy help">One path per line. ~ means the SSH user's home. Select ordinary data folders such as /home/ubuntu/project or /srv/app. Permissions errors stop the copy. Links, special files and nested mounts are skipped and counted. The new image needs /bin/sh, sleep, and head.</ConfigurationHelp></span><textarea aria-label="Cloud files and folders" className="h-24 w-full resize-y rounded-md border bg-background p-2 font-mono text-xs" value={paths} onChange={event => edit(() => setPaths(event.target.value))} placeholder={"~\n/srv/app"} spellCheck={false} required /></label>
            <p className="text-xs text-muted-foreground sm:col-span-2">Uses the saved SSH connection. Keep the cloud server reachable. Files go into a new folder in the selected image; its operating system stays intact. Software, users and services are not installed from copied files.</p>
            <label className="flex items-start gap-2 text-xs sm:col-span-2"><Checkbox checked={reviewed} onCheckedChange={value => setReviewed(value === true)} /><span>I paused writes to these folders or exported live databases. I understand that copied files may contain secrets and cloud download charges may apply.</span></label>
          </fieldset>
          {job ? <p role="status" className="break-all text-xs text-muted-foreground">{job.phase}{busy ? "…" : ""}</p> : null}
          {error || job?.error ? <p role="alert" className="whitespace-pre-wrap text-sm text-destructive-foreground">{error || job?.error}</p> : null}
        </DialogPanel>
        <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{busy ? "Run in background" : "Cancel"}</Button><Button type="submit" loading={busy} disabled={busy || !valid || !reviewed}>{frozen ? "Resume copy" : "Copy files"}</Button></DialogFooter>
      </form>
    </DialogPopup>
  </Dialog>
}
