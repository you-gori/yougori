import { useEffect, useRef, useState } from "react"
import { remoteAccessApi } from "@/api/remote-access-api"
import { Button } from "@/components/ui/button"

export function DeskUpload({ environmentId }: { environmentId: string }) {
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(""), [error, setError] = useState("")
  const current = useRef<string | null>(null), cancelled = useRef(false), locked = useRef(false)
  useEffect(() => () => { cancelled.current = true; if (current.current) void remoteAccessApi.upload(environmentId, { action: "cancel", uploadId: current.current }).catch(() => {}) }, [environmentId])
  const upload = async (files: FileList | null) => {
    if (!files?.length || locked.current) return
    locked.current = true; cancelled.current = false; setBusy(true); setError("")
    try {
      const entries = Array.from(files)
      if (entries.length > 1000 || entries.some(file => file.size > 100 * 1024 * 1024) || entries.reduce((sum, file) => sum + file.size, 0) > 512 * 1024 * 1024) throw new Error("Choose up to 1,000 files, 100 MiB per file and 512 MiB per batch")
      const { uploadId } = await remoteAccessApi.upload<{ uploadId: string }>(environmentId, { action: "begin", files: entries.map(file => ({ path: file.webkitRelativePath || file.name, size: file.size })) })
      current.current = uploadId
      for (const [index, file] of entries.entries()) {
        if (cancelled.current) throw new Error("Upload cancelled")
        for (let offset = 0; offset < file.size; offset += 65536) {
          if (cancelled.current) throw new Error("Upload cancelled")
          const chunk = new Uint8Array(await file.slice(offset, offset + 65536).arrayBuffer())
          let text = ""; for (const byte of chunk) text += String.fromCharCode(byte)
          await remoteAccessApi.upload(environmentId, { action: "chunk", uploadId, file: index, offset, data: btoa(text) })
          setMessage(`${file.name} · ${Math.round(Math.min(offset + chunk.length, file.size) / file.size * 100)}%`)
        }
      }
      if (cancelled.current) throw new Error("Upload cancelled")
      setMessage("Adding your files to the desk…")
      await remoteAccessApi.upload(environmentId, { action: "finish", uploadId }); current.current = null
      setMessage(cancelled.current ? "Upload cancelled" : "Files added. Open the new import drive inside your desktop.")
    } catch (error) { setError(String(error)); if (current.current) await remoteAccessApi.upload(environmentId, { action: "cancel", uploadId: current.current }).catch(() => {}) }
    finally { current.current = null; locked.current = false; setBusy(false) }
  }
  return <section aria-label="Upload into workspace" className="mx-3 flex flex-wrap items-center gap-3 rounded border p-3 text-xs">
    <label className="cursor-pointer rounded border px-3 py-2">Upload files<input aria-label="Upload into workspace" className="sr-only" type="file" multiple disabled={busy} onChange={e => { void upload(e.target.files); e.target.value = "" }} /></label>
    <label className="cursor-pointer rounded border px-3 py-2">Upload folder<input aria-label="Upload folder into workspace" className="sr-only" type="file" multiple {...{ webkitdirectory: "" }} disabled={busy} onChange={e => { void upload(e.target.files); e.target.value = "" }} /></label>
    <span className="flex-1 text-muted-foreground" role="status">{message || "Files enter the desk through an import drive. Downloads are unavailable in restricted workspaces."}</span>
    {busy ? <Button size="xs" variant="outline" onClick={() => { cancelled.current = true }}>Cancel upload</Button> : null}
    {error ? <p role="alert" className="w-full text-destructive-foreground">{error}</p> : null}
  </section>
}
