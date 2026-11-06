import { useId, useState } from "react"
import { sandboxVmApi, visibleText, type VmImage } from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"
import { Download } from "lucide-react"
import { Field, FieldLabel } from "@/components/ui/field"
import { OciImagePicker } from "@/components/dialogs/oci-image-picker"
import { customOciImage, ociImageGroups, type OciImageGroup, type OciImageOption } from "@/data/oci-images"
import { Input } from "@/components/ui/input"

const minimalImage: OciImageOption = { value: "__minimal__", builtin: true, label: "Minimal guest", description: "Start without an OCI workload image", category: "Operating systems" }
const catalogGroups = ociImageGroups.map(group => group.value === "Operating systems" ? { ...group, items: [minimalImage, ...group.items] } : group)
export interface CatalogImage { reference: string; rootGb: number }

export function ImagePicker({ value, disabled, onBusyChange, onChange, onCatalogChange, onReadyChange }: {
  onCatalogChange?(image: CatalogImage | null): void
  onReadyChange?(ready: boolean): void
  value: string; disabled: boolean; onBusyChange?(busy: boolean): void; onChange(value: string, memoryGb?: number): void
}) {
  const id = useId()
  const [catalog, setCatalog] = useState(minimalImage)
  const [catalogRoot, setCatalogRoot] = useState(0.5)
  const [importedChoice, setImportedChoice] = useState<OciImageOption | null>(null)
  const [layout, setLayout] = useState("")
  const [source, setSource] = useState("registry")
  const [reference, setReference] = useState("")
  const [authOrigin, setAuthOrigin] = useState("")
  const [secret, setSecret] = useState("")
  const [root, setRoot] = useState("0.5")
  const [selected, setSelected] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const custom = !value && catalog === customOciImage
  const imageGroups: OciImageGroup[] = onCatalogChange ? catalogGroups : [{ value: "Operating systems", items: [minimalImage] }]
  const choice = value ? { ...(importedChoice ?? catalog), value, displayReference: "Ready to use" } : catalog
  const choose = (item: VmImage | undefined) => {
    setCatalog(minimalImage)
    onReadyChange?.(true)
    onCatalogChange?.(null)
    onChange(item?.id ?? "", item?.image ? item.image.root_bytes / 2 ** 30 + 0.5 : undefined)
  }
  const importImage = async () => {
    const rootGb = Number(root)
    if (!(source === "layout" ? layout.trim() : reference.trim()) || !selected || !Number.isFinite(rootGb) || rootGb < 0.0625 || rootGb > 8) {
      setError("Choose an image, confirm your selection, and give a root size between 0.0625 and 8 GB.")
      return
    }
    setBusy(true)
    onBusyChange?.(true)
    setError("")
    try {
      const imported = source === "layout" ? await sandboxVmApi.importImage(layout.trim(), rootGb)
        : await sandboxVmApi.importRegistryImage(reference.trim(), rootGb, authOrigin.trim() || undefined, secret || undefined)
      setImportedChoice({
        value: imported.id, label: visibleText(source === "registry" ? reference.trim() : layout.trim().split(/[\\/]/).filter(Boolean).at(-1) || "Custom image"),
        category: "Developer tools", description: "Your selected custom image",
      })
      choose(imported)
    } catch (e) { setError(String(e)) }
    finally { setSecret(""); setBusy(false); onBusyChange?.(false) }
  }
  return <fieldset disabled={disabled || busy} className="creation-vm-image">
    <legend className="sr-only">OCI workload image (optional)</legend>
    <Field>
      <FieldLabel>OCI image</FieldLabel>
      <OciImagePicker value={choice} disabled={disabled || busy} groups={imageGroups} onChange={item => {
        if (item.disabled) return
        setError("")
        setSecret("")
        setImportedChoice(null)
        if (item === customOciImage) {
          setCatalog(customOciImage)
          setSelected(false)
          onChange("")
          onCatalogChange?.(null)
          onReadyChange?.(false)
          return
        }
        setCatalog(item)
        onChange("")
        onReadyChange?.(true)
        onCatalogChange?.(item === minimalImage ? null : { reference: item.value, rootGb: catalogRoot })
      }} />
      {catalog !== minimalImage && !value && !custom ? <>
        <p className="creation-help">Downloaded and imported when you create the VM. The selected version is pinned to its content digest.</p>
        <Field>
        <FieldLabel htmlFor={`${id}-catalog-root`}>Writable image storage (GB)</FieldLabel>
        <Input id={`${id}-catalog-root`} className="creation-input" type="number" min={0.0625} max={8} step={0.25} value={catalogRoot} onChange={event => {
          const size = Number(event.target.value)
          setCatalogRoot(size)
          onCatalogChange?.({ reference: catalog.value, rootGb: size })
        }} />
        </Field>
        <p className="creation-help">Reserved inside VM memory. Images up to 256 MiB compressed and 8,000 entries are supported; larger images report the import limit.</p>
      </> : !custom ? <p className="creation-help">{value ? "Your selected image is ready to use." : "Choose an image from the catalogue. Use Custom image for a registry reference or local folder."}</p> : null}
    </Field>
    {custom ? <section aria-label="Custom image import">
      <div className="creation-vm-fields">
        <p className="creation-help">Import your custom image below, then create the environment.</p>
        <Field>
          <FieldLabel htmlFor={`${id}-source`}>Image source</FieldLabel>
          <select id={`${id}-source`} value={source} onChange={e => { setSource(e.target.value); setSelected(false); setSecret("") }} className="creation-vm-select">
            <option value="layout">Local OCI layout</option><option value="registry">Registry image (tag or digest)</option>
          </select>
        </Field>
        {source === "layout" ? <Field>
          <FieldLabel htmlFor={`${id}-layout`}>Layout folder</FieldLabel>
          <div className="creation-vm-input-row">
            <Input id={`${id}-layout`} className="creation-input" placeholder="Choose an OCI layout folder" value={layout} onChange={e => setLayout(e.target.value)} />
            <Button type="button" variant="outline" className="creation-browse" disabled={disabled || busy} onClick={() => void sandboxVmApi.chooseFolder().then(path => { if (path) setLayout(path) }).catch(e => setError(String(e)))}>Choose folder</Button>
          </div>
        </Field> : <>
          <Field>
            <FieldLabel htmlFor={`${id}-reference`}>Registry reference</FieldLabel>
            <Input id={`${id}-reference`} className="creation-input" placeholder="docker.io/library/alpine:3.24" value={reference} onChange={e => setReference(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor={`${id}-auth-origin`}>Token service origin (optional)</FieldLabel>
            <Input id={`${id}-auth-origin`} className="creation-input" placeholder="https://auth.example" value={authOrigin} onChange={e => setAuthOrigin(e.target.value)} />
          </Field>
          <Field>
            <FieldLabel htmlFor={`${id}-token`}>Bearer token (optional)</FieldLabel>
            <Input id={`${id}-token`} type="password" autoComplete="off" className="creation-input" value={secret} onChange={e => setSecret(e.target.value)} />
          </Field>
          <p className="creation-help">Tags are resolved to a verified SHA-256 digest. Docker Hub authentication is automatic; other token services may need their origin. A supplied token is used only for this import.</p>
        </>}
        <Field>
          <FieldLabel htmlFor={`${id}-root`}>Writable image root (GB)</FieldLabel>
          <Input id={`${id}-root`} className="creation-input" inputMode="decimal" value={root} onChange={e => setRoot(e.target.value)} />
        </Field>
        <label className="creation-vm-consent"><input type="checkbox" checked={selected} onChange={e => setSelected(e.target.checked)} />I choose this unsigned image for my own sandboxes.</label>
        <p className="creation-help">The image runs in a private writable root inside the VM. Import accepts OCI tar/gzip layers, up to 256 MiB compressed and 8,000 entries.</p>
        <Button type="button" variant="outline" className="self-start" disabled={disabled || busy || !selected || !(source === "layout" ? layout.trim() : reference.trim())} onClick={() => void importImage()}><Download aria-hidden="true" />Import image</Button>
      </div>
    </section> : null}
    {busy ? <p role="status" className="creation-help">Importing the image in a disposable VM…</p> : null}
    {error ? <p role="alert" className="creation-error">{error}</p> : null}
  </fieldset>
}
