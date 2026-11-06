import { useEffect, useId, useRef, useState } from "react"
import { Cpu, Folder, CircuitBoard, ShieldCheck, SlidersHorizontal } from "lucide-react"
import { sandboxVmApi, type SandboxVmCapabilities, type LaunchRequest } from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"
import { DialogFooter, DialogPanel } from "@/components/ui/dialog"
import { Field, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { ResourceValueControl } from "@/components/resource-value-control"
import { Switch } from "@/components/ui/switch"
import { Checkbox } from "@/components/ui/checkbox"
import { ImagePicker, type CatalogImage } from "./image-picker"

import { defaultNetworkOptions, networkLaunchFields } from "./network-options"
import { NetworkOptionsForm } from "./network-options-form"

export function SandboxVmLaunchForm({ disabled, error, onCancel, onImportBusyChange, onLaunch }: {
  disabled: boolean
  error?: string
  onCancel?(): void
  onImportBusyChange?(busy: boolean): void
  onLaunch(request: LaunchRequest): void
}) {
  const [image, setImage] = useState("")
  const [imageReady, setImageReady] = useState(true)
  const [folder, setFolder] = useState("")
  const [cpu, setCpu] = useState(1)
  const cpuMax = Math.min(255, Math.max(1, navigator.hardwareConcurrency || 255))
  const [catalogImage, setCatalogImage] = useState<CatalogImage | null>(null)
  const [memory, setMemory] = useState(1)
  const [gpu, setGpu] = useState(false)
  const [gpuSupport, setGpuSupport] = useState<SandboxVmCapabilities["gpu"]>({ available: false, reason: "Checking GPU support…" })
  useEffect(() => {
    let active = true
    void sandboxVmApi.capabilities().then(value => { if (active) setGpuSupport(value.gpu) })
      .catch(() => { if (active) setGpuSupport({ available: false, reason: "GPU support could not be checked. Reopen this window after the engine starts." }) })
    return () => { active = false }
  }, [])
  const [imageMinimum, setImageMinimum] = useState(0.5)
  const importLock = useRef(false)
  const [importing, setImporting] = useState(false)
  const locked = disabled || importing
  const minimumMemory = Math.max(imageMinimum, gpu ? (gpuSupport.minimumMemoryGb ?? 4) : 0.5)
  const [network, setNetwork] = useState(defaultNetworkOptions)
  const [gridHosting, setGridHosting] = useState<NonNullable<LaunchRequest["gridHosting"]>>([])
  const [problem, setProblem] = useState("")
  const folderId = useId()

  const launch = async () => {
    if (locked || importLock.current) return
    if (!imageReady) return setProblem("Import your custom image before creating the VM.")
    if (!Number.isInteger(cpu) || cpu < 1 || cpu > cpuMax) return setProblem(`Choose between 1 and ${cpuMax} whole CPU cores.`)
    if (catalogImage && (!Number.isFinite(catalogImage.rootGb) || catalogImage.rootGb < 0.0625 || catalogImage.rootGb > 8)) return setProblem("Writable image storage must be between 0.0625 and 8 GB.")
    const memoryGb = memory
    if (!Number.isFinite(memoryGb) || memoryGb <= 0) return setProblem("Memory must be a positive number of gigabytes.")
    if (memoryGb < minimumMemory || memoryGb > 64) return setProblem(`Reserve between ${minimumMemory} and 64 GB of memory for this VM.`)
    let networkFields: ReturnType<typeof networkLaunchFields>
    try { networkFields = networkLaunchFields(network) }
    catch (reason) { return setProblem(reason instanceof Error ? reason.message : String(reason)) }
    setProblem("")
    let chosenImage = image
    if (catalogImage) {
      importLock.current = true
      setImporting(true); onImportBusyChange?.(true)
      try {
        const imported = await sandboxVmApi.importRegistryImage(catalogImage.reference, catalogImage.rootGb)
        chosenImage = imported.id
        setImage(imported.id)
        setCatalogImage(null)
      } catch (reason) { setProblem(String(reason)); return }
      finally { importLock.current = false; setImporting(false); onImportBusyChange?.(false) }
    }
    onLaunch({ cpu, memoryGb, ...(gpu ? { gpu: true } : {}), ...(gridHosting.length ? { gridHosting } : {}), ...(chosenImage ? { image: chosenImage } : {}), ...(folder.trim() ? { workspace: folder.trim() } : {}), ...networkFields })
  }

  return <form className="contents" noValidate onSubmit={event => { event.preventDefault(); void launch() }}>
    <DialogPanel scrollFade={false} className="p-0!">
      <div className="creation-columns">
        <section aria-label="Environment configuration" className="creation-configuration">
          <div className="creation-section-heading"><h2><SlidersHorizontal aria-hidden="true" />Configuration</h2><span>Sandbox VM</span></div>
          <ImagePicker onReadyChange={setImageReady} onCatalogChange={choice => {
            setCatalogImage(choice)
            const minimum = choice ? Math.ceil((choice.rootGb + 0.5) * 4) / 4 : 0.5
            if (Number.isFinite(minimum)) {
              setImageMinimum(minimum)
              if (choice) setMemory(previous => Math.max(previous, minimum))
            }
          }} value={image} disabled={locked} onBusyChange={value => { setImporting(value); onImportBusyChange?.(value) }} onChange={(value, minimum) => {
            setImage(value)
            const reserved = Math.ceil((minimum ?? 0.5) * 4) / 4
            setImageMinimum(reserved)
            if (minimum) setMemory(previous => Math.max(Number.isFinite(previous) ? previous : 1, reserved))
          }} />
          <Field name="workspace" disabled={locked}>
            <FieldLabel htmlFor={folderId}>Folder it works on<span className="creation-optional">Optional</span></FieldLabel>
            <div className="creation-vm-input-row">
              <Input id={folderId} className="creation-input" disabled={locked} value={folder} placeholder="Choose a project folder" onChange={event => setFolder(event.target.value)} />
              <Button type="button" variant="outline" className="creation-browse" disabled={locked} onClick={() => void sandboxVmApi.chooseFolder().then(path => { if (path) setFolder(path) }).catch(reason => setProblem(String(reason)))}><Folder aria-hidden="true" />Browse</Button>
            </div>
            <p className="creation-help">The VM works on a copy. Review and apply its changes when you’re ready.</p>
            <p className="creation-help">Known credential files are excluded; check the folder for other secrets before using it.</p>
          </Field>
          <NetworkOptionsForm value={network} onChange={setNetwork} disabled={locked} gridHosting={gridHosting.length > 0} />
        </section>
        <section aria-label="Resource allocation" className="creation-resources">
          <div className="creation-section-heading"><h2><Cpu aria-hidden="true" />Resources</h2><span>Fixed allocation</span></div>
          <ResourceValueControl label="CPU" value={cpu} min={1} max={cpuMax} step={1} unit="vCPU" disabled={locked} onChange={setCpu} help="Virtual CPU cores assigned to this VM." />
          <ResourceValueControl label="Memory" value={memory} min={minimumMemory} max={64} step={0.25} unit="GB" disabled={locked} onChange={setMemory} help="Reserved for the VM and its hypervisor. Yougori checks available capacity before creating it." />
          <p className="creation-resource-note">Includes the VM and hypervisor. A 1 GB reservation gives the guest 768 MiB. An imported image may need a larger reservation.</p>
          <dl className="creation-vm-resource-facts">

            <div><dt>Workspace</dt><dd>{folder.trim() ? "Private copy" : "Empty"}</dd></div>
            <div><dt>Image storage</dt><dd>{image || catalogImage ? "Private writable root" : "Minimal guest"}</dd></div>
          </dl>
          <div className="creation-gpu-option">
            <div><label htmlFor={`${folderId}-gpu`}><CircuitBoard aria-hidden="true" />GPU acceleration</label><p id={`${folderId}-gpu-reason`}>{gpuSupport.available ? "Run CUDA inside this VM. The GPU is shared with your computer. Windows will ask to approve the VM helper." : gpuSupport.reason}</p></div>
            <Switch id={`${folderId}-gpu`} checked={gpu} disabled={locked || !gpuSupport.available} onCheckedChange={enabled => { setGpu(enabled); if (enabled) setMemory(previous => Math.max(previous, gpuSupport.minimumMemoryGb ?? 4)) }} aria-describedby={`${folderId}-gpu-reason`} />
          </div>
          <fieldset className="creation-vm-fields" disabled={locked}>
            <legend className="font-medium">Add Grid Hosting</legend>
            <p className="creation-help">Install Yougori grid tools and an AI skill in this VM. Build your own service and accept contributions from PCs or cloud servers.</p>
            {(["gpu", "sandbox"] as const).map(resource => <label key={resource} className="flex items-center gap-3 py-2">
              <Checkbox disabled={locked} checked={gridHosting.includes(resource)} onCheckedChange={checked => setGridHosting(previous => checked ? [...previous, resource] : previous.filter(value => value !== resource))} />
              <span>{resource === "sandbox" ? "Sandbox Grid (CPU and memory)" : "GPU Grid"}</span>
            </label>)}
            <p className="creation-help">GPU hosting accepts contributed model servers. Enable GPU acceleration above to also run CUDA inside this VM. Memory is assigned to jobs, not combined into shared RAM.</p>
          </fieldset>
          <div className="creation-vm-note"><ShieldCheck aria-hidden="true" /><div><h3>Your files stay in your control</h3><p>The VM’s changes stay in its workspace until you review and apply them to your computer.</p></div></div>
        </section>
      </div>
    </DialogPanel>
    <DialogFooter className="creation-footer">
      {problem || error ? <p role="alert" className="creation-error">{problem || error}</p> : null}
      {importing ? <p role="status" className="creation-help">Downloading and preparing the selected image…</p> : null}
      {disabled ? <p role="status" className="creation-help">Creating your Sandbox VM…</p> : null}
      <div className="creation-footer-row">
        <div aria-label="Startup summary" className="creation-summary"><ShieldCheck aria-hidden="true" /><span className="creation-summary-name">Sandbox VM</span><span className="creation-summary-resources">{cpu} vCPU<span>/</span>{Number.isFinite(memory) ? memory : "—"} GB memory</span></div>
        <div className="creation-actions">
          {onCancel ? <Button type="button" variant="ghost" disabled={locked} onClick={onCancel}>Cancel</Button> : null}
          <Button type="submit" className="creation-submit" disabled={locked || !imageReady}>Create environment</Button>
        </div>
      </div>
    </DialogFooter>
  </form>
}
