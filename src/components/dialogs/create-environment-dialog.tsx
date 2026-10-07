import { useEffect, useMemo, useRef, useState, type FormEvent } from "react"
import { ArrowRightIcon, CheckIcon, CloudIcon, FolderOpenIcon, GpuIcon, LinkIcon, SlidersHorizontalIcon, TerminalIcon } from "lucide-react"
import { SharedEnvironmentForm } from "@/components/shared-environment-form"
import { ResourceValueControl } from "@/components/resource-value-control"
import { StorageCapacitySlider } from "@/components/storage-capacity-slider"
import { driveLabel, storageDrives } from "@/lib/storage-drives"
import { OciImagePicker } from "@/components/dialogs/oci-image-picker"
import { LocalBackupDialog } from "@/components/dialogs/local-backup-dialog"
import { CloudEnvironmentDialog } from "@/components/dialogs/cloud-environment-dialog"
import { NeocloudForm } from "@/components/dialogs/neocloud-form"
import { CudaRuntimePanel } from "@/components/dialogs/cuda-runtime-panel"
import type { CudaRuntimeStatus } from "@/api/gpu-api"
import { isolationPresentation } from "@/components/dialogs/environment-creation-options"
import { cn } from "@/lib/utils"
import "./create-environment-dialog.css"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogDescription,
  DialogFooter,
  DialogPanel,
  DialogPopup,
  DialogTitle,
} from "@/components/ui/dialog"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Form } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Radio, RadioGroup } from "@/components/ui/radio-group"
import { Switch } from "@/components/ui/switch"
import { fixedResourceErrors, creationResourceLimits } from "@/lib/resource-controls"
import { Textarea } from "@/components/ui/textarea"
import { platformApi } from "@/api/platform-api"
import { usePlatform } from "@/context/platform-context"
import { customOciImage, defaultOciImage, ociImages, ociStartupCommand, type OciImageOption } from "@/data/oci-images"
import { containerPurposes, containerPurposeImage, type ContainerPurpose } from "@/data/container-purposes"
import { environmentKindDescription, environmentKindLabel } from "@/lib/domain"
import type { EnvironmentKind, StorageAllocation } from "@/types/platform"
import { defaultGpuImage, gpuImageGroups, gpuImageIssue } from "@/data/gpu-images"
import { ownsTour, trackTourCreation, useInstructionsTour } from "@/lib/instructions-tour"
import { useTopicWalkthroughModal } from "@/lib/topic-walkthrough"

const kinds: EnvironmentKind[] = ["container", "microVm", "fullVm", "cloud"]

const runtimeDefaults: Record<EnvironmentKind, string> = {
  cloud: "",
  container: defaultOciImage.value,
  microVm: "builtin:alpine",
  fullVm: "",
  computerBranch: "",
}

export function CreateEnvironmentDialog({ open, onOpenChange, initialKind }: { open: boolean; onOpenChange(open: boolean): void; initialKind?: EnvironmentKind }) {
  const tour = useInstructionsTour()
  const topic = useTopicWalkthroughModal(open)
  const guided = ownsTour(tour) && Boolean(tour?.step.startsWith("create-"))
  const guidedRun = guided ? tour?.run : undefined
  const { createEnvironment, state } = usePlatform()
  const [workflow, setWorkflow] = useState<"cloud" | "neocloud" | "backup" | "shared" | null>(null)
  const [workflowBusy, setWorkflowBusy] = useState(false)
  const [cudaInstalling, setCudaInstalling] = useState(false)
  const [storageDrive, setStorageDrive] = useState("")
  const drives = state ? storageDrives(state.host) : []
  const [kind, setKind] = useState<EnvironmentKind>("container")
  const [gpuEnabled, setGpuEnabled] = useState(false)
  const [internetEnabled, setInternetEnabled] = useState(true)
  const cudaContainer = kind === "container" && gpuEnabled
  const containerRuntime = cudaContainer ? "yougoriCuda" : "yougoriOci"
  const [name, setName] = useState("")
  const [runtime, setRuntime] = useState(runtimeDefaults.container)
  const [selectedOciImage, setSelectedOciImage] = useState<OciImageOption>(defaultOciImage)
  const [useCustomImage, setUseCustomImage] = useState(false)
  const [selectedPurpose, setSelectedPurpose] = useState<ContainerPurpose | null>(null)
  const [containerCommand, setContainerCommand] = useState("sleep 2147483647")
  const [cudaStatus, setCudaStatus] = useState<CudaRuntimeStatus | null>(null)
  const [description, setDescription] = useState("")
  const [cpu, setCpu] = useState(0.5)
  const [memory, setMemory] = useState(0.5)
  const [storage, setStorage] = useState(20)
  const [storageInfo, setStorageInfo] = useState<StorageAllocation | null>(null)
  const [storageError, setStorageError] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const submitLock = useRef(false)
  const [formError, setFormError] = useState("")
  const cpuMaximum = useMemo(() => Math.max(1, state?.host.totalCpu ?? 16), [state?.host.totalCpu])
  const memoryMaximum = useMemo(() => Math.floor((state?.host.totalMemoryGb ?? 32) * 8) / 8, [state?.host.totalMemoryGb])
  const limits = creationResourceLimits(kind, cpuMaximum, memoryMaximum)
  const policyErrors = fixedResourceErrors(cpu, memory, limits)
  const storageMinimum = kind === "microVm" ? 6 : 1
  const storageMaximum = Math.max(storageMinimum, storageInfo?.maximumGb ?? storageMinimum)

  useEffect(() => {
    if (!open) return
    let active = true
    setStorageInfo(null); setStorageError("")
    platformApi.getStorageAllocation(undefined, kind === "fullVm" || kind === "microVm", storageDrive).then(info => {
      if (!active) return
      const required = kind === "microVm" ? 6 : 1
      if (info.maximumGb < required) { setStorageError(`Not enough free space on the Yougori drive. At least ${required} GB is needed, with 2 GB kept free for the host.`); return }
      setStorageInfo(info)
      setStorage(Math.min(kind === "container" ? 20 : kind === "fullVm" ? 64 : 6, info.maximumGb))
    }).catch(reason => { if (active) setStorageError(String(reason)) })
    return () => { active = false }
  }, [open, kind, cudaContainer, storageDrive])

  useEffect(() => {
    if (open) {
      setWorkflow(initialKind === "cloud" ? "cloud" : null)
      setKind(initialKind === "computerBranch" || initialKind === "cloud" ? "container" : initialKind ?? "container")
      setGpuEnabled(false)
      setInternetEnabled(true)
      setCudaStatus(null)
    }
  }, [initialKind, open])

  useEffect(() => {
    setRuntime(runtimeDefaults[kind])
    setSelectedPurpose(null)
    if (kind === "container") {
      const image = cudaContainer ? defaultGpuImage : defaultOciImage
      setRuntime(image.value)
      setSelectedOciImage(image)
      setUseCustomImage(false)
      setContainerCommand(ociStartupCommand(image))
    }
    if (kind === "fullVm") {
      setCpu(Math.min(2, cpuMaximum))
      setMemory(Math.min(4, memoryMaximum))
    } else if (kind === "microVm") {
      setCpu(1)
      setMemory(Math.min(1, memoryMaximum))
    } else {
      setCpu(Math.min(0.5, cpuMaximum))
      setMemory(Math.min(0.5, memoryMaximum))
    }
  }, [cpuMaximum, kind, memoryMaximum, cudaContainer])

  useEffect(() => {
    if (!open) {
      setWorkflow(null)
      setName("")
      setDescription("")
      setFormError("")
      setSubmitting(false)
      submitLock.current = false
      setRuntime(runtimeDefaults.container)
      setSelectedOciImage(defaultOciImage)
      setUseCustomImage(false)
      setSelectedPurpose(null)
      setContainerCommand("sleep 2147483647")
    }
  }, [open])

  const chooseOciImage = (image: OciImageOption | null) => {
    if (!image) return
    setSelectedPurpose(null)
    setSelectedOciImage(image)
    setUseCustomImage(image.value === customOciImage.value)
    setRuntime(image.value === customOciImage.value ? "" : image.value)
    setContainerCommand(ociStartupCommand(image))
    // Keep the service preset small; the host-sized range remains adjustable.
    if (image.value === "docker.io/library/mongo:latest") {
      setCpu(1)
      setMemory(Math.min(0.5, memoryMaximum))
    }
  }

  useEffect(() => {
    if (!open || !guidedRun) return
    setKind("container")
    setGpuEnabled(false)
    setRuntime(defaultOciImage.value)
    setSelectedOciImage(defaultOciImage)
    setUseCustomImage(false)
    setSelectedPurpose(null)
    setContainerCommand(ociStartupCommand(defaultOciImage))
  }, [open, guidedRun])

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitLock.current) return
    if (guided && (kind !== "container" || cudaContainer || runtime !== defaultOciImage.value || containerCommand !== ociStartupCommand(defaultOciImage))) {
      setFormError("The guide uses one default container. Skip the guide to choose another type or image.")
      return
    }
    if (kind === "computerBranch") {
      setFormError("Computer Branch is temporarily unavailable.")
      return
    }
    if (name.trim().length < 2) {
      setFormError("Give the environment a name with at least two characters.")
      return
    }
    if (!runtime.trim()) {
      setFormError(kind === "container"
        ? "Enter an OCI image reference."
        : kind === "microVm"
          ? "Use the built-in image or select a microVM JSON manifest."
          : "Select an installer ISO or an existing virtual disk.")
      return
    }
    if (policyErrors.length) { setFormError(policyErrors[0]!); return }
    if (cudaContainer && (!cudaStatus?.supported || !cudaStatus.installed || cudaStatus.updateAvailable)) { setFormError(cudaStatus?.supported === false ? cudaStatus.detail : "Set up or update NVIDIA CUDA first, then create this GPU environment."); return }
    if (cudaContainer && gpuImageIssue(runtime)) { setFormError(gpuImageIssue(runtime)!); return }
    if (!storageInfo || storageError || !Number.isFinite(storage) || !Number.isInteger(storage) || storage < storageMinimum || storage > storageMaximum) { setFormError(storageError || "Wait for storage capacity to load, then choose an available size."); return }
    if (state?.environments.some(environment => environment.name.toLowerCase() === name.trim().toLowerCase())) {
      setFormError("An environment with this name already exists.")
      return
    }
    submitLock.current = true
    setSubmitting(true)
    setFormError("")
    try {
      if (kind === "container" && !cudaContainer) trackTourCreation(name.trim())
      const creation = createEnvironment({
        name: name.trim(),
        storageGb: storage,
        storageDrive: storageDrive || state?.host.storageDrive || undefined,
        kind,
        runtime: runtime.trim(),
        provider: kind === "container" ? containerRuntime : "qemu",
        containerCommand: kind === "container" ? containerCommand.trim() : undefined,
        networkAccess: internetEnabled,
        gpuAccess: cudaContainer,
        description: description.trim() || (cudaContainer ? "A GPU container using NVIDIA CUDA and the shared WSL kernel." : environmentKindDescription[kind]),
        resourcePolicy: {
          cpu: { min: cpu, preferred: cpu, max: cpu },
          memoryGb: { min: memory, preferred: memory, max: memory },
          priority: "normal",
          dynamic: true,
        },
      })
      // Progress and errors belong to the persisted node and provider. A later
      // result must never close or overwrite a newly opened creation form.
      void creation.catch(() => undefined)
      onOpenChange(false)
    } catch (reason) {
      setFormError(reason instanceof Error ? reason.message : String(reason))
      submitLock.current = false
      setSubmitting(false)
    }
  }

  const chooseBootMedia = async () => {
    setFormError("")
    try {
      const selected = await platformApi.selectBootMedia()
      if (selected) setRuntime(selected)
    } catch (reason) {
      setFormError(reason instanceof Error ? reason.message : String(reason))
    }
  }

  const KindIcon = cudaContainer ? GpuIcon : isolationPresentation[kind].icon

  return (
    <>
    <Dialog modal={!guided && !topic} disablePointerDismissal={guided} onOpenChange={(value, details) => {
      const guideEvent = details.event.target instanceof Element && details.event.target.closest('[data-tour-ui], [data-topic-ui]')
      if (!value && (guideEvent || ((guided || topic) && details.reason === "focus-out"))) { details.cancel(); return }
      if (!submitting && !workflowBusy) onOpenChange(value)
    }} open={open}>
      <DialogPopup bottomStickOnMobile={false} closeProps={{ disabled: submitting || workflowBusy }} className="creation-workbench overflow-hidden" data-create-environment data-create-kind={cudaContainer ? "gpu" : kind}>
        <DialogTitle className="sr-only">New environment</DialogTitle>
        <DialogDescription className="sr-only">Choose an environment type, its image, and resources.</DialogDescription>
            <section aria-label="Isolation options" className="creation-isolation">
              <div className="creation-heading">
                <h2 aria-hidden="true">New environment</h2>
                {!workflow ? <p className="creation-isolation-description">{guided ? "The guide uses one default container for your first website. Other types and images are available after the guide." : cudaContainer ? "GPU containers for AI and computing. NVIDIA CUDA access is included." : isolationPresentation[kind].description}</p> : null}
              </div>
              <div className="creation-type-tabs">
              <RadioGroup aria-label="Environment type" disabled={submitting || workflowBusy} className="creation-types" onValueChange={value => { if (value === "cloud" || value === "neocloud" || value === "backup" || value === "shared") setWorkflow(value); else { setWorkflow(null); setKind(value as EnvironmentKind); if (value !== "container") { setGpuEnabled(false); setCudaStatus(null) } } }} value={workflow ?? kind}>
                {[...kinds, "neocloud", "shared", "backup"].map(item => {
                  const Icon = item === "shared" ? LinkIcon : item === "backup" ? FolderOpenIcon : item === "cloud" || item === "neocloud" ? CloudIcon : isolationPresentation[item as EnvironmentKind].icon
                  return <Label key={item} data-instruction-kind={item} className={cn("creation-type", (workflow ?? kind) === item && "is-selected")}>
                    <Radio className="sr-only" disabled={submitting || workflowBusy || (guided && item !== "container")} value={item} />
                    <Icon aria-hidden="true" /><span>{item === "shared" ? "Shared environment" : item === "backup" ? "Load local backup" : item === "cloud" ? "Cloud environment" : item === "neocloud" ? "Neocloud" : environmentKindLabel[item as EnvironmentKind]}</span>{(workflow ?? kind) === item ? <CheckIcon aria-hidden="true" className="creation-type-check" /> : null}
                  </Label>
                })}
              </RadioGroup>
              </div>
            </section>
        {workflow ? (
          <div className="contents" key={workflow}>
            {workflow === "shared" ? <DialogPanel><SharedEnvironmentForm onClose={() => onOpenChange(false)} onBusyChange={setWorkflowBusy} /></DialogPanel> : workflow === "cloud" ? <CloudEnvironmentDialog embedded open={open} onOpenChange={onOpenChange} onBusyChange={setWorkflowBusy} /> : workflow === "neocloud" ? <NeocloudForm onClose={() => onOpenChange(false)} onBusyChange={setWorkflowBusy} /> : <LocalBackupDialog embedded onClose={() => onOpenChange(false)} onBusyChange={setWorkflowBusy} />}
          </div>
        ) : <Form className="contents" onSubmit={submit}>
          <DialogPanel scrollFade={false} className="p-0!">
            <div className="creation-columns">
              <section aria-label="Environment configuration" className="creation-configuration">
                <div className="creation-section-heading"><h2><TerminalIcon aria-hidden="true" />Configuration</h2><span>{cudaContainer ? "NVIDIA CUDA" : kind === "container" ? "OCI runtime" : "QEMU runtime"}</span></div>
                <div className="creation-toggles">
                {kind === "container" ? <div className="creation-gpu-option" data-instruction-kind="gpu">
                  <div><Label htmlFor="creation-gpu-access"><GpuIcon aria-hidden="true" />GPU access</Label><p>NVIDIA CUDA for AI and GPU workloads</p></div>
                  <Switch id="creation-gpu-access" checked={gpuEnabled} disabled={submitting || cudaInstalling || guided} onCheckedChange={checked => { setCudaStatus(null); setGpuEnabled(checked) }} />
                </div> : null}
                <div className="creation-gpu-option">
                  <div><Label htmlFor="creation-internet-access">Internet access</Label><p>Change any time, no restart</p></div>
                  <Switch id="creation-internet-access" checked={internetEnabled} disabled={submitting} onCheckedChange={setInternetEnabled} />
                </div>
                </div>
                {cudaContainer ? <CudaRuntimePanel key={storageDrive} storageDrive={storageDrive} onBusyChange={setCudaInstalling} onStatus={setCudaStatus} /> : null}
                <Field name="name" data-tour="create-name">
                  <FieldLabel>Name</FieldLabel>
                  <Input disabled={submitting} className="creation-input creation-name" maxLength={80} onChange={event => setName(event.target.value)} placeholder="Ubuntu Development" required type="text" value={name} />
                </Field>
                <Field name="runtime" className="min-w-0" data-tour="create-image">
                <FieldLabel>{kind === "container" ? "OCI image" : kind === "microVm" ? "Direct-kernel microVM source" : "Installer ISO or virtual disk"}</FieldLabel>
                {kind === "container" ? (
                  <div className="flex w-full min-w-0 flex-col gap-2">
                    <OciImagePicker disabled={submitting || guided} onChange={chooseOciImage} value={selectedOciImage} groups={cudaContainer ? gpuImageGroups : undefined} />
                  </div>
                ) : (
                  <div className="flex gap-2">
                    <Input disabled={submitting} className="creation-input font-mono" onChange={(event) => setRuntime(event.target.value)} placeholder={kind === "microVm" ? "builtin:alpine or a microVM JSON manifest" : "Select an .iso, .qcow2, .vhdx, .vmdk, or .img file"} required type="text" value={runtime} />
                    <Button className="creation-browse" disabled={submitting} onClick={chooseBootMedia} type="button" variant="outline">Browse</Button>
                  </div>
                )}
                <FieldDescription className="creation-help">{cudaContainer ? "Compatible Linux bases, or a custom glibc image. Your AI framework or CUDA toolkit must also support your GPU and driver." : kind === "container" ? `${ociImages.length - 1} curated images from public registries, plus any custom OCI reference.` : kind === "microVm" ? "Use built-in Alpine or a JSON manifest with your kernel, root disk, and boot settings." : "An ISO installs into a new disk using your selected storage capacity. Imported disks keep their size if larger; they are never shrunk."}</FieldDescription>
              </Field>
                {kind === "container" && useCustomImage ? <Field name="custom-runtime" className="-mt-2 min-w-0">
                  <FieldLabel className="sr-only">Custom OCI image reference</FieldLabel>
                  <Input disabled={submitting} className="creation-input font-mono" autoFocus onChange={event => setRuntime(event.target.value)} placeholder="registry.example.com/organization/image:tag" required type="text" value={runtime} />
                </Field> : null}
                {cudaContainer && gpuImageIssue(runtime) ? <p role="alert" className="creation-error">{gpuImageIssue(runtime)}</p> : null}
                {kind === "container" && !cudaContainer && !guided ? <div className="creation-purpose-picker">
                  <span id="creation-purpose-label">What are you building?</span>
                  <div aria-labelledby="creation-purpose-label" role="group" className="creation-purpose-options">
                    {containerPurposes.map(purpose => <button
                      key={purpose.id} type="button" disabled={submitting}
                      aria-pressed={selectedPurpose?.id === purpose.id}
                      className={cn("creation-purpose", selectedPurpose?.id === purpose.id && "is-selected")}
                      onClick={() => { chooseOciImage(containerPurposeImage(purpose)); setSelectedPurpose(purpose) }}
                    >{purpose.label}</button>)}
                  </div>
                  <p className="creation-purpose-help" aria-live="polite">{selectedPurpose
                    ? selectedPurpose.description
                    : "Choose a purpose to select a base image, or search the catalog above."}</p>
                  <p className="creation-purpose-hint">Selects an image and startup command only. Your project and additional tools are up to you.</p>
                </div> : null}
                <div className="creation-startup">
                  {kind === "container" ? <Field name="container-command">
                    <FieldLabel>Startup command (optional)</FieldLabel>
                    <div className="creation-command"><span aria-hidden="true">$</span><Input disabled={submitting || guided} className="creation-input font-mono" onChange={event => setContainerCommand(event.target.value)} placeholder="Use the image’s default startup" type="text" value={containerCommand} /></div>
                    <FieldDescription className="creation-help">Leave blank to run the image’s default service.</FieldDescription>
                  </Field> : null}
                  <Field name="description">
                    <FieldLabel>Description <span className="creation-optional">optional</span></FieldLabel>
                    <Textarea disabled={submitting} className="creation-input creation-description" maxLength={220} onChange={event => setDescription(event.target.value)} placeholder="Add a note about this environment…" value={description} />
                  </Field>
                </div>
              </section>
              <section aria-label="Resource allocation" className="creation-resources">
                <div className="creation-section-heading"><h2><SlidersHorizontalIcon aria-hidden="true" />Resources</h2><span>Fixed allocation</span></div>
                <ResourceValueControl label="CPU" max={limits.cpu.max} min={limits.cpu.min} onChange={setCpu} step={limits.cpu.step} unit="CPUs" disabled={submitting} value={cpu} />
                <ResourceValueControl label="Memory" max={limits.memory.max} min={limits.memory.min} onChange={setMemory} step={limits.memory.step} unit="GB" disabled={submitting} value={memory} />
                <label className="flex items-center justify-between gap-3 text-xs"><span>Storage drive</span><select aria-label="Storage drive" className="creation-input h-8 min-w-0 max-w-[75%] rounded-md border bg-background px-2 text-xs" disabled={submitting || cudaInstalling} value={storageDrive} onChange={event => { setStorageInfo(null); setStorageDrive(event.target.value) }}><option value="">{state?.host.storageDrive ? `${driveLabel(state.host.storageDrive)} · Default` : "Default drive"}</option>{drives.filter(drive => drive.path).map(drive => <option key={drive.path} value={drive.path} disabled={drive.readOnly}>{driveLabel(drive.path)} · {drive.freeGb.toFixed(1)} GB free{drive.readOnly ? " · Read-only" : ""}</option>)}{storageDrive && !drives.some(drive => drive.path === storageDrive) ? <option value={storageDrive} disabled>{driveLabel(storageDrive)} · Disconnected</option> : null}</select></label>
                {storageInfo ? <StorageCapacitySlider value={storage} min={storageMinimum} max={storageMaximum} disabled={submitting} container={kind === "container"} onChange={setStorage} /> : <p role="status" className="creation-resource-note">{storageError || "Loading storage capacity…"}</p>}
                <p className="creation-resource-note">Stored on {driveLabel(storageDrive || state?.host.storageDrive || "")} · 2 GB stays free for your computer.</p>
                {kind === "container" ? <p className="creation-resource-note">Writable files, private volumes and logs use this container's limit. Cached images, snapshots and connected folders use additional space.</p> : null}
                {kind === "fullVm" && storage < 64 ? <p className="creation-resource-note">Windows 11 requires a disk of at least 64 GB.</p> : null}
                {policyErrors.length ? <p role="alert" className="creation-error">{policyErrors[0]}</p> : null}
                <p className="creation-resource-note">CPU and memory stay at the values you set. {kind === "microVm" ? "Memory changes apply on restart." : kind === "container" ? "Change the allocation later in configuration." : "Stop the VM before increasing its allocation."}</p>
              </section>
            </div>
          </DialogPanel>
          <DialogFooter className="creation-footer">
            {formError ? <p role="alert" className="creation-error">{formError}</p> : null}
            {submitting ? <p role="status" className="creation-resource-note">{kind === "container" ? "Preparing the runtime and image. The first download can take a few minutes." : "Preparing the boot media and virtual disk."}</p> : null}
            <div className="creation-footer-row">
              <div aria-label="Startup summary" className="creation-summary"><KindIcon aria-hidden="true" /><span className="creation-summary-name" title={name.trim() || "Untitled environment"}>{name.trim() || "Untitled environment"}</span><span className="creation-summary-resources">{cpu} CPUs<span aria-hidden="true">/</span>{memory} GB</span></div>
              <div className="creation-actions"><DialogClose render={<Button disabled={submitting} type="button" variant="ghost" />}>Cancel</DialogClose><Button data-tour="create-submit" className="creation-submit" disabled={policyErrors.length > 0 || (cudaContainer && (!cudaStatus?.supported || !cudaStatus.installed || Boolean(cudaStatus.updateAvailable) || Boolean(gpuImageIssue(runtime))))} loading={submitting} type="submit">Create environment<ArrowRightIcon aria-hidden="true" className="size-4" /></Button></div>
            </div>
          </DialogFooter>
        </Form>}
      </DialogPopup>
    </Dialog>

    </>
  )
}
