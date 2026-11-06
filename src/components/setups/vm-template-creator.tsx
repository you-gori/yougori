import { useEffect, useState } from "react"
import { useSandboxVms } from "@/components/sandbox-vm/sandbox-vm-context"
import { sandboxVmEnvironments } from "@/components/sandbox-vm/sandbox-vm-environments"
import { run } from "@/api/platform-api"
import { hubApi } from "@/api/hub-api"
import { Button } from "@/components/ui/button"
import { Dialog, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter } from "@/components/ui/dialog"
import { useSetupBuilder } from "./builder-context"
import { TemplateCodeGuide } from "./template-code-guide"
import { usePlatformOptional } from "@/context/platform-context"

interface Capture {
  digest: string
  files: string[]
  omitted: string[]
  folder?: string
  sandboxes: { id: string; name: string; files: number; connections: string[] }[]
  questions: { id: string; question: string; type: string }[]
}

export function VmTemplateCreator({ selected = [], open, onClose, onCreateVm }: { selected?: string[]; open: boolean; onClose(): void; onCreateVm?(): void }) {
  const vmFeed = useSandboxVms()
  const platform = usePlatformOptional()
  const { refresh } = vmFeed
  useEffect(() => { if (open) void refresh() }, [open, refresh])
  const builder = useSetupBuilder()
  const vms = sandboxVmEnvironments(vmFeed.status)
  const empty = !!vmFeed.status && !vmFeed.error && !vms.length
  const [chosen, setChosen] = useState(selected)
  const [name, setName] = useState("my-template")
  const [preview, setPreview] = useState<Capture | null>(null)
  const [folder, setFolder] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const validChosen = chosen.filter(id => vms.some(vm => vm.id === id))
  const unavailable = vmFeed.status && !vmFeed.error ? chosen.filter(id => !vms.some(vm => vm.id === id)) : []
  const validName = /^[a-z][a-z0-9-]{0,47}$/.test(name)
  const selectionProblem = !validChosen.length ? "Select at least one Sandbox VM to continue."
    : validChosen.length > 16 ? "Select up to 16 Sandbox VMs in one template."
    : !validName ? "Use a name starting with a lowercase letter, with only lowercase letters, numbers and dashes (up to 48 characters)." : ""
  const request = (operation: "preview" | "export", extra = {}) => run<Capture>("sandbox_vm", {
    action: "template", params: { operation, sandboxes: validChosen, name, ...extra },
  }, () => { throw new Error("Open Yougori Desktop to capture Sandbox VMs.") })
  const review = async () => {
    setBusy(true); setError(""); setPreview(null); setFolder("")
    try { setPreview(await request("preview")) } catch (failure) { setError(String(failure)) } finally { setBusy(false) }
  }
  const save = async () => {
    if (!preview) return
    setBusy(true); setError("")
    try {
      const destination = await hubApi.folder("Choose an empty folder for this template")
      if (!destination) return
      const saved = await request("export", { digest: preview.digest, folder: destination }); setFolder(saved.folder ?? destination)
    }
    catch (failure) { setError(String(failure)) } finally { setBusy(false) }
  }
  return <Dialog open={open} onOpenChange={value => { if (!value && !busy) onClose() }}>
    <DialogPopup className="max-w-2xl" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Create template from VMs</DialogTitle>
        <DialogDescription>{empty ? "Turn an application you build in Sandbox VMs into a setup that others can install." : "Choose one or more of your current Sandbox VMs. Yougori reads their setup declarations, source files and connections."}</DialogDescription>
      </DialogHeader>
      <DialogPanel className="space-y-5">
        {vmFeed.error ? <div role="alert"><p>{vmFeed.error}</p><Button variant="outline" onClick={() => void refresh()}>Retry loading VMs</Button></div> : null}
        {!vmFeed.status && !vmFeed.error ? <p role="status">Loading your VMs…</p> : null}
        {unavailable.length ? <section role="status" className="space-y-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-4" aria-label="Selected environments not included">
          <h3 className="font-medium">These selected environments cannot be included</h3>
          <ul className="space-y-2 text-sm">{unavailable.map(id => {
            const environment = platform?.state?.environments.find(item => item.id === id)
            return <li key={id}><strong>{environment?.name ?? id}</strong><p className="text-muted-foreground">{environment
              ? "This environment is not registered as a Sandbox VM. Template capture needs a VM workspace containing your application’s source and setup declaration."
              : "This VM is no longer available in the current list. Refresh the list or choose another VM."}</p></li>
          })}</ul>
          {validChosen.length ? <p className="text-sm">Your {validChosen.length} selected Sandbox VM{validChosen.length === 1 ? " remains" : "s remain"} selected below.</p> : null}
        </section> : null}
        {empty ? <section className="space-y-3 rounded-xl border p-5" aria-label="No VMs to select">
          <h3 className="font-semibold">No Sandbox VMs available to select</h3>
          <p className="text-sm text-muted-foreground">This button packages VMs you have already built. Standalone model environments do not appear in this list.</p>
          <ol className="list-inside list-decimal space-y-2 text-sm">
            <li>Create a Sandbox VM using {onCreateVm ? "the button below" : "New environment"}.</li>
            <li>Build your website, service or other application inside it.</li>
            <li>Return here, select your VMs, then review and save your template.</li>
          </ol>
          <Button variant="outline" size="sm" onClick={() => void refresh()}>Refresh VM list</Button>
        </section> : null}
        {vms.length > 0 ? <>
        <fieldset disabled={busy} className="space-y-2"><legend className="mb-2 font-medium">Select your Sandbox VMs</legend>
          <div className="max-h-72 space-y-2 overflow-y-auto">{vms.map(vm => <label key={vm.id} className="flex cursor-pointer items-center gap-3 rounded-lg border p-3 has-[:checked]:border-primary has-[:checked]:bg-primary/5">
            <input type="checkbox" checked={chosen.includes(vm.id)} onChange={event => { setChosen(ids => event.target.checked ? [...ids, vm.id] : ids.filter(id => id !== vm.id)); setPreview(null); setFolder("") }} />
            <span>{vm.name}<small className="ml-3 text-muted-foreground">{vm.status}</small></span>
          </label>)}</div>
          {vms.length ? <p className="text-sm text-muted-foreground">{validChosen.length} of {vms.length} VMs selected · Select multiple VMs to include their connections.</p> : null}
        </fieldset>
        <label className="block">Template name<input aria-label="Template name" className="mt-2 w-full rounded-lg border bg-transparent p-3" value={name} disabled={busy} onChange={event => { setName(event.target.value); setPreview(null); setFolder("") }} /></label>
        {selectionProblem ? <p role="status" className="text-sm text-muted-foreground">{selectionProblem}</p> : null}
        </> : null}
        <TemplateCodeGuide />
        {preview ? <section aria-label="Template review" className="space-y-3">
          <h3 className="font-semibold">What this template includes</h3>
          {preview.sandboxes.map(vm => <div key={vm.id} className="rounded-lg border p-3"><strong>{vm.name}</strong> · {vm.files} source files
            <p className="text-sm">{vm.connections.length ? `Connects to: ${vm.connections.join(", ")}` : "No connection to another selected VM"}</p></div>)}
          <h4 className="font-medium">Installer questions</h4>
          {preview.questions.length ? <ul>{preview.questions.map(question => <li key={question.id}>{question.question}{question.type === "secret" ? " · private answer" : ""}</li>)}</ul> : <p>No questions declared.</p>}
          <p className="text-sm text-muted-foreground">Excluded: {preview.omitted.join("; ")}.</p>
        </section> : null}
        {error ? <p role="alert" className="text-destructive">{error}</p> : null}
        {folder ? <p role="status">Saved to {folder}. Ready to test or publish.</p> : null}
      </DialogPanel>
      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={busy}>Close</Button>
        {empty && onCreateVm ? <Button onClick={onCreateVm}>Create Sandbox VM</Button> : null}
        {!folder ? vms.length > 0 ? <Button disabled={busy || !vmFeed.status || !!vmFeed.error || !!selectionProblem} onClick={() => void (preview ? save() : review())}>{busy ? "Reading VMs…" : preview ? "Save template…" : "Review template"}</Button> : null : <>
          <Button variant="outline" onClick={() => { onClose(); builder.open({ mode: "run", folder }) }}>Run template</Button>
          <Button onClick={() => { void hubApi.openConsole("publishTemplate", folder).catch(failure => setError(String(failure))) }}>Publish template</Button>
        </>}
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
