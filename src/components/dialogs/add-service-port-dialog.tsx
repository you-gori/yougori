import { useRef, useState, type FormEvent } from "react"
import { ArrowRightIcon, GlobeIcon, NetworkIcon, PlusIcon, WaypointsIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field"
import { Form } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import type { Environment } from "@/types/platform"
import { isWebsiteTour } from "@/lib/instructions-tour"
import "./add-service-port-dialog.css"

const commonPorts = [3000, 4200, 5173, 8080, 27017]

export function AddServicePortDialog({ environment, onAddPort, onBusyChange }: {
  environment?: Environment
  onAddPort(port: number): void | Promise<void>
  onBusyChange?(busy: boolean): void
}) {
  const [port, setPort] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const submitLock = useRef(false)
  const input = useRef<HTMLInputElement>(null)
  const name = environment?.name ?? "Environment"
  const running = environment?.status === "running"

  const changePort = (value: string) => { setPort(value); setError("") }
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (submitLock.current) return
    const value = port.trim()
    if (environment && isWebsiteTour(environment.id, "demo-port-add") && Number(value) !== 3000) {
      setError("Use port 3000 for this Hello World tutorial. Skip the guide to add a different port.")
      input.current?.focus()
      return
    }
    if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535 || Number(value) === 7443) {
      setError("Enter a port from 1 to 65535. Port 7443 is reserved for Yougori.")
      input.current?.focus()
      return
    }
    if (environment && !busy) {
      submitLock.current = true
      setBusy(true); onBusyChange?.(true)
      try { await onAddPort(Number(value)) }
      catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
      finally { submitLock.current = false; setBusy(false); onBusyChange?.(false) }
    }
  }

  return <DialogPopup closeProps={{ disabled: busy }} data-add-service-port={environment?.id} bottomStickOnMobile={false} className="service-port-workbench max-h-[calc(100dvh-2rem)] max-w-[920px] overflow-hidden sm:max-w-[920px]">
    <DialogHeader className="service-port-header">
      <WaypointsIcon aria-hidden="true" />
      <DialogTitle className="service-port-title text-base leading-5"><span>Add a service port</span><span className="service-port-environment" title={name}> · {name}</span></DialogTitle>
      <DialogDescription className="sr-only">Add the port used by an app inside this environment, then choose how to connect to it.</DialogDescription>
    </DialogHeader>
    <Form className="contents" onSubmit={submit}>
      <DialogPanel scrollFade={false} className="p-0!">
        <div className="service-port-columns">
          <section aria-label="Service port" className="service-port-configuration">
            <Field name="guestPort" invalid={Boolean(error)}>
              <FieldLabel>Guest TCP port</FieldLabel>
              <FieldDescription className="service-port-help">The port your app listens on inside this environment.</FieldDescription>
              <div className="service-port-input-row">
                <Input autoFocus disabled={busy} className="service-port-input" inputMode="numeric" onChange={event => changePort(event.target.value)} placeholder="3000" ref={input} type="text" value={port} />
                <span aria-hidden="true" className="service-port-protocol">TCP</span>
              </div>
              {error ? <FieldError match role="alert" className="service-port-error">{error}</FieldError> : <p className="service-port-range">1–65535 · 7443 reserved for Yougori</p>}
            </Field>
            <div className="service-port-presets" role="group" aria-label="Common service ports">
              <span>Common ports</span>
              <div>{commonPorts.map(value => <button disabled={busy} aria-pressed={port.trim() === String(value)} className="service-port-preset" key={value} onClick={() => changePort(String(value))} type="button">{value}</button>)}</div>
            </div>
            <p className="service-port-detection">{environment?.kind === "fullVm" ? <>In your VM, make the app listen on <code>0.0.0.0</code> so Yougori can reach it.</> : "Containers and managed microVMs detect listening ports automatically. Add one here if it is missing."}</p>
            {!running ? <p role="status" className="service-port-status">{environment ? "You can add the port now. Start this environment before connecting or publishing it." : "This environment is no longer available."}</p> : null}
          </section>
          <section aria-label="What happens next" className="service-port-next">
            <h2>What happens next</h2>
            <ol className="service-port-steps">
              <li><span aria-hidden="true">1</span><div><h3>Add it to the node</h3><p>Your port appears on the environment graph.</p></div></li>
              <li><span aria-hidden="true">2</span><div><h3>Choose who can connect</h3><p>Open its connections or connect it from the graph.</p></div></li>
            </ol>
            <div className="service-port-destinations"><span><NetworkIcon aria-hidden="true" />Local network</span><span><GlobeIcon aria-hidden="true" />Public access / Cloudflare</span></div>
            <p className="service-port-privacy">Adding a port does not publish it or start your app. You choose access separately.</p>
          </section>
        </div>
      </DialogPanel>
      <DialogFooter className="service-port-footer">
        <span className="service-port-footer-note"><ArrowRightIcon aria-hidden="true" />Next: connection options</span>
        <div className="service-port-actions">
          <DialogClose render={<Button disabled={busy} className="rounded-full" type="button" variant="ghost" />}>Cancel</DialogClose>
          <Button className="service-port-submit" disabled={!environment} loading={busy} type="submit"><PlusIcon aria-hidden="true" />Add port</Button>
        </div>
      </DialogFooter>
    </Form>
  </DialogPopup>
}
