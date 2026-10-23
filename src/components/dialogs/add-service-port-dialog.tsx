import { useRef, useState, type FormEvent } from "react"
import { QuickLinkAddress } from "@/components/cloudflare-account-fields"
import { Address, Slot } from "@/components/popup-kit"
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
      <DialogTitle className="service-port-title text-base leading-5"><span>Add a service port</span><span className="service-port-environment" title={name}> · {name}</span></DialogTitle>
      <DialogDescription className="sr-only">Tell Yougori which port your app listens on inside this environment. Nothing is published until you choose who can open it.</DialogDescription>
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
              <li><span aria-hidden="true">1</span><div><h3>It appears on the node</h3><p>The port shows on this environment in the graph, ready to connect.</p></div></li>
              <li><span aria-hidden="true">2</span><div><h3>You choose who can open it</h3><p>Open the port's settings and pick one, or both:</p></div></li>
            </ol>
            <div className="service-port-destinations">
              <span><span><strong>Local network</strong> · devices on your Wi-Fi or office network open <Address>http://<Slot>this PC's address</Slot>:<Slot>port</Slot></Address></span></span>
              <span><span><strong>Public access</strong> · anyone with the link opens a Cloudflare address such as <QuickLinkAddress />, or your own domain</span></span>
            </div>
            <p className="service-port-privacy">Adding a port does not publish it or start your app. Nothing is reachable until you choose.</p>
          </section>
        </div>
      </DialogPanel>
      <DialogFooter className="service-port-footer">
        <span className="service-port-footer-note">Next, you choose who can open it.</span>
        <div className="service-port-actions">
          <DialogClose render={<Button disabled={busy} className="rounded-full" type="button" variant="ghost" />}>Cancel</DialogClose>
          <Button className="service-port-submit" disabled={!environment} loading={busy} type="submit">Add port</Button>
        </div>
      </DialogFooter>
    </Form>
  </DialogPopup>
}
