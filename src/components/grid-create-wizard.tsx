import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { useWizard } from "@/components/use-wizard"
import { Address, Slot } from "@/components/popup-kit"
import {
  blueprintSteps, emptyBlueprint, HTTP_METHODS, rehearse, stepTitle,
  type GridBlueprint, type GridFacts, type GridRehearsal,
} from "@/lib/grid-blueprint"
import {
  CAPABILITY_LEAD, CAPABILITY_NAME, COMPANY_CAPABILITIES, chooseCapability, RESEARCH_IS_ALONE,
  type Capability,
} from "@/lib/grid-capability"
import "@/components/neo-grid.css"
import "@/components/grids.css"

const MIN_PASSWORD = 10

/** What creating a grid needs beside the blueprint: the password, and the sentences somebody
 *  agreed to. A grid is never created with a warning that nobody said yes to. */
export interface GridCreation {
  blueprint: GridBlueprint
  password: string
  accepted: string[]
}

/** One plain row of choices. No cards, no boxes: a radio, its name, one line about it and, where
 *  it helps, what picking it gives you, such as the address people will open. */
function Choice<T extends string>({ name, value, options, onPick, disabled }: {
  name: string
  value: T
  options: Array<{ value: T; label: string; lead?: string; preview?: ReactNode; disabled?: boolean }>
  onPick(value: T): void
  disabled?: boolean
}) {
  return <div className="grid-options" role="radiogroup" aria-label={name}>
    {options.map(option => <label key={option.value} className="grid-choice">
      <input
        type="radio"
        name={name}
        value={option.value}
        checked={value === option.value}
        disabled={disabled || option.disabled}
        onChange={() => onPick(option.value)}
      />
      <span className="grid-choice-words">
        <span className="grid-choice-label">{option.label}</span>
        {option.lead ? <span className="grid-muted">{option.lead}</span> : null}
        {option.preview ? <span className="grid-choice-preview">{option.preview}</span> : null}
      </span>
    </label>)}
  </div>
}

/** The port each kind of hub listens on, for the address shown under "This network only". */
const HUB_PORT: Partial<Record<Capability, number>> = { models: 7460, workspaces: 7463, credentials: 7465 }

/** A question with one answer in it. The hint sits outside the label on purpose: a label is the
 *  name of the field, and a paragraph of explanation is not part of anybody's name for it. */
function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <div className="grid-field grid-ask">
    <label>{label}{children}</label>
    {hint ? <span className="grid-muted">{hint}</span> : null}
  </div>
}

const lines = (text: string) => text.split("\n").map(one => one.trim()).filter(Boolean)

/** Creating a grid: what it is for comes first, then only that grid's own questions, with Back
 *  on every one of them and a dry run before anything at all is written.
 *
 *  Escape closes this dialog, as it does everywhere in the app. Nothing is kept when it does. */
export function GridCreateWizard({ open, onOpenChange, facts, me, onCreate, suggestedAddress }: {
  open: boolean
  onOpenChange(open: boolean): void
  facts: GridFacts
  me: string
  onCreate(creation: GridCreation): Promise<void>
  suggestedAddress(): Promise<string | null>
}) {
  const [answers, setAnswers] = useState<GridBlueprint>(() => emptyBlueprint(me))
  const [password, setPassword] = useState("")
  const [again, setAgain] = useState("")
  const [accepted, setAccepted] = useState<string[]>([])
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const [sourceText, setSourceText] = useState("")
  const steps = useMemo(() => blueprintSteps(), [])

  const close = useCallback(() => {
    setAnswers(emptyBlueprint(me))
    setPassword(""); setAgain(""); setAccepted([]); setError(""); setSourceText("")
    onOpenChange(false)
  }, [me, onOpenChange])

  const wizard = useWizard(steps, answers, close)

  useEffect(() => {
    if (!open) return
    void suggestedAddress().then(found => {
      if (found) setAnswers(current => current.address ? current : { ...current, address: found })
    }).catch(() => undefined)
  }, [open, suggestedAddress])

  const rehearsal: GridRehearsal = useMemo(() => rehearse(answers, facts), [answers, facts])
  const change = (part: Partial<GridBlueprint>) => setAnswers(current => ({ ...current, ...part }))
  const passwordProblem = password.length < MIN_PASSWORD
    ? `Use at least ${MIN_PASSWORD} characters for the password; a short sentence works well.`
    : password !== again ? "The two passwords are not the same." : ""
  const stepProblem = wizard.step.id === "password" ? passwordProblem : wizard.problem
  const research = answers.capabilities.includes("research")
  // Each purpose is served by its own hub, each on its own port.
  const hubPorts = answers.capabilities.flatMap(capability => HUB_PORT[capability] ?? [])
  const everyWarningAccepted = rehearsal.warnings.every(warning => accepted.includes(warning.id))

  const create = async () => {
    if (busy) return
    if (rehearsal.problem) { setError(`Go back to "${stepTitle(rehearsal.problem.step)}": ${rehearsal.problem.why}`); return }
    if (!everyWarningAccepted) { setError("Agree to each sentence above before this grid is created."); return }
    setBusy("Creating the grid"); setError("")
    try {
      await onCreate({ blueprint: answers, password, accepted })
      close()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setBusy("")
    }
  }

  const body = (): ReactNode => {
    const workspaces = answers.workspaces
    const models = answers.models
    const credentials = answers.credentials
    switch (wizard.step.id) {
      case "purpose":
        return <>
          <p className="grid-muted">Pick one, or more than one. Everything after this is only the questions that belong to what you pick.</p>
          <div className="grid-options">
            {[...COMPANY_CAPABILITIES, "research" as Capability].map(capability => <label key={capability} className="grid-choice">
              <input
                type="checkbox"
                checked={answers.capabilities.includes(capability)}
                onChange={() => change({ capabilities: chooseCapability(answers.capabilities, capability) })}
              />
              <span className="grid-choice-words">
                <span className="grid-choice-label">{CAPABILITY_NAME[capability]}</span>
                <span className="grid-muted">{CAPABILITY_LEAD[capability]}</span>
              </span>
            </label>)}
          </div>
          {research ? <p className="grid-note" role="note">{RESEARCH_IS_ALONE}</p> : null}
        </>
      case "name":
        return <Field label="Name" hint="People see this name wherever the grid appears.">
          <Input value={answers.name} placeholder="Acme" autoComplete="organization" onChange={event => change({ name: event.target.value })} />
        </Field>
      case "reach":
        return <>
          <Field label="This computer's address on your network">
            <Input value={answers.address} placeholder="192.168.1.20" onChange={event => change({ address: event.target.value })} />
          </Field>
          <Choice
            name="Who can reach it"
            value={answers.reach.kind}
            onPick={kind => change({ reach: kind === "domain" ? { kind, hostname: "" } : { kind } })}
            options={[
              {
                value: "network",
                label: "This network only",
                lead: "Company computers on the same Wi-Fi, office network or VPN connect straight to this computer. Nothing is published to the internet.",
                preview: answers.address.trim()
                  ? <>{hubPorts.map((port, at) => <span key={port}>{at ? " · " : ""}<Address>{answers.address.trim()}:{port}</Address></span>)}</>
                  : <span className="popup-quiet">This computer's address, once you type it above</span>,
              },
              {
                value: "quick",
                label: "Anywhere, through Cloudflare",
                lead: "Cloudflare's free quick tunnel relays the connection, so it works from any network. No Cloudflare account is needed, and Cloudflare only passes on encrypted traffic it cannot read. The link changes each time this computer restarts.",
                preview: <Address>https://<Slot>random-words</Slot>.trycloudflare.com</Address>,
              },
              {
                value: "domain",
                label: "Your own domain, through Cloudflare",
                lead: "A Cloudflare tunnel on your own account, saved under Public access setups, sends your domain to this computer. The address stays the same.",
                preview: answers.reach.kind === "domain" && answers.reach.hostname.trim()
                  ? <Address>https://{answers.reach.hostname.trim()}</Address>
                  : <span className="popup-quiet">Your domain, once you type it below</span>,
              },
            ]}
          />
          {answers.reach.kind === "domain" ? <Field label="Domain" hint="The one saved under Public access setups, such as grid.acme.com.">
            <Input value={answers.reach.hostname} placeholder="grid.acme.com" onChange={event => change({ reach: { kind: "domain", hostname: event.target.value } })} />
          </Field> : null}
        </>
      case "password":
        return <>
          <p className="grid-muted">Computers join with this and people sign in with it. It is never written in a summary, a record or a log.</p>
          <Field label="Password"><Input type="password" value={password} autoComplete="new-password" onChange={event => setPassword(event.target.value)} /></Field>
          <Field label="Password again"><Input type="password" value={again} autoComplete="new-password" onChange={event => setAgain(event.target.value)} /></Field>
        </>
      case "desks-sharing":
        return <Choice
          name="Who uses a desk"
          value={workspaces.sharing}
          onPick={sharing => change({ workspaces: { ...workspaces, sharing } })}
          options={[
            { value: "each", label: "One person each", lead: "Everybody gets their own desk and nobody else opens it." },
            { value: "shared", label: "Shared by a team", lead: "One desk a team opens in turn." },
          ]}
        />
      case "desks-commitment":
        return <Choice
          name="How much of a computer"
          value={workspaces.commitment}
          onPick={commitment => change({ workspaces: { ...workspaces, commitment } })}
          options={[
            { value: "share", label: "A share of it", lead: "The grid takes only what you give it and leaves the rest alone." },
            { value: "whole", label: "The whole computer", lead: "The grid decides what runs on it. You are asked to agree to this before it happens." },
          ]}
        />
      case "desks-share":
        return <>
          <p className="grid-muted">This is what a committed computer offers the grid, not the size of one desk.</p>
          <div className="grid-fields">
            <Field label="Processor cores"><Input type="number" min={1} value={workspaces.share.cpu} onChange={event => change({ workspaces: { ...workspaces, share: { ...workspaces.share, cpu: Number(event.target.value) } } })} /></Field>
            <Field label="Memory GB"><Input type="number" min={1} value={workspaces.share.memoryGb} onChange={event => change({ workspaces: { ...workspaces, share: { ...workspaces.share, memoryGb: Number(event.target.value) } } })} /></Field>
            <Field label="Disk GB"><Input type="number" min={1} value={workspaces.share.diskGb} onChange={event => change({ workspaces: { ...workspaces, share: { ...workspaces.share, diskGb: Number(event.target.value) } } })} /></Field>
          </div>
          <label className="grid-choice">
            <input type="checkbox" checked={workspaces.share.gpu} onChange={event => change({ workspaces: { ...workspaces, share: { ...workspaces.share, gpu: event.target.checked } } })} />
            <span className="grid-choice-words"><span className="grid-choice-label">Desks may use its graphics card</span></span>
          </label>
        </>
      case "desks-disk":
        return <Field label="Disk for one desk, in GB" hint="This is the only size that belongs to a desk. Cores and memory come from the computer that holds it.">
          <Input type="number" min={1} value={workspaces.deskDiskGb} onChange={event => change({ workspaces: { ...workspaces, deskDiskGb: Number(event.target.value) } })} />
        </Field>
      case "desks-image":
        return <>
          <Choice
            name="What a desk is built from"
            value={workspaces.image.kind}
            onPick={kind => change({ workspaces: {
              ...workspaces,
              // A container image settles what a desk is; anything else is asked outright next.
              kind: kind === "registry" ? "container" : workspaces.kind,
              image: kind === "registry" ? { kind, reference: "" } : kind === "prepared" ? { kind, name: "" } : { kind: "default" },
            } })}
            options={[
              { value: "default", label: "The workspace Yougori builds", lead: "Ready to use, with the usual tools." },
              { value: "registry", label: "A container image", lead: "Any image your company already publishes." },
              { value: "prepared", label: "A prepared workspace", lead: "A disk your company published for this grid." },
            ]}
          />
          {workspaces.image.kind === "registry" ? <Field label="Container image" hint="A container image makes every desk here a container.">
            <Input value={workspaces.image.reference} placeholder="docker.io/library/ubuntu:24.04" onChange={event => change({ workspaces: { ...workspaces, kind: "container", image: { kind: "registry", reference: event.target.value } } })} />
          </Field> : null}
          {workspaces.image.kind === "prepared" ? <Field label="Prepared workspace">
            <Input value={workspaces.image.name} placeholder="Research desktop" onChange={event => change({ workspaces: { ...workspaces, image: { kind: "prepared", name: event.target.value } } })} />
          </Field> : null}
        </>
      case "desks-kind":
        return <Choice
          name="What a desk is"
          value={workspaces.kind}
          onPick={kind => change({ workspaces: { ...workspaces, kind } })}
          options={[
            { value: "container", label: "A container", lead: "Starts in a moment and shares the computer's own system." },
            { value: "microVm", label: "A microVM", lead: "Its own small system, kept apart from the computer." },
            { value: "vm", label: "A virtual machine", lead: "A whole machine of its own, for a prepared disk." },
          ]}
        />
      case "desks-network":
        return <Choice
          name="What a desk can reach"
          value={workspaces.network}
          onPick={network => change({ workspaces: { ...workspaces, network } })}
          options={[
            { value: "standard", label: "The usual", lead: "A desk reaches the internet as the computer does." },
            { value: "restricted", label: "Restricted", lead: "No guest network at all; a desk reaches nothing on its own." },
          ]}
        />
      case "models-model":
        return <Field label="Model" hint="The owner and model, as Hugging Face writes it.">
          <span className="grid-model-field"><span className="grid-box-affix">hf.co/</span>
            <Input value={models.model} placeholder="owner/model" onChange={event => change({ models: { ...models, model: event.target.value.replace(/^(https?:\/\/)?(www\.)?(hf\.co|huggingface\.co)\//i, "") } })} />
          </span>
        </Field>
      case "models-quant":
        return <Choice
          name="Which size of it"
          value={models.quant || "fits"}
          onPick={quant => change({ models: { ...models, quant: quant === "fits" ? "" : quant } })}
          options={[
            { value: "fits", label: "Whichever fits", lead: "Each computer runs the largest one it can." },
            { value: "Q4_K_M", label: "Q4_K_M", lead: "Smaller and faster, on most computers." },
            { value: "Q6_K", label: "Q6_K", lead: "Closer to the original, where there is room." },
            { value: "Q8_0", label: "Q8_0", lead: "Nearly the original, on computers with plenty of memory." },
          ]}
        />
      case "models-scope":
        return <Choice
          name="Which computers run it"
          value={models.scope}
          onPick={scope => change({ models: { ...models, scope } })}
          options={[
            { value: "remaining", label: "The ones without a model", lead: "Leaves every computer that already serves one alone." },
            { value: "all", label: "All of them", lead: "Every computer in the grid, whatever it runs now." },
            { value: "computers", label: "Ones you pick", lead: "You choose them after the grid exists and its computers have joined." },
          ]}
        />
      case "models-percent":
        return <Field label="Percent of those computers">
          <Input type="number" min={1} max={100} value={models.percent} onChange={event => change({ models: { ...models, percent: Number(event.target.value) } })} />
        </Field>
      case "models-idle":
        return <Field label="Minutes with nobody at the keyboard before it serves" hint="Zero serves whatever anybody is doing on the computer.">
          <Input type="number" min={0} value={models.idleAfterMinutes} onChange={event => change({ models: { ...models, idleAfterMinutes: Number(event.target.value) } })} />
        </Field>
      case "models-schedule":
        return <Field label="When it may serve" hint="In your own words and your own time, such as weekdays 19:00 to 07:00. Leave it empty for any time.">
          <Input value={models.schedule} placeholder="any time" onChange={event => change({ models: { ...models, schedule: event.target.value } })} />
        </Field>
      case "credentials-name":
        return <Field label="Name" hint="A name people recognise. Its value is never asked for here; you add that once the grid exists.">
          <Input value={credentials.name} placeholder="Deploy key" onChange={event => change({ credentials: { ...credentials, name: event.target.value } })} />
        </Field>
      case "credentials-destination":
        return <Field label="Destination" hint="The one address it may ever be sent to, over HTTPS.">
          <Input value={credentials.destination} placeholder="https://api.github.com" onChange={event => change({ credentials: { ...credentials, destination: event.target.value } })} />
        </Field>
      case "credentials-methods":
        return <div className="grid-options">
          {HTTP_METHODS.map(method => <label key={method} className="grid-choice">
            <input
              type="checkbox"
              checked={credentials.methods.includes(method)}
              onChange={() => change({ credentials: { ...credentials, methods: credentials.methods.includes(method) ? credentials.methods.filter(one => one !== method) : [...credentials.methods, method] } })}
            />
            <span className="grid-choice-words"><span className="grid-choice-label">{method}</span></span>
          </label>)}
        </div>
      case "credentials-paths":
        return <Field label="Paths" hint="One prefix a line, such as /repos/acme. Leave it empty for any path.">
          <textarea className="grid-sheet-text" rows={4} value={credentials.paths.join("\n")} onChange={event => change({ credentials: { ...credentials, paths: lines(event.target.value) } })} />
        </Field>
      case "credentials-approval":
        return <Choice
          name="Who says yes"
          value={credentials.approval}
          onPick={approval => change({ credentials: { ...credentials, approval } })}
          options={[
            { value: "allow", label: "At once", lead: "Anyone the rule names uses it without asking. Nobody ever sees its value." },
            { value: "ask", label: "An approver decides", lead: "The first use waits for an approver, then runs for a while." },
            { value: "everyTime", label: "An approver decides every time", lead: "Every single use waits for a person." },
          ]}
        />
      case "credentials-rotation":
        return <Choice
          name="How often it is replaced"
          value={credentials.rotateEveryDays === null ? "never" : String(credentials.rotateEveryDays)}
          onPick={value => change({ credentials: { ...credentials, rotateEveryDays: value === "never" ? null : Number(value) } })}
          options={[
            { value: "30", label: "Every 30 days" },
            { value: "90", label: "Every 90 days" },
            { value: "180", label: "Every 180 days" },
            { value: "never", label: "Never", lead: "Nothing replaces it by itself; the date is there for you to see." },
          ]}
        />
      case "research-scope":
        return <Field label="What this research is authorised to do" hint="In a sentence. Everything the work does is held against this.">
          <textarea className="grid-sheet-text" rows={3} value={answers.research.scope} onChange={event => change({ research: { ...answers.research, scope: event.target.value } })} />
        </Field>
      case "research-sources":
        return <Field label="What it works on" hint="One folder, repository or host a line.">
          <textarea
            className="grid-sheet-text"
            rows={4}
            value={sourceText}
            onChange={event => {
              setSourceText(event.target.value)
              change({ research: { ...answers.research, sources: lines(event.target.value).map(value => ({ kind: value.includes("://") ? "repository" as const : value.includes("/") || value.includes("\\") ? "folder" as const : "host" as const, value })) } })
            }}
          />
        </Field>
      case "research-network":
        return <>
          <Choice
            name="What it may reach"
            value={answers.research.network}
            onPick={network => change({ research: { ...answers.research, network } })}
            options={[
              { value: "offline", label: "Nothing at all", lead: "The work runs offline. This is how a research grid starts." },
              { value: "destinations", label: "These destinations only", lead: "Everything else stays offline. You are asked to agree to this." },
            ]}
          />
          {answers.research.network === "destinations" ? <Field label="Destinations" hint="One a line.">
            <textarea className="grid-sheet-text" rows={3} value={answers.research.destinations.join("\n")} onChange={event => change({ research: { ...answers.research, destinations: lines(event.target.value) } })} />
          </Field> : null}
        </>
      case "research-worker":
        return <>
          <Choice
            name="What the work runs in"
            value={answers.research.worker.kind}
            onPick={kind => change({ research: { ...answers.research, worker: { ...answers.research.worker, kind } } })}
            options={[
              { value: "container", label: "A container" },
              { value: "microVm", label: "A microVM", lead: "Its own system, apart from this computer." },
              { value: "vm", label: "A virtual machine" },
            ]}
          />
          <div className="grid-fields">
            <Field label="Processor cores"><Input type="number" min={1} value={answers.research.worker.cpu} onChange={event => change({ research: { ...answers.research, worker: { ...answers.research.worker, cpu: Number(event.target.value) } } })} /></Field>
            <Field label="Memory GB"><Input type="number" min={1} value={answers.research.worker.memoryGb} onChange={event => change({ research: { ...answers.research, worker: { ...answers.research.worker, memoryGb: Number(event.target.value) } } })} /></Field>
            <Field label="Disk GB"><Input type="number" min={1} value={answers.research.worker.diskGb} onChange={event => change({ research: { ...answers.research, worker: { ...answers.research.worker, diskGb: Number(event.target.value) } } })} /></Field>
          </div>
        </>
      case "research-approval":
        return <Choice
          name="When somebody has to say yes"
          value={answers.research.approval}
          onPick={approval => change({ research: { ...answers.research, approval } })}
          options={[
            { value: "beforeStart", label: "Before it starts" },
            { value: "beforeEachSource", label: "Before each source is taken in" },
            { value: "never", label: "Never", lead: "The authorised scope is the only thing holding it." },
          ]}
        />
      case "people":
        return <>
          <Field label="Administrators" hint="One username a line. The first one is the account this computer signs in as.">
            <textarea className="grid-sheet-text" rows={3} value={answers.administrators.join("\n")} onChange={event => change({ administrators: lines(event.target.value) })} />
          </Field>
          <Field label="Approvers" hint="One username a line. They decide what waits for a person.">
            <textarea className="grid-sheet-text" rows={3} value={answers.approvers.join("\n")} onChange={event => change({ approvers: lines(event.target.value) })} />
          </Field>
        </>
      case "summary":
        return <section aria-label="What would happen" className="grid-part">
          <p className="grid-part-title">What would happen <span>nothing is written until you create it</span></p>
          <p className="grid-line">{rehearsal.headline}</p>
          {rehearsal.lines.map(line => <p key={line.label} className="grid-line">
            <span className="grid-key">{line.label}</span>
            <span>{line.value}</span>
          </p>)}
          {rehearsal.wouldCreate.map(sentence => <p key={sentence} className="grid-line grid-muted">{sentence}</p>)}
          {rehearsal.problem
            ? <p role="alert" className="grid-line grid-error">
              Go back to "{stepTitle(rehearsal.problem.step)}": {rehearsal.problem.why}
              {" "}<Button size="xs" variant="ghost" onClick={() => wizard.goTo(rehearsal.problem?.step ?? "purpose")}>Go back to it</Button>
            </p>
            : null}
          {rehearsal.warnings.map(warning => <label key={warning.id} className="grid-choice grid-agree">
            <input
              type="checkbox"
              checked={accepted.includes(warning.id)}
              onChange={() => setAccepted(current => current.includes(warning.id) ? current.filter(one => one !== warning.id) : [...current, warning.id])}
            />
            <span className="grid-choice-words"><span role="alert" className="grid-choice-label">{warning.sentence}</span></span>
          </label>)}
        </section>
      default:
        return null
    }
  }

  return <Dialog open={open} onOpenChange={value => { if (!busy && !value) close() }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Create a grid</DialogTitle>
        <DialogDescription>{wizard.step.title}</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="grid-form" onSubmit={event => { event.preventDefault(); if (wizard.last) void create(); else wizard.next() }}>
          {body()}
          {stepProblem && wizard.step.id !== "summary" ? <p className="grid-note">{stepProblem}</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
        </form>
      </DialogPanel>
      <DialogFooter>
        <span role="status" className="grid-muted">{busy ? `${busy}…` : `Question ${wizard.place} of ${wizard.total}`}</span>
        <Button variant="ghost" disabled={Boolean(busy)} onClick={wizard.back}>Back</Button>
        {wizard.last
          ? <Button
            loading={Boolean(busy)}
            disabled={Boolean(busy) || Boolean(rehearsal.problem) || !everyWarningAccepted}
            onClick={() => void create()}
          >{research ? "Open Swarm Mining" : "Create the grid"}</Button>
          : <Button disabled={Boolean(stepProblem)} onClick={() => wizard.next()}>Next</Button>}
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
