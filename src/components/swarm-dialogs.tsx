import { useEffect, useState } from "react"
import { swarmApi, type SwarmOffer, type SwarmWorker } from "@/api/swarm-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import "@/components/neo-grid.css"
import "@/components/swarm.css"
import { ClosedBountyDialog } from "./closed-bounty-dialog"
import { Terms } from "./swarm-terms"
import { readResearch } from "@/lib/research-authorisation"

const HF = "hf.co/"
const withoutPrefix = (value: string) => value.trimStart().replace(/^(https?:\/\/)?(www\.)?(hf\.co|huggingface\.co)\//i, "")
const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

const SUGGESTED = [
  { id: "mradermacher/Llama-3.2-3B-Instruct-abliterated-GGUF", label: "Llama 3.2 3B", note: "3B · fastest" },
  { id: "bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF", label: "Qwen2.5 Coder 7B", note: "7B · code" },
  { id: "mradermacher/Qwen3-VL-8B-Instruct-abliterated-GGUF", label: "Qwen3 8B", note: "8B" },
  { id: "mradermacher/Huihui-Qwen3.5-9B-abliterated-GGUF", label: "Qwen3.5 9B", note: "9B · all-round" },
  { id: "mradermacher/gemma-3-12b-it-projection-abliterated-GGUF", label: "Gemma 3 12B", note: "12B" },
  { id: "mradermacher/Huihui-Qwen3-14B-abliterated-v2-GGUF", label: "Qwen3 14B", note: "14B" },
  { id: "huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF", label: "Qwen3.8 27B", note: "27B · strongest" },
]

/** Join bounty hunting, or start a closed bounty on a source you give it. Both create a worker;
 *  a closed bounty then runs on this computer against the source, with nothing sent to the board. */
export function WorkerSetupDialog(props: { open: boolean; onOpenChange(open: boolean): void; mode: "join" | "closed"; onReady(message: string): void }) {
  return props.mode === "closed" ? <ClosedBountyDialog {...props} /> : <PublicWorkerSetupDialog {...props} />
}
function PublicWorkerSetupDialog({ open, onOpenChange, onReady }: { open: boolean; onOpenChange(open: boolean): void; onReady(message: string): void }) {
  const [name, setName] = useState("")
  const [model, setModel] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => { if (open) { setError(""); setName("Bounty worker") } }, [open])

  const problem = !name.trim() ? "Name the worker."
    : !model.trim() ? "Give the model it runs on, as owner/model."
    : ""

  const create = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      // A worker made here starts with what the Grids wizard was told to authorise, so
      // nobody is asked the same questions twice.
      const authorised = readResearch()
      await swarmApi.prepare({
        name: name.trim(),
        model: HF + model.trim(),
        ...(authorised ? { resources: { cpu: authorised.worker.cpu, memoryGb: authorised.worker.memoryGb }, workspaceQuotaGb: authorised.worker.diskGb } : {}),
      })
      onReady(`${name.trim()} joined; choose a bounty for it`)
      onOpenChange(false)
    } catch (reason) {
      setError(message(reason))
    } finally {
      setBusy(false)
    }
  }

  return <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Join bounty hunting</DialogTitle>
        <DialogDescription>A worker joins the public Yougori bounty board. You choose which bounty it accepts and the resources it uses.</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="grid-form" onSubmit={event => { event.preventDefault(); void create() }}>
          <div className="grid-field">
            <label htmlFor="swarm-name">Worker name</label>
            <Input id="swarm-name" value={name} disabled={busy} onChange={event => setName(event.target.value)} />
          </div>
          <div className="grid-field">
            <label htmlFor="swarm-model">Model it runs on</label>
            <label className="grid-box grid-model-field">
              <span className="grid-box-affix" aria-hidden="true">{HF}</span>
              <input id="swarm-model" aria-label="Model" value={model} disabled={busy} placeholder="owner/model-GGUF" spellCheck={false} autoComplete="off" onChange={event => setModel(withoutPrefix(event.target.value))} />
            </label>
            <p className="grid-hint">Use a <strong>GGUF</strong> model — a Hugging Face repo with <code>.gguf</code> files, which runs efficiently on this computer's GPU or CPU. Larger models need more memory.</p>
            <div className="swarm-suggest" role="group" aria-label="Suggested GGUF models">
              {SUGGESTED.map(suggestion => <button key={suggestion.id} type="button" disabled={busy} aria-pressed={model === suggestion.id} title={suggestion.id} onClick={() => setModel(suggestion.id)}>
                <strong>{suggestion.label}</strong><span>{suggestion.note}</span>
              </button>)}
            </div>
            <p className="grid-hint swarm-suggest-note">Uncensored (abliterated) GGUF models, small to large — a worker needs one that will not refuse security work. First run downloads it.</p>
            <p className="grid-hint">A GPU rented in NeoCloud can run a worker's model only for a closed bounty whose host allows it. Public bounties run on this computer, because the board doesn't ask their owners yet whether their code may go to an outside provider.</p>
          </div>
          {busy ? <p role="status" className="grid-hint">Setting up the worker and its model. The first run downloads the model.</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          <button type="submit" hidden aria-hidden="true" tabIndex={-1} />
        </form>
      </DialogPanel>
      <DialogFooter>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} title={problem || undefined} onClick={() => void create()}>Create worker</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}

/** Pick a bounty for a waiting worker. Accepting records that the person is authorized to test the
 *  target and accepts its rules; without both ticks the worker will not accept. */
export function AcceptBountyDialog({ worker, onOpenChange, onAccepted }: { worker: SwarmWorker | null; onOpenChange(open: boolean): void; onAccepted(message: string): void }) {
  const [offers, setOffers] = useState<SwarmOffer[] | null>(null)
  const [chosen, setChosen] = useState<SwarmOffer | null>(null)
  const [authorized, setAuthorized] = useState(false)
  const [rules, setRules] = useState(false)
  const [payment, setPayment] = useState(false)
  const [reportPolicy, setReportPolicy] = useState("review")
  const [budget, setBudget] = useState("30")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!worker) return
    let alive = true
    setOffers(null); setChosen(null); setAuthorized(false); setRules(false); setPayment(false); setError("")
    swarmApi.offers(worker.id).then(list => { if (alive) setOffers(list) }).catch(reason => { if (alive) { setOffers([]); setError(message(reason)) } })
    return () => { alive = false }
  }, [worker])

  if (!worker) return null
  const minutes = Number(budget)
  const problem = !chosen ? "Choose a bounty."
    : !authorized ? "Confirm you are authorized to test this target."
    : !payment ? "Accept the publisher's payment terms."
    : !rules ? "Accept the bounty's rules."
    : !Number.isInteger(minutes) || minutes < 5 || minutes > 240 ? "Set a time budget of 5–240 minutes."
    : ""

  const accept = async () => {
    if (busy || problem || !chosen) return
    setBusy(true); setError("")
    try {
      await swarmApi.accept(worker.id, chosen, minutes, reportPolicy)
      onAccepted(`${worker.name} accepted ${chosen.bounty.title ?? chosen.bounty.id}`)
      onOpenChange(false)
    } catch (reason) {
      setError(message(reason))
    } finally {
      setBusy(false)
    }
  }

  const terms = chosen?.bounty.terms?.serviceRules?.text
  return <Dialog open={Boolean(worker)} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog swarm-accept" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Choose a bounty for {worker.name}</DialogTitle>
        <DialogDescription>Only accept a bounty whose target you are authorized to test. Yougori records your authorization with the bounty's publisher.</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        {offers === null ? <p className="grid-hint">Looking for bounties…</p>
          : offers.length === 0 ? <p className="grid-hint">No bounties are open for this worker right now. Leave it waiting; new bounties appear here.</p>
          : <ul className="swarm-offers" aria-label="Bounties">
            {offers.map(offer => <li key={offer.id}>
              <button type="button" aria-pressed={chosen?.id === offer.id} onClick={() => { setChosen(offer); setAuthorized(false); setRules(false); setPayment(false) }}>
                <strong>{offer.bounty.title ?? offer.bounty.id}</strong>
                <span>{offer.bounty.publisher ? `${offer.bounty.publisher} · ` : ""}{typeof offer.bounty.reward === "object" ? `${offer.bounty.reward.amount ?? ""} ${offer.bounty.reward.currency ?? "USDC"}` : offer.bounty.reward ?? "reward on the board"}</span>
                {offer.bounty.summary ? <span className="swarm-offer-summary">{offer.bounty.summary}</span> : null}
              </button>
            </li>)}
          </ul>}

        {chosen ? <section className="swarm-consent" aria-label="Authorization">
          {chosen.bounty.terms?.objective ? <p>{chosen.bounty.terms.objective}</p> : null}
          {chosen.bounty.terms?.inScope ? <p className="grid-hint"><strong>Scope:</strong> {chosen.bounty.terms.inScope}</p> : null}
          {chosen.bounty.terms?.authorization ? <details><summary>Publisher authorization</summary><Terms value={chosen.bounty.terms.authorization} /></details> : null}
          <details><summary>Sandbox commands and network access</summary><Terms value={chosen.bounty.terms?.target ?? { setupCommand: chosen.bounty.terms?.setupCommand, testCommand: chosen.bounty.terms?.testCommand }} /></details>
          {chosen.bounty.scope ? <p className="grid-hint"><strong>Scope:</strong> {chosen.bounty.scope}</p> : null}
          {chosen.bounty.authorization ? <details className="grid-access"><summary>Authorization the publisher requires</summary><p>{chosen.bounty.authorization}</p></details> : null}
          {terms ? <details className="grid-access"><summary>Service rules</summary><p>{terms}</p></details> : null}
          <label className="swarm-check"><input type="checkbox" checked={authorized} disabled={busy} onChange={event => setAuthorized(event.target.checked)} /><span>I am authorized to test this target, and this computer may work it under the bounty's scope.</span></label>
          <label className="swarm-check"><input type="checkbox" checked={rules} disabled={busy} onChange={event => setRules(event.target.checked)} /><span>I accept the bounty's service rules.</span></label>
          <label className="swarm-check"><input type="checkbox" checked={payment} disabled={busy} onChange={event => setPayment(event.target.checked)} /><span>I understand the publisher pays rewards directly. Yougori does not hold or guarantee the funds.</span></label>
          <div className="grid-field"><label htmlFor="public-report">Report submission</label><select id="public-report" value={reportPolicy} onChange={event => setReportPolicy(event.target.value)} disabled={busy}><option value="review">Review reports before submission</option><option value="automatic">Submit supported reports automatically</option></select></div>
          <div className="grid-field grid-field-narrow">
            <label htmlFor="swarm-budget">Time budget (minutes)</label>
            <Input id="swarm-budget" type="number" min={5} max={240} value={budget} disabled={busy} onChange={event => setBudget(event.target.value)} />
          </div>
        </section> : null}
        {error ? <p role="alert" className="grid-error">{error}</p> : null}
      </DialogPanel>
      <DialogFooter>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} title={problem || undefined} onClick={() => void accept()}>Accept bounty</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
