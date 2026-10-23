import { useState } from "react"
import { ChevronDownIcon } from "lucide-react"
import { gridApi, type GridHarness, type GridHub, type SwarmRun, type SwarmStrategy } from "@/api/grid-api"
import { Button } from "@/components/ui/button"
import { useArmed } from "@/components/use-armed"

/** Runs a change on the grid, reports it, and reads the status again. Resolves true only when the
 *  change went through, so a form clears itself after success and keeps its fields on failure. */
export type GridRun = (job: string, work: () => Promise<unknown>, done?: string) => Promise<boolean>

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)
const MAX_COMPUTERS = 32

const strategies: Record<SwarmStrategy, { label: string; round: string; explain: (computers: number) => string }> = {
  plan: {
    label: "Plan & delegate",
    round: "Rounds",
    explain: computers => `The lead splits each request into up to ${computers} independent tasks, one per computer, then combines the results. More rounds let it fill gaps.`,
  },
  mixture: {
    label: "Mixture",
    round: "Layers",
    explain: computers => `${computers} computers each answer the whole request; the lead writes one answer from all of them. A second layer lets them improve on each other first.`,
  },
}

function SwarmResult({ result }: { result: SwarmRun }) {
  const { trace } = result
  const parts = trace.rounds?.flatMap(round => round.tasks ?? []) ?? trace.layers?.flatMap(layer => layer.answers) ?? []
  const note = trace.rounds?.find(round => round.note)?.note
  return <div className="grid-swarm-result" aria-label="Swarm result">
    <p className="grid-swarm-summary">{parts.length} {trace.strategy === "plan" ? (parts.length === 1 ? "task" : "tasks") : (parts.length === 1 ? "answer" : "answers")} on {trace.computersUsed.length} {trace.computersUsed.length === 1 ? "computer" : "computers"} · {trace.seconds} s{trace.final?.computer ? ` · combined by ${trace.final.computer}` : ""}</p>
    {note ? <p className="grid-note">{note}</p> : null}
    <ul className="grid-swarm-parts">
      {parts.map((part, index) => <li key={`${part.title}-${index}`} data-failed={part.error ? true : undefined}>
        <strong>{part.title}</strong>
        <span>{part.computer ?? "no computer"} · {part.model} · {part.seconds} s</span>
        {part.error ? <em>{part.error}</em> : null}
      </li>)}
    </ul>
    <div className="grid-swarm-answer">{result.answer}</div>
  </div>
}

function SwarmRow({ harness, run }: { harness: GridHarness; run: GridRun }) {
  const { armed, arm, disarm } = useArmed()
  const [open, setOpen] = useState(false)
  const [prompt, setPrompt] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [result, setResult] = useState<SwarmRun | null>(null)
  const strategy = strategies[harness.strategy]
  const tryIt = async () => {
    if (busy || !prompt.trim()) return
    setBusy(true); setError(""); setResult(null)
    try { setResult(await gridApi.runHarness(harness.name, prompt.trim())) }
    catch (reason) { setError(message(reason)) }
    finally { setBusy(false) }
  }
  const rounds = harness.rounds > 1 ? ` · ${harness.rounds} ${strategy.round.toLowerCase()}` : ""
  return <>
    <div className="grid-line">
      <i aria-hidden="true" className="grid-dot" data-online={harness.ready || undefined} />
      <strong>{harness.model}</strong>
      <span className="grid-muted">{strategy.label} · {harness.lead} leads · {harness.computers} {harness.computers === 1 ? "computer" : "computers"} × {harness.workers.join(", ")}{rounds}{harness.ready ? "" : " · waiting for its models"}</span>
      <span className="grid-line-actions">
        <Button size="icon-xs" variant="ghost" aria-expanded={open} aria-label={open ? `Hide ${harness.model}` : `Try ${harness.model}`} onClick={() => setOpen(value => !value)}>
          <ChevronDownIcon aria-hidden="true" className="grid-chevron" data-open={open || undefined} />
        </Button>
        <Button size="xs" variant={armed === harness.id ? "destructive" : "ghost"} aria-label={`Remove ${harness.model}`} onClick={() => armed === harness.id ? (disarm(), void run(`Removing ${harness.model}`, () => gridApi.removeHarness(harness.id), `${harness.model} removed`)) : arm(harness.id)}>{armed === harness.id ? "Confirm" : "Remove"}</Button>
      </span>
    </div>
    {open ? <div className="grid-swarm-try">
      <form className="grid-line" onSubmit={event => { event.preventDefault(); void tryIt() }}>
        <textarea className="grid-box grid-swarm-prompt" aria-label={`Prompt for ${harness.model}`} rows={2} value={prompt} disabled={busy} placeholder="Ask the swarm something worth splitting up" onChange={event => setPrompt(event.target.value)} />
        <Button size="sm" type="submit" className="grid-run" disabled={busy || !prompt.trim()} loading={busy}>Run</Button>
      </form>
      {busy ? <p role="status" className="grid-note">The swarm is working on up to {harness.computers} {harness.computers === 1 ? "computer" : "computers"}…</p> : null}
      {error ? <p role="alert" className="grid-error grid-swarm-error">{error}</p> : null}
      {result ? <SwarmResult result={result} /> : null}
      <p className="grid-note">Apps call it with any grid API key as the model <code>{harness.model}</code>; the reply carries a <code>yougori_swarm</code> trace like the one above.</p>
    </div> : null}
  </>
}

function NewSwarm({ models, total, run }: { models: string[]; total: number; run: GridRun }) {
  const [name, setName] = useState("")
  const [strategy, setStrategy] = useState<SwarmStrategy>("plan")
  const [lead, setLead] = useState("")
  const [workers, setWorkers] = useState<string[]>([])
  const [computers, setComputers] = useState(String(Math.min(Math.max(total, 1), 5)))
  const [rounds, setRounds] = useState("1")
  if (!models.length) return <p className="grid-line grid-muted">Assign models to computers above first; a swarm uses the models the grid runs.</p>
  const leader = models.includes(lead) ? lead : models[0] ?? ""
  const team = workers.filter(worker => models.includes(worker))
  const count = Number(computers)
  const layers = strategy === "plan" ? 3 : 2
  const problem = !name ? "Name the swarm."
    : !/^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$/.test(name) ? "Use lowercase letters, digits and dashes."
    : !team.length ? "Pick at least one worker model."
    : !Number.isInteger(count) || count < 1 || count > MAX_COMPUTERS ? `Choose 1–${MAX_COMPUTERS} computers.`
    : ""
  const toggle = (model: string) => setWorkers(current => current.includes(model) ? current.filter(item => item !== model) : [...current, model])
  const add = () => {
    if (problem) return
    void run(`Adding swarm/${name}`, () => gridApi.addHarness({ name, strategy, lead: leader, workers: team, computers: count, rounds: Math.min(Number(rounds), layers) }), `swarm/${name} added`)
      .then(ok => { if (ok) { setName(""); setWorkers([]) } })
  }
  return <form className="grid-swarm-new" aria-label="New swarm" onSubmit={event => { event.preventDefault(); add() }}>
    <div className="grid-line grid-plan-form">
      <label className="grid-box grid-model-field grid-swarm-name">
        <span className="grid-box-affix" aria-hidden="true">swarm/</span>
        <input aria-label="Swarm name" value={name} placeholder="research" spellCheck={false} autoComplete="off" onChange={event => setName(event.target.value.toLowerCase().replace(/^swarm\//, "").replace(/[^a-z0-9-]/g, ""))} />
      </label>
      <span className="grid-seg grid-swarm-strategy" role="group" aria-label="Strategy">
        {(Object.keys(strategies) as SwarmStrategy[]).map(key => <button key={key} type="button" aria-pressed={strategy === key} onClick={() => { setStrategy(key); if (key === "mixture" && Number(rounds) > 2) setRounds("2") }}>{strategies[key].label}</button>)}
      </span>
      <select aria-label="Lead model" className="grid-box grid-select" value={leader} onChange={event => setLead(event.target.value)}>
        {models.map(model => <option key={model} value={model}>Lead: {model}</option>)}
      </select>
      <label className="grid-box grid-percent-field grid-swarm-count">
        <input aria-label="Computers per call" type="number" min={1} max={MAX_COMPUTERS} value={computers} onChange={event => setComputers(event.target.value)} />
        <span className="grid-box-affix" aria-hidden="true">PCs</span>
      </label>
      <select aria-label={strategies[strategy].round} className="grid-box grid-select" value={rounds} onChange={event => setRounds(event.target.value)}>
        {Array.from({ length: layers }, (_, index) => String(index + 1)).map(value => <option key={value} value={value}>{value} {value === "1" ? strategies[strategy].round.toLowerCase().replace(/s$/, "") : strategies[strategy].round.toLowerCase()}</option>)}
      </select>
    </div>
    <div className="grid-line grid-swarm-workers">
      <span className="grid-command-label">Workers</span>
      <span className="grid-swarm-chips" role="group" aria-label="Worker models">
        {models.map(model => <button key={model} type="button" aria-pressed={team.includes(model)} onClick={() => toggle(model)}>{model}</button>)}
      </span>
      <Button size="sm" type="submit" className="grid-run" disabled={Boolean(problem)} title={problem || undefined}>Add swarm</Button>
    </div>
    <p className="grid-note">{strategies[strategy].explain(Number.isInteger(count) && count > 0 ? count : 1)} {total ? `The grid has ${total} ${total === 1 ? "computer" : "computers"}; extra work waits for the next free one.` : ""}</p>
  </form>
}

/** Swarms: one call from an app runs a team of models across several of the grid's computers. */
export function GridSwarms({ hub, run }: { hub: GridHub; run: GridRun }) {
  const models = [...new Set(hub.plans.map(plan => plan.model))]
  return <section aria-label="Swarms" className="grid-part">
    <p className="grid-part-title">Swarms <span>one call, several computers</span></p>
    {hub.harnesses.map(harness => <SwarmRow key={harness.id} harness={harness} run={run} />)}
    <NewSwarm models={models} total={hub.computers.total} run={run} />
  </section>
}
