import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { stepAfter, useWizard, type AskedStep } from "@/components/use-wizard"
import { hubApi, type SavedTemplate } from "@/api/hub-api"
import { CATALOGUE, withAvailability, type CatalogueEntry } from "@/api/setups/catalogue"
import { changedAnswers, draftAnswers, errorText, isUnavailable, newOperationId, SetupCommandError, secretBindings, setupsApi, type PlanAsk } from "@/api/setups/setups-api"
import { setupFeed, useOperation, useSetupFeed } from "@/api/setups/progress"
import type {
  CapabilityGroup, CapabilityReport, Diagnostic, GridProfile, NextAction, RecipeSlug, SettingDescriptor, SetupDraft, SetupPlan, SetupStepId, SourceRef,
} from "@/api/setups/types"
import { usePlatformOptional } from "@/context/platform-context"
import { storageDrives, driveLabel } from "@/lib/storage-drives"
import { CapabilityBoard, SettingFields } from "./capability-board"
import { answered, canTurnOn, fieldCandidates, fieldId, gridKinds, gridKindProblem, nameProblem, needsGridKind, profileOfRecipe, questionField, selectedIds, selectionProblem, toggled, withGridKind } from "./draft"
import { hubRefFrom } from "./setup-link"
import type { BuilderIntent, EntryKind } from "./setup-intent"
import { SetupSource } from "./setup-source"
import { ALL_ACTIONS, GENERAL_ACTIONS, useNextActions } from "./use-next-actions"
import type { DetailTab } from "./setup-detail"
import { DiagnosticList, SetupOutputs, SetupProgress, SetupReadiness, SetupReview } from "./setup-views"
import "./setups.css"

/** Creating a template, running one, or changing an installed setup, in one place.
 *
 *  The steps are the ones every setup has: what it starts from and its name, which capabilities
 *  it has, compute and storage, models and tools, an administrator when one is needed, people and
 *  access, a concrete review, progress that survives closing this window, and what is ready.
 *  Steps with nothing to ask are skipped. Every step has Back and Cancel. The engine checks,
 *  plans and applies; this only shows what it said.
 *
 *  A template starts from capabilities the author adds, or from something imported: there is no
 *  starter catalogue to pick from first. The questions asked afterwards are the ones the engine
 *  reads from the choices, so this and the CLI ask the same things of the same draft.
 */

type StepId = "entry" | "source" | "capabilities" | "template" | "compute" | "models" | "admin" | "people" | "review" | "progress" | "ready"
type Mode = BuilderIntent["mode"]

interface EntryState {
  kind: EntryKind
  setupId: string | null
  environments: string[]
  path: string
  hubRef: string
}

interface Answers {
  mode: Mode
  running: boolean
  draft: SetupDraft
  entry: EntryState
  entries: CatalogueEntry[]
  secrets: Record<string, string>
  repeated: Record<string, string>
  operationId: string | null
  loadFailed: boolean
  profile: GridProfile
  /** A new setup on this computer can pick which drive its sandboxes go on, so the compute step
   *  opens for that even when the template asks nothing else there. False for a change. */
  canChooseDrive: boolean
  /** The drive chosen for a new setup's sandboxes, or "". */
  storageDrive: string
}

/** A template with Storage drive keeps its data where the person running it says, so on a
 *  computer with more than one drive it waits for that choice. */
function driveProblem(answers: Pick<Answers, "canChooseDrive" | "draft" | "storageDrive">) {
  return answers.canChooseDrive && answers.draft.capabilities["data.storage_drive"]?.selected && !answers.storageDrive ? "Choose the drive its data is kept on to go on." : ""
}

/** Which step asks a question when the question does not say. */
const STEP_OF_GROUP: Record<CapabilityGroup, SetupStepId> = {
  grid_workers: "compute",
  automation_recovery: "compute",
  ai_models: "models",
  people_access: "people",
  website_api: "people",
  files_data: "people",
}

/** The questions asked at this step: those of selected capabilities, and those of no capability. */
function questionsAt(step: SetupStepId, answers: Pick<Answers, "draft" | "entries">): SettingDescriptor[] {
  const groupOf = new Map(answers.entries.map(entry => [entry.descriptor.id, entry.descriptor.group]))
  return (answers.draft.questions ?? []).filter(question => {
    if (question.capability && !answers.draft.capabilities[question.capability]?.selected) return false
    const group = question.group ?? (question.capability ? groupOf.get(question.capability) : undefined) ?? "people_access"
    return (question.step ?? STEP_OF_GROUP[group]) === step
  })
}

/** The first question at this step that must be answered and isn't, in words, or "". */
function unanswered(step: SetupStepId, answers: Pick<Answers, "draft" | "entries" | "secrets">) {
  for (const question of questionsAt(step, answers)) {
    if (!question.required || question.editable === false) continue
    const value = question.kind === "secret" ? answers.secrets[questionField(question)]
      : question.capability ? answers.draft.capabilities[question.capability]?.settings[question.id] ?? question.default
      : answers.draft.answers?.[question.id] ?? question.default
    if (value === undefined || value === "") return `Answer "${question.label}" to go on.`
  }
  return ""
}

function entryProblem(entry: EntryState) {
  switch (entry.kind) {
    case "setup": return entry.setupId ? "" : "Choose a setup."
    case "environments": return entry.environments.length ? "" : "Choose at least one environment."
    case "folder": return entry.path ? "" : "Choose the project folder."
    case "compose": return entry.path ? "" : "Choose the Compose file."
    case "hub": return hubRefFrom(entry.hubRef) ? "" : "Enter a Hub address, such as hub/publisher/name."
    default: return ""
  }
}

const STEPS: (AskedStep<Answers> & { id: StepId; modes: Mode[] })[] = [
  {
    id: "entry", modes: ["create"], title: "How do you want to start?",
    when: () => true,
    problem: answers => nameProblem(answers.draft.name) || entryProblem(answers.entry),
  },
  {
    id: "source", modes: ["run"], title: "Choose what to set up",
    when: () => true,
    problem: answers => entryProblem(answers.entry) || nameProblem(answers.draft.name),
  },
  {
    id: "capabilities", modes: ["create", "run", "configure"], title: "Choose what it can do",
    when: () => true,
    // An author's draft also has to say which kind of grid it is when it has one; a template
    // being run or changed already says so in its source.
    problem: answers => answers.loadFailed ? "This setup couldn't be read, so it can't be changed here." : selectionProblem(answers.draft, answers.entries, answers.profile) || (answers.mode === "create" ? gridKindProblem(answers.draft) : ""),
  },
  { id: "template", modes: ["create"], title: "Your template", when: () => true, problem: () => "" },
  { id: "compute", modes: ["create", "run", "configure"], title: "Compute, storage and limits", when: answers => answers.running && (questionsAt("compute", answers).length > 0 || answers.canChooseDrive), problem: answers => unanswered("compute", answers) || driveProblem(answers) },
  { id: "models", modes: ["create", "run", "configure"], title: "Models, tools and sign-ins", when: answers => answers.running && questionsAt("models", answers).length > 0, problem: answers => unanswered("models", answers) },
  {
    id: "admin", modes: ["create", "run"], title: "Administrator",
    when: answers => answers.running && questionsAt("admin", answers).length > 0,
    problem: answers => {
      for (const question of questionsAt("admin", answers)) {
        if (question.kind !== "secret") continue
        const field = questionField(question)
        if (!answers.secrets[field]) return `Enter ${question.label.toLowerCase()}.`
        if (answers.secrets[field] !== answers.repeated[field]) return `The two entries for ${question.label.toLowerCase()} are different.`
      }
      return unanswered("admin", answers)
    },
  },
  { id: "people", modes: ["create", "run", "configure"], title: "People, connections and access", when: answers => answers.running && questionsAt("people", answers).length > 0, problem: answers => unanswered("people", answers) },
  { id: "review", modes: ["create", "run", "configure"], title: "What will happen", when: answers => answers.running, problem: answers => selectionProblem(answers.draft, answers.entries, answers.profile) },
  { id: "progress", modes: ["create", "run", "configure"], title: "Setting it up", when: answers => answers.running && Boolean(answers.operationId), problem: () => "" },
  { id: "ready", modes: ["create", "run", "configure"], title: "What is ready", when: answers => answers.running && Boolean(answers.operationId), problem: () => "" },
]

/** How a template starts: by adding capabilities, first and by default, or by importing something
 *  that already describes one. */
const ENTRY_OPTIONS: { kind: EntryKind; label: string; lead: string }[] = [
  { kind: "blank", label: "Add capabilities", lead: "Start empty and choose what it can do from the six groups." },
  { kind: "hub", label: "Import a Hub template", lead: "Start from a template someone published." },
  { kind: "folder", label: "Import a project folder", lead: "Read a project and suggest what it needs." },
  { kind: "compose", label: "Import a Compose file", lead: "Turn a supported Compose file into a template." },
  { kind: "setup", label: "Use an existing setup", lead: "Make a template from something already set up here." },
  { kind: "environments", label: "Use environments on this computer", lead: "Make a template from sandboxes you choose." },
]

/** Where a template to run comes from: the Hub, or a folder holding one on this computer. */
const SOURCE_OPTIONS: { kind: EntryKind; label: string; lead: string }[] = [
  { kind: "hub", label: "A template from the Hub", lead: "Community templates are not checked by Yougori. Read the files first." },
  { kind: "folder", label: "A template folder on this computer", lead: "One you saved, exported or downloaded, with its yougori-template.yaml." },
]

const CAPTURE_NOTE = "This makes a template, not a copy. Not copied: disks, runtime data, sign-ins, variable values and access to folders on this computer, and you choose which files are included. To take a whole environment with its data, use Download under My computer, which has its own review."
const IN_PROGRESS_STEPS: StepId[] = ["review", "progress", "ready"]
const TYPED = new Set(["text", "password", "number", "email", "url"])

/** A folder the person picks on this computer, for a template's folder binding. */
function isFolderQuestion(question: SettingDescriptor) {
  return question.binding === "folder"
}

/** Why a folder can't be used, if it can't: the planner's own rule (format::folder_choice_problem),
 *  so a folder picked here is never refused later. */
function folderProblem(path: string) {
  const text = path.trim()
  if (!text) return ""
  const windowsDrive = /^[A-Za-z]:[\\/]/.test(text)
  if (!(text.startsWith("/") || windowsDrive || text.startsWith("\\\\"))) {
    return "That is not a full path. Choose a folder on this computer."
  }
  if (text.split(/[\\/]/).some(part => part === "..")) return "Choose the folder's own full path, without .."
  return ""
}

/** One folder binding: what it is for, what the setup may do with it, and a picker.
 *  The sentence under it is the engine's own (`draft::folder_access`), so a person reads the same
 *  words here, in the CLI and in the review. */
function FolderField({ question, value, onPick, onProblem }: {
  question: SettingDescriptor
  value: string
  onPick(path: string): void
  onProblem(message: string): void
}) {
  const id = fieldId(question.id)
  return <div className="setup-field">
    <label htmlFor={id}>{question.label}{question.required ? <span className="setup-note"> (needed)</span> : null}</label>
    <div className="setup-field-inline">
      <input id={id} className="setup-input" type="text" readOnly aria-describedby={`${id}-access`} value={value} placeholder="No folder chosen" />
      <Button
        size="sm"
        variant="secondary"
        onClick={async () => {
          try {
            const { open: choose } = await import("@tauri-apps/plugin-dialog")
            const picked = await choose({ directory: true, multiple: false, title: question.label })
            if (typeof picked !== "string") return
            const problem = folderProblem(picked)
            if (problem) { onProblem(problem); return }
            onProblem("")
            onPick(picked)
          } catch {
            onProblem("Choosing a folder needs Yougori Desktop.")
          }
        }}
      >{value ? "Change folder" : "Choose folder"}</Button>
      {value && !question.required
        ? <Button size="sm" variant="link" onClick={() => onPick("")}>Use none</Button>
        : null}
    </div>
    {question.help ? <span className="setup-note">{question.help}</span> : null}
    {question.access ? <span className="setup-note" id={`${id}-access`}>{question.access}</span> : null}
  </div>
}

function Field({ label, hint, htmlFor, children }: { label: string; hint?: string; htmlFor: string; children: ReactNode }) {
  return <div className="setup-field">
    <label htmlFor={htmlFor}>{label}</label>
    {children}
    {hint ? <span className="setup-note" id={`${htmlFor}-hint`}>{hint}</span> : null}
  </div>
}

/** "Where should its sandboxes be stored?", for a new setup only. The default is the usual drive —
 *  nothing is sent, and the engine chooses. Any other choice is one of this computer's drives that
 *  can take sandboxes, with its free space shown, and it stays once set: a sandbox can't move drives
 *  in place. `drives` are already filtered to the ones the engine would accept. */
function StorageDriveField({ drives, value, onChange, required = false }: { drives: { path: string; freeGb: number }[]; value: string; onChange(drive: string): void; required?: boolean }) {
  return <section className="setup-settings-group" aria-label="Storage">
    <h4>Storage</h4>
    <Field label="Where should its sandboxes be stored?" htmlFor={fieldId("storage-drive")} hint="They stay on this drive. To use another drive later you make the setup again on it.">
      <select id={fieldId("storage-drive")} className="setup-input" value={value} onChange={event => onChange(event.target.value)}>
        <option value="">{required ? "Choose a drive" : "The usual drive"}</option>
        {drives.map(drive => <option key={drive.path} value={drive.path}>{driveLabel(drive.path)} · {drive.freeGb.toFixed(0)} GB free</option>)}
        {value && !drives.some(drive => drive.path === value) ? <option value={value} disabled>{driveLabel(value)} · not available now</option> : null}
      </select>
    </Field>
  </section>
}

function emptyDraft(intent: BuilderIntent): SetupDraft {
  const capabilities: SetupDraft["capabilities"] = {}
  if (intent.mode === "configure") {
    // An update plans the newest version of the template against the setup's own choices.
    const source: SourceRef = intent.update ? { kind: "hub", ...intent.update } : { kind: "installed_setup", setupId: intent.setupId }
    return { name: intent.setupName ?? "", source, capabilities }
  }
  return { name: "", capabilities }
}

function firstEntry(intent: BuilderIntent): EntryState {
  const base: EntryState = { kind: "blank", setupId: null, environments: [], path: "", hubRef: "" }
  if (intent.mode === "configure") return { ...base, kind: "setup", setupId: intent.setupId }
  if (intent.mode === "run" && intent.folder) return { ...base, kind: "folder", path: intent.folder }
  if (intent.hubRef) return { ...base, kind: "hub", hubRef: intent.hubRef }
  if (intent.mode === "run") return { ...base, kind: "hub" }
  return { ...base, kind: intent.entry ?? "blank", environments: intent.environments ?? [] }
}

/** A Hub address with its version pinned. A setup never follows a moving latest, so an address
 *  without a version is pinned to the version the Hub has now. */
async function pinnedHub(ref: string): Promise<SourceRef> {
  const [, publisher, name, version] = ref.match(/^hub\/([^/]+)\/([^@]+)(?:@(.+))?$/) ?? []
  if (!publisher || !name) throw new Error("This is not a Hub address.")
  if (version) return { kind: "hub", publisher, name, version }
  const item = await hubApi.detail(publisher, name)
  const latest = item.version?.version ?? item.latestVersion
  if (!latest) throw new Error(`${ref} has no version that can be run.`)
  return { kind: "hub", publisher, name, version: latest }
}

export interface TemplateBuilderProps {
  intent: BuilderIntent
  open: boolean
  onClose(): void
  /** Opens My setups, after something was set up, on that setup's tab when one is named. */
  onShowSetups?(setupId: string | null, tab?: DetailTab): void
  /** Where focus goes back to when this closes. */
  returnFocus?: React.RefObject<HTMLElement | null>
}

export function TemplateBuilder({ intent, open, onClose, onShowSetups, returnFocus }: TemplateBuilderProps) {
  const mode = intent.mode
  const steps = useMemo(() => STEPS.filter(step => step.modes.includes(mode)), [mode])
  const initialDraft = useMemo(() => emptyDraft(intent), [intent])
  const [draft, setDraft] = useState<SetupDraft>(initialDraft)
  const [entry, setEntry] = useState<EntryState>(() => firstEntry(intent))
  const [running, setRunning] = useState(mode !== "create")
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const [repeated, setRepeated] = useState<Record<string, string>>({})
  const [statuses, setStatuses] = useState<CapabilityReport[] | null>(null)
  const [engine, setEngine] = useState<"checking" | "ready" | "unavailable" | "failed">("checking")
  const [manifest, setManifest] = useState<string | null>(null)
  const [project, setProject] = useState<string | null>(null)
  const [saved, setSaved] = useState<SavedTemplate | null>(null)
  /** Files the generated template carries beside its two, such as the cloud model gateway. */
  const [extraFiles, setExtraFiles] = useState<Record<string, string>>({})
  const [checked, setChecked] = useState<Diagnostic[] | null>(null)
  const [published, setPublished] = useState("")
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([])
  // Plain notes from an import (a Compose file): what it carried over, shown before Continue.
  const [importNotes, setImportNotes] = useState<string[]>([])
  // What the engine's generator put in the source because a choice needs it, by id: the same
  // "added for you" the CLI's `template new` reports.
  const [added, setAdded] = useState<string[]>([])
  const [validateState, setValidateState] = useState<{ unavailable: boolean; error: string }>({ unavailable: false, error: "" })
  const [view, setView] = useState<"choose" | "source">("choose")
  const [plan, setPlan] = useState<{ key: string; plan: SetupPlan } | null>(null)
  const [planError, setPlanError] = useState<{ key: string; error: Error } | null>(null)
  const [operationId, setOperationId] = useState<string | null>(null)
  const [setupId, setSetupId] = useState<string | null>(mode === "configure" ? intent.setupId : null)
  const [busy, setBusy] = useState("")
  const [error, setError] = useState<ReactNode>("")
  const [confirmingClose, setConfirmingClose] = useState(false)
  const [confirmingCancel, setConfirmingCancel] = useState(false)
  const [loaded, setLoaded] = useState(mode !== "configure")
  const [loadFailed, setLoadFailed] = useState(false)
  /** What counts as unchanged: the draft as it started, or as the engine read it in. */
  const [baseline, setBaseline] = useState<SetupDraft>(initialDraft)
  const [checkAttempt, setCheckAttempt] = useState(0)
  const [copied, setCopied] = useState(false)
  const [agreed, setAgreed] = useState<string[]>([])
  /** The drive a new setup's sandboxes are stored on. "" means the usual drive: nothing is sent and
   *  the engine chooses. Only asked for a new setup; a change keeps the drive the setup is already on. */
  const [storageDrive, setStorageDrive] = useState("")
  const pendingFocus = useRef<string | null>(null)
  /** Counts "Go to" links, so one that stays on the same step and view still moves focus. */
  const [focusTick, setFocusTick] = useState(0)
  const groupFocus = useRef<CapabilityGroup | null>(intent.group ?? null)
  const searched = useRef(intent.mode === "create" ? intent.capability ?? null : null)
  const heading = useRef<HTMLHeadingElement>(null)
  /** The operation id for applying one reviewed plan: made on the first click, sent again
   *  unchanged when that same plan is retried, and never reused for a different plan. */
  const pendingOperation = useRef<{ digest: string; id: string } | null>(null)
  const platform = usePlatformOptional()
  const feed = useSetupFeed()
  const operation = useOperation(operationId)

  // A capability wired only for some grid profiles is unsupported in a setup of another one. The
  // profile is the kind of grid the draft says it is, from its author or its source.
  const installed = intent.mode === "configure" ? feed.setups?.find(one => one.setupId === intent.setupId)?.profile : undefined
  const profile = installed ?? profileOfRecipe(draft.recipe) ?? "generic"
  // While a template is being made its kind of grid can still change, so what belongs to another
  // kind is offered with it; a setup that exists keeps the kind it has.
  const switchable = mode === "create" && !installed
  const entries = useMemo(() => withAvailability(CATALOGUE, statuses, profile, { running, switchable }), [statuses, profile, running, switchable])
  // Chosen, but not something the grid kind chosen for it holds.
  const misfits = useMemo(() => profileOfRecipe(draft.recipe) ? entries.filter(entry => entry.availability === "other_grid" && draft.capabilities[entry.descriptor.id]?.selected) : [], [entries, draft.recipe, draft.capabilities])
  const names = useMemo(() => Object.fromEntries(entries.map(one => [one.descriptor.id, one.descriptor.name])), [entries])
  // The drives a new setup's sandboxes could go on, by the same rule the engine checks: a real
  // drive of this computer that can be written to, isn't removable, and has room to start one.
  const drives = useMemo(
    () => (platform?.state?.host ? storageDrives(platform.state.host) : []).filter(drive => drive.path && !drive.readOnly && !drive.removable && drive.freeGb >= 10),
    [platform?.state],
  )
  // A change keeps the drive its sandboxes are on, so the choice is only offered for a new setup,
  // and only when this computer has more than one drive it could go on.
  const canChooseDrive = intent.mode !== "configure" && drives.length > 1
  const answers: Answers = { mode, running, draft, entry, entries, secrets, repeated, operationId, loadFailed, profile, canChooseDrive, storageDrive }
  const started = Boolean(operationId)
  const dirty = JSON.stringify(draft) !== JSON.stringify(baseline) || Object.values(secrets).some(Boolean)
  const choiceProblem = selectionProblem(draft, entries, profile)

  const close = useCallback(() => { setConfirmingClose(false); onClose() }, [onClose])
  const nextActions = useNextActions({ onActivity: onShowSetups ? () => { close(); onShowSetups(setupId, "activity") } : undefined })
  const requestClose = useCallback(() => {
    if (started || !dirty) close()
    else setConfirmingClose(true)
  }, [started, dirty, close])
  const wizard = useWizard(steps, answers, requestClose)
  const step = wizard.step.id as StepId

  // What this computer can use, asked when the builder opens. A failed check is asked again,
  // waiting longer each time; until one succeeds nothing can be turned on.
  useEffect(() => {
    let live = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const wait = Math.min(2_000 * 2 ** Math.max(0, checkAttempt - 1), 30_000)
    const ask = () => setupsApi.capabilities()
      .then(result => { if (live) { setStatuses(result); setEngine("ready") } })
      .catch(reason => {
        if (!live) return
        if (isUnavailable(reason)) { setEngine("unavailable"); return }
        setEngine("failed")
        setCheckAttempt(attempt => attempt + 1)
      })
    if (checkAttempt === 0) void ask()
    else timer = setTimeout(() => void ask(), wait)
    return () => { live = false; if (timer) clearTimeout(timer) }
  }, [checkAttempt])

  // A capability a search led to is chosen once this computer has been checked, and only if it
  // can really be used here.
  useEffect(() => {
    const id = searched.current
    if (!id || !statuses) return
    searched.current = null
    const found = entries.find(one => one.descriptor.id === id)
    if (found && !draft.capabilities[id]?.selected && canTurnOn(draft, found)) setDraft(current => toggled(current, found.descriptor, true))
  }, [statuses, entries, draft])

  // An installed setup is read into the same choices a new one has.
  useEffect(() => {
    if (intent.mode !== "configure") return
    let live = true
    setupsApi.validate({ source: { kind: "installed_setup", setupId: intent.setupId } })
      .then(result => {
        if (!live) return
        if (!result.draft) { setLoadFailed(true); setError("Yougori couldn't read what this setup is made of, so it can't be changed here yet. Nothing was changed."); setLoaded(true); return }
        const read = { ...result.draft, name: result.draft.name || initialDraft.name, source: initialDraft.source }
        setDraft(read)
        setBaseline(read)
        setManifest(result.manifest); setProject(result.project ?? null); setDiagnostics(result.diagnostics ?? []); setLoaded(true)
      })
      .catch(reason => { if (live) { setLoadFailed(true); setError(isUnavailable(reason) ? "Changing a setup is not available in this build of Yougori yet. Nothing was changed." : `${errorText(reason)} Nothing was changed.`); setLoaded(true) } })
    return () => { live = false }
  }, [intent, initialDraft])

  // The engine checks the draft and writes its source while an author chooses its capabilities.
  // A template being run or changed is checked by its plan instead, against its own source.
  useEffect(() => {
    if (mode !== "create" || (step !== "capabilities" && step !== "template")) return
    let live = true
    const timer = setTimeout(() => {
      setupsApi.validate({ draft })
        .then(result => {
          if (!live) return
          setManifest(result.manifest); setProject(result.project ?? null); setExtraFiles(result.files && typeof result.files === "object" ? result.files : {}); setDiagnostics(result.diagnostics ?? []); setAdded(Array.isArray(result.added) ? result.added.filter(id => typeof id === "string") : []); setValidateState({ unavailable: false, error: "" })
          // The questions the template it makes asks when it runs, so "Run it here" asks them.
          // Taken only when they change, so this check isn't run again for nothing.
          const asked = result.draft?.questions
          if (Array.isArray(asked)) setDraft(current => JSON.stringify(current.questions ?? []) === JSON.stringify(asked) ? current : { ...current, questions: asked })
        })
        .catch(reason => { if (live) setValidateState(isUnavailable(reason) ? { unavailable: true, error: "" } : { unavailable: false, error: errorText(reason) }) })
    }, 350)
    return () => { live = false; clearTimeout(timer) }
  }, [draft, step, mode])

  // A step change moves focus to the step's heading, so it is read out and Tab starts there. A
  // "Go to" link sends it to the field instead.
  useEffect(() => {
    if (!open) return
    const frame = requestAnimationFrame(() => {
      const wanted = pendingFocus.current
      pendingFocus.current = null
      if (wanted) {
        // The field itself when it is on screen, otherwise the capability it belongs to.
        const target = [wanted, ...fieldCandidates(wanted)].map(field => document.getElementById(fieldId(field))).find(Boolean)
        if (target) { target.scrollIntoView?.({ block: "center" }); target.focus(); return }
      }
      // A search that led to a group opens the capabilities there, the first time they show.
      const group = step === "capabilities" && view === "choose" && loaded ? groupFocus.current : null
      const groupHeading = group ? document.getElementById(`setup-group-${group}`) : null
      if (groupHeading) {
        groupFocus.current = null
        groupHeading.scrollIntoView?.({ block: "start" })
        groupHeading.focus()
        return
      }
      heading.current?.focus()
    })
    return () => cancelAnimationFrame(frame)
  }, [step, view, open, loaded, focusTick])

  useEffect(() => { if (confirmingClose) document.getElementById("setup-keep-editing")?.focus() }, [confirmingClose])

  const given = useMemo(() => {
    const asked = new Set((draft.questions ?? [])
      .filter(question => question.kind === "secret" && (!question.capability || draft.capabilities[question.capability]?.selected))
      .map(questionField))
    return Object.fromEntries(Object.entries(secrets).filter(([field, value]) => value && asked.has(field)))
  }, [secrets, draft])
  // A new setup can be put on a chosen drive; a change keeps the drive it is on, so the choice is
  // only sent, and only part of what is re-planned, when the setup is new.
  const askDrive = intent.mode !== "configure" && storageDrive ? storageDrive : undefined
  const planKey = JSON.stringify([draft, Object.keys(given).sort(), askDrive ?? ""])

  const makePlan = useCallback(async () => {
    setBusy("Working out what would happen")
    try {
      const ask: PlanAsk = {
        ...(draft.source ? { source: draft.source } : { draft }),
        name: draft.name.trim(),
        answers: intent.mode === "configure" && intent.update ? changedAnswers(draft, baseline) : draftAnswers(draft),
        bindings: secretBindings(Object.keys(given)),
        ...(intent.mode === "configure" ? { existingSetup: intent.setupId } : {}),
        ...(askDrive ? { storageDrive: askDrive } : {}),
      }
      const made = await setupsApi.plan(ask)
      setPlan({ key: planKey, plan: made })
      setPlanError(null)
      // A new review starts with nothing agreed to.
      setAgreed([])
    } catch (reason) {
      setPlan(null)
      setPlanError({ key: planKey, error: reason instanceof Error ? reason : new Error(String(reason)) })
    } finally {
      setBusy("")
    }
  }, [intent, draft, baseline, given, planKey, askDrive])

  // The review is made when the step is reached, and again whenever what it reviews changed.
  useEffect(() => {
    if (step !== "review" || busy || started || choiceProblem) return
    if (plan?.key === planKey || planError?.key === planKey) return
    void makePlan()
  }, [step, busy, started, choiceProblem, plan, planError, planKey, makePlan])

  const goToField = (field: string) => {
    pendingFocus.current = field
    setFocusTick(tick => tick + 1)
    setView("choose")
    if (field === "name") wizard.goTo(mode === "run" ? "source" : mode === "create" ? "entry" : "capabilities")
    else wizard.goTo("capabilities")
  }

  /** Reads a setup, folder or Hub template into choices. A blank start needs nothing read. */
  async function expand(from: typeof entry = entry): Promise<boolean> {
    const entry = from
    if (entry.kind === "blank") { setDraft(current => ({ ...current, source: null, environments: [] })); return true }
    setBusy("Reading it")
    setError("")
    try {
      const start: SetupDraft = { name: draft.name.trim(), capabilities: {} }
      if (entry.kind === "setup" && entry.setupId) start.source = { kind: "installed_setup", setupId: entry.setupId }
      else if (entry.kind === "folder") start.source = { kind: "local_folder", path: entry.path }
      else if (entry.kind === "hub") start.source = await pinnedHub(hubRefFrom(entry.hubRef) ?? "")
      // A Compose file and chosen environments are both captured by the engine into a draft; they are
      // not a lasting source the setup follows, so they go straight to validate and the draft stands
      // on its own. Their notes (what was left out) are shown before Continue.
      const captureSource =
        entry.kind === "compose" ? { kind: "compose" as const, path: entry.path }
        : entry.kind === "environments" ? { kind: "environments" as const, environments: entry.environments }
        : null
      const result = captureSource
        ? await setupsApi.validate({ source: captureSource })
        : await setupsApi.validate(start.source ? { source: start.source } : { draft: start })
      if (result.valid === false && !result.draft) {
        setDiagnostics(result.diagnostics ?? [])
        setError(result.diagnostics?.[0]?.message ?? "This template could not be read.")
        return false
      }
      const read = result.draft ?? start
      // The kind of grid is the source's own word, when it has one.
      setDraft({ ...read, name: start.name || read.name || "", source: start.source ?? read.source ?? null, recipe: read.recipe ?? null, environments: start.environments ?? read.environments })
      setManifest(result.manifest); setProject(result.project ?? null)
      setDiagnostics(result.diagnostics ?? [])
      // An import's notes (what a Compose file carried over) are shown before Continue.
      // The engine sends import notes as diagnostics now (one shape for drafts and imports);
      // filtering to strings silently dropped every one of them.
      setImportNotes(captureSource ? (result.notes ?? []).map(note => (typeof note === "string" ? note : note.message)) : [])
      return true
    } catch (reason) {
      setError(isUnavailable(reason)
        ? mode === "create"
          ? "This build of Yougori can't read setups, folders or Hub templates yet. Add capabilities instead, or try again after updating."
          : "This build of Yougori can't read folders or Hub templates yet, so nothing can be set up from one. Try again after updating."
        : errorText(reason))
      return false
    } finally {
      setBusy("")
    }
  }

  async function readSource(text: string): Promise<boolean> {
    setBusy("Reading the source")
    try {
      const result = await setupsApi.validate({ source: text })
      if (!result.draft) {
        setDiagnostics(result.diagnostics ?? [])
        setValidateState({ unavailable: false, error: "The engine couldn't read this source. Your edits are kept: fix the problems below and try again." })
        return false
      }
      setDraft(result.draft)
      setManifest(result.manifest); setProject(result.project ?? null)
      setDiagnostics(result.diagnostics ?? [])
      setValidateState({ unavailable: false, error: "" })
      return true
    } catch (reason) {
      setValidateState(isUnavailable(reason) ? { unavailable: true, error: "" } : { unavailable: false, error: `${errorText(reason)} Your edits are kept.` })
      return false
    } finally {
      setBusy("")
    }
  }

  async function next() {
    if (wizard.problem || busy) return
    setError("")
    if ((step === "entry" || step === "source") && !(await expand())) return
    wizard.next()
  }

  function runHere() {
    if (choiceProblem) return
    setRunning(true)
    const following = stepAfter(steps, { ...answers, running: true }, "template")
    if (following) wizard.goTo(following.id)
  }

  const reviewAgain = () => { pendingOperation.current = null; setError(""); setPlan(null); setPlanError(null) }

  async function apply() {
    if (!plan || busy || choiceProblem) return
    if (pendingOperation.current?.digest !== plan.plan.digest) pendingOperation.current = { digest: plan.plan.digest, id: newOperationId() }
    setBusy("Starting")
    setError("")
    try {
      const offered = new Set((plan.plan.consents ?? []).map(consent => consent.id))
      const result = await setupsApi.apply(plan.plan, pendingOperation.current.id, given, agreed.filter(id => offered.has(id)))
      setOperationId(result.operationId)
      setSetupId(result.setupId)
      pendingOperation.current = null
      // Secret values were only for this; nothing keeps them now.
      setSecrets({})
      setRepeated({})
      void setupFeed.refresh(result.setupId)
      wizard.goTo("progress")
    } catch (reason) {
      const code = reason instanceof SetupCommandError ? reason.code : ""
      if (code === "plan_expired" || code.includes("revision")) {
        // A fresh review replaces the old one by itself; nothing is applied until it is read.
        pendingOperation.current = null
        setPlan(null)
        setPlanError(null)
        setError(`${code === "plan_expired" ? "This review expired before it was applied" : "This setup changed since the review"}, so nothing was changed. A fresh review is below: check it, then set it up again.`)
      } else if (code === "setup_busy") {
        const other = reason instanceof SetupCommandError ? reason.operation : null
        pendingOperation.current = null
        setError(<>Another change to this setup is still running, so nothing new was started.{other ? <> <Button size="xs" variant="link" onClick={() => { setError(""); setOperationId(other); wizard.goTo("progress") }}>Show its progress</Button></> : null}</>)
      } else {
        // A retry of the same click joins the same operation; a refusal gets a new id next time.
        if (!(reason instanceof SetupCommandError && reason.retryable)) pendingOperation.current = null
        setError(isUnavailable(reason) ? "Setting this up is not available in this build of Yougori yet. Nothing was changed." : errorText(reason))
      }
    } finally {
      setBusy("")
    }
  }

  async function operationAction(action: NextAction) {
    if (GENERAL_ACTIONS.has(action.kind)) { nextActions.act(action); return }
    if (!operationId) return
    if (action.kind === "cancel") { setConfirmingCancel(true); return }
    if (action.kind === "review") { setOperationId(null); reviewAgain(); wizard.goTo("review"); return }
    if (!setupId) return
    const target = action.kind === "continue" || action.kind === "reconcile" ? action.operation || operationId : operationId
    setBusy(action.kind === "reconcile" ? "Checking what happened" : "Trying again")
    try {
      const result = await setupsApi.action(setupId, action.kind === "reconcile" ? "reconcile" : "retry", { operationId: target })
      if (result?.operationId) setOperationId(result.operationId)
      void setupFeed.refresh(setupId)
    } catch (reason) {
      setError(errorText(reason))
    } finally {
      setBusy("")
    }
  }

  async function cancelOperation() {
    if (!operationId) return
    setConfirmingCancel(false)
    setBusy("Cancelling")
    try {
      await setupsApi.cancel(operationId)
      void setupFeed.refresh(setupId ?? undefined)
    } catch (reason) {
      setError(errorText(reason))
    } finally {
      setBusy("")
    }
  }

  /** Writes the template into a folder somebody picks: empty, or the one it was saved in before. */
  async function saveToFolder() {
    if (!manifest || busy) return
    setError("")
    let folder: string | null = null
    try {
      const { open: choose } = await import("@tauri-apps/plugin-dialog")
      const picked = await choose({ directory: true, multiple: false, title: "Choose a folder for this template" })
      folder = typeof picked === "string" ? picked : null
    } catch {
      setError("Saving a template needs Yougori Desktop.")
      return
    }
    if (!folder) return
    setBusy("Saving the template")
    try {
      setSaved(await hubApi.saveTemplateDraft({ folder, template: manifest, project, ...(Object.keys(extraFiles).length ? { files: extraFiles } : {}) }))
      setChecked(null)
      setPublished("")
    } catch (reason) {
      setError(errorText(reason))
    } finally {
      setBusy("")
    }
  }

  /** Reads the saved folder back the way a publish would, and says what it found. */
  async function checkSaved() {
    if (!saved || busy) return
    setBusy("Checking the folder")
    setError("")
    try {
      const result = await setupsApi.validate({ source: { kind: "local_folder", path: saved.folder } })
      setChecked(result.diagnostics ?? [])
    } catch (reason) {
      setError(isUnavailable(reason) ? "Checking templates is not available in this build of Yougori yet. The files are saved." : errorText(reason))
    } finally {
      setBusy("")
    }
  }

  async function publishSaved() {
    if (!saved || busy) return
    setBusy("Opening a console")
    setError("")
    try {
      const result = await hubApi.openConsole("publishTemplate", saved.folder)
      setPublished(`A console window opened with ${result.command}. It checks the folder, shows what will be uploaded, and asks before anything is published.`)
    } catch (reason) {
      setError(errorText(reason))
    } finally {
      setBusy("")
    }
  }

  async function pickPath(kind: "folder" | "compose") {
    try {
      const { open: choose } = await import("@tauri-apps/plugin-dialog")
      const picked = await choose(kind === "folder"
        ? { directory: true, multiple: false, title: "Choose the project folder" }
        : { directory: false, multiple: false, title: "Choose the Compose file", filters: [{ name: "Compose file", extensions: ["yml", "yaml"] }] })
      if (typeof picked === "string") {
        const chosen = { ...entry, path: picked }
        setEntry(chosen)
        // Convert a chosen Compose file at once, so what it carried over (and anything it could not)
        // is shown on this step, before Continue. Choosing a folder stays read on Continue as before.
        if (kind === "compose") await expand(chosen)
      }
    } catch {
      setError("Choosing a file needs Yougori Desktop.")
    }
  }

  const adding = intent.mode === "configure" && Boolean(intent.addCapability)
  const updating = intent.mode === "configure" ? intent.update : undefined
  const title = mode === "create" ? "Create template" : mode === "run" ? "Run a template" : updating ? `Update ${draft.name || "this setup"} to ${updating.version}` : adding ? `Add a capability to ${draft.name || "this setup"}` : `Configure ${draft.name || "this setup"}`
  const stepTitle = step === "capabilities" && mode === "run" ? "Choose what to include"
    : step === "capabilities" && mode === "configure" ? (adding ? "Add a capability" : "Change what it can do")
    : wizard.step.title
  const engineNote = engine === "unavailable"
    ? "This build of Yougori can't check or create setups yet. You can look through what templates can do; setting one up needs a newer Yougori."
    : engine === "failed" ? "Yougori couldn't check what this computer supports, so nothing is marked available yet." : ""

  const setSecret = (field: string, value: string) => setSecrets(current => ({ ...current, [field]: value }))
  const valueOf = (question: SettingDescriptor) => question.capability ? draft.capabilities[question.capability]?.settings[question.id] : draft.answers?.[question.id]
  const editableFor = (question: SettingDescriptor) => mode === "create" || !question.capability || (draft.capabilities[question.capability]?.runnerEditable ?? true)

  const questionsBody = (at: SetupStepId) => {
    const all = questionsAt(at, answers)
    // A folder the person picks on this computer is asked with a picker, and with the same
    // sentence about what the setup may do with it that the review and the CLI use.
    const folders = all.filter(isFolderQuestion)
    const questions = all.filter(question => !isFolderQuestion(question))
    const byCapability = new Map<string, SettingDescriptor[]>()
    for (const question of questions) byCapability.set(question.capability ?? "", [...(byCapability.get(question.capability ?? "") ?? []), question])
    return <div className="setup-step-settings">
      {folders.length > 0 ? <section className="setup-settings-group" aria-label="Folders on this computer">
        <h4>Folders on this computer</h4>
        {folders.map(question => <FolderField
          key={question.id}
          question={question}
          value={typeof draft.answers?.[question.id] === "string" ? String(draft.answers[question.id]) : ""}
          onPick={value => setDraft(current => answered(current, question, value))}
          onProblem={setError}
        />)}
      </section> : null}
      {[...byCapability.entries()].map(([capability, asked]) => <section key={capability || "general"} className="setup-settings-group" aria-label={capability ? names[capability] ?? capability : "General"}>
        <h4>{capability ? names[capability] ?? capability : "General"}</h4>
        <SettingFields
          questions={asked}
          values={valueOf}
          editable={asked.every(editableFor)}
          author={false}
          secrets={secrets}
          onAnswer={(question, value) => setDraft(current => answered(current, question, value))}
          onSecret={setSecret}
        />
        {at === "admin" ? asked.filter(question => question.kind === "secret").map(question => {
          const field = questionField(question)
          return <Field key={field} label={`${question.label} again`} htmlFor={`${fieldId(field)}-again`}>
            <input id={`${fieldId(field)}-again`} className="setup-input" type="password" autoComplete="new-password" value={repeated[field] ?? ""} onChange={event => setRepeated(current => ({ ...current, [field]: event.target.value }))} />
          </Field>
        }) : null}
      </section>)}
    </div>
  }

  function body() {
    switch (step) {
      case "entry": return <>
        <Field label="Template name" htmlFor={fieldId("name")} hint="People see this name on the Hub.">
          <input id={fieldId("name")} className="setup-input" value={draft.name} aria-describedby={`${fieldId("name")}-hint`} onChange={event => setDraft({ ...draft, name: event.target.value })} />
        </Field>
        <fieldset className="setup-options">
          <legend>Start from</legend>
          {ENTRY_OPTIONS.map(option => <label key={option.kind} className="grid-choice">
            <input type="radio" name="setup-entry" value={option.kind} checked={entry.kind === option.kind} onChange={() => setEntry({ ...entry, kind: option.kind })} />
            <span className="grid-choice-words"><span className="grid-choice-label">{option.label}</span><span className="setup-note">{option.lead}</span></span>
          </label>)}
        </fieldset>
        {entry.kind === "setup" ? <fieldset className="setup-options">
          <legend>Which setup</legend>
          {feed.unavailable ? <p className="setup-note">Setups are not available in this build yet.</p>
            : !feed.setups ? <p className="setup-note" role="status">Reading your setups…</p>
            : feed.setups.filter(one => !one.adoptedLegacy).length ? feed.setups.filter(one => !one.adoptedLegacy).map(one => <label key={one.setupId} className="grid-choice">
              <input type="radio" name="setup-entry-setup" checked={entry.setupId === one.setupId} onChange={() => setEntry({ ...entry, setupId: one.setupId })} />
              <span className="grid-choice-label">{one.name}</span>
            </label>) : <p className="setup-note">Nothing is set up on this computer yet.</p>}
        </fieldset> : null}
        {entry.kind === "environments" ? <fieldset className="setup-options">
          <legend>Which environments</legend>
          {(platform?.state?.environments ?? []).filter(one => one.id !== platform?.state?.cliEnvironmentId).map(one => <label key={one.id} className="grid-choice">
            <input type="checkbox" checked={entry.environments.includes(one.id)} onChange={event => { setImportNotes([]); setEntry({ ...entry, environments: event.target.checked ? [...entry.environments, one.id] : entry.environments.filter(id => id !== one.id) }) }} />
            <span className="grid-choice-label">{one.name}</span>
          </label>)}
          {!(platform?.state?.environments ?? []).length ? <p className="setup-note">There are no environments on this computer yet.</p> : null}
          {entry.environments.length ? <Button size="xs" variant="outline" className="setup-inline-button" disabled={Boolean(busy)} onClick={() => void expand(entry)}>See what would be captured</Button> : null}
        </fieldset> : null}
        {entry.kind === "folder" || entry.kind === "compose" ? <div className="setup-field">
          <span className="setup-field-label">{entry.kind === "folder" ? "Project folder" : "Compose file"}</span>
          <span className="setup-path">{entry.path || "None chosen yet"}</span>
          <Button size="xs" variant="outline" className="setup-inline-button" onClick={() => void pickPath(entry.kind as "folder" | "compose")}>{entry.path ? "Choose another" : entry.kind === "folder" ? "Choose a folder" : "Choose a file"}</Button>
        </div> : null}
        {(entry.kind === "compose" || entry.kind === "environments") && importNotes.length ? <ul className="setup-callout" aria-label="What the import brought over">{importNotes.map((note, index) => <li key={index}>{note}</li>)}</ul> : null}
        {entry.kind === "hub" ? <Field label="Hub address" htmlFor="setup-entry-hub" hint="For example hub/publisher/name, or hub/publisher/name@1.2.0 for one version.">
          <input id="setup-entry-hub" className="setup-input" value={entry.hubRef} spellCheck={false} aria-describedby="setup-entry-hub-hint" onChange={event => setEntry({ ...entry, hubRef: event.target.value })} />
        </Field> : null}
        {entry.kind === "setup" || entry.kind === "environments" || entry.kind === "folder" || entry.kind === "compose" ? <p className="setup-callout" role="note">{CAPTURE_NOTE}</p> : null}
      </>
      case "source": return <>
        <fieldset className="setup-options">
          <legend>Where it comes from</legend>
          {SOURCE_OPTIONS.map(option => <label key={option.kind} className="grid-choice">
            <input type="radio" name="setup-source" value={option.kind} checked={entry.kind === option.kind} onChange={() => setEntry({ ...entry, kind: option.kind })} />
            <span className="grid-choice-words"><span className="grid-choice-label">{option.label}</span><span className="setup-note">{option.lead}</span></span>
          </label>)}
        </fieldset>
        {entry.kind === "hub" ? <Field label="Hub address" htmlFor="setup-source-hub" hint="For example hub/publisher/name.">
          <input id="setup-source-hub" className="setup-input" value={entry.hubRef} spellCheck={false} aria-describedby="setup-source-hub-hint" onChange={event => setEntry({ ...entry, hubRef: event.target.value })} />
        </Field> : null}
        {entry.kind === "folder" ? <div className="setup-field">
          <span className="setup-field-label">Template folder</span>
          <span className="setup-path">{entry.path || "None chosen yet"}</span>
          <Button size="xs" variant="outline" className="setup-inline-button" onClick={() => void pickPath("folder")}>{entry.path ? "Choose another" : "Choose a folder"}</Button>
        </div> : null}
        <Field label="Name for this setup" htmlFor={fieldId("name")} hint="Each setup on this computer has its own name.">
          <input id={fieldId("name")} className="setup-input" value={draft.name} aria-describedby={`${fieldId("name")}-hint`} onChange={event => setDraft({ ...draft, name: event.target.value })} />
        </Field>
      </>
      case "capabilities": return !loaded ? <p role="status" className="setup-note">Reading {draft.name || "this setup"}…</p> : loadFailed ? null : <>
        <span className="grid-seg setup-views" role="group" aria-label="Show">
          <button type="button" aria-pressed={view === "choose"} onClick={() => setView("choose")}>Capabilities</button>
          <button type="button" aria-pressed={view === "source"} onClick={() => setView("source")}>Source</button>
        </span>
        {view === "choose"
          ? <>
            {mode === "create" && needsGridKind(draft) ? <GridKindField value={draft.recipe ?? null} leavesOut={profile => selectedIds(draft).filter(id => { const kinds = CATALOGUE.find(one => one.id === id)?.profiles ?? []; return kinds.length > 0 && !kinds.includes(profile) }).map(id => names[id] ?? id)} onPick={slug => setDraft(current => ({ ...current, recipe: slug }))} /> : null}
            {mode === "create" && misfits.length ? <p className="setup-callout" role="note">
              A {gridKinds().find(kind => kind.slug === draft.recipe)?.name ?? "grid of this kind"} can't hold {misfits.map(entry => entry.descriptor.name).join(", ")}. Choose another kind of grid above, or turn {misfits.length === 1 ? "it" : "them"} off.{" "}
              <Button size="xs" variant="outline" onClick={() => setDraft(current => misfits.reduce((next, entry) => toggled(next, entry.descriptor, false), current))}>Turn {misfits.length === 1 ? "it" : "them"} off</Button>
            </p> : null}
            {mode === "create" && added.length ? <p className="setup-callout" role="note">Added for you (needed by your choices): {added.map(id => names[id] ?? id).join(", ")}. {added.length === 1 ? "It is" : "They are"} in the source because something you chose needs {added.length === 1 ? "it" : "them"}; tick {added.length === 1 ? "it" : "them"} here to go on, or turn off what needs {added.length === 1 ? "it" : "them"}.</p> : null}
            <CapabilityBoard
              entries={entries}
              draft={draft}
              mode={mode}
              diagnostics={diagnostics}
              secrets={secrets}
              focusGroup={intent.group ?? null}
              profile={profile}
              onDraft={next => setDraft(mode === "create" ? withGridKind(next) : next)}
              onSecret={setSecret}
              onGoTo={goToField}
            />
          </>
          : <SetupSource manifest={manifest} diagnostics={diagnostics} names={names} unavailable={validateState.unavailable || engine === "unavailable"} error={validateState.error} busy={Boolean(busy)} onUseSource={readSource} onGoTo={goToField} />}
      </>
      case "template": {
        const chosen = selectedIds(draft).map(id => names[id] ?? id)
        return <>
          <p className="setup-lead">{chosen.length ? `${draft.name || "This template"} has ${chosen.length === 1 ? "one capability" : `${chosen.length} capabilities`}: ${chosen.join(", ")}.` : `${draft.name || "This template"} has no capabilities yet.`}</p>
          <SetupSource manifest={manifest} diagnostics={diagnostics} names={names} unavailable={validateState.unavailable || engine === "unavailable"} error={validateState.error} busy={Boolean(busy)} onUseSource={readSource} onGoTo={goToField} />
          <section className="setup-save" aria-label="Save and share">
            <h4>Save and share</h4>
            {!manifest ? <p className="setup-note">Saving needs the source, which this build of Yougori can't write yet.</p>
              : !saved ? <p className="setup-note">Save it to a new folder, or to the folder it was saved in before. Nothing else in that folder is touched.</p>
              : <p role="status" className="setup-note">Saved to <span className="setup-path">{saved.folder}</span>: {saved.written.join(", ")}.{saved.keptReadme ? " The README already there was kept." : ""}</p>}
            <div className="setup-actions">
              <Button size="xs" variant="outline" disabled={!manifest || Boolean(busy)} onClick={() => void saveToFolder()}>{saved ? "Save again…" : "Save to a folder…"}</Button>
              {saved ? <Button size="xs" variant="outline" disabled={Boolean(busy)} onClick={() => void checkSaved()}>Check it</Button> : null}
              {saved ? <Button size="xs" variant="outline" disabled={Boolean(busy)} onClick={() => void publishSaved()}>Publish…</Button> : null}
            </div>
            {checked ? checked.length ? <DiagnosticList diagnostics={checked} names={names} label="What the check found" /> : <p role="status" className="setup-note">The check found no problems.</p> : null}
            {published ? <p role="status" className="setup-note">{published}</p> : null}
          </section>
          <p className="setup-note">Or run it here first.</p>
        </>
      }
      case "compute": return <>
        {canChooseDrive ? <div className="setup-step-settings"><StorageDriveField drives={drives} value={storageDrive} onChange={setStorageDrive} required={Boolean(draft.capabilities["data.storage_drive"]?.selected)} /></div> : null}
        {questionsBody("compute")}
      </>
      case "models": return <>
        {questionsBody("models")}
        <p className="setup-note">Sign-ins open in their own window, named after the provider and this setup. This one stays open.</p>
      </>
      case "admin": return <>
        <p className="setup-note">This setup needs an administrator account of its own. Choose a new password: it is used to set it up and is never shown again.</p>
        {questionsBody("admin")}
      </>
      case "people": return questionsBody("people")
      case "review": {
        if (planError?.key === planKey) {
          const failure = planError.error
          return <p role="alert" className="grid-error">
            {isUnavailable(failure) ? "Planning setups is not available in this build of Yougori yet. Nothing was changed." : failure.message}{" "}
            {!isUnavailable(failure) ? <Button size="xs" variant="link" onClick={() => setPlanError(null)}>Try again</Button> : null}
          </p>
        }
        if (!plan || plan.key !== planKey) return <p role="status" className="setup-note">Working out what would happen…</p>
        return <>
          <SetupReview plan={plan.plan} names={names} onGoTo={goToField} agreed={agreed} onAgree={(id, on) => setAgreed(current => on ? [...current.filter(one => one !== id), id] : current.filter(one => one !== id))} />
          {Object.keys(given).length ? <p className="setup-note">Secrets you entered are used to set it up and are not shown here.</p> : null}
        </>
      }
      case "progress": return operation
        ? <>
          <SetupProgress operation={operation} onAction={action => void operationAction(action)} busy={Boolean(busy)} idPrefix="setup-builder-operation" handles={ALL_ACTIONS} agreeFor={plan && operationId ? { setupId: plan.plan.setupId, operationId } : null} />
          {nextActions.said ? <p role="status" className="setup-callout">{nextActions.said}</p> : null}
          {confirmingCancel ? <p className="setup-confirm" role="group" aria-label="Cancel this operation?">
            <span>Cancel it? What is already done is kept, and you can remove it afterwards.</span>
            <Button size="xs" variant="destructive-outline" onClick={() => void cancelOperation()}>Cancel the operation</Button>
            <Button size="xs" variant="ghost" onClick={() => { document.getElementById("setup-builder-operation-cancel")?.focus(); setConfirmingCancel(false) }}>Keep going</Button>
          </p> : null}
          <p className="setup-note">You can close this window. It keeps going. Select its sandboxes and choose Configure to see its progress.</p>
        </>
        : <p role="status" className="setup-note">{feed.unavailable ? "Progress can't be read in this build of Yougori." : "Reading progress…"}</p>
      case "ready": {
        const detail = setupId ? feed.details[setupId] : undefined
        return <>
          {detail ? <SetupReadiness capabilities={detail.capabilities} names={names} onAction={nextActions.act} /> : <p role="status" className="setup-note">Reading what is ready…</p>}
          <SetupOutputs outputs={detail?.outputs} />
          {nextActions.said ? <p role="status" className="setup-callout">{nextActions.said}</p> : null}
          <p className="setup-note">Next: select its sandboxes in My computer and choose Configure to manage the setup or complete its sign-ins.</p>
        </>
      }
      default: return null
    }
  }

  const finished = operation?.state === "completed"
  const primary = (() => {
    switch (step) {
      case "template": return <>
        <Button variant="outline" disabled={!manifest} onClick={() => {
          if (!manifest) return
          void navigator.clipboard?.writeText(manifest).then(() => setCopied(true), () => setError("Couldn't copy. Select the source and copy it instead."))
        }}>{copied ? "Copied" : "Copy source"}</Button>
        <Button disabled={Boolean(busy) || Boolean(choiceProblem)} title={choiceProblem || undefined} onClick={runHere}>Run it here</Button>
      </>
      case "review": return <Button loading={busy === "Starting"} disabled={Boolean(busy) || Boolean(choiceProblem) || !plan || plan.key !== planKey || Boolean(plan.plan.blockers?.length)} onClick={() => void apply()}>{updating ? `Update to ${updating.version}` : mode === "configure" ? "Apply changes" : "Set it up"}</Button>
      case "progress": return finished ? <Button onClick={() => wizard.goTo("ready")}>See what's ready</Button> : null
      case "ready": return <>
        {onShowSetups ? <Button variant="outline" onClick={() => { close(); onShowSetups(setupId) }}>Open setup configuration</Button> : null}
        <Button onClick={close}>Done</Button>
      </>
      default: return <Button disabled={Boolean(wizard.problem) || Boolean(busy) || !loaded} onClick={() => void next()}>Next</Button>
    }
  })()

  return <Dialog open={open} onOpenChange={value => { if (!value) requestClose() }}>
    <DialogPopup className="setup-builder" bottomStickOnMobile={false} initialFocus={heading} finalFocus={returnFocus ?? true}>
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{engineNote || (mode === "create" ? "Choose what it can do. Nothing is created until you review it." : "Nothing changes until you review what will happen.")}</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form
          className="setup-form"
          onSubmit={event => event.preventDefault()}
          onKeyDown={event => {
            // Enter in a typed answer moves on, as it does in any form. Search boxes, choices and
            // the source editor keep Enter for themselves.
            const target = event.target
            if (event.key !== "Enter" || !(target instanceof HTMLInputElement) || !TYPED.has(target.type)) return
            event.preventDefault()
            if (step !== "template" && !IN_PROGRESS_STEPS.includes(step)) void next()
          }}
        >
          <h3 ref={heading} tabIndex={-1} className="setup-step-title">{stepTitle}</h3>
          {body()}
          {wizard.problem && (!IN_PROGRESS_STEPS.includes(step) || step === "review") ? <p className="setup-note setup-problem" role={step === "review" ? "alert" : undefined}>{wizard.problem}</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          {/* The source view lists every problem itself; the cards list their own, so only the ones
              about the whole template, or about a field no card holds (its name, its kind of
              grid), are added here, each with a way to its field. */}
          {step === "capabilities" && view === "choose" && loaded && !loadFailed ? <DiagnosticList diagnostics={diagnostics.filter(one => !one.field?.startsWith("capabilities."))} names={names} onGoTo={goToField} label="About the whole template" /> : null}
        </form>
      </DialogPanel>
      <DialogFooter className="setup-footer">
        <span role="status" className="grid-muted">{busy ? `${busy}…` : `Step ${wizard.place} of ${wizard.total}`}</span>
        {started
          ? <Button variant="ghost" onClick={close}>Close</Button>
          : <Button id="setup-cancel" variant="ghost" onClick={requestClose}>Cancel</Button>}
        {confirmingClose ? <span className="setup-confirm" role="group" aria-label="Discard this draft?">
          <span>Discard this draft? Nothing has been created.</span>
          <Button variant="destructive-outline" onClick={close}>Discard</Button>
          <Button id="setup-keep-editing" variant="ghost" onClick={() => { document.getElementById("setup-cancel")?.focus(); setConfirmingClose(false) }}>Keep editing</Button>
        </span> : <>
          {!started ? <Button variant="outline" disabled={busy === "Starting"} onClick={wizard.back}>Back</Button> : null}
          {primary}
        </>}
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}

/** "Which kind of grid?", asked only while a grid is chosen: its people, models and credentials
 *  are served by different trusted code, and the engine's generator refuses a grid without one.
 *  The same question, in the same words, as the CLI's `template new`, both read from the shared
 *  registry's table. A problem about `recipe`
 *  sends focus here. */
function GridKindField({ value, leavesOut, onPick }: { value: string | null; leavesOut(profile: GridProfile): string[]; onPick(slug: RecipeSlug): void }) {
  return <fieldset className="setup-options" id={fieldId("recipe")} tabIndex={-1}>
    <legend>Which kind of grid?</legend>
    <p className="setup-note">A grid serves one of these. Each is run by its own part of Yougori.</p>
    {gridKinds().map(kind => {
      const left = leavesOut(kind.profile)
      return <label key={kind.slug} className="grid-choice">
        <input type="radio" name="setup-grid-kind" value={kind.slug} checked={value === kind.slug} onChange={() => onPick(kind.slug)} />
        <span className="grid-choice-words">
          <span className="grid-choice-label">{kind.name}</span>
          <span className="setup-note">{kind.hint}</span>
          {left.length ? <span className="setup-note">Can't hold what you chose: {left.join(", ")}.</span> : null}
        </span>
      </label>
    })}
  </fieldset>
}
