/** What the create wizard collects, what it would do, and what somebody has to agree to first.
 *
 *  Three rules hold this file together.
 *
 *  There is no password in a blueprint. A dry run is printed, read aloud and kept, so a secret
 *  can never be part of one. The password travels beside it, to the one call that uses it.
 *
 *  Every answer goes where it actually belongs. Grid Core's workspace `Quota` holds a desk's
 *  disk, its sessions and what may be carried off it; CPU and memory are not in it at all, they
 *  are part of what a computer offers the grid. So the wizard asks for the share a computer
 *  gives once, and for the disk one desk gets separately, and says which is which.
 *
 *  A credential is recorded here as a shape and never as a value. `Credential::new` refuses one
 *  without a vault entry holding its value, and the wizard deliberately carries none, so the
 *  credential is created after the grid exists, in a step that takes the value on its own.
 */
import { CAPABILITY_NAME, capabilitiesSentence, kindFor, type Capability } from "@/lib/grid-capability"
import type { RealmKind, WorkspaceKind } from "@/api/grids/types"

export type Commitment = "share" | "whole"
export type DeskSharing = "each" | "shared"
export type DeskNetwork = "standard" | "restricted"
export type ApprovalMode = "allow" | "ask" | "everyTime"
export type ResearchApproval = "beforeStart" | "beforeEachSource" | "never"

export type GridImage =
  | { kind: "default" }
  | { kind: "registry"; reference: string }
  | { kind: "prepared"; name: string }

export interface Share {
  cpu: number
  memoryGb: number
  diskGb: number
  gpu: boolean
}

/** Sandbox workspaces. `kind` is a field of Grid Core's `Image`, so it is always settled: it is
 *  derived where the answer already decides it and asked outright where it does not. */
export interface WorkspaceAnswers {
  sharing: DeskSharing
  commitment: Commitment
  /** What a committed computer offers the grid. This is the host's side, not a desk's. */
  share: Share
  /** What one desk may fill. This is the desk's side, and the only one of the four in a quota. */
  deskDiskGb: number
  kind: WorkspaceKind
  image: GridImage
  network: DeskNetwork
}

export interface ModelAnswers {
  /** Without the `hf.co/` prefix, which the field shows and never asks anybody to type. */
  model: string
  quant: string
  scope: "all" | "remaining" | "computers"
  computers: string[]
  percent: number
  /** Minutes with nobody at the keyboard before it serves. 0 serves whatever anybody is doing. */
  idleAfterMinutes: number
  /** In words, in this computer's own time. Empty means any time. */
  schedule: string
}

export interface CredentialAnswers {
  name: string
  destination: string
  methods: string[]
  paths: string[]
  approval: ApprovalMode
  rotateEveryDays: number | null
}

export interface ResearchSource {
  kind: "folder" | "repository" | "host"
  value: string
}

export interface ResearchAnswers {
  scope: string
  sources: ResearchSource[]
  network: "offline" | "destinations"
  destinations: string[]
  worker: { kind: WorkspaceKind; cpu: number; memoryGb: number; diskGb: number; gpu: boolean }
  approval: ResearchApproval
}

export interface GridBlueprint {
  name: string
  capabilities: Capability[]
  address: string
  reach: { kind: "network" } | { kind: "quick" } | { kind: "domain"; hostname: string }
  administrators: string[]
  approvers: string[]
  workspaces: WorkspaceAnswers
  models: ModelAnswers
  credentials: CredentialAnswers
  research: ResearchAnswers
}

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const

export function emptyBlueprint(me = "you"): GridBlueprint {
  return {
    name: "",
    capabilities: [],
    address: "",
    reach: { kind: "network" },
    administrators: [me],
    approvers: [me],
    workspaces: {
      sharing: "each",
      commitment: "share",
      share: { cpu: 4, memoryGb: 8, diskGb: 120, gpu: false },
      deskDiskGb: 40,
      kind: "container",
      image: { kind: "default" },
      network: "standard",
    },
    models: { model: "", quant: "", scope: "remaining", computers: [], percent: 100, idleAfterMinutes: 0, schedule: "" },
    credentials: { name: "", destination: "", methods: [...HTTP_METHODS], paths: [], approval: "ask", rotateEveryDays: 90 },
    research: {
      scope: "",
      sources: [],
      network: "offline",
      destinations: [],
      worker: { kind: "microVm", cpu: 4, memoryGb: 8, diskGb: 40, gpu: false },
      approval: "beforeStart",
    },
  }
}

/** One question. `when` decides whether this grid is asked it at all, and `problem` is the
 *  sentence that stops the wizard moving on. */
export interface Step {
  id: string
  title: string
  when(answers: GridBlueprint): boolean
  problem(answers: GridBlueprint): string
}

const has = (capability: Capability) => (answers: GridBlueprint) => answers.capabilities.includes(capability)
const always = () => true
const fine = () => ""
const whole = (value: number, low: number, high: number) => Number.isFinite(value) && value >= low && value <= high

const NAMES = /^[a-z][a-z0-9 ._-]{0,40}$/i

/** The questions, in the order they are asked. Purpose first, always: nothing else is asked
 *  until a grid knows what it is for, and from then on only that purpose's questions exist. */
export function blueprintSteps(): Step[] {
  return [
    {
      id: "purpose",
      title: "What is this grid for?",
      when: always,
      problem: answers => answers.capabilities.length ? "" : "Choose what this grid is for.",
    },
    {
      id: "name",
      title: "What is it called?",
      when: always,
      problem: answers => answers.name.trim() ? "" : "Give the grid a name people will recognise, such as your company's.",
    },
    {
      id: "reach",
      title: "Who can reach it?",
      when: always,
      problem: answers => {
        if (!answers.address.trim()) return "Give this computer's address on your network."
        if (answers.reach.kind === "domain" && !answers.reach.hostname.trim()) return "Give the domain this grid answers on."
        return ""
      },
    },
    {
      // The password is asked for here and kept nowhere near a blueprint: the wizard holds it in
      // its own hand and passes it straight to the one call that uses it.
      id: "password",
      title: "What password do people join with?",
      when: always,
      problem: fine,
    },
    {
      id: "desks-sharing",
      title: "Who uses a desk?",
      when: has("workspaces"),
      problem: fine,
    },
    {
      id: "desks-commitment",
      title: "How much of a computer may this grid use?",
      when: has("workspaces"),
      problem: fine,
    },
    {
      id: "desks-share",
      title: "What does a committed computer give it?",
      when: answers => answers.capabilities.includes("workspaces") && answers.workspaces.commitment === "share",
      problem: answers => {
        const { cpu, memoryGb, diskGb } = answers.workspaces.share
        if (!whole(cpu, 1, 256)) return "Give between 1 and 256 processor cores."
        if (!whole(memoryGb, 1, 2048)) return "Give between 1 and 2048 GB of memory."
        if (!whole(diskGb, 1, 20_000)) return "Give between 1 and 20000 GB of disk."
        return ""
      },
    },
    {
      id: "desks-disk",
      title: "How much disk does one desk get?",
      when: has("workspaces"),
      problem: answers => whole(answers.workspaces.deskDiskGb, 1, 2048) ? "" : "A desk's disk is between 1 and 2048 GB.",
    },
    {
      id: "desks-image",
      title: "What is a desk built from?",
      when: has("workspaces"),
      problem: answers => {
        const image = answers.workspaces.image
        if (image.kind === "registry" && !image.reference.trim()) return "Give the container image, such as docker.io/library/ubuntu:24.04."
        if (image.kind === "prepared" && !image.name.trim()) return "Give the name of the prepared workspace your company published."
        return ""
      },
    },
    {
      id: "desks-kind",
      title: "Is a desk a container, a microVM or a VM?",
      // A container image settles it; anything else is asked, because the grid records what each
      // desk is and cannot guess it.
      when: answers => answers.capabilities.includes("workspaces") && answers.workspaces.image.kind !== "registry",
      problem: fine,
    },
    {
      id: "desks-network",
      title: "What can a desk reach?",
      when: has("workspaces"),
      problem: fine,
    },
    {
      id: "models-model",
      title: "Which model?",
      when: has("models"),
      problem: answers => answers.models.model.trim() ? "" : "Give a model, such as owner/model.",
    },
    {
      id: "models-quant",
      title: "Which size of it?",
      when: has("models"),
      problem: fine,
    },
    {
      id: "models-scope",
      title: "Which computers run it?",
      when: has("models"),
      problem: answers =>
        answers.models.scope === "computers" && !answers.models.computers.length
          ? "Pick at least one computer, or let the grid choose."
          : "",
    },
    {
      id: "models-percent",
      title: "How many of them?",
      when: answers => answers.capabilities.includes("models") && answers.models.scope !== "computers",
      problem: answers => whole(answers.models.percent, 1, 100) ? "" : "Choose between 1 and 100 percent of the computers.",
    },
    {
      id: "models-idle",
      title: "When may it serve?",
      when: has("models"),
      problem: answers => whole(answers.models.idleAfterMinutes, 0, 720) ? "" : "Wait between 0 and 720 minutes before serving.",
    },
    {
      id: "models-schedule",
      title: "At what times?",
      when: has("models"),
      problem: fine,
    },
    {
      id: "credentials-name",
      title: "What is the credential called?",
      when: has("credentials"),
      problem: answers =>
        NAMES.test(answers.credentials.name.trim())
          ? ""
          : "Give the credential a name people will recognise, such as Deploy key.",
    },
    {
      id: "credentials-destination",
      title: "Where may it be sent?",
      when: has("credentials"),
      problem: answers =>
        /^https:\/\/[^\s]+$/.test(answers.credentials.destination.trim())
          ? ""
          : "Give one address it may be sent to, over HTTPS.",
    },
    {
      id: "credentials-methods",
      title: "Which kinds of request?",
      when: has("credentials"),
      problem: answers => answers.credentials.methods.length ? "" : "Allow at least one kind of request.",
    },
    {
      id: "credentials-paths",
      title: "Which paths?",
      when: has("credentials"),
      problem: answers =>
        answers.credentials.paths.every(path => path.startsWith("/"))
          ? ""
          : "A path begins with a slash, such as /repos/acme.",
    },
    {
      id: "credentials-approval",
      title: "Who says yes?",
      when: has("credentials"),
      problem: fine,
    },
    {
      id: "credentials-rotation",
      title: "How often is it replaced?",
      when: has("credentials"),
      problem: answers =>
        answers.credentials.rotateEveryDays === null || whole(answers.credentials.rotateEveryDays, 1, 3650)
          ? ""
          : "Replace it between 1 and 3650 days from now, or never.",
    },
    {
      id: "research-scope",
      title: "What is this research authorised to do?",
      when: has("research"),
      problem: answers => answers.research.scope.trim().length >= 10 ? "" : "Say in a sentence what this research may do.",
    },
    {
      id: "research-sources",
      title: "What does it work on?",
      when: has("research"),
      problem: answers => answers.research.sources.length ? "" : "Name at least one folder, repository or host it may work on.",
    },
    {
      id: "research-network",
      title: "What may it reach?",
      when: has("research"),
      problem: answers =>
        answers.research.network === "destinations" && !answers.research.destinations.length
          ? "Name at least one destination, or keep it offline."
          : "",
    },
    {
      id: "research-worker",
      title: "What does the work run in?",
      when: has("research"),
      problem: answers => {
        const { cpu, memoryGb, diskGb } = answers.research.worker
        if (!whole(cpu, 1, 256)) return "Give between 1 and 256 processor cores."
        if (!whole(memoryGb, 1, 2048)) return "Give between 1 and 2048 GB of memory."
        if (!whole(diskGb, 1, 2048)) return "Give between 1 and 2048 GB of disk."
        return ""
      },
    },
    {
      id: "research-approval",
      title: "When does somebody have to say yes?",
      when: has("research"),
      problem: fine,
    },
    {
      id: "people",
      title: "Who administers it, and who approves?",
      when: always,
      problem: answers => (answers.administrators.length ? "" : "A grid needs at least one administrator."),
    },
    {
      id: "summary",
      title: "What would happen",
      when: always,
      problem: fine,
    },
  ]
}

/** The questions this grid is actually asked, with the purpose answered as it is now. */
export function askedSteps(answers: GridBlueprint): Step[] {
  return blueprintSteps().filter(step => step.when(answers))
}

/** One thing about to happen that somebody has to agree to, in the words they are shown. */
export interface GridWarning {
  id: string
  sentence: string
}

export interface RehearsalLine {
  label: string
  value: string
}

export interface GridRehearsal {
  /** The grid this would be, in one sentence. */
  headline: string
  lines: RehearsalLine[]
  wouldCreate: string[]
  warnings: GridWarning[]
  /** Which question to go back to, when something cannot be built as asked. */
  problem: { step: string; why: string } | null
}

/** What this computer already knows, which the dry run needs and the answers do not hold. */
export interface GridFacts {
  /** This computer's own name, because it is the one that holds the key. */
  computer: string
  /** The computers that have already joined something here, by name. */
  computers: string[]
  /** What this computer already hosts, so a second grid of the same kind is not promised. */
  alreadyHere: Capability[]
}

const list = (names: readonly string[]) => {
  if (!names.length) return ""
  if (names.length === 1) return names[0] as string
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1] as string}`
}

const kindWord: Record<WorkspaceKind, string> = { container: "a container", microVm: "a microVM", vm: "a virtual machine" }

function imageWords(image: GridImage): string {
  if (image.kind === "registry") return `the container image ${image.reference.trim()}`
  if (image.kind === "prepared") return `the prepared workspace called ${image.name.trim()}`
  return "the workspace Yougori builds by default"
}

/** Everything creating this grid would do, and nothing done.
 *
 *  Not one line of this names a file, a folder, a vault entry or an identifier. A person reads
 *  where their grid lives, not where a database file is.
 */
export function rehearse(answers: GridBlueprint, facts: GridFacts): GridRehearsal {
  const kind: RealmKind = kindFor(answers.capabilities)
  const name = answers.name.trim() || "this grid"
  const problem = askedSteps(answers)
    .map(step => ({ step: step.id, why: step.problem(answers) }))
    .find(found => found.why) ?? null

  const already = answers.capabilities.filter(capability => facts.alreadyHere.includes(capability))
  const lines: RehearsalLine[] = [
    {
      label: "Records",
      value: already.length
        ? `Kept on ${facts.computer}, in Yougori's own folder for grids. This computer already runs a grid for ${capabilitiesSentence(already)}, and that one is left as it is.`
        : `Kept on ${facts.computer}, in Yougori's own folder for grids. Nothing is written there until you create it.`,
    },
    {
      label: "Key",
      value: `${facts.computer} mints the key and keeps it in this computer's credential store, under the grid's own name. A backup of this grid can only be restored with it.`,
    },
    {
      label: "Stored for it",
      value: answers.capabilities.includes("credentials")
        ? "Its key, and one entry of its own for each credential's value. A value is never in the grid's records, in a backup or in this summary."
        : "Its key, and nothing else. No value of any kind is kept beside it.",
    },
    {
      label: "Reach",
      value: answers.reach.kind === "network"
        ? `On your own network only, at ${answers.address.trim() || "this computer"}. Nothing of it is published.`
        : answers.reach.kind === "quick"
          ? `Through a quick public link as well as your own network. The link changes each time this computer restarts.`
          : `At ${answers.reach.hostname.trim()} as well as on your own network.`,
    },
    { label: "Administrators", value: list(answers.administrators) || "Nobody yet" },
    {
      label: "Approvers",
      value: answers.capabilities.includes("credentials") || answers.capabilities.includes("research")
        ? list(answers.approvers) || "Nobody yet, so nothing that needs approval can be agreed to"
        : "Nothing in this grid waits for an approver.",
    },
    {
      label: "Computers",
      value: facts.computers.length
        ? `${list(facts.computers)} ${facts.computers.length === 1 ? "is" : "are"} already connected to this computer and can be asked to join.`
        : "Only this computer, until others join with the invite.",
    },
  ]

  const wouldCreate: string[] = []
  if (answers.capabilities.includes("models")) {
    const where = answers.models.scope === "computers"
      ? `${answers.models.computers.length} chosen ${answers.models.computers.length === 1 ? "computer" : "computers"}`
      : answers.models.scope === "all"
        ? `${answers.models.percent}% of every computer in the grid`
        : `${answers.models.percent}% of the computers without a model`
    wouldCreate.push(`One model plan: ${answers.models.model.trim() || "a model"} on ${where}.`)
  }
  if (answers.capabilities.includes("workspaces")) {
    // There is no grid-wide setting for a desk's kind, its image or its disk: each desk takes
    // them when it is ordered. So this says what ordering one will do, rather than promising a
    // desk that creating the grid does not make.
    wouldCreate.push(
      `Every desk you order here is built as ${kindWord[answers.workspaces.kind]} from ${imageWords(answers.workspaces.image)}, with ${answers.workspaces.deskDiskGb} GB of disk, ${answers.workspaces.sharing === "each" ? "for one person" : "for a team to share"}. No desk is ordered now.`,
    )
    wouldCreate.push(
      answers.workspaces.commitment === "whole"
        ? `${facts.computer} is committed whole on the Sandbox Grid's own page once the grid exists. This screen does not do it.`
        : `${facts.computer} offering ${answers.workspaces.share.cpu} cores, ${answers.workspaces.share.memoryGb} GB of memory and ${answers.workspaces.share.diskGb} GB of disk${answers.workspaces.share.gpu ? ", and its graphics card" : ""}.`,
    )
  }
  if (answers.capabilities.includes("credentials")) {
    wouldCreate.push(
      `A place for ${answers.credentials.name.trim() || "one credential"} is made after the grid exists, in the step that takes its value. Nothing is sent anywhere but ${answers.credentials.destination.trim() || "the address you gave"}.`,
    )
  }
  if (answers.capabilities.includes("research")) {
    wouldCreate.push(
      `What you authorised, kept for Swarm Mining's own setup: ${answers.research.sources.length} ${answers.research.sources.length === 1 ? "source" : "sources"}, a worker in ${kindWord[answers.research.worker.kind]}. The worker itself is made there, with its model.`,
    )
  }

  // A sentence somebody has to agree to describes something that then happens. Committing a
  // computer whole happens on the Sandbox Grid's own page, so it is said here and agreed to
  // there, where the computer is actually given away.
  const warnings: GridWarning[] = []
  if (answers.reach.kind === "quick") {
    warnings.push({
      id: "public-link",
      sentence: `A quick public link makes ${name} reachable from outside your network. Anyone holding the invite and the password can reach it from anywhere.`,
    })
  }
  if (answers.reach.kind === "domain") {
    warnings.push({
      id: "published-domain",
      sentence: `${name} answers at ${answers.reach.hostname.trim()} from outside your network, for as long as the domain points here.`,
    })
  }
  if (answers.capabilities.includes("models") && answers.models.scope === "all" && answers.models.percent === 100) {
    warnings.push({
      id: "every-computer",
      sentence: `This puts ${answers.models.model.trim() || "the model"} on every computer in ${name}. Each one removes the model it runs now to make room.`,
    })
  }
  if (answers.capabilities.includes("credentials") && answers.credentials.approval === "allow") {
    warnings.push({
      id: "credential-at-once",
      sentence: `Anyone this grid allows may use ${answers.credentials.name.trim() || "this credential"} at once, without asking. Nobody ever sees its value.`,
    })
  }
  if (answers.capabilities.includes("research") && answers.research.network === "destinations") {
    warnings.push({
      id: "research-reaches-out",
      sentence: `This research grid may reach ${list(answers.research.destinations) || "the destinations you named"}. Everything else stays offline.`,
    })
  }
  if (
    (answers.capabilities.includes("credentials") || answers.capabilities.includes("research"))
    && answers.approvers.length === 1
    && answers.administrators.includes(answers.approvers[0] as string)
  ) {
    warnings.push({
      id: "only-approver",
      sentence: `${answers.approvers[0] as string} is the only approver, so their own requests are recorded as decided by themselves.`,
    })
  }

  const headline = kind === "research"
    ? `${name} would be research of its own, and what you authorise here is what Swarm Mining's setup is given.`
    : `${name} would be a company grid for ${capabilitiesSentence(answers.capabilities)}.`

  return { headline, lines, wouldCreate, warnings, problem }
}

/** The title of a question, for the sentence that sends somebody back to it. */
export function stepTitle(id: string): string {
  return blueprintSteps().find(step => step.id === id)?.title ?? "an earlier question"
}

/** What each capability is called where a grid is named by what it does. */
export const PURPOSE_NAME = CAPABILITY_NAME
