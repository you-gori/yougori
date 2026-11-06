import { useId, useMemo, useState } from "react"
import { AVAILABILITY_TEXT, GROUPS, selectable, type CatalogueEntry } from "@/api/setups/catalogue"
import type { CapabilityChoice, CapabilityGroup, ChoiceMode, Diagnostic, GridProfile, SettingDescriptor, SettingValue, SetupDraft } from "@/api/setups/types"
import { Button } from "@/components/ui/button"
import { answered, canTurnOn, conflictsWith, fieldId, kindsFor, missingRequirements, questionField, questionsOf, selectAll, toggled, withItsGrid } from "./draft"
import { DiagnosticList } from "./setup-views"
import { GroupMark, StateLabel } from "./setup-marks"
import { findSetupMatches } from "./setup-search"
import { AVAILABILITY_TONE } from "./setup-words"

/** The main creation screen: all six shared groups of capabilities, Grid & workers first, each
 *  card with what it is, examples, what it needs and whether it can be used here. Nothing is
 *  behind an Advanced panel, and there is no starter catalogue in front of it: a template is made
 *  by adding capabilities here, or by importing one. Planned and unsupported capabilities are
 *  shown, so they can be found, but can't be turned on. */

export type BoardMode = "create" | "run" | "configure"

const MODES: { value: ChoiceMode; label: string; lead: string }[] = [
  { value: "required", label: "Required", lead: "Always included." },
  { value: "default", label: "On by default", lead: "Included unless they turn it off." },
  { value: "optional", label: "Optional", lead: "Off unless they turn it on." },
]

const MODE_LINE: Record<ChoiceMode, string> = {
  required: "Required by this template.",
  default: "Included by default. You can turn it off.",
  optional: "Optional. Turn it on if you want it.",
}

const shownValue = (question: SettingDescriptor, value: SettingValue | undefined) =>
  question.kind === "toggle" ? (value ? "On" : "Off")
    : question.kind === "choice" ? question.options?.find(option => option.value === value)?.label ?? (value === undefined || value === "" ? "Not set" : String(value))
    : value === undefined || value === "" ? "Not set" : String(value)

/** The questions of one capability, or of one step. Secret answers are kept apart from the draft
 *  and never shown back. An author sets defaults; secrets are only asked when it runs. */
export function SettingFields({ questions, values, editable, author, secrets, onAnswer, onSecret }: {
  questions: SettingDescriptor[]
  values(question: SettingDescriptor): SettingValue | undefined
  /** False when the author locked these settings for people who run it. */
  editable: boolean
  author: boolean
  secrets: Record<string, string>
  onAnswer(question: SettingDescriptor, value: SettingValue): void
  onSecret(field: string, value: string): void
}) {
  if (!questions.length) return <p className="setup-note">Nothing to set for this one.</p>
  return <div className="setup-fields">
    {questions.map(question => {
      const field = questionField(question)
      const id = fieldId(field)
      const value = values(question) ?? question.default
      const described = question.help ? `${id}-help` : undefined
      const help = question.help ? <span className="setup-note" id={`${id}-help`}>{question.help}</span> : null
      if (question.kind === "secret") {
        return <div key={field} className="setup-field">
          {author
            ? <><span className="setup-field-label">{question.label}</span><span className="setup-note">Asked when it runs. Never stored in the template.</span></>
            : <><label htmlFor={id}>{question.label}</label><input id={id} className="setup-input" type="password" autoComplete="new-password" aria-describedby={described} value={secrets[field] ?? ""} onChange={event => onSecret(field, event.target.value)} /></>}
          {help}
        </div>
      }
      if (!editable || question.editable === false) {
        return <div key={field} className="setup-field">
          <span className="setup-field-label">{question.label}</span>
          <span id={id} tabIndex={-1}>{shownValue(question, value)} <span className="setup-note">· set by the template's author</span></span>
          {help}
        </div>
      }
      if (question.kind === "toggle") {
        return <div key={field} className="setup-field setup-field-inline">
          <label><input id={id} type="checkbox" aria-describedby={described} checked={Boolean(value)} onChange={event => onAnswer(question, event.target.checked)} /> {question.label}</label>
          {help}
        </div>
      }
      if (question.kind === "choice") {
        return <div key={field} className="setup-field">
          <label htmlFor={id}>{question.label}</label>
          <select id={id} className="setup-input" aria-describedby={described} aria-required={question.required || undefined} value={value === undefined ? "" : String(value)} onChange={event => onAnswer(question, event.target.value)}>
            {value === undefined || value === "" ? <option value="">Choose…</option> : null}
            {(question.options ?? []).map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
          {help}
        </div>
      }
      return <div key={field} className="setup-field">
        <label htmlFor={id}>{question.label}{question.required ? <span className="setup-note"> (needed)</span> : null}</label>
        <input
          id={id}
          className="setup-input"
          type={question.kind === "number" ? "number" : "text"}
          aria-required={question.required || undefined}
          min={question.min}
          max={question.max}
          aria-describedby={described}
          value={value === undefined ? "" : String(value)}
          onChange={event => onAnswer(question, question.kind === "number" && event.target.value !== "" ? Number(event.target.value) : event.target.value)}
        />
        {help}
      </div>
    })}
  </div>
}

function CapabilityCard({ entry, entries, draft, mode, profile, names, diagnostics, secrets, onDraft, onSecret, onGoTo }: {
  entry: CatalogueEntry
  entries: Map<string, CatalogueEntry>
  profile: GridProfile
  draft: SetupDraft
  mode: BoardMode
  names: Record<string, string>
  diagnostics: Diagnostic[]
  secrets: Record<string, string>
  onDraft(next: SetupDraft): void
  onSecret(field: string, value: string): void
  onGoTo(field: string): void
}) {
  const { descriptor, availability, reason } = entry
  const choice = draft.capabilities[descriptor.id]
  const selected = Boolean(choice?.selected)
  const [configuring, setConfiguring] = useState(false)
  const base = useId()
  const conflicts = conflictsWith(draft, descriptor)
  // People who run a template can't remove what it requires; nobody can turn on what is planned
  // or unsupported here, or what clashes with something already chosen. What belongs to another
  // kind of grid is turned on with its grid, while a template is being made.
  const locked = mode !== "create" && choice?.mode === "required" && selected
  const switches = availability === "other_grid" && mode === "create"
  const disabled = locked || (!selected && ((!selectable(availability) && !switches) || conflicts.length > 0))
  const kinds = kindsFor(descriptor)
  const missing = selected ? missingRequirements(draft, descriptor, profile) : []
  const editable = mode === "create" || (choice?.runnerEditable ?? true)
  const questions = questionsOf(draft, descriptor.id)
  const own = diagnostics.filter(diagnostic => diagnostic.field === `capabilities.${descriptor.id}` || diagnostic.field?.startsWith(`capabilities.${descriptor.id}.`))
  const name = (id: string) => names[id] ?? id
  const closeConfigure = () => { setConfiguring(false); requestAnimationFrame(() => document.getElementById(`${base}-configure`)?.focus()) }
  const set = (next: Partial<CapabilityChoice>) => onDraft({ ...draft, capabilities: { ...draft.capabilities, [descriptor.id]: { ...(choice ?? { selected: true, mode: "default", runnerEditable: true, settings: {} }), ...next } } })
  return <article className="setup-card" data-selected={selected || undefined} data-availability={availability} aria-labelledby={`${base}-name`}>
    <div className="setup-card-head">
      <label className="setup-card-pick">
        <input
          id={fieldId(`capabilities.${descriptor.id}`)}
          type="checkbox"
          checked={selected}
          disabled={disabled}
          aria-describedby={`${base}-summary ${base}-state`}
          onChange={event => onDraft(event.target.checked && switches ? withItsGrid(draft, descriptor) : toggled(draft, descriptor, event.target.checked))}
        />
        <span className="setup-card-name" id={`${base}-name`}>{descriptor.name}</span>
      </label>
      <span id={`${base}-state`}><StateLabel tone={AVAILABILITY_TONE[availability]}>{AVAILABILITY_TEXT[availability]}</StateLabel></span>
    </div>
    <p className="setup-card-summary" id={`${base}-summary`}>{descriptor.summary}</p>
    {descriptor.examples.length ? <p className="setup-note">For example: {descriptor.examples.join("; ")}.</p> : null}
    {descriptor.requires.length ? <p className="setup-note">Needs {descriptor.requires.map(group => group.map(name).join(" or ")).join(", and ")}.</p> : null}
    {descriptor.permissions.length ? <p className="setup-note">Allowed to: {descriptor.permissions.map(permission => permission.replace(/_/g, " ")).join(", ")}.</p> : null}
    {reason && availability !== "available" ? <p className="setup-note">{reason}</p> : null}
    {selected && switches && kinds.length === 1 && draft.recipe !== kinds[0]!.slug ? <div className="setup-card-actions">
      <Button size="xs" variant="outline" onClick={() => onDraft(withItsGrid(draft, descriptor))}>Make it a {kinds[0]!.name}</Button>
    </div> : null}
    {conflicts.length && !selected ? <p className="setup-note">Can't be used with {conflicts.map(name).join(" or ")}, which is chosen.</p> : null}
    {mode !== "create" && choice ? <p className="setup-note">{MODE_LINE[choice.mode]}</p> : null}
    {missing.length ? <div className="setup-needs" role="note">
      {missing.map(group => {
        // Only what can really be turned on here is offered; the rest is said in words.
        const addable = group.filter(id => canTurnOn(draft, entries.get(id)))
        return <p key={group.join("|")}>
          {descriptor.name} also needs {group.length > 1 ? "one of " : ""}{group.map(name).join(" or ")}.{" "}
          {addable.map(id => <Button key={id} size="xs" variant="outline" onClick={() => onDraft(selectAll(draft, [id]))}>Add {name(id)}</Button>)}
          {!addable.length ? <span>None of them can be used here, so {descriptor.name} can't be either. Turn it off to go on.</span> : null}
        </p>
      })}
    </div> : null}
    {mode === "create" && selected ? <fieldset className="setup-creator">
      <legend>For people who run it</legend>
      <div className="setup-creator-modes">
        {MODES.map(option => <label key={option.value} className="setup-radio">
          <input type="radio" name={`${base}-mode`} value={option.value} checked={choice?.mode === option.value} onChange={() => set({ mode: option.value })} />
          <span>{option.label}<span className="setup-note"> {option.lead}</span></span>
        </label>)}
      </div>
      <label className="setup-radio"><input type="checkbox" checked={choice?.runnerEditable ?? true} onChange={event => set({ runnerEditable: event.target.checked })} /><span>They can change its settings</span></label>
    </fieldset> : null}
    {questions.length && selected ? <div className="setup-card-actions">
      <Button id={`${base}-configure`} size="xs" variant="outline" aria-expanded={configuring} aria-controls={`${base}-settings`} onClick={() => configuring ? closeConfigure() : setConfiguring(true)}>{configuring ? "Done" : "Configure"}</Button>
      {!editable ? <span className="setup-note">Settings are set by the template's author.</span> : null}
    </div> : null}
    {configuring && selected ? <div id={`${base}-settings`} className="setup-card-settings" onKeyDown={event => { if (event.key === "Escape") { event.stopPropagation(); closeConfigure() } }}>
      <SettingFields
        questions={questions}
        values={question => choice?.settings[question.id]}
        editable={editable}
        author={mode === "create"}
        secrets={secrets}
        onAnswer={(question, value) => onDraft(answered(draft, question, value))}
        onSecret={onSecret}
      />
    </div> : null}
    <DiagnosticList diagnostics={own} names={names} onGoTo={onGoTo} label={`Problems with ${descriptor.name}`} />
  </article>
}

export function CapabilityBoard({ entries, draft, mode, profile = "generic", diagnostics, secrets, focusGroup, onDraft, onSecret, onGoTo }: {
  entries: CatalogueEntry[]
  /** The grid profile the setup presents as, which can waive some requirements. */
  profile?: GridProfile
  draft: SetupDraft
  mode: BoardMode
  diagnostics: Diagnostic[]
  secrets: Record<string, string>
  focusGroup?: CapabilityGroup | null
  onDraft(next: SetupDraft): void
  onSecret(field: string, value: string): void
  onGoTo(field: string): void
}) {
  const [query, setQuery] = useState("")
  const names = useMemo(() => Object.fromEntries(entries.map(entry => [entry.descriptor.id, entry.descriptor.name])), [entries])
  const byId = useMemo(() => new Map(entries.map(entry => [entry.descriptor.id, entry])), [entries])
  // People who run a template see what it declares; authors and owners see everything there is.
  const offered = mode === "run" ? entries.filter(entry => entry.descriptor.id in draft.capabilities) : entries
  const searching = query.trim().length >= 2
  const matches = useMemo(() => findSetupMatches(query, entries.map(entry => entry.descriptor)), [query, entries])
  const shown = searching
    ? offered.filter(entry => matches.groups.some(group => group.group === entry.descriptor.group && (!group.capabilities.length || group.capabilities.some(one => one.id === entry.descriptor.id))))
    : offered
  return <div className="setup-board">
    <div className="setup-board-tools">
      <input
        type="search"
        className="setup-input setup-search"
        aria-label="Find a capability"
        placeholder="Find a capability: GPU, team, API, database, backup…"
        value={query}
        onChange={event => setQuery(event.target.value)}
      />
      {searching ? <span role="status" className="setup-note">{shown.length ? `${shown.length} found` : "Nothing found"}</span> : null}
    </div>
    {GROUPS.map(group => {
      const cards = shown.filter(entry => entry.descriptor.group === group.id)
      const total = offered.filter(entry => entry.descriptor.group === group.id).length
      return <section key={group.id} className="setup-group" aria-labelledby={`setup-group-${group.id}`} data-group={group.id}>
        <h4 id={`setup-group-${group.id}`} className="setup-group-title" tabIndex={-1} data-focus-group={focusGroup === group.id ? "" : undefined}>
          <GroupMark group={group.id} />
          <span>{group.name}</span>
          <span className="setup-group-lead">{group.lead}</span>
        </h4>
        {cards.length
          ? <div className="setup-cards">{cards.map(entry => <CapabilityCard key={entry.descriptor.id} entry={entry} entries={byId} profile={profile} draft={draft} mode={mode} names={names} diagnostics={diagnostics} secrets={secrets} onDraft={onDraft} onSecret={onSecret} onGoTo={onGoTo} />)}</div>
          : <p className="setup-note setup-group-empty">{searching && total ? "Nothing here matches." : mode === "run" ? "This template doesn't use this." : "Nothing in this group yet."}</p>}
      </section>
    })}
  </div>
}
