import type { ReactNode } from "react"
import type { CapabilityGroup } from "@/api/setups/types"

/** Marks drawn for setups, in the sidebar's hand: one stroke weight, one solid accent each, no
 *  stock symbols. Every mark sits beside words that say the same thing, so colour and shape are
 *  never the only way a state is told. */

function Svg({ className, size, children }: { className: string; size?: number; children: ReactNode }) {
  return <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
    {children}
  </svg>
}

/** My setups: three parts of one setup joined up, the first of them running. */
export function SetupsNavMark() {
  return <Svg className="app-nav-icon">
    <rect x="3.5" y="3.5" width="7" height="7" rx="1.8" fill="currentColor" stroke="none" />
    <rect x="13.5" y="3.5" width="7" height="7" rx="1.8" />
    <rect x="8.5" y="13.5" width="7" height="7" rx="1.8" />
    <path d="M10.5 7h3M12 10.5v3" />
  </Svg>
}

const groupMarks: Record<CapabilityGroup, ReactNode> = {
  // Computers in a row, one of them taking work.
  grid_workers: <><rect x="3" y="6" width="5" height="5" rx="1.2" fill="currentColor" stroke="none" /><rect x="9.5" y="6" width="5" height="5" rx="1.2" /><rect x="16" y="6" width="5" height="5" rx="1.2" /><path d="M5.5 14v2.5h13V14M12 16.5V19" /></>,
  // A model's nodes joined into an N.
  ai_models: <><path d="M6.5 17.5v-11l11 11v-11" /><circle cx="6.5" cy="6.5" r="1.9" fill="currentColor" stroke="none" /><circle cx="17.5" cy="17.5" r="1.9" fill="currentColor" stroke="none" /></>,
  // A page with its address line.
  website_api: <><rect x="3.5" y="4.5" width="17" height="15" rx="2.5" /><path d="M3.5 9h17" /><circle cx="6.6" cy="6.8" r=".9" fill="currentColor" stroke="none" /><path d="M8 14h8M8 16.8h5" /></>,
  // Two people, one in front.
  people_access: <><circle cx="9" cy="8.5" r="3" fill="currentColor" stroke="none" /><path d="M3.8 19a5.2 5.2 0 0 1 10.4 0" /><circle cx="16.5" cy="9" r="2.4" /><path d="M15.8 14.2A4.4 4.4 0 0 1 20.6 19" /></>,
  // Stacked discs of stored data.
  files_data: <><ellipse cx="12" cy="6.5" rx="7" ry="2.6" fill="currentColor" stroke="none" /><path d="M5 6.5v5.5c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V6.5M5 12v5.5c0 1.4 3.1 2.6 7 2.6s7-1.2 7-2.6V12" /></>,
  // A loop that comes back round, with its marker.
  automation_recovery: <><path d="M18.5 12a6.5 6.5 0 1 1-2-4.7" /><path d="M17.2 3.8v3.9h-3.9" /><circle cx="12" cy="12" r="1.9" fill="currentColor" stroke="none" /></>,
}

export function GroupMark({ group }: { group: CapabilityGroup }) {
  return <Svg className="setup-group-mark">{groupMarks[group]}</Svg>
}

/** The tone of a state, which picks its mark. The words beside it say which state it is. */
export type StateTone = "ok" | "busy" | "attention" | "off" | "blocked" | "planned" | "unknown"

const stateMarks: Record<StateTone, ReactNode> = {
  ok: <><circle cx="12" cy="12" r="8" fill="currentColor" stroke="none" /><path d="m8.4 12.2 2.4 2.4 4.8-5" stroke="var(--setup-mark-ink, #fff)" strokeWidth={2} /></>,
  busy: <><path d="M12 4a8 8 0 1 1-8 8" /><circle cx="12" cy="12" r="2.4" fill="currentColor" stroke="none" /></>,
  attention: <><circle cx="12" cy="12" r="8" /><path d="M12 7.8v5" strokeWidth={2} /><circle cx="12" cy="16.2" r="1.2" fill="currentColor" stroke="none" /></>,
  off: <><circle cx="12" cy="12" r="8" /><rect x="9" y="9" width="6" height="6" rx="1" fill="currentColor" stroke="none" /></>,
  blocked: <><circle cx="12" cy="12" r="8" /><path d="m6.6 17.4 10.8-10.8" /></>,
  planned: <><circle cx="12" cy="12" r="8" strokeDasharray="2.4 2.6" /><path d="M12 8.5V12l2.4 1.6" /></>,
  unknown: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" /></>,
}

export function StateMark({ tone }: { tone: StateTone }) {
  return <Svg className="setup-state-mark">{stateMarks[tone]}</Svg>
}

/** A mark and its words, as one unit. */
export function StateLabel({ tone, children }: { tone: StateTone; children: ReactNode }) {
  return <span className="setup-state" data-tone={tone}><StateMark tone={tone} /><span>{children}</span></span>
}
