import { useId, useRef, type KeyboardEvent, type ReactNode } from "react"
import "@/components/popup-kit.css"

/** The pieces every popup is built from, so each one reads the same way: what it does, the few
 *  things it asks with what each answer gives you, the result before the main button is pressed,
 *  and what is still needed, said beside that button rather than hidden in its tooltip. */

/** A titled group of related questions. */
export function PopupGroup({ title, hint, children }: { title: string; hint?: ReactNode; children: ReactNode }) {
  const id = useId()
  return <div className="popup-group" role="group" aria-labelledby={id}>
    <div className="popup-group-head">
      <h3 className="popup-group-title" id={id}>{title}</h3>
      {hint ? <p className="popup-group-hint">{hint}</p> : null}
    </div>
    {children}
  </div>
}

export interface ChoiceOption<T extends string> {
  value: T
  title: string
  /** How it works, in a sentence or two, naming any outside service it relies on. */
  detail: ReactNode
  /** What picking it gives you, shown before anything happens. Real values only. */
  preview?: ReactNode
  disabled?: boolean
}

/** A few choices as cards, one picked. The arrow keys move between them, as in any radio group,
 *  and only the picked card is a tab stop. Each card is named by its title alone; how it works
 *  and what it gives you are its description. */
export function ChoiceCards<T extends string>({ label, value, options, onPick, disabled }: {
  label: string
  value: T
  options: readonly ChoiceOption<NoInfer<T>>[]
  onPick(value: NoInfer<T>): void
  disabled?: boolean
}) {
  const id = useId()
  const group = useRef<HTMLDivElement>(null)
  const usable = options.filter(option => !option.disabled)
  const picked = options.some(option => option.value === value) ? value : usable[0]?.value
  const move = (event: KeyboardEvent<HTMLButtonElement>, from: T) => {
    const step = event.key === "ArrowDown" || event.key === "ArrowRight" ? 1
      : event.key === "ArrowUp" || event.key === "ArrowLeft" ? -1
      : 0
    if (!step || disabled || !usable.length) return
    event.preventDefault()
    const at = usable.findIndex(option => option.value === from)
    const next = usable[(at + step + usable.length) % usable.length]!
    onPick(next.value)
    group.current?.querySelectorAll<HTMLButtonElement>("[role=radio]")[options.indexOf(next)]?.focus()
  }
  return <div className="popup-field">
    <span className="popup-label" id={`${id}-label`}>{label}</span>
    <div ref={group} className="popup-choices" role="radiogroup" aria-labelledby={`${id}-label`}>
      {options.map((option, at) => <button
        key={option.value}
        type="button"
        role="radio"
        className="popup-choice"
        aria-checked={option.value === value}
        aria-labelledby={`${id}-${at}`}
        aria-describedby={`${id}-${at}-detail`}
        tabIndex={option.value === picked ? 0 : -1}
        disabled={disabled || option.disabled}
        onClick={() => onPick(option.value)}
        onKeyDown={event => move(event, option.value)}
      >
        <span className="popup-choice-title" id={`${id}-${at}`}>{option.title}</span>
        <span id={`${id}-${at}-detail`}>
          <span className="popup-choice-detail">{option.detail}</span>
          {option.preview ? <span className="popup-choice-preview">{option.preview}</span> : null}
        </span>
      </button>)}
    </div>
  </div>
}

/** An address, link or code exactly as it will appear. */
export function Address({ children }: { children: ReactNode }) {
  return <code className="popup-address">{children}</code>
}

/** The part of an address a service fills in, such as the words Cloudflare picks. */
export function Slot({ children }: { children: ReactNode }) {
  return <span className="popup-slot">{children}</span>
}

/** The result of the main button, said before it is pressed. */
export function Outcome({ title, children }: { title: string; children: ReactNode }) {
  const id = useId()
  return <div className="popup-outcome" role="note" aria-labelledby={id}>
    <span className="popup-outcome-title" id={id}>{title}</span>
    <div className="popup-outcome-body">{children}</div>
  </div>
}

/** The one thing still needed before the main button works. It sits in the footer beside the
 *  buttons, so a disabled button always has its reason in sight. */
export function StillNeeded({ children }: { children: ReactNode }) {
  return children ? <p className="popup-needed" aria-live="polite">{children}</p> : null
}

/** Where a hub can be reached from. */
export type ReachKind = "network" | "quick"

/** Where a hub can be reached from, with the address people will use under each choice: the
 *  computer's own address and port on the company network, or the shape of the link Cloudflare
 *  hands out, with the part Cloudflare picks marked as such. */
export function ReachCards({ who, value, onPick, address, port, disabled }: {
  who: "computers" | "people"
  value: ReachKind
  onPick(value: ReachKind): void
  /** This computer's address as typed in the popup. */
  address: string
  /** The port the hub listens on. */
  port: number
  disabled?: boolean
}) {
  const here = address.trim()
  return <ChoiceCards
    label={who === "people" ? "Where people can sign in from" : "Where computers can join from"}
    value={value}
    onPick={onPick}
    disabled={disabled}
    options={[
      {
        value: "network",
        title: "This network only",
        detail: `${who === "people" ? "People connect" : "Computers connect"} over the same Wi-Fi, office network or VPN, straight to this computer. Nothing is published to the internet.`,
        preview: here ? <Address>{here}:{port}</Address> : <span className="popup-quiet">This computer's address, port {port}</span>,
      },
      {
        value: "quick",
        title: "Anywhere, through Cloudflare",
        detail: "Cloudflare's free quick tunnel relays the connection, so it works from any network. No Cloudflare account is needed, and Cloudflare only passes on encrypted traffic it cannot read.",
        preview: <Address>https://<Slot>random-words</Slot>.trycloudflare.com</Address>,
      },
    ]}
  />
}

/** What the quick link means once it is chosen: when the real address appears, and that it moves. */
export function QuickLinkNote({ who }: { who: "computers" | "people" }) {
  return <p className="popup-note">
    Cloudflare picks the words when the hub starts, and the exact link shows on this grid's page
    straight after. It changes each time this computer restarts; {who === "people" ? "people" : "computers"} then
    need the new invite.
  </p>
}
