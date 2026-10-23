import type { ButtonHTMLAttributes, ReactNode } from "react"
import { ArrowRightIcon } from "lucide-react"
import "@/components/prompx.css"

type PillTone = "dark" | "light" | "peach"

/** The PrompX pill: the label, then a round arrow. Dark for the page's main action, light for the rest. */
export function PillButton({ tone = "dark", children, className, ...props }: { tone?: PillTone; children: ReactNode } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button type="button" className={`pill pill-${tone}${className ? ` ${className}` : ""}`} {...props}>
    <span className="pill-label">{children}</span>
    <span className="pill-circle" aria-hidden="true"><ArrowRightIcon /></span>
  </button>
}

/** A page's two-tone headline (the statement, then a quieter line), its actions, and an optional
 *  control on the right such as the account. */
export function PageHeader({ title, lead, actions, aside }: { title: string; lead: string; actions?: ReactNode; aside?: ReactNode }) {
  return <header className="page-header">
    <h1 className="page-title">{title}<span>{lead}</span></h1>
    {aside ? <div className="page-aside">{aside}</div> : null}
    {actions ? <div className="page-actions">{actions}</div> : null}
  </header>
}
