import { migrationHeading, outcomeWords, permissionWords, productText, readProduct, recordedWords, type ProductReply } from "@/api/setups/product"

/** How a document's permission lines are headed: where a setup or a plan asks for them, and where
 *  a setup declares them. Declarations grant no access. */
const PERMISSION_LINES = {
  /** Shown elsewhere on the same page (the permissions panel), so not repeated. */
  none: null,
  asks: { heading: "Asks for", label: "What its capabilities ask for", note: "" },
  declares: { heading: "Declared permissions", label: "What its capabilities request", note: "Capability declarations grant no access. Approval and enforcement are checked separately." },
} as const

/** A product document (CORE-07) from any reply that carries one: a setup's own (`setup_get`, the
 *  one `yougori template status` shows), a plan's (its review) or a setup's read-back permissions.
 *  It shows the permission lines with their status, the inventory of the setup's move to VM
 *  sandboxes and what needs the person. Every word comes from the engine's document; nothing here
 *  decides, grants or changes anything, and an inventory says plainly that nothing has changed. */
export function SetupProduct({ detail, lines = "asks" }: { detail: ProductReply | undefined; lines?: keyof typeof PERMISSION_LINES }) {
  if (!detail) return null
  const read = readProduct(detail.product, detail.setupId ?? detail.summary?.setupId)
  if (!read) {
    return detail.productUnavailable
      ? <p className="setup-note">Yougori can't show this setup's product view: {productText(detail.productUnavailable)}.</p>
      : null
  }
  if (!read.readable) return <p className="setup-note">{read.reason}</p>
  const { view } = read
  const headed = PERMISSION_LINES[lines]
  const permissions = headed ? view.permissions ?? [] : []
  const items = view.migration?.items ?? []
  const refusals = view.refusals ?? []
  if (!permissions.length && !items.length && !refusals.length) return null
  return <section className="setup-permissions" aria-label="Product view">
    {headed && permissions.length ? <>
      <h4 className="setup-permissions-head">{headed.heading}</h4>
      {headed.note ? <p className="setup-note">{headed.note}</p> : null}
      <ul className="setup-plain-list" aria-label={headed.label}>
        {permissions.map((line, index) => <li key={`${line.kind}-${index}`}>{productText(line.text)} ({productText(permissionWords(line.status))})</li>)}
      </ul>
    </> : null}
    {items.length && view.migration ? <>
      <h4 className="setup-permissions-head">{migrationHeading(view.migration.status)}</h4>
      <ul className="setup-plain-list" aria-label="Move to VM sandboxes">
        {items.map((item, index) => <li key={`${productText(item.subject)}-${index}`}>{productText(item.subject)} ({productText(recordedWords(item.recorded))}): {productText(outcomeWords(item.outcome))}</li>)}
      </ul>
    </> : null}
    {refusals.length ? <>
      <h4 className="setup-permissions-head">Needs you</h4>
      <ul className="setup-plain-list" aria-label="What needs you">
        {refusals.map((refusal, index) => <li key={index}>{productText(refusal.reason)}. What you can do: {productText(refusal.remedy_text).replace(/\.$/, "")}.</li>)}
      </ul>
    </> : null}
  </section>
}
