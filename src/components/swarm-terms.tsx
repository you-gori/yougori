/** Somebody else's terms, read as words.
 *
 *  A bounty's authorization, the commands its sandbox runs and a worker's finding report all
 *  arrive as whatever the publisher wrote. They are shown to a person who is being asked to agree
 *  to them, so they are laid out as a list of plain lines rather than dumped as JSON: nobody
 *  consents to a brace. Nothing here rewrites a word; only the names of the fields are turned
 *  into English, and the values are passed through exactly as they arrived. */

/** A field's name, as a person would say it: `setupCommand` reads "Setup command". */
const words = (key: string) =>
  key
    .replace(/[_-]+/g, " ")
    .replace(/([a-z\d])([A-Z])/g, (_, before: string, after: string) => `${before} ${after.toLowerCase()}`)
    .replace(/^./, character => character.toUpperCase())

/** One value, in words. A nested object becomes one line of its own fields. */
const phrase = (value: unknown): string =>
  typeof value === "string" ? value
    : typeof value === "boolean" ? (value ? "yes" : "no")
      : Array.isArray(value) ? value.map(phrase).join(", ")
        : value && typeof value === "object"
          ? Object.entries(value as Record<string, unknown>).map(([key, inner]) => `${words(key)}: ${phrase(inner)}`).join("; ")
          : String(value)

/** The whole of somebody else's terms, one line per field, in the order they were written.
 *
 *  A publisher who wrote none of this is ordinary, and a report that has no detail yet is too,
 *  so nothing here depends on the terms being there at all. */
export function Terms({ value }: { value: Record<string, unknown> | null | undefined }) {
  const lines = Object.entries(value ?? {}).filter(([, inner]) => inner !== null && inner !== undefined && inner !== "")
  if (!lines.length) return <p className="grid-hint">Nothing was given here.</p>
  return <dl className="swarm-terms">
    {lines.map(([key, inner]) => <div key={key}><dt>{words(key)}</dt><dd>{phrase(inner)}</dd></div>)}
  </dl>
}
