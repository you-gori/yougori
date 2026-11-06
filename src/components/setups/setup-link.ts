import type { BuilderIntent } from "./setup-intent"

/** Where an address opens the app.
 *
 *  Every address that has ever opened a page still opens one. The branded grids no longer have
 *  their own pages, so every word that used to name one — `grids`, `neo`, `sandbox`, `desks`,
 *  `access`, `swarm` and the rest — now opens My setups rather than erroring, and so does an
 *  address that named one of the old starter recipes. The newer words go to Hub, My setups and My
 *  computer; a Hub address opens the builder on that template. An address that names nothing this
 *  app knows opens My computer, as an empty address always has.
 */
export type LinkedPage = "sandboxes" | "hub" | "setups"

export interface AppLocation {
  page: LinkedPage
  /** The setup to bring forward on My setups. */
  setupId: string | null
  builder: BuilderIntent | null
}

const PAGES: Record<string, LinkedPage> = {
  setups: "setups", "my-setups": "setups", mysetups: "setups", setup: "setups", installed: "setups", instances: "setups",
  hub: "hub", templates: "hub", template: "hub", tools: "hub", explore: "hub",
  computer: "sandboxes", "my-computer": "sandboxes", sandboxes: "sandboxes", environments: "sandboxes", home: "sandboxes", overview: "sandboxes",
  // The grids are gone; every word that named one now opens My setups instead of erroring.
  grids: "setups", "all-grids": "setups", grid: "setups", neo: "setups", sandbox: "setups", desks: "setups", access: "setups", swarm: "setups", research: "setups", credentials: "setups", models: "setups", workspaces: "setups",
}

const SETUP_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const HUB_REF = /^(?:hub\/)?([a-z0-9][a-z0-9_-]{0,63})\/([a-z0-9][a-z0-9_-]{0,63})(?:@([0-9][0-9A-Za-z.-]{0,63}))?$/

/** A Hub address in the form the builder takes, or null. */
export function hubRefFrom(value: string | null | undefined) {
  const match = value?.trim().match(HUB_REF)
  return match ? `hub/${match[1]}/${match[2]}${match[3] ? `@${match[3]}` : ""}` : null
}

export function appLocationFromSearch(search: string): AppLocation {
  const none: AppLocation = { page: "sandboxes", setupId: null, builder: null }
  const parameters = new URLSearchParams(search)
  // An old `?grid=<word>` address named a grid page that is gone; it now opens My setups.
  if ((parameters.get("grid") ?? "").trim()) return { ...none, page: "setups" }
  const setupId = parameters.get("setup")?.trim() ?? ""
  if (setupId && SETUP_ID.test(setupId)) return { ...none, page: "setups", setupId }
  const template = parameters.get("template") ?? ""
  const hubRef = hubRefFrom(template || parameters.get("run"))
  if (parameters.get("create") === "template") return { ...none, page: "hub", builder: { mode: "create", ...(hubRef ? { hubRef, entry: "hub" } : {}) } }
  // An old `?recipe=<word>` address opened the builder on a starter recipe. There are none now;
  // My setups is where a template is run, so that is where it opens. The word is never read.
  if ((parameters.get("recipe") ?? "").trim()) return { ...none, page: "setups" }
  if (hubRef) return { ...none, page: "hub", builder: { mode: "run", hubRef } }
  // A `?template=<word>` that is not a Hub address opens the Hub, where templates are found.
  if (template.trim()) return { ...none, page: "hub" }
  const page = PAGES[(parameters.get("page") ?? "").trim().toLowerCase()]
  return page ? { ...none, page } : none
}
