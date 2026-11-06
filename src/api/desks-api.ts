import { run } from "./platform-api"

/** Serves a shared sandbox (`shared://desk/…`), not a product page.
 *
 *  The Sandbox Grid page and its admin surface are gone; what remains is the one call a shared
 *  sandbox's remote workspace makes to reconnect to its desk. The engine still handles the
 *  `shared://desk/` runtime scheme, so this keeps that reconnect working from My computer. */
const desktop = (): never => { throw new Error("Opening a shared sandbox requires Yougori Desktop") }

export const desksApi = {
  /** Reconnects to the desk behind a `shared://desk/…` sandbox. */
  refreshDesk: () => run<unknown>("desk_refresh", {}, desktop),
}
