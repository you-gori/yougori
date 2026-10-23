/** Four grids, one client.
 *
 *  `grids` is a plain object of plain function properties, on purpose. A test or a browser
 *  fixture may replace any one of them, the way the browser tests already replace the four
 *  product modules, and a page that reads a method at call time keeps working when one is
 *  replaced underneath it. It is not a class, it is not frozen, and it is not a proxy.
 *
 *  Nothing in it replaces a product module. The four modules keep their paths, their names,
 *  their types and their answers; they now send through the same one call path, so request
 *  names, typed refusals and the redaction pass cover what the pages already do. A page moves
 *  to `grids` when its own test moves with it, one page at a time.
 */
import { models } from "@/api/grids/profiles/models"
import { workspaces } from "@/api/grids/profiles/workspaces"
import { credentials } from "@/api/grids/profiles/credentials"
import { research } from "@/api/grids/profiles/research"
import { rollout } from "@/api/grids/rollout"
import { deliver, subscribe, watch } from "@/api/grids/events"

export const grids = {
  models,
  workspaces,
  credentials,
  research,
  rollout,
  events: { subscribe, watch, deliver },
}

export * from "@/api/grids/types"
export * from "@/api/grids/errors"
export { GRID_EVENT, forgetWatches, type EventFilter, type EventKind, type GridEvent, type Watch, type WatchStore } from "@/api/grids/events"
export { useWatch, type Watching } from "@/api/grids/use-watch"
export { MOST, mentions, paginate, where } from "@/api/grids/page"
export type {
  ApprovalFilter, AuditFilter, CredentialFilter, GrantFilter, HostFilter, Page, PageRequest,
  PersonFilter, ResearchFilter, WorkspaceFilter,
} from "@/api/grids/page"
export { CAPABILITY_DOING, capabilityOf, enabled, guard, may, ROLE_FROM_ACCESS, ROLE_FROM_DESKS, type Held } from "@/api/grids/permits"
export { ACTION_NAMES, ROLE_ACTIONS, ROLE_IMPLIES } from "@/api/grids/permits.generated"
export { REDACTED, onLeak, safePath, safeUrl, scrub, type FieldPolicy, type Leak } from "@/api/grids/redact"
export { CARRIES_REQUEST_ID, call, cliOnly, requestId, resetTransport, setTransport, type Transport } from "@/api/grids/wire"
export { DESKTOP_ONLY, decodeUtf8, readInvite, tunnelOf, type Done, type Invite, type InviteKind } from "@/api/grids/profiles/shared"
export {
  DESK_STATE_FROM_WORKSPACE, LEGACY_METHODS, STAGE_FROM_WORKER, WORKER_STATES_CORE_CANNOT_HOLD,
  WORKSPACE_STATE_FROM_DESK, type LegacyRow,
} from "@/api/grids/compat"
export {
  HEADING_PHRASE, ROLLOUT_PRODUCTS, ROLLOUT_STAGES, humanSentence, nextStage, previousStage,
  productOf, stageInfo,
  type Band, type MoveCount, type NotWired, type ObservationLine, type ObservationReading,
  type ProductMeta, type ProductWord, type ProfileObservation, type ProfileStanding,
  type RehearsalReading, type RolloutHeading, type RolloutProfile, type RolloutStage,
  type RolloutStanding, type StageInfo,
} from "@/api/grids/rollout"
