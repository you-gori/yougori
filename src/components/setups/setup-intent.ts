import type { CapabilityGroup } from "@/api/setups/types"

/** What a new template starts from: capabilities the author adds, or something imported. */
export type EntryKind = "blank" | "setup" | "environments" | "folder" | "compose" | "hub"

/** Why the builder was opened, and where it starts.
 *
 *  - create: an author makes a template, adding capabilities from the shared groups, or starting
 *    from a setup, a folder, a Compose file, chosen environments or a Hub template.
 *  - run: somebody sets up a template on this computer, from the Hub or a folder.
 *  - configure: the owner of an installed setup changes it or adds a capability, or moves it to
 *    the newest version of its Hub template (`update`), keeping the choices they made. */
export type BuilderIntent =
  | { mode: "create"; entry?: EntryKind; environments?: string[]; hubRef?: string; group?: CapabilityGroup; capability?: string }
  | { mode: "run"; hubRef?: string; folder?: string; group?: CapabilityGroup }
  | { mode: "configure"; setupId: string; setupName?: string; addCapability?: boolean; group?: CapabilityGroup; update?: { publisher: string; name: string; version: string } }
