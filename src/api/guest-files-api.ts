import { platformApi } from "@/api/platform-api"

// File browsing and editing inside an environment, built on the same audited
// guest command path as the terminal. Nothing here touches the PC filesystem.
export interface GuestEntry { name: string; directory: boolean }
export interface GuestDirectory { path: string; entries: GuestEntry[] }

export const maximumEditableBytes = 262144
const chunkBytes = 12288

export function quote(value: string) { return `'${value.replaceAll("'", `'\\''`)}'` }
export function joinPath(directory: string, name: string) {
  return `${directory.replace(/\/+$/, "")}/${name}`.replace(/^$/, "/")
}

function encodeText(value: string) {
  const bytes = new TextEncoder().encode(value)
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function decodeText(base64: string) {
  const binary = atob(base64.replace(/\s+/g, ""))
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0))
  if (bytes.includes(0)) throw new Error("This looks like a binary file, so it is not opened in the editor.")
  // Only UTF-8 text is edited: anything else would be silently changed on the way in and out.
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  } catch {
    throw new Error("This file is not UTF-8 text, so it is not opened in the editor; converting it would change its characters.")
  }
}

/** SHA-256 of a text's UTF-8 bytes, as `sha256sum` prints it, to notice a file changed since it was read. */
export async function textDigest(text: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("")
}

/** A name beside the file that no other save or file uses: the save's own staging file. */
function stagingName(path: string) {
  const bytes = new Uint8Array(6)
  crypto.getRandomValues(bytes)
  return `${path}.yougori-save-${Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("")}`
}

async function shell(environmentId: string, command: string) {
  const result = await platformApi.executeEnvironmentCommand(environmentId, command)
  if (result.exitCode !== 0) throw new Error((result.stderr || result.stdout || "The environment refused this file operation.").trim())
  return result.stdout
}

export const guestFilesApi = {
  async list(environmentId: string, path: string): Promise<GuestDirectory> {
    const target = path.trim() || "."
    // `ls -A -p` marks directories with a trailing slash in both BusyBox and
    // GNU coreutils, so one listing works across container images.
    const output = await shell(environmentId, `cd ${quote(target)} && pwd && ls -A -p`)
    const [resolved, ...names] = output.split("\n")
    const entries = names
      .map(name => name.replace(/\r$/, ""))
      .filter(Boolean)
      .map(name => ({ name: name.replace(/\/$/, ""), directory: name.endsWith("/") }))
      .sort((a, b) => Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name))
    return { path: (resolved ?? target).trim() || target, entries }
  },

  async read(environmentId: string, path: string) {
    const file = quote(path)
    const size = Number((await shell(environmentId, `wc -c < ${file}`)).trim())
    if (!Number.isFinite(size)) throw new Error("This file could not be measured.")
    if (size > maximumEditableBytes) throw new Error(`This file is larger than ${Math.round(maximumEditableBytes / 1024)} KB, so it is not opened in the editor.`)
    return decodeText(await shell(environmentId, `base64 ${file}`))
  },

  /** Replaces `path` with `contents`. With `original` (the text as it was read), the file is
   *  left alone if it changed meanwhile, so an edit made elsewhere is not overwritten. */
  async write(environmentId: string, path: string, contents: string, original?: string) {
    const encoded = encodeText(contents)
    const file = quote(path)
    // Guest commands are length limited, so a long file is appended in pieces into a staging
    // file of this save's own (created exclusively, never a pre-existing file), decoded beside
    // it, and only then moved over the original in one step: a failed decode or an interrupted
    // save leaves the original as it was.
    const staging = stagingName(path)
    const temporary = quote(staging)
    const decoded = quote(`${staging}.out`)
    const cleanup = `rm -f ${temporary} ${decoded}`
    await shell(environmentId, `(set -C && : > ${temporary})`)
    try {
      for (let offset = 0; offset < encoded.length; offset += chunkBytes) {
        await shell(environmentId, `printf %s ${quote(encoded.slice(offset, offset + chunkBytes))} >> ${temporary}`)
      }
      const unchanged = original === undefined ? "" : `if [ "$(sha256sum < ${file} | cut -c1-64)" != ${quote(await textDigest(original))} ]; then echo 'The file changed since you opened it. Reload it, then save again.' >&2; exit 3; fi && `
      await shell(environmentId, `${unchanged}base64 -d < ${temporary} > ${decoded} && mv -f ${decoded} ${file} && rm -f ${temporary}`)
    } catch (reason) {
      await shell(environmentId, cleanup).catch(() => undefined)
      throw reason
    }
  },

  async create(environmentId: string, path: string, directory: boolean) {
    const target = quote(path)
    await shell(environmentId, directory ? `mkdir ${target}` : `set -C && : > ${target}`)
  },

  async remove(environmentId: string, path: string, directory: boolean) {
    await shell(environmentId, directory ? `rmdir ${quote(path)}` : `rm -f -- ${quote(path)}`)
  },
}
