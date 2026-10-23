import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { platformApi } from "@/api/platform-api"
import { guestFilesApi, joinPath, maximumEditableBytes, quote, textDigest } from "@/api/guest-files-api"

vi.mock("@/api/platform-api", () => ({ platformApi: { executeEnvironmentCommand: vi.fn() } }))

const execute = vi.mocked(platformApi.executeEnvironmentCommand)
const ok = (stdout: string) => ({ stdout, stderr: "", exitCode: 0 })
const commands = () => execute.mock.calls.map(call => call[1])
beforeEach(() => { execute.mockResolvedValue(ok("")) })
afterEach(() => { vi.resetAllMocks() })

describe("Environment files", () => {
  it("quotes names so a file cannot break out of its command", () => {
    expect(quote("it's here.txt")).toBe(`'it'\\''s here.txt'`)
    expect(quote("a; rm -rf /")).toBe("'a; rm -rf /'")
    expect(joinPath("/workspace/", "app.js")).toBe("/workspace/app.js")
  })

  it("lists directories first and keeps the resolved path", async () => {
    execute.mockResolvedValue(ok("/workspace\nnotes.txt\nsrc/\napp.js\n"))
    const listing = await guestFilesApi.list("env-a", ".")
    expect(listing.path).toBe("/workspace")
    expect(listing.entries).toEqual([
      { name: "src", directory: true },
      { name: "app.js", directory: false },
      { name: "notes.txt", directory: false },
    ])
  })

  it("refuses a file that is too large to edit before reading it", async () => {
    execute.mockResolvedValue(ok(`${maximumEditableBytes + 1}\n`))
    await expect(guestFilesApi.read("env-a", "/workspace/big.bin")).rejects.toThrow(/larger than/)
    expect(commands()).toHaveLength(1)
  })

  it("decodes text and refuses binary content", async () => {
    execute.mockResolvedValueOnce(ok("12\n")).mockResolvedValueOnce(ok(btoa("hello guest\n")))
    expect(await guestFilesApi.read("env-a", "/workspace/notes.txt")).toBe("hello guest\n")
    execute.mockResolvedValueOnce(ok("4\n")).mockResolvedValueOnce(ok(btoa("a\0b\0")))
    await expect(guestFilesApi.read("env-a", "/workspace/app.bin")).rejects.toThrow(/binary/)
  })

  it("refuses text that is not UTF-8 rather than changing its characters", async () => {
    execute.mockResolvedValueOnce(ok("4\n")).mockResolvedValueOnce(ok(btoa("caf\xe9")))
    await expect(guestFilesApi.read("env-a", "/workspace/legacy.txt")).rejects.toThrow(/not UTF-8/)
  })

  it("writes long files in pieces into its own staging file and replaces the original in one move", async () => {
    await guestFilesApi.write("env-a", "/workspace/app.js", "x".repeat(40000))
    const sent = commands()
    const staging = sent[0]?.match(/^\(set -C && : > '(\/workspace\/app\.js\.yougori-save-[0-9a-f]{12})'\)$/)?.[1]
    expect(staging, "the staging file is created exclusively, under a name of its own").toBeTruthy()
    expect(sent.filter(command => command.startsWith("printf %s ")).length).toBeGreaterThan(1)
    expect(sent.at(-1)).toBe(`base64 -d < '${staging}' > '${staging}.out' && mv -f '${staging}.out' '/workspace/app.js' && rm -f '${staging}'`)
    expect(sent.at(-1)).not.toContain("> '/workspace/app.js'")
  })

  it("checks the file is unchanged since it was read before replacing it, and cleans up when not", async () => {
    const digest = await textDigest("old text")
    execute.mockResolvedValue(ok(""))
    await guestFilesApi.write("env-a", "/workspace/notes.txt", "new text", "old text")
    const final = commands().at(-1) ?? ""
    expect(final.startsWith(`if [ "$(sha256sum < '/workspace/notes.txt' | cut -c1-64)" != '${digest}' ]; then echo 'The file changed since you opened it. Reload it, then save again.' >&2; exit 3; fi && base64 -d`)).toBe(true)
    execute.mockReset()
    execute.mockImplementation(async (_environment, command) => command.startsWith("if [") ? { stdout: "", stderr: "The file changed since you opened it. Reload it, then save again.", exitCode: 3 } : ok(""))
    await expect(guestFilesApi.write("env-a", "/workspace/notes.txt", "new text", "old text")).rejects.toThrow(/changed since you opened it/)
    expect(commands().at(-1)).toMatch(/^rm -f '\/workspace\/notes\.txt\.yougori-save-[0-9a-f]{12}' '\/workspace\/notes\.txt\.yougori-save-[0-9a-f]{12}\.out'$/)
  })

  it("reports the environment's own error instead of claiming success", async () => {
    execute.mockResolvedValue({ stdout: "", stderr: "sh: can't create /etc/passwd: Permission denied", exitCode: 1 })
    await expect(guestFilesApi.create("env-a", "/etc/passwd", false)).rejects.toThrow(/Permission denied/)
  })
})
