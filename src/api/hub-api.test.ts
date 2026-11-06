import { describe, expect, it, vi } from "vitest"

const run = vi.hoisted(() => vi.fn())
vi.mock("@/api/platform-api", () => ({ run }))

import { HUB_WARNING, hubApi, hubCommand, plainFilePath, runsNatively, searchWords } from "./hub-api"

describe("hub api helpers", () => {
  it("keeps search text to plain words the engine forwards unchanged", () => {
    expect(searchWords("  Model Gateway ")).toBe("model+gateway")
    expect(searchWords("100% & more?!")).toBe("100+more")
    expect(searchWords("a..b c")).toBe("a.b+c")
    expect(searchWords("%2e%2e/x#frag")).toBe("2e+2e+x+frag")
    expect(searchWords("one two three four five six seven")).toBe("one+two+three+four+five+six")
    expect(searchWords("")).toBe("")
  })
  it("sends only plain file paths through the proxy", () => {
    for (const path of ["README.md", "app/server.js", "tools/httpie/yougori-tool.yaml"]) expect(plainFilePath(path)).toBe(true)
    for (const path of ["my file.txt", "a/../b", "a//b", "é.txt", "x%20y"]) expect(plainFilePath(path)).toBe(false)
  })
  it("builds the run command and the fixed warning", () => {
    expect(hubCommand({ publisher: "ana", name: "my-api", kind: "template" })).toBe("yougori run hub/ana/my-api")
    expect(hubCommand({ publisher: "ana", name: "aider", kind: "tool" }, "1.0.0")).toBe("yougori tool add hub/ana/aider@1.0.0")
    expect(HUB_WARNING("template")).toBe("Not checked by Yougori. Community templates can contain harmful code, including viruses. Read the files first and run only what you trust.")
  })
})

describe("saving a template the builder made", () => {
  it("sends the folder and the engine's source, and leaves out parts it does not have", async () => {
    run.mockResolvedValue({ folder: "D:/t", name: "acme", written: ["yougori-template.yaml", "README.md"], keptReadme: false })
    await hubApi.saveTemplateDraft({ folder: "D:/t", template: "name: acme", project: null })
    expect(run).toHaveBeenLastCalledWith("hub_save_template_draft", { request: { folder: "D:/t", template: "name: acme" } }, expect.any(Function))
    await hubApi.saveTemplateDraft({ folder: "D:/t", template: "name: acme", project: "project: acme", summary: "Desks." })
    expect(run).toHaveBeenLastCalledWith("hub_save_template_draft", { request: { folder: "D:/t", template: "name: acme", project: "project: acme", summary: "Desks." } }, expect.any(Function))
  })
})

describe("which templates are set up here and which in a console", () => {
  it("sets up format 2 here, format 1 here only when it asks nothing, and the rest through the CLI", () => {
    const web = [{ name: "web" }]
    expect(runsNatively({ kind: "template", format: 2 })).toBe(true)
    expect(runsNatively({ kind: "template", format: 1 }, { format: 2 })).toBe(true)
    // Format 1 with a summary and no questions: here. With questions, or no summary: the console.
    expect(runsNatively({ kind: "template" }, { environments: web })).toBe(true)
    expect(runsNatively({ kind: "template" }, { environments: web, inputs: [{ id: "key", question: "API key", type: "secret" }] })).toBe(false)
    expect(runsNatively({ kind: "template" })).toBe(false)
    expect(runsNatively({ kind: "tool", format: 2 })).toBe(false)
    // The switch is one set: without 1 in it, every format 1 template keeps the console.
    expect(runsNatively({ kind: "template" }, { environments: web }, new Set([2]))).toBe(false)
  })
})
