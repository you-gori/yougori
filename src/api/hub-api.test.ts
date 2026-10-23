import { describe, expect, it } from "vitest"
import { HUB_WARNING, hubCommand, plainFilePath, searchWords } from "./hub-api"

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
