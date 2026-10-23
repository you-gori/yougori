import { test, expect, type Page } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

const invite = (fingerprint: string, address = "https://grid.acme.com") =>
  "grid-invite:" + Buffer.from(JSON.stringify({ v: 1, c: "Acme", a: address, f: fingerprint })).toString("base64url")

/** Replaces the grid API with an in-page engine that records every call. */
async function mockGrid(page: Page) {
  await page.evaluate(async () => {
    const path = "/src/api/grid-api.ts"
    const { gridApi } = await import(path)
    // The models page reads its membership and assignment through the grids client and makes every
    // change on the grid through it; the host and join dialogs and the swarm panel still call gridApi.
    const gridsPath = "/src/api/grids/index.ts"
    const { grids } = await import(gridsPath)
    type Call = { method: string; args: unknown[] }
    const calls: Call[] = []
    const state: { hub: unknown; member: unknown; harnesses: Array<Record<string, unknown>> } = { hub: null, member: null, harnesses: [] }
    const record = (method: string, args: unknown[]) => { calls.push({ method, args }) }
    const hub = (plans: unknown[], members: unknown[]) => ({
      id: "g1", name: "Acme", address: "192.168.1.20", port: 7460, url: "https://192.168.1.20:7460/v1", fingerprint: "AB:CD", createdAt: "",
      computers: { total: members.length, capable: members.length, online: members.length }, plans, planWarning: null, members,
      queue: { waiting: 0, running: 0 }, harnesses: state.harnesses, tunnel: { kind: "quick", domain: null, url: "https://acme.trycloudflare.com", connected: true, error: null },
      invite: "grid-invite:eyJ2IjoxfQ",
    })
    const laptop = { id: "m1", name: "Design laptop", platform: "windows", joinedAt: "", capable: true, excluded: false, planId: null, jobs: 3, online: true, lastSeenSeconds: 2, address: "192.168.1.30", appVersion: "1.0.21", running: 0, models: [] }
    const studio = { id: "m2", name: "Studio PC", platform: "windows", joinedAt: "", capable: true, excluded: false, planId: null, jobs: 0, online: true, lastSeenSeconds: 1, address: "192.168.1.31", appVersion: "1.0.21", running: 0, models: [] }
    Object.assign(window, { __grid: { calls, state } })
    gridApi.status = async () => ({ hub: state.hub, hubError: null, member: state.member, memberError: null })
    gridApi.suggestedAddress = async () => "192.168.1.20"
    gridApi.create = async (...args: unknown[]) => { record("create", args); state.hub = hub([], [laptop, studio]); return { message: "Created Acme's grid" } }
    grids.models.addPlan = async (...args: unknown[]) => {
      record("addPlan", args)
      type Member = { id: string; name: string; planId: string | null }
      const current = state.hub as { plans: Array<{ id: string }>; members: Member[] }
      const asked = args[0] as { model: string; target: { kind: string; hosts?: string[]; percent?: number } }
      const target = asked.target
      const picked = target.kind === "hosts" ? target.hosts! : []
      const id = `p${current.plans.length + 1}`
      const members = current.members.map(member => target.kind === "hosts" ? (picked.includes(member.id) ? { ...member, planId: id } : member) : member.planId ? member : { ...member, planId: id })
      const scope = target.kind === "hosts" ? { kind: "computers", members: picked } : { kind: target.kind }
      const names = target.kind === "hosts" ? members.filter(member => picked.includes(member.id)).map(member => member.name) : []
      const plan = { id, model: asked.model, quant: null, percent: target.percent ?? 100, rules: "always on", computers: members.filter(member => member.planId === id).length, target: 1, ready: 0, scope, names }
      state.hub = hub([...current.plans, plan], members)
      return {}
    }
    grids.models.removeHost = async (...args: unknown[]) => { record("removeComputer", args); const current = state.hub as { plans: unknown[] }; state.hub = hub(current.plans, []); return {} }
    grids.models.scheduleDeletion = async (...args: unknown[]) => {
      record("delete", args)
      // Later: paused for three days, restorable. Now: every computer heard, so the hub is gone.
      if (args[0] === "later" && state.hub) state.hub = { ...state.hub, closing: { requestedAt: 1, until: Math.floor(Date.now() / 1000) + 3 * 86400, gone: false, told: 0, computers: 2, tellUntil: 0 } }
      else state.hub = null
      return { deleted: true }
    }
    grids.models.restore = async (...args: unknown[]) => { record("restore", args); if (state.hub) state.hub = { ...state.hub, closing: null }; return {} }
    const setExcluded = (id: unknown, excluded: boolean) => {
      const current = state.hub as { plans: unknown[]; members: Array<Record<string, unknown>> }
      state.hub = { ...current, members: current.members.map(member => member.id === id ? { ...member, excluded, planId: excluded ? null : member.planId } : member) }
    }
    grids.models.drainHost = async (...args: unknown[]) => { record("excludeComputer", args); setExcluded(args[0], true); return {} }
    grids.models.bringHostBack = async (...args: unknown[]) => { record("includeComputer", args); setExcluded(args[0], false); return {} }
    gridApi.join = async (...args: unknown[]) => {
      record("join", args)
      state.member = { gridId: "g1", grid: "Acme", hub: "https://grid.acme.com", fingerprint: "AB:CD:EF", memberId: "m9", joinedAt: "", connected: true, error: null, capable: true, backend: "cuda", assignment: { model: "hf.co/acme/assistant" }, rules: "always on", state: "serving", reason: null, jobs: 12, failures: 0, lastError: null }
      return { message: "Joined Acme's Closed Neo Grid." }
    }
    grids.models.leave = async (...args: unknown[]) => { record("leave", args); state.member = null; return { left: true } }
    gridApi.addHarness = async (...args: unknown[]) => {
      record("addHarness", args)
      const made = args[0] as Record<string, unknown>
      state.harnesses = [...state.harnesses, { ...made, id: `swarm-${state.harnesses.length + 1}`, model: `swarm/${String(made.name)}`, tasks: made.computers, ready: true }]
      return { missing: [] }
    }
    gridApi.removeHarness = async (...args: unknown[]) => { record("removeHarness", args); state.harnesses = state.harnesses.filter(item => item.id !== args[0]); return {} }
    gridApi.runHarness = async (...args: unknown[]) => {
      record("runHarness", args)
      const part = (title: string, computer: string) => ({ title, model: "acme/worker", computer, seconds: 2.4, answer: `${title} done` })
      return {
        model: "swarm/research", answer: "Open in spring; prices are fair and rivals are few.", usage: { promptTokens: 40, completionTokens: 20 },
        trace: { harness: "swarm/research", strategy: "plan", computersUsed: ["Lead PC", "Design laptop", "Studio PC", "Render box"], seconds: 6.2, final: { model: "acme/lead", computer: "Lead PC" },
          rounds: [{ round: 1, planner: "Lead PC", tasks: [part("Prices", "Design laptop"), part("Risks", "Studio PC"), { ...part("Rivals", "Render box"), error: "timed out", answer: undefined }] }] },
      }
    }
  })
}

const calls = (page: Page) => page.evaluate(() => (window as unknown as { __grid: { calls: Array<{ method: string; args: unknown[] }> } }).__grid.calls)

async function seedHub(page: Page, models: string[]) {
  await page.evaluate(async models => {
    const grid = (window as unknown as { __grid: { state: Record<string, unknown> } }).__grid
    const member = (id: string, name: string) => ({ id, name, platform: "windows", joinedAt: "", capable: true, excluded: false, planId: "p1", jobs: 0, online: true, lastSeenSeconds: 1, address: null, appVersion: "1.0.21", running: 0, models: [] as unknown[] })
    const members = [member("m1", "Design laptop"), member("m2", "Studio PC"), member("m3", "Render box")]
    const plans = models.map((model, index) => ({ id: `p${index + 1}`, model, quant: null, percent: 100, rules: "always on", computers: 1, target: 1, ready: 1, scope: { kind: "all" }, names: [] }))
    if (models.length) {
      members[0]!.models = [{ model: models[0], state: "loading", progress: { phase: "downloading", done: 4e9, total: 16e9, rate: 45e6 } }]
      members[1]!.models = [{ model: models[0], state: "available" }]
      members[2]!.models = [{ model: models[0], state: "person_active" }]
    }
    grid.state.hub = { id: "g1", name: "Acme", address: "192.168.1.20", port: 7460, url: "", fingerprint: "AB", createdAt: "", computers: { total: 3, capable: 3, online: 3 }, plans, planWarning: null, members, queue: { waiting: 0, running: 0 }, invite: "grid-invite:eyJ2IjoxfQ", get harnesses() { return grid.state.harnesses } }
  }, models)
}

async function openNeoGrid(page: Page) {
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  await mockGrid(page)
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Neo Grid", exact: true }).click()
  await expect(page.getByRole("region", { name: "Neo Grid workspace" })).toBeVisible()
}

test("Host a grid creates a hub and the board manages its computers and models", async ({ page }) => {
  await openNeoGrid(page)
  await expect(page.getByText("Host or join a model grid")).toBeVisible()
  await page.getByRole("button", { name: "Host a grid", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Host a grid" })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByLabel("This computer's address")).toHaveValue("192.168.1.20")
  const host = dialog.getByRole("button", { name: "Host grid", exact: true })
  const rule = dialog.locator("#grid-password-rule")
  const match = dialog.locator("#grid-password-match")
  await expect(rule).toHaveText("At least 10 characters. A short sentence works well.")
  await dialog.getByLabel("Company name").fill("Acme")
  await dialog.getByLabel("Company password").fill("short")
  await dialog.getByLabel("Type it again").fill("short")
  await expect(rule).toHaveText("5 of 10 characters")
  await expect(host).toBeDisabled()
  await dialog.getByLabel("Company password").fill("correct horse battery")
  await dialog.getByLabel("Type it again").fill("correct horse batterx")
  await expect(rule).toHaveText("Long enough · 21 characters")
  await expect(match).toHaveText("The passwords do not match")
  await expect(host).toBeDisabled()
  await dialog.getByLabel("Type it again").fill("correct horse battery")
  await expect(match).toHaveText("Passwords match")
  await dialog.getByRole("radio", { name: /Anywhere/ }).click()
  await expect(host).toBeEnabled()
  await host.click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).find(call => call.method === "create")?.args).toEqual(["Acme", "192.168.1.20", "correct horse battery", "quick"])

  const board = page.getByRole("region", { name: "Neo Grid workspace" })
  await expect(board.getByRole("region", { name: "Hosted grid" })).toContainText("Acme")
  await expect(board.getByRole("region", { name: "Hosted grid" })).toContainText("https://acme.trycloudflare.com")
  const connect = board.getByRole("region", { name: "Connect other computers" })
  await expect(connect).toContainText("irm https://yougori.com/install.ps1 | iex")
  await connect.getByRole("button", { name: "macOS · Linux" }).click()
  await expect(connect).toContainText("curl -fsSL https://yougori.com/install.sh | sh")
  await expect(connect).toContainText("yougori grid join --invite grid-invite:")
  await expect(connect).toContainText("yougori join grid")
  await expect(connect).not.toContainText("correct horse battery")
  await expect(board.getByRole("region", { name: "Hosted grid" }).getByRole("button", { name: "Copy invite" })).toBeEnabled()
  // The invite inside the join command starts blurred, with its own Unblur button beside it.
  const joinCommand = connect.locator("code", { hasText: "yougori grid join --invite" })
  await expect(joinCommand).toHaveAttribute("data-blurred")
  await expect(connect.locator("code", { hasText: "install.sh" })).not.toHaveAttribute("data-blurred")
  await connect.getByRole("button", { name: "Unblur" }).click()
  await expect(joinCommand).not.toHaveAttribute("data-blurred")
  await connect.getByRole("button", { name: "Hide" }).click()
  await expect(joinCommand).toHaveAttribute("data-blurred")
  // Compact: the hosted grid's own line is a single row.
  const head = await board.getByRole("region", { name: "Hosted grid" }).boundingBox()
  expect(head!.height).toBeLessThanOrEqual(48)

  await expect(board.getByRole("region", { name: "Computers", exact: true })).toContainText("Design laptop")
  await expect(page.getByRole("button", { name: "Host a grid", exact: true })).toBeDisabled()

  const models = board.getByRole("region", { name: "Models", exact: true })
  const runOn = board.getByLabel("Run it on")
  // hf.co/ is written in front of the field and cannot be deleted; a pasted link keeps one prefix.
  const modelField = board.getByLabel("Run a model on the computers")
  await expect(models.locator(".grid-model-field")).toContainText("hf.co/")
  await expect(modelField).toHaveValue("")
  await modelField.focus()
  await page.keyboard.press("Backspace")
  await expect(models.locator(".grid-model-field")).toContainText("hf.co/")
  await modelField.fill("https://huggingface.co/acme/vision")
  await expect(modelField).toHaveValue("acme/vision")
  await modelField.fill("hf.co/acme/vision")
  await expect(modelField).toHaveValue("acme/vision")
  await modelField.fill("")
  // Every control in the assign row is the same height.
  const heights = await models.locator(".grid-plan-form > *").evaluateAll(nodes => nodes.map(node => Math.round(node.getBoundingClientRect().height)))
  expect(new Set(heights).size, `assign row heights ${heights.join("/")}`).toBe(1)
  // Pick one computer: the target follows the pick and no share is asked.
  await board.getByRole("checkbox", { name: "Select Studio PC" }).check()
  await expect(runOn).toHaveValue("selected")
  await expect(runOn.locator("option:checked")).toHaveText("The selected computer")
  await expect(board.getByLabel("Share of computers (%)")).toHaveCount(0)
  await expect(models).toContainText("the model they ran before is deleted from them")
  await board.getByLabel("Run a model on the computers").fill("hf.co/acme/coder")
  await expect(board.getByLabel("Run a model on the computers")).toHaveValue("acme/coder")
  await board.getByRole("button", { name: "Assign", exact: true }).click()
  await expect(models).toContainText("hf.co/acme/coder")
  await expect(models).toContainText("Studio PC")
  expect((await calls(page)).filter(call => call.method === "addPlan").at(-1)?.args).toEqual([{ model: "hf.co/acme/coder", target: { kind: "hosts", hosts: ["m2"] } }])
  await expect(board.getByRole("checkbox", { name: "Select Studio PC" })).not.toBeChecked()
  // The rest get a share of the computers without a model.
  await expect(runOn).toHaveValue("remaining")
  await board.getByLabel("Run a model on the computers").fill("hf.co/acme/assistant")
  await board.getByLabel("Share of computers (%)").fill("50")
  await board.getByRole("button", { name: "Assign", exact: true }).click()
  await expect(models).toContainText("50% of computers without a model")
  expect((await calls(page)).filter(call => call.method === "addPlan").at(-1)?.args).toEqual([{ model: "hf.co/acme/assistant", target: { kind: "remaining", percent: 50 } }])
  // Or a share of all computers.
  await runOn.selectOption("all")
  await board.getByLabel("Run a model on the computers").fill("hf.co/acme/vision")
  await board.getByLabel("Share of computers (%)").fill("25")
  await board.getByRole("button", { name: "Assign", exact: true }).click()
  await expect(models).toContainText("25% of all computers")
  expect((await calls(page)).filter(call => call.method === "addPlan").at(-1)?.args).toEqual([{ model: "hf.co/acme/vision", target: { kind: "all", percent: 25 } }])

  const remove = board.getByRole("button", { name: "Remove Design laptop" })
  await remove.click()
  await expect(remove).toHaveText("Confirm")
  await remove.click()
  await expect(board.getByRole("region", { name: "Computers", exact: true })).not.toContainText("Design laptop")
  expect((await calls(page)).some(call => call.method === "removeComputer" && call.args[0] === "m1")).toBe(true)

  // Deleting asks how. In three days: paused, said so, and Restore brings it back.
  await board.getByRole("button", { name: "Delete grid" }).click()
  await board.getByRole("button", { name: "Delete in 3 days" }).click()
  await expect(board.getByRole("status").filter({ hasText: "Paused, deleted on" })).toContainText("unless you restore it")
  await board.getByRole("button", { name: "Restore", exact: true }).click()
  await expect(board.getByRole("status").filter({ hasText: "Paused" })).toHaveCount(0)
  // Now: deleted at once.
  await board.getByRole("button", { name: "Delete grid" }).click()
  await board.getByRole("button", { name: "Delete now" }).click()
  expect((await calls(page)).filter(call => call.method === "delete").map(call => call.args[0])).toEqual(["later", "now"])
  expect((await calls(page)).some(call => call.method === "restore")).toBe(true)
  await expect(page.getByText("Host or join a model grid")).toBeVisible()
  await expect(page.getByRole("button", { name: "Host a grid", exact: true })).toBeEnabled()
})

test("Join a closed grid uses the invite and password, then shows the membership", async ({ page }) => {
  await openNeoGrid(page)
  await page.getByRole("button", { name: "Join a closed grid", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Join a closed grid" })
  const join = dialog.getByRole("button", { name: "Join grid", exact: true })
  await dialog.getByLabel("Invite from your admin").fill("hello")
  await expect(join).toBeDisabled()
  await expect(dialog).toContainText("That is not a grid invite")
  const code = invite("ABCDEF")
  await dialog.getByLabel("Invite from your admin").fill(code)
  await expect(dialog).toContainText("Acme")
  await expect(join).toBeDisabled()
  await dialog.getByLabel("Company password").fill("correct horse battery")
  await join.click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).find(call => call.method === "join")?.args).toEqual([code, "correct horse battery"])

  const joined = page.getByRole("region", { name: "Joined grid" })
  await expect(joined).toContainText("Acme")
  await expect(joined).toContainText("Connected · hf.co/acme/assistant · serving")
  expect((await joined.boundingBox())!.height).toBeLessThanOrEqual(48)
  const details = page.getByRole("list", { name: "This computer in the grid" })
  await expect(details).toHaveCount(0)
  await joined.getByRole("button", { name: "Show details" }).click()
  await expect(details).toContainText("Connected to the hub")
  await expect(details).toContainText("https://grid.acme.com")
  await expect(details).toContainText("hf.co/acme/assistant")
  await joined.getByRole("button", { name: "Hide details" }).click()
  await expect(details).toHaveCount(0)

  // A new invite for the same grid only moves this computer; no password is asked.
  await page.getByRole("button", { name: "Join a closed grid", exact: true }).click()
  await dialog.getByLabel("Invite from your admin").fill(invite("AB:CD:EF", "https://new.trycloudflare.com"))
  await expect(dialog.getByLabel("Company password")).toHaveCount(0)
  await dialog.getByRole("button", { name: "Move to the new address" }).click()
  await expect(dialog).toBeHidden()
  const joins = (await calls(page)).filter(call => call.method === "join")
  expect(joins.at(-1)?.args[1]).toBeUndefined()

  await joined.getByRole("button", { name: "Leave grid" }).click()
  await joined.getByRole("button", { name: "Confirm leave" }).click()
  await expect(page.getByText("Host or join a model grid")).toBeVisible()
})

test("Join Yougori grid opens the public Neo Grid", async ({ page }) => {
  await openNeoGrid(page)
  await page.getByRole("button", { name: "Join Yougori grid", exact: true }).click()
  await expect(page.getByRole("dialog", { name: "Neo Grid" })).toBeVisible()
  await expect(page.getByRole("dialog", { name: "Neo Grid" }).getByRole("region", { name: "Shared models" })).toBeVisible()
})

test("A swarm is set up from the grid's models and one run shows which computer did each task", async ({ page }) => {
  await openNeoGrid(page)
  await seedHub(page, [])
  const swarms = page.getByRole("region", { name: "Swarms", exact: true })
  // The seeded hub only reaches the page on the next status poll (4s), so this needs the same
  // headroom the "New swarm" assertion below already uses.
  await expect(swarms).toContainText("Assign models to computers above first", { timeout: 10000 })
  await seedHub(page, ["Acme/Lead", "Acme/Worker"])
  const form = swarms.getByRole("form", { name: "New swarm" })
  await expect(form).toBeVisible({ timeout: 10000 })
  const add = form.getByRole("button", { name: "Add swarm" })
  await expect(add).toBeDisabled()

  // The name keeps its swarm/ prefix; models come from what the grid runs.
  const name = form.getByLabel("Swarm name")
  await name.fill("swarm/Research Team!")
  await expect(name).toHaveValue("researchteam")
  await name.fill("research")
  await form.getByLabel("Lead model").selectOption("Acme/Lead")
  await form.getByRole("button", { name: "Acme/Worker" }).click()
  await expect(form.getByRole("button", { name: "Acme/Worker" })).toHaveAttribute("aria-pressed", "true")
  await form.getByLabel("Computers per call").fill("3")
  await expect(form).toContainText("The lead splits each request into up to 3 independent tasks, one per computer")
  await form.getByLabel("Rounds").selectOption("2")
  // Mixture allows two layers at most.
  await form.getByRole("button", { name: "Mixture" }).click()
  await expect(form.getByLabel("Layers").locator("option")).toHaveCount(2)
  await expect(form).toContainText("3 computers each answer the whole request")
  await form.getByRole("button", { name: "Plan & delegate" }).click()
  await expect(form.getByLabel("Rounds").locator("option")).toHaveCount(3)
  await form.getByLabel("Rounds").selectOption("2")
  await expect(add).toBeEnabled()
  await add.click()
  const added = (await calls(page)).find(call => call.method === "addHarness")?.args
  expect(added).toEqual([{ name: "research", strategy: "plan", lead: "Acme/Lead", workers: ["Acme/Worker"], computers: 3, rounds: 2 }])

  // Its row reads like the plans above; the chevron opens a place to try it.
  await expect(swarms).toContainText("swarm/research")
  await expect(swarms).toContainText("Plan & delegate · Acme/Lead leads · 3 computers × Acme/Worker · 2 rounds")
  await swarms.getByRole("button", { name: "Try swarm/research" }).click()
  const prompt = swarms.getByLabel("Prompt for swarm/research")
  await prompt.fill("Should we open a shop in Lyon?")
  await swarms.getByRole("button", { name: "Run", exact: true }).click()
  const result = swarms.getByLabel("Swarm result")
  await expect(result).toContainText("3 tasks on 4 computers · 6.2 s · combined by Lead PC")
  await expect(result).toContainText("Prices")
  await expect(result).toContainText("Design laptop · acme/worker · 2.4 s")
  await expect(result).toContainText("Render box")
  await expect(result).toContainText("timed out")
  await expect(result).toContainText("Open in spring; prices are fair and rivals are few.")
  expect((await calls(page)).find(call => call.method === "runHarness")?.args).toEqual(["research", "Should we open a shop in Lyon?"])
  await expect(swarms).toContainText("as the model swarm/research")

  // Removing asks once more on the same button.
  const remove = swarms.getByRole("button", { name: "Remove swarm/research" })
  await remove.click()
  await expect(remove).toHaveText("Confirm")
  await remove.click()
  await expect(swarms).not.toContainText("swarm/research", { timeout: 10000 })
  expect((await calls(page)).some(call => call.method === "removeHarness" && call.args[0] === "swarm-1")).toBe(true)
})

test("A computer shows what it is doing, download included, and can be left out and brought back", async ({ page }) => {
  await openNeoGrid(page)
  await seedHub(page, ["Qwen/Qwen3-8B"])
  const computers = page.getByRole("region", { name: "Computers", exact: true })
  await expect(computers).toBeVisible({ timeout: 10000 })

  // A download says how far it has come, with a bar; the others say it in plain words.
  await expect(computers).toContainText("Downloading Qwen/Qwen3-8B · 4.0 of 16.0 GB · 45 MB/s")
  const bar = computers.getByRole("progressbar", { name: "Design laptop progress" })
  await expect(bar).toHaveAttribute("aria-valuenow", "25")
  await expect(computers).toContainText("Ready · serving Qwen/Qwen3-8B")
  await expect(computers).toContainText("Paused while its person works · Qwen/Qwen3-8B")

  // Leaving a computer out asks once more, then it gets no model and no work.
  const leave = computers.getByRole("button", { name: "Leave Design laptop out" })
  await leave.click()
  await expect(leave).toHaveText("Confirm")
  await leave.click()
  await expect(computers).toContainText("Left out · gets no model and no work")
  await expect(computers.getByRole("progressbar", { name: "Design laptop progress" })).toHaveCount(0)
  await expect(computers.getByRole("checkbox", { name: "Select Design laptop" })).toBeDisabled()
  expect((await calls(page)).some(call => call.method === "excludeComputer" && call.args[0] === "m1")).toBe(true)

  // Bringing it back needs no second click, and it takes a model again.
  await computers.getByRole("button", { name: "Bring Design laptop back" }).click()
  await expect(computers).not.toContainText("Left out")
  await expect(computers.getByRole("checkbox", { name: "Select Design laptop" })).toBeEnabled()
  expect((await calls(page)).some(call => call.method === "includeComputer" && call.args[0] === "m1")).toBe(true)
})
