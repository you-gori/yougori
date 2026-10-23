import { test, expect, type Page } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

/** Replaces the swarm engine with an in-page fake that records calls; no worker ever runs. */
async function mockSwarm(page: Page) {
  await page.evaluate(async () => {
    const path = "/src/api/swarm-api.ts"
    const { swarmApi } = await import(path)
    type Call = { method: string; args: unknown[] }
    const calls: Call[] = []
    const state: { workers: Array<Record<string, unknown>> } = { workers: [] }
    Object.assign(window, { __swarm: { calls, state } })
    const record = (method: string, args: unknown[]) => calls.push({ method, args })
    const worker = (over: Record<string, unknown>) => ({ id: "worker-1", name: "Bounty worker", model: "hf.co/acme/model", state: "ready_waiting", stage: "", gpu: "NVIDIA", resources: {}, workspaceQuotaGb: 20, keepResident: false, error: null, summary: "", createdAt: 0, ...over })
    swarmApi.workers = async () => state.workers as never
    swarmApi.prepare = async (...args: unknown[]) => { record("prepare", args); const made = worker({ id: "worker-1", name: (args[0] as { name: string }).name, model: (args[0] as { model: string }).model }); state.workers = [...state.workers, made]; return made as never }
    swarmApi.practiceStart = async (...args: unknown[]) => { record("practiceStart", args); const id = args[0]; state.workers = state.workers.map(item => item.id === id ? { ...item, state: "running", stage: "Working on your source" } : item); return {} as never }
    swarmApi.activity = async (...args: unknown[]) => { record("activity", args); return { worker: state.workers[0], latest: 1, events: [{ seq: 1, kind: "turn", at: 1, stage: "Reading", text: "Reading the source" }] } as never }
    swarmApi.pause = async (...args: unknown[]) => { record("pause", args); state.workers = state.workers.map(item => item.id === args[0] ? { ...item, state: "paused" } : item); return {} as never }
    swarmApi.resume = async (...args: unknown[]) => { record("resume", args); state.workers = state.workers.map(item => item.id === args[0] ? { ...item, state: "ready_waiting" } : item); return {} as never }
    swarmApi.remove = async (...args: unknown[]) => { record("remove", args); state.workers = state.workers.filter(item => item.id !== args[0]); return {} as never }
    swarmApi.offers = async (...args: unknown[]) => {
      record("offers", args)
      return [{ id: "offer-1", termsVersion: 1, termsDigest: "d1", sourceRevision: "r1", authorizationDigest: "a1",
        bounty: { id: "bounty-7", title: "Review the checkout service", summary: "Look for logic flaws in the checkout flow.", publisher: "Acme Store", reward: "€500", scope: "checkout.acme.test only", authorization: "The publisher authorizes testing of checkout.acme.test.", terms: { sourceDigest: "s1", serviceRules: { version: 2, digest: "rd1", text: "Do not disrupt the service." } } } }] as never
    }
    swarmApi.accept = async (...args: unknown[]) => { record("accept", args); state.workers = state.workers.map(item => item.id === args[0] ? { ...item, state: "running", stage: "Working on the bounty", bountyId: "bounty-7" } : item); return {} as never }
  })
}

const calls = (page: Page) => page.evaluate(() => (window as unknown as { __swarm: { calls: Array<{ method: string; args: unknown[] }> } }).__swarm.calls)

/** Replaces the private bounty engine and the file picker; no project is read and nothing is hosted. */
async function mockBounty(page: Page) {
  await page.evaluate(async () => {
    const path = "/src/api/bounty-api.ts"
    const { bountyApi } = await import(path)
    const calls: Array<{ method: string; args: unknown[] }> = []
    Object.assign(window, { __bounty: { calls } })
    const record = (method: string, args: unknown[]) => calls.push({ method, args })
    const preview = { ticket: "ticket-1", policy: { termsDigest: "d1", bountyId: "private-1", objective: "Investigate the checkout service" } }
    bountyApi.suggestedAddress = async () => "192.168.1.20"
    bountyApi.status = async () => ({ host: null })
    bountyApi.choosePath = async (...args: unknown[]) => { record("choosePath", args); return "C:/projects/checkout" }
    bountyApi.inspect = async (...args: unknown[]) => {
      record("inspectProject", args)
      return { importId: "import-1", name: "Checkout service", fileCount: 2, bytes: 2048, files: ["app.py", "requirements.txt"], excluded: [".env"],
        suggestedTarget: { kind: "api", setupCommand: "pip install -r requirements.txt", startCommand: "python app.py", testCommand: "", port: 5000, healthPath: "/health", installNetwork: true } } as never
    }
    bountyApi.host = async (...args: unknown[]) => { record("hostProject", args); return { host: { address: "127.0.0.1", bounty: { title: "Checkout service" }, members: [] }, preview } as never }
    bountyApi.start = async (...args: unknown[]) => { record("startWorker", args); return { worker: { id: "worker-1" } } as never }
  })
}

const bountyCalls = (page: Page) => page.evaluate(() => (window as unknown as { __bounty: { calls: Array<{ method: string; args: unknown[] }> } }).__bounty.calls)

async function mockAccount(page: Page, signedIn: boolean) {
  await page.evaluate(async signedIn => {
    const path = "/src/api/market-api.ts"
    const { marketApi } = await import(path)
    marketApi.status = async () => ({ website: "https://yougori.test", signedIn, account: signedIn ? { email: "me@acme.test", wallet: null, creditMicros: 0, earningsMicros: 0, availableMicros: 0 } : null, login: null, shares: [] })
    marketApi.listen = async () => () => {}
  }, signedIn)
}

async function openSwarm(page: Page, signedIn = false) {
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  await mockSwarm(page)
  await mockAccount(page, signedIn)
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Swarm Mining", exact: true }).click()
  await expect(page.getByRole("region", { name: "Swarm Mining workspace" })).toBeVisible()
}

test("Join bounty hunting creates a worker and a bounty is accepted only with authorization", async ({ page }) => {
  await openSwarm(page)
  await expect(page.getByText("Hunt a bounty with a worker")).toBeVisible()
  await page.getByRole("button", { name: "Join bounty hunting", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Join bounty hunting" })
  await expect(dialog).toBeVisible()
  const create = dialog.getByRole("button", { name: "Create worker" })
  await expect(dialog).toContainText("Use a GGUF model")
  // A suggested uncensored GGUF model fills the field.
  await dialog.getByRole("button", { name: /Qwen2.5 Coder 7B/ }).click()
  await expect(dialog.getByLabel("Model", { exact: true })).toHaveValue("bartowski/Qwen2.5-Coder-7B-Instruct-abliterated-GGUF")
  await dialog.getByLabel("Model", { exact: true }).fill("hf.co/acme/model")
  await expect(dialog.getByLabel("Model", { exact: true })).toHaveValue("acme/model")
  await create.click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).find(c => c.method === "prepare")?.args).toEqual([{ name: "Bounty worker", model: "hf.co/acme/model" }])

  const board = page.getByRole("region", { name: "Swarm Mining workspace" })
  await expect(board.getByRole("region", { name: "Workers" })).toContainText("Ready · waiting for a bounty to accept")

  // Choosing a bounty needs both authorization ticks before it can be accepted.
  await board.getByRole("button", { name: "Choose bounty" }).click()
  const accept = page.getByRole("dialog", { name: "Choose a bounty for Bounty worker" })
  const confirm = accept.getByRole("button", { name: "Accept bounty" })
  await expect(confirm).toBeDisabled()
  await accept.getByRole("button", { name: /Review the checkout service/ }).click()
  await expect(accept).toContainText("checkout.acme.test only")
  await expect(confirm).toBeDisabled()
  await accept.getByRole("checkbox", { name: /authorized to test this target/ }).check()
  await expect(confirm).toBeDisabled()
  await accept.getByRole("checkbox", { name: /accept the bounty's service rules/ }).check()
  await expect(confirm).toBeDisabled()
  await accept.getByRole("checkbox", { name: /publisher pays/ }).check()
  await expect(confirm).toBeEnabled()
  await confirm.click()
  await expect(accept).toBeHidden()
  const accepted = (await calls(page)).find(c => c.method === "accept")
  expect(accepted?.args[0]).toBe("worker-1")
  expect((accepted?.args[1] as { bounty: { id: string } }).bounty.id).toBe("bounty-7")
  expect(accepted?.args[2]).toBe(30)
  await expect(board.getByRole("region", { name: "Workers" })).toContainText("Working on the bounty")

  // Its activity opens from the chevron.
  await board.getByRole("button", { name: "Show Bounty worker activity" }).click()
  await expect(board.getByRole("log", { name: "Worker activity" })).toContainText("Reading the source")
})

test("A closed bounty hosts a project on this computer and needs its authorization", async ({ page }) => {
  await openSwarm(page)
  await mockBounty(page)
  await page.getByRole("button", { name: "Create closed bounty", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Create a closed bounty" })
  await expect(dialog).toContainText("host the bounty on this computer or your LAN")
  const host = dialog.getByRole("button", { name: "Host bounty" })
  await expect(host).toBeDisabled()

  // Choosing a project shows what would be shared and what was left out.
  await dialog.getByRole("button", { name: "Choose folder" }).click()
  await expect(dialog).toContainText("Checkout service · 2 files")
  await expect(dialog).toContainText("app.py")
  await expect(dialog).toContainText(".env")
  await expect(host).toBeDisabled()

  // Hosting needs the scope in writing and the explicit authorization.
  await dialog.getByLabel("Authorized scope and test accounts").fill("We own this application; test the imported copy.")
  await expect(host).toBeDisabled()
  await dialog.getByRole("checkbox", { name: /I authorize testing this project/ }).check()
  await expect(host).toBeEnabled()
  await host.click()
  // The bounty is live; the same dialog turns into the host's own first worker.
  await expect(page.getByRole("dialog", { name: "Start a private worker" })).toBeVisible()

  const hosted = (await bountyCalls(page)).find(call => call.method === "hostProject")
  expect(hosted).toBeTruthy()
  const request = hosted?.args[0] as { importId: string; authorization: string; confirmed: boolean; visibility: string }
  expect(request.importId).toBe("import-1")
  expect(request.confirmed).toBe(true)
  expect(request.visibility).toBe("local")
  expect(request.authorization).toContain("We own this application")
})

test("Create bounty in Yougori opens the website", async ({ page }) => {
  await openSwarm(page)
  await page.evaluate(async () => {
    const path = "/src/api/workspace-api.ts"
    const { workspaceApi } = await import(path)
    Object.assign(window, { __opened: [] as string[] })
    workspaceApi.openUrl = async (url: string) => { (window as unknown as { __opened: string[] }).__opened.push(url) }
  })
  await page.getByRole("button", { name: "Create bounty in Yougori", exact: true }).click()
  const opened = await page.evaluate(() => (window as unknown as { __opened: string[] }).__opened)
  expect(opened.some(url => url.endsWith("/swarm"))).toBe(true)
})

test("The account sign-in control sits by the Swarm Mining title and opens the account panel", async ({ page }) => {
  await openSwarm(page, false)
  const board = page.getByRole("region", { name: "Swarm Mining workspace" })
  const signIn = board.getByRole("button", { name: "Sign in to your Yougori account" })
  await expect(signIn).toBeVisible()
  await signIn.click()
  await expect(page.getByRole("dialog", { name: "Neo Grid" })).toBeVisible()
  await page.keyboard.press("Escape")

  // Signed in, it shows the account instead.
  await openSwarm(page, true)
  const account = page.getByRole("region", { name: "Swarm Mining workspace" }).getByRole("button", { name: "Your Yougori account" })
  await expect(account).toContainText("me@acme.test")
})

test("A worker that failed shows a Retry button that resumes the preparation", async ({ page }) => {
  await openSwarm(page)
  await page.evaluate(() => {
    const swarm = (window as unknown as { __swarm: { state: { workers: Array<Record<string, unknown>> } } }).__swarm
    swarm.state.workers = [{ id: "worker-1", name: "Bounty worker", model: "hf.co/acme/model", state: "stopped", stage: "", gpu: "NVIDIA", resources: {}, workspaceQuotaGb: 20, keepResident: false, error: "Connect your Yougori account before registering a bounty worker", summary: "", createdAt: 0 }]
  })
  const workers = page.getByRole("region", { name: "Workers" })
  await expect(workers).toContainText("Connect your Yougori account")
  // While errored it is not offered Pause, only Retry.
  await expect(workers.getByRole("button", { name: "Pause", exact: true })).toHaveCount(0)
  await workers.getByRole("button", { name: "Retry", exact: true }).click()
  expect((await calls(page)).some(c => c.method === "resume" && c.args[0] === "worker-1")).toBe(true)
})
