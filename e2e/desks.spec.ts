import { test, expect, type Page } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

const invite = (fingerprint: string, address = "192.168.1.20:7463") =>
  "desk-invite:" + Buffer.from(JSON.stringify({ v: 1, c: "Acme", a: address, f: fingerprint })).toString("base64url")

/** Replaces the sandbox grid API with an in-page engine that records every call. */
async function mockDesks(page: Page) {
  await page.evaluate(async () => {
    const path = "/src/api/desks-api.ts"
    const { desksApi } = await import(path)
    type Call = { method: string; args: unknown[] }
    const calls: Call[] = []
    const laptop = { id: "m1", name: "Design laptop", platform: "windows", joinedAt: "", capable: false, excluded: false, planId: null, jobs: 0, online: true, lastSeenSeconds: 2, address: "192.168.1.30", appVersion: "1.0.21", running: 0, models: [], capacity: { cpu: 8, cpuUsedPercent: 23, memoryGb: 32, usedMemoryGb: 12, freeDiskGb: 300, gpu: false, gpuUsedPercent: null as number | null, onBattery: false, inUse: false }, share: { cpu: 4, memoryGb: 15, diskGb: 150, gpu: false, idleOnly: false }, shareSet: false, desks: 0 }
    const busy = { ...laptop, id: "m2", name: "Studio PC", capacity: { ...laptop.capacity, cpu: 16, cpuUsedPercent: 70, memoryGb: 64, usedMemoryGb: 40, freeDiskGb: 80, gpu: true, gpuUsedPercent: 55, inUse: true }, share: { cpu: 2, memoryGb: 8, diskGb: 50, gpu: true, idleOnly: false }, shareSet: true }
    const state: { hub: Record<string, unknown> | null; member: unknown; members: Array<typeof laptop>; people: Array<Record<string, unknown>>; desks: Array<Record<string, unknown>>; login: unknown } = { hub: null, member: null, members: [laptop, busy], people: [], desks: [], login: null }
    const record = (method: string, args: unknown[]) => { calls.push({ method, args }) }
    const rebuild = () => { if (state.hub) state.hub = { ...state.hub, people: state.people, desks: state.desks, members: state.members.map(member => ({ ...member, desks: state.desks.filter(desk => desk.hostId === member.id).length })) } }
    Object.assign(window, { __desks: { calls, state } })
    desksApi.status = async () => ({ hub: state.hub, hubError: null, member: state.member, memberError: null, hosting: [], desk: state.login ?? null }) as never
    desksApi.suggestedAddress = async () => "192.168.1.20"
    desksApi.create = async (...args: unknown[]) => {
      record("create", args)
      state.hub = { id: "d1", name: String(args[0]), address: String(args[1]), port: 7463, fingerprint: "AB:CD", createdAt: "", computers: { total: 2, capable: 0, online: 2 }, members: [laptop, busy], desks: [], people: [], invite: "desk-invite:eyJ2IjoxfQ", tunnel: args[3] === "quick" ? { kind: "quick", domain: null, url: "https://acme.trycloudflare.com", connected: true, error: null } : undefined }
      return { message: "Acme's sandbox grid is running" } as never
    }
    desksApi.join = async (...args: unknown[]) => { record("join", args); state.member = { gridId: "d1", grid: "Acme", hub: "192.168.1.20:7463", fingerprint: "AB:CD:EF", memberId: "m9", joinedAt: 0, connected: true, error: null, orders: 0 }; return { message: "Joined" } as never }
    desksApi.leave = async (...args: unknown[]) => { record("leave", args); state.member = null; return {} as never }
    desksApi.setComputerShare = async (...args: unknown[]) => { record("setComputerShare", args); state.members = state.members.map(member => member.id === args[0] ? { ...member, share: args[1] as typeof member.share, shareSet: true } : member); rebuild(); return {} as never }
    desksApi.suggestComputerShare = async (...args: unknown[]) => { record("suggestComputerShare", args); state.members = state.members.map(member => member.id === args[0] ? { ...member, share: { cpu: 8, memoryGb: 31, diskGb: 40, gpu: true, idleOnly: false }, shareSet: false } : member); rebuild(); return {} as never }
    desksApi.delete = async (...args: unknown[]) => {
      record("delete", args)
      // Later: paused for three days, restorable. Now: every computer heard, so the hub is gone.
      if (args[0] === "later" && state.hub) state.hub = { ...state.hub, closing: { requestedAt: 1, until: Math.floor(Date.now() / 1000) + 3 * 86400, gone: false, told: 0, computers: 2, tellUntil: 0 } }
      else state.hub = null
      return {} as never
    }
    desksApi.restore = async (...args: unknown[]) => { record("restore", args); if (state.hub) state.hub = { ...state.hub, closing: null }; return {} as never }
    const orderDesk = (name: string, person: { id: string; name: string; username: string } | undefined, made: { kind?: string; cpu: number; memoryGb: number; diskGb: number; gpu: boolean }) => {
      const kind = made.kind ?? "container"
      const desk = {
        id: `desk-${state.desks.length + 1}`, name, spec: { kind, cpu: made.cpu, memoryGb: made.memoryGb, diskGb: made.diskGb, gpu: made.gpu, image: "builtin:alpine" },
        summary: `${kind} · ${made.cpu} CPU · ${made.memoryGb} GB memory · ${made.diskGb} GB disk${made.gpu ? " · GPU" : ""}`,
        personId: person?.id ?? null, person: person?.name ?? null, username: person?.username ?? null,
        state: "building", note: "Building on its computer", hostId: "m1", host: "Design laptop", hostOnline: true, reachable: false, environmentId: null, attempts: 1, createdAt: 0, updatedAt: 0,
      }
      state.desks = [...state.desks, desk]
      return desk
    }
    const enterprise = {
      images: [{ id: "image-1", name: "Research desktop", version: "2026.10", description: "Prepared research tools", applications: ["Python", "RStudio"], spec: { kind: "vm", cpu: 2, memoryGb: 8, diskGb: 40, gpu: false, image: "https://images.example.test/research.qcow2" }, sha256: "a".repeat(64), createdAt: 0 }],
      roles: [{ id: "role-1", name: "Research Kazakhstan", imageId: "image-1", access: "restricted", description: "Research", createdAt: 0 }], connections: [] as Record<string, unknown>[], computerLimit: null, audit: [],
    }
    desksApi.manage = async (request: Record<string, unknown>) => {
      record("manage", [request])
      if (request.action === "personAdd") {
        const person = { id: `person-${state.people.length + 1}`, username: String(request.username).toLowerCase(), name: String(request.name), adminRole: request.adminRole, roleId: request.roleId, createdAt: 0, lastLoginAt: null, desks: [] as string[] }
        state.people.push(person)
        if (request.roleId) person.desks = [orderDesk(`${person.name}'s desk`, person, { kind: "vm", cpu: 2, memoryGb: 8, diskGb: 40, gpu: false }).id]
        rebuild(); return person as never
      }
      if (request.action === "deskRemove") { state.desks = state.desks.filter(d => d.id !== request.id); rebuild(); return {} as never }
      if (request.action === "personUpdate") { state.people = state.people.map(person => person.id === request.id ? { ...person, ...(request.adminRole ? { adminRole: request.adminRole } : {}), ...("roleId" in request ? { roleId: request.roleId } : {}) } : person); rebuild(); return {} as never }
      if (request.action === "connectionAdd") { enterprise.connections.push({ ...request, id: `connection-${enterprise.connections.length}` }); return {} as never }
      return { id: "d1", name: "Acme", actor: "owner", adminRole: "administrator", people: state.people, desks: state.desks, members: state.members, enterprise } as never
    }
    desksApi.refreshDesk = async () => state.login as never
    desksApi.addPerson = async (...args: unknown[]) => {
      record("addPerson", args)
      const person = { id: `person-${state.people.length + 1}`, username: String(args[0]).toLowerCase(), name: String(args[1]), createdAt: 0, lastLoginAt: null, desks: [] as string[] }
      state.people = [...state.people, person]
      if (args[3]) person.desks = [orderDesk(`${person.name}'s desk`, person, args[3] as { cpu: number; memoryGb: number; diskGb: number; gpu: boolean }).id]
      rebuild()
      return person as never
    }
    desksApi.removePerson = async (...args: unknown[]) => { record("removePerson", args); state.people = state.people.filter(person => person.id !== args[0]); rebuild(); return {} as never }
    desksApi.addDesk = async (...args: unknown[]) => {
      record("addDesk", args)
      const made = args[0] as { name: string; person: string | null; kind: string; cpu: number; memoryGb: number; diskGb: number; gpu: boolean }
      const person = state.people.find(person => person.username === made.person) as { id: string; name: string; username: string } | undefined
      const desk = orderDesk(made.name, person, made)
      rebuild()
      return desk as never
    }
    desksApi.assignDesk = async (...args: unknown[]) => { record("assignDesk", args); const person = state.people.find(person => person.id === args[1]); state.desks = state.desks.map(desk => desk.id === args[0] ? { ...desk, personId: person?.id ?? null, person: person?.name ?? null } : desk); rebuild(); return {} as never }
    desksApi.retryDesk = async (...args: unknown[]) => { record("retryDesk", args); return {} as never }
    desksApi.removeDesk = async (...args: unknown[]) => { record("removeDesk", args); state.desks = state.desks.filter(desk => desk.id !== args[0]); rebuild(); return {} as never }
    desksApi.login = async (...args: unknown[]) => {
      record("login", args)
      state.login = { gridId: "d1", grid: "Acme", username: args[1], personId: "person-1", name: "Ada Lovelace", signedInAt: 0, desks: [{ id: "desk-1", name: "Design desk", state: "ready", note: "Ready", host: "Design laptop", environmentId: "env-desk", address: "192.168.1.30:40123" }] }
      return state.login as never
    }
    desksApi.logout = async (...args: unknown[]) => { record("logout", args); state.login = null; return {} as never }
  })
}

const calls = (page: Page) => page.evaluate(() => (window as unknown as { __desks: { calls: Array<{ method: string; args: unknown[] }> } }).__desks.calls)

async function openDesks(page: Page) {
  page.on("pageerror", error => { console.log(`PAGEERROR ${error.message}\n${error.stack ?? ""}`) })
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  await mockDesks(page)
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Sandbox Grid", exact: true }).click()
  await expect(page.getByRole("region", { name: "Sandbox Grid workspace" })).toBeVisible()
}

test("Hosting a sandbox grid: computers and their shares, people with their desks, and the enterprise fold", async ({ page }) => {
  await openDesks(page)
  await expect(page.getByText("Host or join a sandbox grid")).toBeVisible()
  await page.getByRole("button", { name: "Host a sandbox grid", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Host a sandbox grid" })
  await expect(dialog.getByLabel("This computer's address")).toHaveValue("192.168.1.20")
  await expect(dialog).toContainText("port 7463")
  await dialog.getByLabel("Company name").fill("Acme")
  await dialog.getByLabel("Company password").fill("correct horse battery")
  await dialog.getByLabel("Type it again").fill("correct horse battery")
  await dialog.getByRole("radio", { name: /Anywhere/ }).click()
  await dialog.getByRole("button", { name: "Host grid", exact: true }).click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).find(call => call.method === "create")?.args).toEqual(["Acme", "192.168.1.20", "correct horse battery", "quick"])

  const board = page.getByRole("region", { name: "Sandbox Grid workspace" })
  await expect(board.getByRole("region", { name: "Hosted sandbox grid" })).toContainText("Acme")
  await expect(board.getByRole("region", { name: "Hosted sandbox grid" })).toContainText("https://acme.trycloudflare.com")
  await expect(board.getByRole("region", { name: "Connect computers" })).toContainText("from anywhere")
  await expect(board.getByRole("region", { name: "Connect computers" })).toContainText("yougori desks join --invite desk-invite:")
  // Each computer shows what it has and is using, and what the grid may take from it.
  const computers = board.getByRole("region", { name: "Computers", exact: true })
  const laptop = computers.getByRole("region", { name: "Design laptop", exact: true })
  await expect(laptop).toContainText("Nobody using it")
  await expect(laptop).toContainText("8 cores · 23% busy")
  await expect(laptop).toContainText("12 of 32 GB used")
  await expect(laptop).toContainText("300 GB free")
  await expect(laptop).toContainText("Grid may use 4 CPU · 15 GB memory · 150 GB disk")
  await expect(laptop).toContainText("Suggested")
  const studio = computers.getByRole("region", { name: "Studio PC", exact: true })
  await expect(studio).toContainText("In use")
  await expect(studio).toContainText("55% busy")
  await expect(studio).toContainText("Grid may use 2 CPU · 8 GB memory · 50 GB disk · GPU")
  await expect(studio).not.toContainText("Suggested")
  await expect(page.getByRole("button", { name: "Host a sandbox grid", exact: true })).toBeDisabled()

  // The admin changes the share of the computer in use: a labelled form, saved as one call.
  await studio.getByRole("button", { name: "Adjust share" }).click()
  const shareForm = studio.getByRole("form", { name: "Share of Studio PC" })
  await shareForm.getByLabel("CPU cores").fill("4")
  await shareForm.getByLabel("Memory (GB)").fill("16")
  await shareForm.getByLabel("Only while nobody is using it").check()
  await shareForm.getByRole("button", { name: "Save share" }).click()
  expect((await calls(page)).find(call => call.method === "setComputerShare")?.args).toEqual(["m2", { cpu: 4, memoryGb: 16, diskGb: 50, gpu: true, idleOnly: true }])
  await expect(studio).toContainText("Grid may use 4 CPU · 16 GB memory · 50 GB disk · GPU · only while nobody is using it")
  await expect(shareForm).toBeHidden()
  await studio.getByRole("button", { name: "Adjust share" }).click()
  await studio.getByRole("button", { name: "Use suggested" }).click()
  expect((await calls(page)).some(call => call.method === "suggestComputerShare" && call.args[0] === "m2")).toBe(true)
  await expect(studio).toContainText("Grid may use 8 CPU · 31 GB memory · 40 GB disk · GPU")
  await expect(studio).toContainText("Suggested")

  // A person is added with their desk: its size is part of the same form.
  const people = board.getByRole("region", { name: "People", exact: true })
  const newPerson = people.getByRole("form", { name: "New person" })
  const addPerson = newPerson.getByRole("button", { name: "Add person and their desk" })
  await newPerson.getByLabel("Username", { exact: true }).fill("Ada.Lovelace")
  await newPerson.getByLabel("Name", { exact: true }).fill("Ada Lovelace")
  await expect(addPerson).toBeDisabled()
  await newPerson.getByLabel("Password").fill("correct horse battery")
  await newPerson.getByLabel("Memory (GB)").fill("8")
  await newPerson.getByRole("checkbox", { name: "GPU" }).check()
  await addPerson.click()
  await expect(people).toContainText("ada.lovelace · Ada Lovelace's desk: container · 2 CPU · 8 GB memory · 20 GB disk · GPU · Building on Design laptop · never signed in")
  expect((await calls(page)).find(call => call.method === "addPerson")?.args).toEqual(["Ada.Lovelace", "Ada Lovelace", "correct horse battery", { cpu: 2, memoryGb: 8, diskGb: 20, gpu: true }])
  await expect(laptop).toContainText("1 desk")

  // The desk lists with every other sandbox the grid hosts; there is no separate order form.
  const desks = board.getByRole("region", { name: "Desks", exact: true })
  await expect(desks).toContainText("Ada Lovelace's desk")
  await expect(desks).toContainText("Building")
  await expect(desks).toContainText("Ada Lovelace · on Design laptop")
  await expect(desks.getByRole("form")).toHaveCount(0)

  // Enterprise matters live in one fold: who may manage the grid, and company workspaces.
  const fold = board.locator("details.grid-fold").first()
  await fold.locator("summary").click()
  const admin = board.getByRole("region", { name: "Sandbox Grid administration" })
  await admin.getByLabel("Administrative permission for Ada Lovelace").selectOption("administrator")
  expect((await calls(page)).some(call => call.method === "manage" && (call.args[0] as { action: string; adminRole: string }).action === "personUpdate" && (call.args[0] as { adminRole: string }).adminRole === "administrator")).toBe(true)
  await expect(people).toContainText("ada.lovelace · administrator")
  await admin.getByRole("tab", { name: "Company workspaces" }).click()
  await admin.getByLabel("Name", { exact: true }).fill("Company Citrix")
  await admin.getByLabel("HTTPS workspace URL").fill("https://company.example.test/workspace")
  await admin.getByRole("button", { name: "Add workspace" }).click()
  await expect(admin).toContainText("Company Citrix")
  await expect(admin).toContainText("Citrix · everyone signed in")

  // Removing a desk asks once more and deletes it. The page takes one action at a time, so wait
  // for the last to settle first.
  await expect(board).toHaveAttribute("aria-busy", "false")
  const remove = desks.getByRole("button", { name: "Remove Ada Lovelace's desk" })
  await remove.click()
  await expect(remove).toHaveText("Confirm")
  await remove.click()
  await expect(desks).not.toContainText("Ada Lovelace's desk")
  await expect(people).toContainText("no desk yet")
  expect((await calls(page)).some(call => call.method === "removeDesk" && call.args[0] === "desk-1")).toBe(true)

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
  await expect(page.getByText("Host or join a sandbox grid")).toBeVisible()
})

test("A desk moving to another computer shows its progress, and a silent hub asks about leaving", async ({ page }) => {
  await openDesks(page)
  await page.evaluate(async () => {
    const path = "/src/api/desks-api.ts"
    const { desksApi } = await import(path)
    const moving = {
      id: "desk-1", name: "Ada Lovelace's desk", spec: { kind: "container", cpu: 2, memoryGb: 8, diskGb: 20, gpu: false, image: "" },
      summary: "container · 2 CPU · 8 GB memory · 20 GB disk", personId: "person-1", person: "Ada Lovelace", username: "ada.lovelace",
      state: "moving", note: "Its data is packed and waiting for a computer with room", hostId: null, host: null, hostOnline: false,
      reachable: false, environmentId: null, attempts: 1, createdAt: 0, updatedAt: 0, movingFrom: null, parcelBytes: 3 * 1073741824,
    }
    const silent = Math.floor(Date.now() / 1000) - 9 * 86400
    desksApi.status = async () => ({
      hub: { id: "d1", name: "Acme", address: "192.168.1.20", port: 7463, fingerprint: "AB", createdAt: "", computers: { total: 1, capable: 0, online: 1 }, members: [], desks: [moving], people: [{ id: "person-1", username: "ada.lovelace", name: "Ada Lovelace", createdAt: 0, lastLoginAt: null, desks: ["desk-1"] }] },
      hubError: null, member: null, memberError: null, hosting: [], desk: null,
    }) as never
    ;(window as unknown as { __silent: number }).__silent = silent
  })
  const desks = page.getByRole("region", { name: "Desks", exact: true })
  await expect(desks).toContainText("Moving · 3.0 GB of data packed")
  await expect(desks).toContainText("waiting for a computer with room")
  const people = page.getByRole("region", { name: "People", exact: true })
  await expect(people).toContainText("Moving · 3.0 GB of data packed")

  // A hub that has been silent for over a week asks whether to leave, and promises nothing goes.
  await page.evaluate(async () => {
    const path = "/src/api/desks-api.ts"
    const { desksApi } = await import(path)
    const silent = (window as unknown as { __silent: number }).__silent
    desksApi.status = async () => ({
      hub: null, hubError: null, hosting: [], desk: null, memberError: null,
      member: { gridId: "d1", grid: "Acme", hub: "192.168.1.20:7463", fingerprint: "AB", memberId: "m9", joinedAt: 0, connected: false, error: "Cannot reach the grid hub", orders: 0, unreachableSince: silent },
    }) as never
  })
  const board = page.getByRole("region", { name: "Sandbox Grid workspace" })
  await expect(board.getByRole("status").filter({ hasText: "has not answered" })).toContainText("Acme's hub has not answered for 9 days")
  await expect(board.getByRole("status").filter({ hasText: "has not answered" })).toContainText("nothing here is removed by leaving")
})

test("Joining a sandbox grid with the desk invite and the password", async ({ page }) => {
  await openDesks(page)
  await page.getByRole("button", { name: "Join a sandbox grid", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Join a sandbox grid" })
  const join = dialog.getByRole("button", { name: "Join grid", exact: true })
  await dialog.getByLabel("Invite from your admin").fill("grid-invite:eyJ2IjoxfQ")
  await expect(dialog).toContainText("That is not a sandbox grid invite")
  await expect(join).toBeDisabled()
  const code = invite("ABCDEF")
  await dialog.getByLabel("Invite from your admin").fill(code)
  await expect(dialog).toContainText("Acme")
  await dialog.getByLabel("Company password").fill("correct horse battery")
  await join.click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).find(call => call.method === "join")?.args).toEqual([code, "correct horse battery"])
  const joined = page.getByRole("region", { name: "Joined sandbox grid" })
  await expect(joined).toContainText("Acme")
  await expect(joined).toContainText("Connected · hosting 0 desks")
  await joined.getByRole("button", { name: "Leave grid" }).click()
  await joined.getByRole("button", { name: "Confirm leave" }).click()
  await expect(page.getByText("Host or join a sandbox grid")).toBeVisible()
})

test("A person opens their desk with the invite, their username and their password, and can sign out", async ({ page }) => {
  await openDesks(page)
  await page.getByRole("button", { name: "Open my desk", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Open my desk" })
  const signIn = dialog.getByRole("button", { name: "Sign in", exact: true })
  await dialog.getByLabel("Grid invite from your admin").fill("hello")
  await expect(dialog).toContainText("That is not a sandbox grid invite")
  const code = invite("ABCDEF")
  await dialog.getByLabel("Grid invite from your admin").fill(code)
  await expect(dialog).toContainText("Acme")
  await dialog.getByLabel("Username").fill("ada.lovelace")
  await expect(signIn).toBeDisabled()
  await dialog.getByLabel("Password").fill("correct horse battery")
  await signIn.click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).find(call => call.method === "login")?.args).toEqual([code, "ada.lovelace", "correct horse battery"])
  await expect(page.getByText("Signed in to Acme as Ada Lovelace")).toBeVisible()
  const mine = page.getByRole("region", { name: "My desk" })
  await expect(mine).toContainText("Design desk: in your sandbox list")
  await mine.getByRole("button", { name: "Sign out" }).click()
  await expect(page.getByText("Signed in to Acme as Ada Lovelace")).toHaveCount(0)
  expect((await calls(page)).some(call => call.method === "logout")).toBe(true)
})
