// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { VaultRowMenu } from "@/components/vault-row-menu"
import { blockedBy } from "@/lib/vault-delete"
import { vaultApi, type VaultPending, type VaultStatus } from "@/api/vault-api"

vi.mock("@/api/vault-api", () => ({ vaultApi: { control: vi.fn(), status: vi.fn() } }))
afterEach(() => { cleanup(); vi.clearAllMocks() })

const running: VaultStatus = { running: true, locked: false, items: [], clients: [], pending: [], activity: [] }
const approval: VaultPending = { id: "req-1", ready: true, destroy: true, operation: "vault", expiresAt: "", title: "Delete your Personal Vault?", description: "This permanently deletes every item in Personal Vault. Deny keeps everything.", allowLabel: "Delete everything", client: { id: "desktop", executable: "Yougori.exe" } as VaultPending["client"] }
beforeEach(() => { vi.mocked(vaultApi.status).mockResolvedValue(running) })

/** What the native right-click item does, and nothing more: it only asks the app to confirm. */
const askToDelete = () => fireEvent(window, new CustomEvent("yougori-delete-vault"))
const reply = (value: unknown) => vi.mocked(vaultApi.control).mockResolvedValue(value as { token?: string })
const confirmButton = () => screen.getByRole("button", { name: "Delete everything" })
const typeTheWord = async () => fireEvent.change(await screen.findByLabelText("Type delete to confirm"), { target: { value: "delete" } })

describe("Delete my vault", () => {
  it("shows nothing until the native menu asks for it", () => {
    render(<VaultRowMenu />)
    expect(screen.queryByRole("button", { name: "Delete everything" })).not.toBeInTheDocument()
  })

  it("will not delete until the word is typed, and then only asks the broker", async () => {
    reply({ destroyed: true })
    render(<VaultRowMenu />)
    askToDelete()
    await waitFor(() => expect(confirmButton()).toBeDisabled())
    expect(vaultApi.control).not.toHaveBeenCalled()
    await typeTheWord()
    await waitFor(() => expect(confirmButton()).toBeEnabled())
    fireEvent.click(confirmButton())
    // "destroy" takes no id: it raises the broker's own approval rather than deleting.
    await waitFor(() => expect(vaultApi.control).toHaveBeenCalledWith("destroy"))
  })

  it("shows the broker's approval in the dialog and deletes only once it is approved there", async () => {
    // The delete waits for the broker's approval, as it does for real; the tests used to resolve
    // it at once, so none of them ever reached the approval nobody could click.
    let finish: (value: unknown) => void = () => undefined
    vi.mocked(vaultApi.control).mockImplementation(action => action === "destroy" ? new Promise(resolve => { finish = resolve }) as never : Promise.resolve({}) as never)
    render(<VaultRowMenu />)
    askToDelete()
    await typeTheWord()
    await waitFor(() => expect(confirmButton()).toBeEnabled())
    fireEvent.click(confirmButton())
    expect(await screen.findByText("Waiting for Personal Vault to ask for your approval…")).toBeInTheDocument()
    vi.mocked(vaultApi.status).mockResolvedValue({ ...running, pending: [approval] })
    const asked = await screen.findByRole("region", { name: "Personal Vault approval" }, { timeout: 3000 })
    expect(within(asked).getByText(/Deny keeps everything/)).toBeInTheDocument()
    fireEvent.click(within(asked).getByRole("button", { name: "Delete everything" }))
    await waitFor(() => expect(vaultApi.control).toHaveBeenCalledWith("approve", "req-1"))
    finish({ destroyed: true })
    await waitFor(() => expect(screen.queryByText("Delete your Personal Vault?")).not.toBeInTheDocument())
  })

  it("keeps the vault when the approval is denied, and says nothing was deleted", async () => {
    let refuse: (reason: unknown) => void = () => undefined
    vi.mocked(vaultApi.control).mockImplementation(action => action === "destroy" ? new Promise((_, reject) => { refuse = reject }) as never : Promise.resolve({}) as never)
    vi.mocked(vaultApi.status).mockResolvedValue({ ...running, pending: [approval] })
    render(<VaultRowMenu />)
    askToDelete()
    await typeTheWord()
    await waitFor(() => expect(confirmButton()).toBeEnabled())
    fireEvent.click(confirmButton())
    const asked = await screen.findByRole("region", { name: "Personal Vault approval" }, { timeout: 3000 })
    fireEvent.click(within(asked).getByRole("button", { name: "Keep my vault" }))
    await waitFor(() => expect(vaultApi.control).toHaveBeenCalledWith("deny", "req-1"))
    refuse(new Error("Nothing was deleted. The deletion was declined or timed out. Run Delete my vault again when you're ready."))
    expect(await screen.findByRole("alert")).toHaveTextContent("Nothing was deleted")
    expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled()
  })

  it("explains, instead of offering a delete, when the vault cannot be reached or needs an update", async () => {
    expect(blockedBy(running)).toBeNull()
    expect(blockedBy({ ...running, running: false })).toMatch(/isn’t running/)
    expect(blockedBy({ ...running, updateRequired: true, notice: "Personal Vault does not recognize this copy of Yougori yet. Select Update vault to register it." })).toMatch(/does not recognize .* Then choose Delete my vault again\./)
    vi.mocked(vaultApi.status).mockResolvedValue({ ...running, running: false })
    render(<VaultRowMenu />)
    askToDelete()
    expect(await screen.findByText("Personal Vault can’t be deleted right now")).toBeInTheDocument()
    expect(screen.getByText(/isn’t running/)).toHaveTextContent("Nothing was deleted.")
    expect(screen.queryByLabelText("Type delete to confirm")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Delete everything" })).not.toBeInTheDocument()
    expect(vaultApi.control).not.toHaveBeenCalled()
  })

  it("offers nothing to delete when the vault's state cannot be read", async () => {
    vi.mocked(vaultApi.status).mockRejectedValue(new Error("broker gone"))
    render(<VaultRowMenu />)
    askToDelete()
    expect(await screen.findByText(/could not read Personal Vault’s state \(broker gone\)/)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Delete everything" })).not.toBeInTheDocument()
  })

  it("says a delete answered without confirmation plainly, never as something to run again", async () => {
    reply({ destroyed: false })
    render(<VaultRowMenu />)
    askToDelete()
    await typeTheWord()
    await waitFor(() => expect(confirmButton()).toBeEnabled())
    fireEvent.click(confirmButton())
    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("without saying the vault was deleted")
    expect(alert).not.toHaveTextContent("again")
  })

  it("says a finished delete finished, and names what it could not clean up afterwards", async () => {
    const token = "The Cloudflare tunnel token for vault.example.com is still saved in Windows Credential Manager, under Windows Credentials, as yougori-private-vault-gateway-v1:49732.Yougori.CloudflareTunnel.v1."
    reply({ destroyed: true, leftBehind: [token] })
    render(<VaultRowMenu />)
    askToDelete()
    await typeTheWord()
    await waitFor(() => expect(confirmButton()).toBeEnabled())
    fireEvent.click(confirmButton())
    expect(await screen.findByText("Your Personal Vault was deleted")).toBeInTheDocument()
    expect(screen.getByText(token)).toBeInTheDocument()
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Delete everything" })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Done" }))
    await waitFor(() => expect(screen.queryByText("Your Personal Vault was deleted")).not.toBeInTheDocument())
  })

  it("shows a delete that stopped part way as the broker words it", async () => {
    const partial = "Personal Vault was only partly deleted. Its key is gone, so what remains can no longer be read, but these files are still there: C:\\ProgramData\\YougoriVault\\S-1\\contents.age."
    vi.mocked(vaultApi.control).mockRejectedValue(new Error(partial))
    render(<VaultRowMenu />)
    askToDelete()
    await typeTheWord()
    await waitFor(() => expect(confirmButton()).toBeEnabled())
    fireEvent.click(confirmButton())
    expect(await screen.findByRole("alert")).toHaveTextContent("only partly deleted")
    expect(screen.queryByText("Your Personal Vault was deleted")).not.toBeInTheDocument()
  })

  it("surfaces the broker's own refusal rather than a generic failure", async () => {
    vi.mocked(vaultApi.control).mockRejectedValue(new Error("Nothing was deleted. Bring Yougori to the front, then choose Delete my vault again."))
    render(<VaultRowMenu />)
    askToDelete()
    await typeTheWord()
    await waitFor(() => expect(confirmButton()).toBeEnabled())
    fireEvent.click(confirmButton())
    expect(await screen.findByRole("alert")).toHaveTextContent("Bring Yougori to the front")
  })
})
