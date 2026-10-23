// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import type { ReactNode } from "react"
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { vaultApi } from "@/api/vault-api"
import { VaultSandboxRow } from "@/components/vault-sandbox-row"

vi.mock("@/api/vault-api", () => ({ vaultApi: { status: vi.fn(), control: vi.fn(), bootstrap: vi.fn(), addItems: vi.fn() } }))
// The vault dialog polls on its own, and none of this is about what it shows.
vi.mock("@/components/personal-vault", () => ({ PersonalVault: () => <span>Personal Vault MCP</span> }))

/** The row belongs to the sandbox table, so it has to be rendered inside one. */
const Table = ({ children }: { children: ReactNode }) => <table><tbody>{children}</tbody></table>
/** Running, because the delete dialog rightly offers nothing against a vault that is not; these
 *  tests are about the dialog outliving its row, not about an offline vault. */
const status = (created: boolean) => ({ running: true, locked: true, items: [], clients: [], pending: [], activity: [], setup: { created } })
/** What a finished delete could not clean up: somebody has to go and remove this by hand. */
const token = "The Cloudflare tunnel token for vault.example.com is still saved in Windows Credential Manager, under Windows Credentials, as yougori-private-vault-gateway-v1:49732.Yougori.CloudflareTunnel.v1."

beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { cleanup(); vi.useRealTimers(); vi.resetAllMocks() })

it("keeps what the delete left behind on screen after the row itself goes", async () => {
  vi.mocked(vaultApi.status).mockResolvedValue(status(true) as never)
  vi.mocked(vaultApi.control).mockResolvedValue({ destroyed: true, leftBehind: [token] } as never)
  render(<VaultSandboxRow />, { wrapper: Table })
  await act(async () => { await Promise.resolve() })
  expect(screen.getByRole("row")).toBeInTheDocument()

  fireEvent(window, new CustomEvent("yougori-delete-vault"))
  await act(async () => { await Promise.resolve() })
  fireEvent.change(screen.getByLabelText("Type delete to confirm"), { target: { value: "delete" } })
  fireEvent.click(screen.getByRole("button", { name: "Delete everything" }))
  await act(async () => { await Promise.resolve() })
  expect(screen.getByText(token)).toBeInTheDocument()

  // A finished delete forgets the setup, so the next poll drops the row out of the table.
  vi.mocked(vaultApi.status).mockResolvedValue(status(false) as never)
  await act(async () => { await vi.advanceTimersByTimeAsync(4000) })
  expect(screen.queryByRole("row")).not.toBeInTheDocument()

  // The row has gone. The one place that names the leftover credential must not go with it.
  expect(screen.getByText(token)).toBeInTheDocument()
})

it("keeps a partly deleted vault's list of files on screen even if the row goes", async () => {
  // Today this delete leaves the setup in place, so the row stays and the message with it. That
  // is the app's choice, not this dialog's: the files it names are the person's only way to
  // finish by hand, so they have to survive the row either way.
  const partly = "Personal Vault was only partly deleted. Its key is gone, so what remains can no longer be read, but these files are still there: C:\\ProgramData\\YougoriVault\\S-1\\contents.age."
  vi.mocked(vaultApi.status).mockResolvedValue(status(true) as never)
  vi.mocked(vaultApi.control).mockRejectedValue(new Error(partly))
  render(<VaultSandboxRow />, { wrapper: Table })
  await act(async () => { await Promise.resolve() })

  fireEvent(window, new CustomEvent("yougori-delete-vault"))
  await act(async () => { await Promise.resolve() })
  fireEvent.change(screen.getByLabelText("Type delete to confirm"), { target: { value: "delete" } })
  fireEvent.click(screen.getByRole("button", { name: "Delete everything" }))
  await act(async () => { await Promise.resolve() })
  expect(screen.getByRole("alert")).toHaveTextContent("only partly deleted")

  vi.mocked(vaultApi.status).mockResolvedValue(status(false) as never)
  await act(async () => { await vi.advanceTimersByTimeAsync(4000) })
  expect(screen.queryByRole("row")).not.toBeInTheDocument()
  expect(screen.getByRole("alert")).toHaveTextContent("contents.age")
})
