import { WindowControls } from "./window-controls"

const vaultNotice = (error: string) => error.includes("Container disk needs recovery")
  ? "Your vault container disk needs recovery. Its data was left in place. You can open Yougori and retry from Personal Vault MCP."
  : error.includes("taking longer than expected")
    ? "Your Personal Vault is taking longer than expected to start. You can open Yougori now; it keeps starting in the background."
    : "Your Personal Vault could not start. You can open Yougori and retry from Personal Vault MCP."

export function LoadingScreen({ error, onRetry, onContinue, continueKind = "vault", message = "Starting your workspace…" }: { error?: string | null; onRetry?: () => void; onContinue?: () => void; continueKind?: "vault" | "cli"; message?: string }) {
  const vault = Boolean(onContinue) && continueKind === "vault"
  return (
    <main className="startup-screen" aria-label={error ? "Yougori startup error" : "Loading Yougori"} aria-busy={!error}>
      <div data-tauri-drag-region className="fixed inset-x-0 top-0 z-50 flex h-14 items-center justify-end px-4"><WindowControls /></div>
      <div className="startup-content">
        <p className="startup-brand">Yougori</p>
        {error ? (
          <>
            <div role="alert">
              <p className="startup-title">{vault ? "Personal Vault needs attention" : onContinue ? "The CLI didn’t start" : "Yougori couldn’t start"}</p>
              <p className="startup-message">{vault ? vaultNotice(error) : onContinue ? `${error} You can open Yougori now and start a terminal later from the CLI view.` : error}</p>
            </div>
            <div className="flex flex-wrap justify-center gap-3">
              {onRetry ? <button className="startup-retry" onClick={onRetry} type="button">Try again</button> : null}
              {onContinue ? <button className="startup-retry" onClick={onContinue} type="button">Open Yougori</button> : null}
            </div>
            {vault ? <details className="mx-auto mt-5 max-w-xl px-4 text-left text-xs"><summary className="cursor-pointer">Technical details</summary><pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words">{error}</pre></details> : null}
          </>
        ) : (
          <>
            <div className="startup-track" aria-hidden="true"><span /></div>
            <p className="startup-message" role="status">{message}</p>
          </>
        )}
      </div>
    </main>
  )
}
