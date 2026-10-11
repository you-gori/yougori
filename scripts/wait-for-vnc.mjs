import { setTimeout as delay } from "node:timers/promises"

class VncProtocolError extends Error {}

// Test fixtures must wait for the display protocol, not just a spawned process
// or an open TCP port. EGL initialization can finish after page navigation.
function greeting(url, timeoutMs, signal) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, ["binary"])
    socket.binaryType = "arraybuffer"
    let bytes = Buffer.alloc(0), settled = false
    const finish = error => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener("abort", aborted)
      socket.close()
      if (error) reject(error)
      else resolve()
    }
    const aborted = () => finish(signal.reason)
    const timer = setTimeout(() => finish(new Error("No VNC greeting received")), timeoutMs)
    socket.addEventListener("error", event => finish(new Error(event.error?.message || event.message || "VNC WebSocket connection failed")))
    socket.addEventListener("close", event => finish(new Error(`VNC WebSocket closed before its greeting (${event.code})`)))
    socket.addEventListener("message", event => {
      bytes = Buffer.concat([bytes, Buffer.from(event.data)]).subarray(0, 12)
      if (bytes.length < 12) return
      finish(/^RFB \d{3}\.\d{3}\n$/.test(bytes.toString("ascii")) ? undefined : new VncProtocolError("Unexpected VNC greeting"))
    })
    signal?.addEventListener("abort", aborted, { once: true })
    if (signal?.aborted) aborted()
  })
}

/** @param {string} url @param {{ timeoutMs?: number, signal?: AbortSignal }} [options] */
export async function waitForVnc(url, { timeoutMs = 15_000, signal } = {}) {
  const deadline = performance.now() + timeoutMs
  let lastError
  while (performance.now() < deadline) {
    signal?.throwIfAborted()
    try {
      await greeting(url, Math.min(1_000, deadline - performance.now()), signal)
      signal?.throwIfAborted()
      return
    } catch (error) {
      signal?.throwIfAborted()
      // A different service on this port will not become VNC by reconnecting.
      // Preserve the protocol error instead of replacing it with a later timeout.
      if (error instanceof VncProtocolError) throw error
      lastError = error
    }
    await delay(Math.max(0, Math.min(100, deadline - performance.now())), undefined, { signal })
  }
  throw new Error(`VNC did not become ready within ${timeoutMs}ms: ${lastError?.message ?? "no connection"}`, { cause: lastError })
}
