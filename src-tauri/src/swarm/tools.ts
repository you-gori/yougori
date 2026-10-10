import { tool } from "@opencode-ai/plugin"
import { randomUUID } from "node:crypto"
import { mkdir, writeFile, rename, readFile, lstat, unlink } from "node:fs/promises"

const spool = "/srv/yougori-swarm/spool"
const evidence = tool.schema.array(tool.schema.object({
  name: tool.schema.string().min(1).max(160),
  contentBase64: tool.schema.string().max(49152),
})).max(4).default([])

async function request(action: string, params: unknown, sessionID: string) {
  const id = randomUUID()
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(sessionID)) throw new Error("Invalid managed session")
  // A late tool from an aborted session cannot adopt a new task's context.
  const accepted = JSON.parse(await readFile(`/srv/yougori-swarm/.yougori/bounty/session-${sessionID}.json`, "utf8"))
  const context = {
    bountyId: accepted.policy?.bountyId,
    termsVersion: accepted.policy?.termsVersion,
    leaseId: accepted.task?.leaseId,
    generation: accepted.task?.generation,
  }
  if (!context.bountyId || !context.termsVersion || !context.leaseId || !Number.isInteger(context.generation)) {
    throw new Error("No current accepted bounty and task lease. Synchronize before requesting a tool.")
  }
  const bytes = JSON.stringify({ id, action, params, context })
  if (Buffer.byteLength(bytes) > 65536) throw new Error("Tool request exceeds 64 KiB. Attach concise reproduction evidence.")
  await mkdir(spool, { recursive: true, mode: 0o700 })
  const pending = `${spool}/${id}.pending`
  await writeFile(pending, bytes, { flag: "wx", mode: 0o600 })
  await rename(pending, `${spool}/${id}.request`)
  const reply = `${spool}/${id}.response`
  const deadline = Date.now() + 90000
  while (Date.now() < deadline) {
    try {
      const stat = await lstat(reply)
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw new Error("Invalid tool response")
      const result = await readFile(reply, "utf8")
      // The native owner durably records the result before writing this file.
      // Acknowledge only after reading it; unknown/timeout receipts stay intact.
      const acknowledged = `${spool}/${id}.ack`
      try {
        await writeFile(acknowledged, id, { flag: "wx", mode: 0o600 })
        for (const path of [reply, acknowledged]) {
          try { await unlink(path) } catch (error: any) {
            if (error?.code !== "ENOENT") throw error
          }
        }
      } catch { /* Receipt is already known; the owner reclaims any durable acknowledgment. */ }
      return result
    } catch (error: any) {
      // Native publication briefly owns the checked receipt before chown.
      if (error?.code !== "ENOENT" && error?.code !== "EACCES") throw error
    }
    await new Promise(resolve => setTimeout(resolve, 200))
  }
  throw new Error(`Tool receipt pending: ${id}. Do not create a duplicate submission.`)
}

export const attempt = tool({
  description: "Record an evidenced completed attempt under your current task lease. Never announce a guess as a solved bounty.",
  args: {
    outcome: tool.schema.enum(["not_reproduced", "candidate", "inconclusive", "blocked", "interrupted"]),
    observations: tool.schema.string().min(1).max(8000),
    expected: tool.schema.string().max(4000),
    limitations: tool.schema.string().max(4000), evidence,
  },
  execute: (args, context) => request("attempt", args, context.sessionID),
})
export const report = tool({
  description: "Prepare a private evidence-backed finding for review or submission under the accepted report policy.",
  args: {
    title: tool.schema.string().min(1).max(200), component: tool.schema.string().min(1).max(400),
    reproduction: tool.schema.string().min(1).max(12000), observed: tool.schema.string().min(1).max(8000),
    expected: tool.schema.string().min(1).max(8000), impact: tool.schema.string().min(1).max(8000),
    limitations: tool.schema.string().max(4000), evidence,
    attemptIds: tool.schema.array(tool.schema.string().max(100)).max(32).optional(),
  },
  execute: (args, context) => request("report", args, context.sessionID),
})
export const reply = tool({
  description: "Check private-reply routing. Investigation prose is not delivered to humans; the supervisor answers private participant messages separately.",
  args: { content: tool.schema.string().min(1).max(8192), replyTo: tool.schema.string().max(100).optional() },
  execute: (args, context) => request("reply", args, context.sessionID),
})
export const check = tool({
  description: "Run one company-approved command in the separate offline test sandbox. 0 is setup, 1 is tests. No arbitrary commands or outside targets.",
  args: { index: tool.schema.number().int().min(0).max(1) },
  execute: (args, context) => request("check", args, context.sessionID),
})
