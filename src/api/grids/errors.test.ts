// @vitest-environment jsdom
import { describe, expect, it } from "vitest"
import {
  CapabilityOffError, CliOnlyError, ConflictError, DesktopOnlyError, GridError, NeedsApprovalError,
  NotAllowedError, classify, say,
} from "@/api/grids/errors"

describe("typed refusals", () => {
  it("keeps the engine's own words, whatever it decides they mean", () => {
    const sentences = [
      "Open Yougori Desktop to host or join a Closed Neo Grid",
      "No computer with the ID m9 is in this grid",
      "That hub cannot be reached from this computer",
      "This request needs an approver",
      "Something nobody has a pattern for",
    ]
    for (const sentence of sentences) expect(classify(sentence, "grid_status", "keen-heron-0a1b").message).toBe(sentence)
  })

  it("reads each kind of refusal from the sentence the Rust produces", () => {
    expect(classify("Open Yougori Desktop to use Swarm Mining", "x", "r").failure).toBe("desktopOnly")
    expect(classify("Desks are managed from the main Yougori window", "x", "r").failure).toBe("desktopOnly")
    expect(classify("This request needs an approver before it can run", "x", "r").failure).toBe("needsApproval")
    expect(classify("That request was already decided", "x", "r").failure).toBe("conflict")
    expect(classify("This grid does not broker credentials", "x", "r").failure).toBe("capabilityOff")
    expect(classify("You may not change plans in this grid", "x", "r").failure).toBe("notAllowed")
    expect(classify("No computer with the ID m9 is in this grid", "x", "r").failure).toBe("notFound")
    expect(classify("The hub stopped answering", "x", "r").failure).toBe("offline")
    expect(classify("That model is not ready yet", "x", "r").failure).toBe("notReady")
  })

  it("stays unknown rather than guessing", () => {
    const error = classify("Something nobody has a pattern for", "grid_status", "calm-otter-1122")
    expect(error.failure).toBe("unknown")
    expect(error.command).toBe("grid_status")
    expect(error.requestId).toBe("calm-otter-1122")
  })

  it("can build every kind it declares, which is what makes them usable at all", () => {
    const made: GridError[] = [
      new NotAllowedError("manageModels", ["user"], "grid_plan_add", "r"),
      new CapabilityOffError("credentials", "broker credentials", "access_manage", "r"),
      new NeedsApprovalError("Someone else has to agree first", "cred-1", null, "access_manage", "r"),
      new ConflictError("Somebody changed this", 3, 4, "desks_assign", "r"),
      new DesktopOnlyError("Open Yougori Desktop to use Swarm Mining", "swarm_dispatch", "r"),
      new CliOnlyError("yougori grid password --yes", "grid_password", "r"),
    ]
    expect(made.map(error => error.failure)).toEqual(["notAllowed", "capabilityOff", "needsApproval", "conflict", "desktopOnly", "cliOnly"])
    for (const error of made) expect(error).toBeInstanceOf(Error)
  })

  it("says an action in words rather than printing its identifier", () => {
    expect(new NotAllowedError("manageModels", ["user"], "grid_plan_add", "r").message).toBe("This account may not manage models in this grid")
    expect(new NotAllowedError("approveCredential", ["user"], "access_manage", "r").message).toBe("This account may not approve a credential request in this grid")
  })

  it("names the command line to run, with the confirmation the route asks for", () => {
    expect(new CliOnlyError("yougori grid revoke-key KEY_ID --yes", "grid_key_revoke", "r").message)
      .toBe("The desktop does not offer this yet. Run `yougori grid revoke-key KEY_ID --yes` instead.")
  })

  it("gives a page the sentence inside anything that was thrown", () => {
    expect(say(new Error("A sentence"))).toBe("A sentence")
    expect(say("A bare string")).toBe("A bare string")
  })
})
