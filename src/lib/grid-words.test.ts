import { expect, it } from "vitest"
import { actionSentence, momentsAgo, personName, timelineLine } from "@/lib/grid-words"

it("turns a dotted action into a sentence, and never shows the token", () => {
  expect(actionSentence("realm.lifecycle")).toBe("This grid changed state.")
  expect(actionSentence("realm.created")).toBe("This grid was created.")
  expect(actionSentence("principal.suspended")).toBe("A person was suspended.")
  expect(actionSentence("device.enrolled")).toBe("A computer joined this grid.")
  expect(actionSentence("model.plan.added")).toBe("A model plan was added.")
  expect(actionSentence("credential.sent")).toBe("A credential was used on a request.")
  expect(actionSentence("workspace.image.refused")).toBe("The image of a desk was refused.")
  expect(actionSentence("workspace.sessions.closed")).toBe("A session of a desk was closed.")
  expect(actionSentence("research.scope.frozen")).toBe("The scope of research was frozen.")
  expect(actionSentence("work.cancelled")).toBe("A piece of work was cancelled.")
})

it("still reads as English for an action nobody has words for yet", () => {
  expect(actionSentence("realm.somethingnew")).toBe("This grid changed.")
  expect(actionSentence("mystery.thing")).toBe("Something in this grid changed.")
  expect(actionSentence("")).toBe("Something in this grid changed.")
  for (const action of ["realm.lifecycle", "mystery.thing", "realm.somethingnew", "workspace.image.refused"]) {
    // A sentence ends in a full stop and has no dotted token left anywhere in it.
    expect(actionSentence(action)).not.toContain(action)
    expect(actionSentence(action)).not.toMatch(/\w\.\w/)
    expect(actionSentence(action)).toMatch(/^[A-Z].*\.$/)
  }
})

it("says the four grids' own words too, so one timeline reads as one thing", () => {
  expect(actionSentence("use")).toBe("A credential was used on a request.")
  expect(actionSentence("deny")).toBe("A request was refused.")
  expect(actionSentence("signin")).toBe("Somebody signed in.")
})

it("turns a principal id into a person's name, and never shows an id", () => {
  const people = new Map([["person-9f31ac", "Ada Lovelace"], ["grace", "Grace Hopper"]])
  expect(personName("person-9f31ac", people)).toBe("Ada Lovelace")
  expect(personName("grace", people)).toBe("Grace Hopper")
  expect(personName("system", people)).toBe("Yougori itself")
  expect(personName("person-4b81de", people)).toBe("Somebody who has since left")
  expect(personName("", people)).toBe("Somebody")
  // A product that already writes a username keeps it.
  expect(personName("ada", new Map())).toBe("ada")
})

it("says how long ago in words", () => {
  const now = 1_000_000
  expect(momentsAgo(now - 10, now)).toBe("just now")
  expect(momentsAgo(now - 300, now)).toBe("5 min ago")
  expect(momentsAgo(now - 7200, now)).toBe("2 h ago")
  expect(momentsAgo(now - 172_800, now)).toBe("2 days ago")
})

it("builds one line of the timeline with a refusal marked as one", () => {
  const people = new Map([["person-9f31ac", "Ada Lovelace"]])
  const line = timelineLine(
    { id: "1", at: 990_000, principal: "person-9f31ac", action: "capability.refused", decision: "refused", reason: "This grid does not broker credentials." },
    people,
    1_000_000,
  )
  expect(line).toEqual({
    id: "1",
    when: "2 h ago",
    who: "Ada Lovelace",
    what: "Something this grid does was refused.",
    why: "This grid does not broker credentials.",
    refused: true,
  })
})
