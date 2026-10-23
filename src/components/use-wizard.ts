/** One question at a time, with Back on every one of them.
 *
 *  The rule is the one the command line's own wizard already has: Back walks to the previous
 *  question that was actually asked, so it never lands on a question this grid skipped, and Back
 *  from the first question closes the wizard without changing anything. In the browser, Escape
 *  closes the dialog as it does everywhere else; Ctrl+C is the terminal's rule and has nothing
 *  to do with this.
 */
import { useCallback, useMemo, useState } from "react"

export interface AskedStep<A> {
  id: string
  title: string
  when(answers: A): boolean
  problem(answers: A): string
}

/** The question after this one, given the answers as they are now. */
export function stepAfter<A>(steps: readonly AskedStep<A>[], answers: A, fromId: string): AskedStep<A> | null {
  const at = steps.findIndex(step => step.id === fromId)
  for (let next = at + 1; next < steps.length; next += 1) {
    const step = steps[next] as AskedStep<A>
    if (step.when(answers)) return step
  }
  return null
}

/** The questions this set of answers is asked, in order. */
export function stepsAsked<A>(steps: readonly AskedStep<A>[], answers: A): AskedStep<A>[] {
  return steps.filter(step => step.when(answers))
}

export interface Wizard<A> {
  step: AskedStep<A>
  /** Which question this is of the ones this grid is asked, counting from one. */
  place: number
  total: number
  canGoBack: boolean
  /** Empty while the question may be left. */
  problem: string
  last: boolean
  next(): void
  /** Goes back one question, or closes when this is the first. */
  back(): void
  /** Goes back to a named question, for a summary that sends somebody to the one that is wrong. */
  goTo(id: string): void
}

/** `onClose` is called by Back from the first question, and by nothing else here. */
export function useWizard<A>(steps: readonly AskedStep<A>[], answers: A, onClose: () => void): Wizard<A> {
  const first = steps[0] as AskedStep<A>
  const [trail, setTrail] = useState<string[]>([first.id])
  const current = useMemo(
    () => steps.find(step => step.id === trail[trail.length - 1]) ?? first,
    [steps, trail, first],
  )
  const asked = useMemo(() => stepsAsked(steps, answers), [steps, answers])
  const next = useCallback(() => {
    if (current.problem(answers)) return
    const following = stepAfter(steps, answers, current.id)
    if (following) setTrail(walked => [...walked, following.id])
  }, [answers, current, steps])
  const back = useCallback(() => {
    setTrail(walked => {
      if (walked.length <= 1) {
        onClose()
        return walked
      }
      return walked.slice(0, -1)
    })
  }, [onClose])
  const goTo = useCallback((id: string) => {
    setTrail(walked => {
      const at = walked.indexOf(id)
      return at === -1 ? [...walked, id] : walked.slice(0, at + 1)
    })
  }, [])
  const place = Math.max(1, asked.findIndex(step => step.id === current.id) + 1)
  return {
    step: current,
    place,
    total: Math.max(asked.length, place),
    canGoBack: true,
    problem: current.problem(answers),
    last: !stepAfter(steps, answers, current.id),
    next,
    back,
    goTo,
  }
}
