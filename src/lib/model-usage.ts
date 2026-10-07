import type { ModelUsage, UsageCounters, UsageRequest } from "@/api/projects-api"

export interface UsageDay extends UsageCounters { date: Date }
const dayKey = (date: Date) => `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`
const empty = (): UsageCounters => ({ requests: 0, prompt_tokens: 0, completion_tokens: 0, errors: 0, rejected: 0, yougori: 0, api: 0 })

/** Groups the server's hourly buckets into the last `days` local calendar days, oldest first. */
export function usageByDay(usage: ModelUsage, days: number, now = new Date()): UsageDay[] {
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const result = Array.from({ length: days }, (_, i) => ({ ...empty(), date: new Date(today.getFullYear(), today.getMonth(), today.getDate() - (days - 1 - i)) }))
  const index = new Map(result.map((day, i) => [dayKey(day.date), i]))
  for (const [hour, counters] of Object.entries(usage.hours)) {
    const i = index.get(dayKey(new Date(Number(hour) * 3_600_000)))
    if (i === undefined) continue
    const day = result[i]!
    for (const key of Object.keys(empty()) as (keyof UsageCounters)[]) day[key] = (day[key] ?? 0) + (counters[key] ?? 0)
  }
  return result
}

export function sumDays(days: UsageDay[]): UsageCounters {
  const total = empty()
  for (const day of days) for (const key of Object.keys(total) as (keyof UsageCounters)[]) total[key] = (total[key] ?? 0) + (day[key] ?? 0)
  return total
}

/** Average generation speed across completed replies, in tokens per second. */
export function averageSpeed(recent: UsageRequest[], field: "prompt_tokens" | "completion_tokens" = "completion_tokens"): number | null {
  const done = recent.filter(r => r.outcome === "ok" && r[field] > 0 && r.seconds > 0)
  const seconds = done.reduce((sum, r) => sum + r.seconds, 0)
  return seconds ? done.reduce((sum, r) => sum + r[field], 0) / seconds : null
}
