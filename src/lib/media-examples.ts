/** Usage examples of a media model's API, shared by the API panel and the guest workspace's
 * API skill dialog. */
export type MediaExample = "curl" | "powershell" | "python" | "javascript" | "skill"

/** The examples of a media model: its OpenAI-shaped route where one fits (images, speech,
 * videos), else the job routes every kind has. The same examples as the CLI's /api menu. A model
 * that starts from an image (image-to-image, image-to-video) reads it from input.png. */
export function mediaExample(kind: MediaExample, base: string, model: string, task: string, key?: string) {
  const q = JSON.stringify
  const keyExpression = key ? q(key) : 'os.environ["YOUGORI_MODEL_API_KEY"]'
  const bearer = key ?? "$YOUGORI_MODEL_API_KEY"
  const images = task.endsWith("to-image")
  const speech = task === "text-to-speech"
  const video = task.endsWith("to-video")
  const fromImage = task.startsWith("image-to")
  const openaiImages = images && !fromImage
  const input: Record<string, string | number> = speech ? { text: "Hello from Yougori." } : video ? { prompt: "Waves rolling onto a beach at sunset", seconds: 2 } : task === "text-to-audio" ? { prompt: "Rain on a tin roof", seconds: 5 } : { prompt: "A red bicycle leaning on a white wall", count: 1 }
  const inputJson = q(input)
  const output = video ? "video.mp4" : images ? "image-1.png" : "audio.wav"
  switch (kind) {
    case "python": return openaiImages ? `# pip install openai
import base64, os
from openai import OpenAI

client = OpenAI(base_url="${base}", api_key=${keyExpression})
result = client.images.generate(model="${model}", prompt="A red bicycle leaning on a white wall", n=1, size="512x512", response_format="b64_json")
with open("image.png", "wb") as file:
    file.write(base64.b64decode(result.data[0].b64_json))` : speech ? `# pip install openai
import os
from openai import OpenAI

client = OpenAI(base_url="${base}", api_key=${keyExpression})
with client.audio.speech.with_streaming_response.create(model="${model}", voice="default", input="Hello from Yougori.", response_format="wav") as response:
    response.stream_to_file("speech.wav")` : `import ${fromImage ? "base64, " : ""}json, os, time, urllib.request

base = "${base}"
headers = {"Authorization": "Bearer " + ${keyExpression}, "Content-Type": "application/json"}
${fromImage ? `# The image to start from, as a data URL.
image = "data:image/png;base64," + base64.b64encode(open("input.png", "rb").read()).decode()
request = urllib.request.Request(base + "/jobs", data=json.dumps({"input": {**${inputJson}, "image": image}}).encode(), headers=headers)` : `request = urllib.request.Request(base + "/jobs", data=json.dumps({"input": ${inputJson}}).encode(), headers=headers)`}
job = json.load(urllib.request.urlopen(request))
while job["status"] in ("queued", "running"):
    job = json.load(urllib.request.urlopen(urllib.request.Request(base + "/jobs/" + job["id"] + "?wait=30", headers=headers)))
for item in job["output"]["files"]:
    with urllib.request.urlopen(urllib.request.Request(base + item["url"][3:], headers=headers)) as response, open(item["name"], "wb") as file:
        file.write(response.read())`
    case "javascript": return `// Save as example.mjs, then run: node example.mjs
import { ${fromImage ? "readFile, " : ""}writeFile } from "node:fs/promises"

const base = "${base}"
const headers = { Authorization: \`Bearer \${${key ? q(key) : "process.env.YOUGORI_MODEL_API_KEY"}}\`, "Content-Type": "application/json" }
${fromImage ? `// The image to start from, as a data URL.
const image = "data:image/png;base64," + (await readFile("input.png")).toString("base64")
let job = await (await fetch(base + "/jobs", { method: "POST", headers, body: JSON.stringify({ input: { ...${inputJson}, image } }) })).json()` : `let job = await (await fetch(base + "/jobs", { method: "POST", headers, body: JSON.stringify({ input: ${inputJson} }) })).json()`}
while (job.status === "queued" || job.status === "running") job = await (await fetch(\`\${base}/jobs/\${job.id}?wait=30\`, { headers })).json()
for (const file of job.output.files) {
  const bytes = await (await fetch(base + file.url.slice(3), { headers })).arrayBuffer()
  await writeFile(file.name, Buffer.from(bytes))
}`
    case "curl": return openaiImages ? `curl ${base}/images/generations \\
  -H "Authorization: Bearer ${bearer}" -H "Content-Type: application/json" \\
  -d '{"model": ${q(model)}, "prompt": "A red bicycle leaning on a white wall", "n": 1, "size": "512x512", "response_format": "b64_json"}'` : speech ? `curl ${base}/audio/speech --output speech.wav \\
  -H "Authorization: Bearer ${bearer}" -H "Content-Type: application/json" \\
  -d '{"model": ${q(model)}, "input": "Hello from Yougori.", "response_format": "wav"}'` : `# Submit, then poll until it ends, then fetch the file named in the output
${fromImage ? `IMAGE="data:image/png;base64,$(base64 < input.png | tr -d '\\n')"
curl ${base}/jobs -H "Authorization: Bearer ${bearer}" -H "Content-Type: application/json" -d "{\\"input\\": ${q({ ...input, image: "$IMAGE" }).replace(/"/g, '\\"')}}"` : `curl ${base}/jobs -H "Authorization: Bearer ${bearer}" -H "Content-Type: application/json" -d '{"input": ${inputJson}}'`}
curl "${base}/jobs/JOB_ID?wait=30" -H "Authorization: Bearer ${bearer}"
curl ${base}/files/JOB_ID.1 -H "Authorization: Bearer ${bearer}" --output ${output}`
    case "powershell": return `$headers = @{ Authorization = "Bearer ${key ?? "$env:YOUGORI_MODEL_API_KEY"}" }
${fromImage ? `$image = "data:image/png;base64," + [Convert]::ToBase64String([IO.File]::ReadAllBytes("input.png"))
$body = @{ input = @{ ${Object.entries(input).map(([name, value]) => `${name} = ${typeof value === "number" ? value : `"${value}"`}`).join("; ")}; image = $image } } | ConvertTo-Json -Depth 4
$job = Invoke-RestMethod -Method Post -Uri "${base}/jobs" -Headers $headers -ContentType "application/json" -Body $body` : `$job = Invoke-RestMethod -Method Post -Uri "${base}/jobs" -Headers $headers -ContentType "application/json" -Body '{"input": ${inputJson}}'`}
while ($job.status -in "queued", "running") { $job = Invoke-RestMethod -Uri "${base}/jobs/$($job.id)?wait=30" -Headers $headers }
foreach ($file in $job.output.files) { Invoke-WebRequest -Uri ("${base}" + $file.url.Substring(3)) -Headers $headers -OutFile $file.name }`
    case "skill": return `---
name: yougori-media-api
description: Make ${task.replace(/-/g, " ")} with the user's Yougori model through its job API.
---

# Yougori media model

Model: ${model} (${task})
API base URL: ${base}

${key ? `API key: ${key}\n\nThe user included this key on purpose; send it as the bearer token and keep it out of source code, commits and logs.` : "Obtain the API key from Yougori's API access panel and provide it as the YOUGORI_MODEL_API_KEY environment variable. Do not put the key in this skill, source code, or logs."}

Every request sends Authorization: Bearer <key>. The model generates one job at a time; up to 16 wait in order.

1. POST /jobs with JSON {"input": {...}}: ${speech ? "text (and voice)" : "prompt, negative_prompt, width, height, steps, guidance, seed" + (images ? ", count (1-8)" : video ? ", seconds, fps" : ", seconds")}${task.startsWith("image-to") ? ", and image as a data URL" : ""}. The answer is the job: id, status (queued, running, succeeded, failed, cancelled), progress.
2. GET /jobs/ID?wait=30 until the status is final. GET /jobs/ID/result gives the output; its files list names each file with a url under /files.
3. GET /files/ID downloads a file (PNG, MP4 or WAV). POST /jobs/ID/cancel stops a job. Files are kept for a limited time; download what you need.
${images ? "\nPOST /images/generations also works in OpenAI's shape (prompt, n, size, response_format b64_json or url)." : speech ? "\nPOST /audio/speech also works in OpenAI's shape (input, voice, response_format wav) and answers the WAV bytes." : video ? "\nPOST /videos, GET /videos/ID and GET /videos/ID/content follow OpenAI's video objects." : ""}
Report a failed job's error to the user instead of retrying it in a loop.
`
  }
}
