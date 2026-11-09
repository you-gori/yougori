import type { ModelRun } from "@/api/projects-api"

/** Options describe the running model server: public links and streaming change what callers can do. */
export function modelApiSkill(model: Pick<ModelRun, "model" | "apiUrl">, options: { public?: boolean; streaming?: boolean; apiKey?: string; json?: boolean } = {}): string {
  const credentials = options.apiKey
    ? `API key: ${options.apiKey}

The user included this key on purpose. Send it as the bearer token and keep it out of source code, commits and logs.`
    : "Obtain the API key separately from Yougori's API access panel and provide it as the YOUGORI_MODEL_API_KEY environment variable in the calling process. Do not put the key in this skill, source code, or logs."
  const keyExpression = options.apiKey ? JSON.stringify(options.apiKey) : `os.environ["YOUGORI_MODEL_API_KEY"]`
  const where = options.public
    ? "This is a public HTTPS address: it works from any computer, container or online agent. It lasts while Yougori and the model environment keep running; if it stops working, ask the user for the current link."
    : "Run requests on the PC hosting Yougori. Localhost inside another container or on an online agent is not this PC."
  // The launch enforces a JSON reply format (health's structuredOutput): say how to ask for it.
  const fields = (options.streaming
    ? "Supported fields: model, messages, max_tokens (1–4096), temperature (0–2), stream. With stream:true the reply arrives as OpenAI-style server-sent events (chat.completion.chunk) ending with data: [DONE]."
    : "This model is non-streaming; use stream:false. Supported fields: model, messages, max_tokens (1–2048), temperature (0–2), stream.")
    + (options.json ? ' response_format asks for JSON: {"type": "json_object"} for any object, or {"type": "json_schema", "json_schema": {"name": ..., "schema": ..., "strict": true}} for a shape; the server holds the reply to it.' : "")
  return `---
name: yougori-model-api
description: Call the user's Yougori Hugging Face model for text generation through its authenticated OpenAI-compatible chat API.
---

# Yougori model API

Model: ${model.model}
API base URL: ${model.apiUrl}

${where} Keep Yougori and the model environment running; wait for Chat to report ready.

${credentials}

POST to /chat/completions under the base URL with Authorization: Bearer <key> and Content-Type: application/json. Any OpenAI-compatible client works when given this base URL and key. ${fields} Messages contain only role (system, user, assistant) and text content. Tool calling, images and other OpenAI fields are rejected.

Python example (standard library):

\`\`\`python
import json
import os
import urllib.request

payload = {
    "model": ${JSON.stringify(model.model)},
    "messages": [{"role": "user", "content": "Hello!"}],
    "max_tokens": 256,
    "stream": False,
}
request = urllib.request.Request(
    ${JSON.stringify(`${model.apiUrl}/chat/completions`)},
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + ${keyExpression},
        "Content-Type": "application/json",
    },
)
with urllib.request.urlopen(request, timeout=600) as response:
    result = json.load(response)
print(result["choices"][0]["message"]["content"])
\`\`\`

Keep the request under 64 KiB, with at most 128 messages and 32,768 content characters. The model's context window may be smaller. Updated GGUF and vLLM runners generate several requests together (four and eight by default); others answer one at a time. Up to 128 more wait in order for up to five minutes. Allow for queue time in your client timeout; 429 means the queue is full, and 504 means the wait or generation timed out. For 401, check the key; for 429, wait and retry once; for a loading response, check Chat/startup logs before retrying. Shorten the conversation for context or GPU memory errors. Report persistent failures instead of looping.
`
}
