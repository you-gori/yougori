# Example answers

Non-sensitive answers for scripted runs. They contain no API keys or sign-ins.

```text
yougori template run ./examples/hub/ai-workspace --inputs answers/several-tools.json --secrets - --yes
```

Pass API keys as JSON on standard input, for example `{"gemini_api_key": "..."}` for `several-tools.json`. Scripted runs never copy sign-ins from this computer; open each tool afterwards to sign in.
