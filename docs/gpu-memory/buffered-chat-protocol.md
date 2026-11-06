# Buffered Chat Completions validation

G07 / GPU-W11 source integration, 29 October 2026, implemented by one agent.
The production `model_request` Chat Completions path and `model_chat` now reuse
the shared request, turn and tool-schema contracts for ordinary JSON responses.
Other model control/diagnostic endpoints keep their existing response path.

## Request and transport

Requests are validated before opening the model connection. Buffered chat refuses
`stream: true`; streaming has its existing separate path. The same request carries
protocol 1 with `json` or `json,tools`; tool-result history also requires tools.
The authenticated Python relay matches the selected mode/features to the body and
configured route before loading/generation, and acknowledges the selection.

Success from an older plain-text runner remains explicitly `legacy`. Tool-aware
success requires an exact acknowledgement. Unknown, duplicate, mismatched or
partial agreement headers do not downgrade. An earlier protocol-1 runner without
JSON negotiation may refuse the new request; restart it with the updated engine.
The agreement proves route/version compatibility, not model tool-calling quality.

The existing bounded HTTP parser now supports JSON as well as SSE. It checks
content type, identity encoding, Content-Length/chunked framing, header and trailer
limits, duplicate/ambiguous framing, and premature closure. Buffered replies retain
the existing 2 MiB total response limit and 30-minute whole-response deadline;
errors have a separate 64 KiB cap. Dropping/timing out the future drops its owned
connection. No tool call becomes observable before complete HTTP and JSON parsing.
Service errors become fixed classifications or actionable agreement refusals,
without echoing backend error messages.

## Complete-turn validation

A response must contain exactly one assistant choice at index zero, an explicit
recognized finish reason, and correctly typed content/refusal fields. Legacy
`function_call` payloads are refused. Complete buffered calls are internally
normalized into a single declared turn for the existing shared assembler and
request validator; this normalization is not evidence of a streamed exchange.

The shared validator checks declared tool names, complete argument JSON/schema,
forced/disabled choices, parallel-call policy, call identity/order and bounded
argument/call counts. Every call must pass before the completion is returned. Returned calls are
rebuilt from their validated ID, type, name and arguments, dropping unchecked
extra call fields.
Refused/truncated turns retain content, refusal, finish and usage but have their
tool calls removed. Missing finish reasons and malformed calls never become
successful completions. The JSON envelope remains available with `servingProtocol`
metadata added.

The Python llama.cpp/vLLM relay also stops inventing a `stop` reason, assistant
role or first choice from malformed backend results. It requires one complete
backend choice, rejects mixed error/success payloads, and preserves refusal,
reasoning and tool fields for the host
validator. Backend reads have an explicit size check; generation locks and
connections are released on errors.

## Verification

- Offline Python: 231 tests across twelve suites passed. Covers JSON negotiation,
  early mode refusals, malformed backend completions, preserved refusal/finish and
  generation cleanup. Older incomplete synthetic fixtures were corrected.
- Native model-runner gate: 187 tests passed, including eight buffered adapter
  cases and the real Rust/Python buffered HTTP integration case. The new fixture
  initially discarded request messages; it was corrected before the final pass.
- Final Python review rerun encountered one Windows connection-abort in an
  existing malformed-header test; all 49 tests in that affected suite passed
  unchanged on focused rerun. The other eleven suites passed.
- CLI skill/catalog gates: 20 tests passed (11 skill and 9 catalog checks).
- All-target native compilation passed, with seven existing unused measurement
  API warnings. Shared target: `D:/YougoriBuildCache/target`; test scratch stays
  under `D:/YougoriBuildCache/scratch`.
- Scoped AST, rustfmt, UTF-8/LF, whitespace and documentation link checks passed.

Native coverage includes text/usage preservation, schema-invalid and parallel
calls, forced/disabled choices, every-call validation, truncation/refusal, malformed
terminal fields, legacy agreements, chunked and byte-fragmented UTF-8 JSON,
ambiguous/incomplete framing, redacted errors, size bounds and stalled connections.
The actual Rust reader and Python HTTP relay are tested together for buffered
text, tools, truncation, invalid arguments and mode mismatches. Only inference is
synthetic; no models or GPU workloads are run.

## Remaining G07 scope

Actual model/runner/dialect conformance evidence, capability publication,
Responses/Messages endpoint adapters and integrated agent acceptance remain open.
This does not modify the shared protocol library or establish model fidelity.
No app installation, release, commit or live worker operation is part of this task.
