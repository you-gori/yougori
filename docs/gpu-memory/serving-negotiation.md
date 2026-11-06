# Runner wire negotiation — G07 / GPU-W02 / GPU-W11

Host-streamed chat now negotiates with the real Python model service on the
generation request itself. There is no preceding health probe or automatic retry.
The existing authenticated guest/SSH transport and public command signatures stay
the same. This is source implementation, not an installation or release.

## Contract and admission

The host derives requirements from the shared `RequestProfile` and the message
history. It sends exactly one of each header:

```text
X-Yougori-Serving-Protocol: 1
X-Yougori-Serving-Features: stream
```

For declared functions or assistant/tool-result history, the feature value is
`stream,tools`. Even a disabled tool choice still passes function definitions to
the runner and therefore needs its tool-aware route.

After authentication, the runner checks the single-valued headers, version and
known feature selection. It compares that selection with the parsed request body
and checks that a requested tool route is configured (`tools_enabled`). Existing
request validation still runs. Failures return bounded, fixed error codes before
`gpu_enter`, model preparation or generation; they remain failed attempts in
existing usage/timing accounting. Merely sending these headers grants no authority.

Once validation passes, the Python handler attaches the exact selection to its
response through its common header writer. This covers the existing llama.cpp,
vLLM and Transformers paths. Upstream inference response headers cannot supply
the agreement. Unmodified public OpenAI clients need no custom headers and retain
their existing request-validation behavior.

The host checks successful response headers before delivering any display or tool
data. It rejects duplicate/partial acknowledgements, unknown versions, mismatched
or unknown feature values, and attempts to change the selection in HTTP trailers.
It does not retry by stripping fields or fall back after a malformed agreement.
The completed-turn/schema checks from [host streaming](host-stream-protocol.md)
remain mandatory after a successful agreement.

## Compatibility

An older runner with neither header can serve plain-text requests under the same
strict stream validator. Completion metadata explicitly reports:

```json
{"servingProtocol":{"version":null,"mode":"legacy","features":[]}}
```

Before delivering a successful tool-aware response, the host requires protocol 1
and the exact `stream,tools` acknowledgement. Without it, the host closes the
connection and asks for a model
restart with the updated engine. An old runner may have started generation before
the host discovers its missing acknowledgement, but no reply/tool delta from that
response reaches the caller. No automatic resubmission can duplicate that work.

A matching response reports `version: 1`, `mode: "negotiated"` and the selected
feature list. Cancellation before completion keeps the existing cancelled result.
Known negotiation error codes become fixed actionable host messages without
echoing backend error text; other failures use the shared error taxonomy.

## Evidence boundary and remaining work

The acknowledgement means that the service accepted this wire version, request
shape and configured route. It is **not** proof that a model calls tools correctly,
honors parallel/tool-choice instructions, preserves semantic context, or matches
a reference implementation. No `CapabilityRow` is minted or advertised from it.

G07 still needs actual model/runner/dialect conformance evidence, published
capability/version matrices and other supported endpoint integrations. The current
single-version refusal is deliberate; future versions require an explicit adapter
and tests rather than an inferred downgrade.

Tests cover real Python HTTP admission, the Rust response reader and their combined
socket path, with preparation/inference replaced by disposable synthetic output.
They include a text turn, streamed tool arguments, headerless clients, tool-result
continuations, malformed/duplicate headers, unavailable routes, authentication
order and version/body disagreement. No live engine, GPU, model downloads or
external providers are used.

## Verification record

29 October: all 221 offline Python tests across twelve suites passed; all 173
native model-runner tests passed, including the real Rust/Python negotiation and
tool-stream integration. Timing test doubles now use real HTTP header containers
so duplicate-header semantics match production. The relay's opening assistant
event is included in the integration assertions. No failures or skips remain in
these gates. Packaging checks also passed with the expanded embedded helper.

The all-target native check passed with seven existing unused measurement-API
warnings. The CLI skill gate passed (11 tests); after updating the completion-field
description in `cli/src/catalog.rs`, the combined skill/catalog gate passed all
20 tests. No command parameters changed, so `parse.rs` needs no new argument path.
Scoped rustfmt, Python AST, UTF-8/LF, whitespace and documentation-link checks
passed. Cargo gates were serialized in this session using the shared build target.

## Buffered endpoint follow-up

The [buffered Chat Completions adapter](buffered-chat-protocol.md) extends this
agreement with `json` and `json,tools`. It validates complete HTTP/JSON replies
and uses the same request/tool policy, with explicit older-runner handling.
The streaming feature selections and their semantics are unchanged.
