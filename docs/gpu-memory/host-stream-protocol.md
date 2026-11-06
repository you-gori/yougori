# Host streaming protocol adoption — G07 / GPU-W11

The environment-scoped `model_runner::stream_deltas` path now uses the existing
`serving_protocol` request profile, SSE decoder, stream assembler and completed-turn
validator. Desktop chat, CLI polled chat and internal callers share this path.
There is no new command or independent capability registry.

## Implemented behavior

- Validate request tool schemas and policy before opening the model connection.
  Environment-scoped requests can omit `model`: a parsing-only placeholder fills
  that field, without changing the request sent to the runner or claiming a model
  identity for conformance evidence.
- Decode HTTP/1.0 and HTTP/1.1 close-delimited, content-length and chunked bodies.
  Reject ambiguous lengths, unsupported transfer/content encodings, oversized
  headers and truncated framing. SSE media type is checked as a header value.
- Decode UTF-8 across read boundaries without lossy replacement. Use the shared
  SSE rules for LF, CRLF, CR, comments, a leading BOM and multiline events.
- Display accepted content, refusal and reasoning text while generation runs.
  Keep tool argument fragments private until a finish reason and `[DONE]` complete
  the turn. Validate all calls against declared names, schemas, tool choice and
  parallel-call policy before sending one complete `tool_calls` delta.
- Fail malformed/duplicate/out-of-order events, missing finish events, disconnected
  streams and legacy `function_call` deltas. A forced named tool can use `stop`;
  an ordinary tool response cannot silently substitute that finish reason.
- Preserve raw finish reasons and usage extensions. Refusal and truncation discard
  pending calls. Cancellation also discards calls, including a cancellation raised
  by a text callback in the same read as the terminal event.
- Classify quota, context, authentication and other service failures using the
  shared code/status taxonomy. Error messages and code strings supplied by the
  backend are not copied to the user. Rate/overload errors retain the existing
  `busy`/`retry shortly` signal used by callers.

Bounds are 8 MiB total wire response, 16 KiB headers and trailers, 64 KiB error
bodies, 32 calls and 64 KiB arguments per call. The existing 30-minute read-idle
timeout remains; cancellation now covers error-body reads too. Dropping the reader
closes the model connection. These are host engineering bounds, not model limits.

For close-delimited HTTP, the terminal SSE event ends reading after all events
already in that read have been checked; the client does not wait for socket EOF.
For content-length/chunked HTTP, the declared body must also finish before calls
are released. No completion can vouch for bytes a peer sends after the client has
closed the connection. Displayed text cannot be retracted if a later frame fails.

## Validation and remaining scope

Tests exercise the production async reader over disposable byte/duplex streams,
including one-byte reads, HTTP framing boundaries, parallel argument interleaving,
all-or-nothing validation, cancellation, timeouts, malformed streams and limits.
They use no live engine, GPU, credentials, downloads or external services.

Validation on 29 October: all 167 model-runner tests passed, including the 19
streaming tests, and all 11 CLI skill tests passed. Shared target directory;
Cargo gates run sequentially in this session. The all-target native check also
passed, with seven existing unused measurement-API warnings. Scoped rustfmt,
UTF-8/LF, whitespace and local documentation-link checks passed.

The subsequent [wire negotiation implementation](serving-negotiation.md) adds
protocol 1 and explicit legacy behavior. G07 remains open for real
model/runner/dialect capability evidence, endpoint advertisement, broader version
matrices and integrated agent-task acceptance.
This change does not route Responses or Messages endpoints through this adapter,
change the Python public API relay, prove model fidelity, or publish a supported
capability row from fixtures. The existing protocol library remains the authority
for those contracts. Source changes require a later rebuild/install to reach the
installed application.
