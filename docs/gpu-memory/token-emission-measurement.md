# Token emission measurement

Implemented by one agent on 29 October 2026 as the client-emission/reporting slice
of G01 / GPU-W00. This extends the existing private measurement pipeline; it adds
no public API command and changes no ordinary uninstrumented request.

## Production path

An explicit recording journal window enables token observation for streamed
llama.cpp/vLLM chat requests. The relay asks the backend for `logprobs: true`,
`top_logprobs: 0`, and final usage. No extra alternatives are requested. Backend
rejection remains a recorded failed attempt, never a silent unmeasured retry.

For each text chunk the relay checks the sampled token byte arrays against the
exact UTF-8 content it forwards. Only a successful write and flush yields a
monotonic timestamp, captured immediately after flush. Tokens delivered together
share that timestamp. Unicode byte fragments can join inside one chunk; fragments
that cannot be matched exactly stay unavailable. Token strings, byte arrays,
probabilities, prompts and credentials are never persisted in timing records.

A trace is complete only if the stream succeeds, every content chunk has a valid
byte mapping, and final backend completion usage equals the observed token count.
Tools, hidden reasoning, stripped output, missing/null metadata, repeated usage,
count mismatches and traces exceeding 256 tokens do not become exact records.
The bounded observed prefix and explicit `complete: false` remain available.
The existing 8 KiB journal-record and total window limits still apply.

The optional `tokens` extension is version 1 with source
`openai-logprobs-flush`, `complete`, `emittedMs`, and `outputTokens`. Python replay
and Rust collection validate its closed schema, duration ordering, bounds and
relation to accepted/admitted/completed request boundaries. Unknown extensions
fail closed. Older records retain their conversion and replay behavior.

## Reporting

With a complete trace and caller-supplied ready-at-arrival metadata, the Rust
adapter now emits successful CORE-08 Serving reports with RequestAccepted,
RequestDequeued, one TokenEmitted per verified token, and RequestCompleted.
Output counts match the events. Existing report code derives time to first token,
request/queue latency and inter-token gaps. Same-flush tokens legitimately have
zero gaps; no interpolation creates artificial decode work.

The follow-up [demand-load integration](demand-load-measurement.md) supplies
completed wrapper load boundaries for loads wholly inside an accepted request.
Other demand-load/wake requests still retain an explicit gap instead of being
relabelled ready. Missing metadata,
failed and incomplete attempts remain in the raw accounting denominator.
Snapshots and sealed journal replay preserve both conversions and gaps.

These are server-side flush times, not client receipt, network latency, GPU token
generation, scheduler, CUDA or prefill clocks. Buffered and Transformers output
remain explicitly without exact emission observations. Logprob instrumentation
can affect performance; benchmark context and comparisons must disclose it.
Real backend/version qualification and hardware performance belong to E02/E03.

## Tests

Regression coverage includes Unicode token pieces, multi-token flushes, missing
and malformed metadata, mismatched usage, tools/reasoning, overflow, cancellation,
backend errors, strict schemas, journal restart replay and opt-in behavior.
A cross-language integration test runs the real HTTP relay, journal, Rust
collector, cursor, adapter and durable sink, then reopens its completed output.
Only model preparation/inference are synthetic. No models or GPUs are started.

Backend protocol references (checked 29 October 2026):
- [vLLM chat serving implementation](https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/openai/chat_completion/serving.py)
- [llama.cpp server protocol implementation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/server-task.cpp)

These describe upstream protocol expectations, not proof that every installed
backend/version supplies an exact trace. Runtime validation remains mandatory.

## Verification record

- Offline Python gate: 205 tests across twelve suites passed. After tightening
  timestamp capture to the immediate flush boundary, the 27 timing and 18 journal
  tests were rerun and passed.
- Native model-runner filter: 149 tests passed, including four new report cases
  and the real HTTP-to-sink streaming case; no failures or ignored tests.
- All-target native compilation passed, with seven existing unused measurement
  API warnings. Final focused measurement/replay rerun: 39 tests passed,
  including the compatibility correction and HTTP-to-sink persistence/reopen.

Shared build target: `D:/YougoriBuildCache/target`; scratch under its sibling
`scratch` directory. Source AST, UTF-8, LF and scoped whitespace checks passed.
No live engine, GPU, downloads, app installation, commit, push or release occurred.
