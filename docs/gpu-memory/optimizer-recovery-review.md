# GPU-W01: failed-load memory recovery

The existing unload path retained uncertain residency after cleanup failed, but
the failed-load path did not. `gpu_after_load()` swallowed an allocator
`RuntimeError`, cleared `GPU_LOADING`, and left status `error`. The next health
observation then reported `resident: false`, even though release was unconfirmed.
A failed llama.cpp startup could also leave its owned native process running;
failed-load cleanup previously did not inspect or terminate that process.

The shared release routine in `model_runner/gpu_optimizer.py` now serves both
explicit unload and failed-load cleanup. It checks the owned native process,
terminates a running process, waits up to 10 seconds, then kills and waits up to
5 seconds if needed. The process handle is retained on failure and discarded
only after a confirmed exit. A later retry can observe an already exited process
without sending another termination signal. Only then are model references
dropped and the allocator cache cleared.

Failed-load cleanup starts with `releaseUncertain: true`. It clears that flag only
after cleanup succeeds while holding the generation lock with no active request.
If the generation lock is busy, requests remain active, or cleanup raises, the
model continues to report conservative residency. The error is a fixed recovery
message rather than backend exception text. `GPU_LOADING` is cleared and waiting
requests are notified in all ordinary failure cases, so they receive the error
instead of waiting for a loader that has already finished. Successful cleanup
preserves the original load error; cleanup does not turn a failed load into ready.

The existing pre-load uncertainty guard also rejects another load when automatic
memory management is disabled. A later permitted unload can reconcile the retained
process or allocator state, after which the normal loader may run again. Pins,
active requests, preparation leases and generation locks retain their existing
unload protections; this change does not bypass them for automatic recovery.

## Verification and scope

On 28 October 2026, all 24 focused optimizer tests passed. Four new tests cover:

- failed allocator cleanup, conservative residency, rejected admission with the
  optimizer enabled or disabled, and a successful cleanup retry;
- failed native startup whose owned process is successfully stopped;
- native cleanup timeouts, waiter notification, retained process ownership and
  reconciliation after the process eventually exits;
- refusal to claim memory release while generation is locked or requests are active.

```powershell
python -B -m unittest discover -s src-tauri/src -p gpu_optimizer_test.py -v
```

Tests use mocked allocators/processes and existing local condition/socket fixtures.
No GPU workload, external model, installed engine or app was run. Parent integration
runs the complete offline model gate. Rust scheduling code and shared CORE modules
are unchanged. This routine only owns `ENGINE_PROCESS`; it does not supervise an
external native service or an entire process tree. OS waits remain cooperative,
and no hardware memory-release or performance evidence is claimed. The broader
GPU-W01 acceptance and isolated hardware comparisons remain open.
