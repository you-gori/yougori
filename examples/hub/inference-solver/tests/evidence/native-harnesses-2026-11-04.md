# Native VM harness and infrastructure checks — 2026-11-04

The actual pinned clients ran in Yougori Sandbox VMs on Windows/QEMU-WHPX,
using an isolated development engine and disposable website accounts. No Docker
daemon, host execution fallback, external target or paid provider resource was used.
The model for these harness checks was a local HTTP fixture. These results prove
the exercised client/relay/tool paths, not model quality or a complete security scan.

| Harness | Result | Exercised path |
| --- | --- | --- |
| HexStrike | Passed | Pinned HTTP/MCP server, inference, MCP file creation, tool result returned to model |
| Plandex | Passed | Actual CLI, PostgreSQL and server, headless plan through the fixed model relay |
| Strix | Passed | Actual agent/SDK, loopback Caido, guest command execution and its result returned to model, completed report |
| PentAGI | Passed | Actual server, PostgreSQL/pgvector, model probing, task flow, guest command and file write/read, completed result |
| Shannon | Passed | Real Temporal server/worker, fixed model registry, model inference and successful model-validation workflow; no penetration test |

[Artifact versions, hashes and runtime-log hashes](native-harnesses-2026-11-04.json)
identify these local runs. Full logs remain in the recorded local scratch paths.
Shannon's final directory-placeholder correction was applied to its disposable
VM before the worker started. Its published image was then rebuilt with that
same helper and checked byte-for-byte; the successful run used the corrected
helper with the same verified dependency package.
The earlier [container checks](harness-runtime-2026-11-02.md) are historical;
they do not establish native VM compatibility for the other sixteen profiles.
Pi separately passed the native VM inference path before this batch.

## Defects found and fixed

- Plandex: preserve the model configuration in upstream's final fallback result
  to avoid a nil dereference; use a context budget large enough for its own prompts.
- Strix: import its module instead of the exported function, use supported SDK
  arguments and explicit guest path grants, and remove container-runtime probing.
- PentAGI: use its actual OpenAI endpoint setting, supply required log pagination,
  and give its non-root runtime a writable guest work directory. Its execution
  adapter's Go tests check actual commands, file transfer, traversal/link refusal
  and cancellation. Those tests ran during the pinned image build.
- Shannon: split the large verified tool package from its bounded boot image,
  omit desktop-only catalogs, and preserve the harness name while reading archive
  entries so its requested 3 GB filesystem is actually imported. The latter has
  a regression test, including cache reuse with different filesystem budgets.
  Keep canonical reports in the staged workspace instead of passing an unsupported
  customer-output path to upstream's workflow.
- Website: prevent two Windows processes from binding the same port and splitting
  compute state; retry model health refresh after temporary storage failures.
- Local model: completed CUDA setup, restored sharing, and verified an actual
  website inference response from Qwen2.5-0.5B on the laptop GPU. The temporary
  scoped test key was revoked.

Failed runtime attempts were retained locally. Two test-fixture defects were also
fixed: endpoint health now refreshes during slow image preparation, and streamed
usage is emitted at completion rather than falsely ending Plandex's stream early.
Strix and PentAGI assertions require a real tool result, not an echoed command.

## Infrastructure

The real grid test passed website HTTP launch, contributor execution, a Linux
guest command, stop and website reconciliation. Other HTTP/database tests cover
resource limits, host-bound results, private/open/password enrollment, admin-only
wallet changes, duplicate server refusal, unavailable VM runtimes and 1–8 GPU
quote totals. Provider transport is substituted: no paid rental was performed.

Browser validation passes desktop/mobile account flows, guest-first catalogs,
the existing card layout, inline infrastructure controls and authorization.
The combined Python suite passed **124 tests, zero failures**. A direct socket
connection from the real Shannon VM to an external address failed with Linux
`ENETUNREACH` (101); host relay tests separately check allowed paths, credentials
and redirect refusal.
At this initial checkpoint, wallet configuration only saved receiving addresses.
The subsequent [installed-engine and payments checkpoint](installed-engine-payments-2026-11-04.md)
implements automatic settlement and credits and updates the normal installation.

## Reproduce

Use a disposable development engine with native Sandbox VM support. Set
`INFERENCE_SOLVER_YOUGORI` to its CLI, `YOUGORI_ACCEPTANCE_ENDPOINT` to its isolated
endpoint and `SOLVER_VM_IMAGES` to the publisher's artifact directory. Then run:

```powershell
python -I -B examples/hub/inference-solver/tests/runtime_harnesses.py NAME --root PATH/TO/DISPOSABLE-CACHE
python -I -B examples/hub/inference-solver/tests/runtime_grid.py --root PATH/TO/DISPOSABLE-GRID
python -I -B -m unittest discover -s examples/hub/inference-solver/tests -p 'test_*.py'
node examples/hub/inference-solver/tests/browser.mjs
```

Publisher images are built with Buildah in a separate Linux build environment,
using `scripts/build-vm-images.py NAME --split-tools --output DIRECTORY`.
Buildah is not a client runtime requirement. Large tool packages are verified and
extracted inside each ephemeral VM, which adds startup time.

At this initial checkpoint, the live website preview used the installed 1.1.1 engine for model serving.
It lacks the native VM API; the grid checks above used the isolated development
engine. This work does not install a new app/CLI or claim that the old engine can
run these harnesses. The Python website sandbox also needs an explicitly attached
trusted controller before it can manage host resources.
