# Pinned CPU checkpoint verification job

`scripts/test-model-checkpoints.py` runs the two dependency-requiring numerical
suites separately from the stdlib offline gate:

- `scripts/model-checkpoint.test.py`: tiny random safetensors checkpoints,
  loading/generation, exact logits and tied/configuration compatibility.
- `scripts/model-decisions.test.py`: tiny real decision-model inference.

No published model weights, GPU, installed Yougori engine or external account are
needed. The job never installs packages. Python 3.12 and the five exact versions
in [the requirement manifest](../../scripts/model-checkpoints-requirements.txt)
must already be available in the selected interpreter. The runner's three
`MODEL_DEPENDENCIES` pins are checked by parsing its source; drift fails the job.
CPU PyTorch is pinned to `2.8.0+cpu`, and safetensors to `0.8.0`.
Transformers 5.18.0 requires safetensors >=0.8.0; the former 0.6.2 pin
prevented pip from resolving this environment and was corrected on 29 October 2026.

The direct dependency pins are exact; this file is not a hash-locked transitive
dependency or signed supply-chain manifest. Preserve the environment's complete
`pip freeze --all` output when reproducing a run, in addition to this job's source
hashes and checked versions. A broader dependency/update policy remains release
work. Reference package sources: [PyTorch CPU wheels](https://download.pytorch.org/whl/cpu/torch/),
[safetensors 0.8.0 metadata](https://pypi.org/pypi/safetensors/0.8.0/json).

## Prepare an isolated environment

These operator commands install only into an explicit disposable environment.
Run from the repository; the recorded validation below identifies the tested source
and environment:

```powershell
py -3.12 -m venv D:/YougoriBuildCache/scratch/checkpoint-cpu312
$checkpointPython = 'D:/YougoriBuildCache/scratch/checkpoint-cpu312/Scripts/python.exe'
& $checkpointPython -I -m pip install --index-url https://download.pytorch.org/whl/cpu 'torch==2.8.0+cpu'
& $checkpointPython -I -m pip install -r scripts/model-checkpoints-requirements.txt
& $checkpointPython -I -m pip freeze --all
python -I -B scripts/test-model-checkpoints.py --python $checkpointPython --scratch-root D:/YougoriBuildCache/scratch --report D:/YougoriBuildCache/scratch/checkpoint-job-report.json
```

On Linux, use Python 3.12 to create the same environment and select its `bin/python`.
Use a fresh small environment; unrelated packages can change import behavior.
Archive the freeze output with the report when claiming reproducibility. Clean
the disposable environment after its validation use according to the build-cache
policy. Dependency installation uses network access; test execution uses offline
HF/Transformers settings and locally generated tiny checkpoints.

## Behavior and result

Each preflight and suite runs under the selected interpreter with `-I -B`, an
allowlisted environment, its own temporary home/cache and hidden CUDA devices.
Credentials, proxies, Python paths and inherited `YOUGORI_*` values are excluded.
Offline flags are cooperation settings, not an OS network or device sandbox.

Preflight has a 30-second timeout. Each suite defaults to 300 seconds; `--timeout`
accepts 1–1800 seconds. Timed-out or interrupted owned children are terminated
and reaped; Windows also targets their owned process tree. The checkpoint suites
themselves start no child processes. The known suites are an explicit list,
not discovery.

Any missing/wrong version stops before numerical tests. Zero tests, skips,
expected failures, unexpected successes, errors and assertion failures all fail
the job. A failed first suite does not hide the second suite's outcome. A changed
source hash between the start and end prevents a green result.

The job emits a bounded JSON object to stdout and optionally writes it atomically
with `--report`. It records fixed suite names, source SHA-256 digests, checked
dependency/Python versions, counts, outcomes and monotonic wall durations. It does
not copy prompts, responses, traceback text, absolute local paths, credentials or child output
into the report. Child result shape and size are checked before publication.

Missing dependencies are **unavailable numerical coverage**, never a passing
checkpoint run. This job establishes neither real GPU performance nor VM isolation.

## Implementation verification

The stdlib regression command is:

```powershell
python -I -B scripts/test-model-checkpoints.test.py -v
```

On 28 October 2026, all 13 job regressions passed, including real short-lived
preflight/timeout children, missing dependency gating, false-green rejection,
interruption cleanup, source drift and atomic report failure. The default Python
environment lacked the pinned numerical dependencies. No numerical checkpoint
pass or dependency installation is claimed by these job tests.

## Numerical execution — 29 October 2026

Manager 3 corrected the incompatible safetensors pin and ran both numerical
suites in the isolated Python 3.12 CPU environment: **8 passed, no failures,
errors or skips**. The 13 job-control regressions also passed, and `pip check`
found no broken requirements. See the [source/dependency identities, results and
previous failed attempt](evidence/2026-10-29-cpu-checkpoints/README.md).
This completes E04's CPU-job execution portion; changed GPU backend numerical
comparisons remain open.
