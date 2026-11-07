# Megakernel runners

A megakernel runner serves a model inside a Yougori inference with the owner's own decode
kernel instead of vLLM. It is one launch mode of a vLLM-format model, saved with the model's
other launch settings, so the same switch works on this computer, on Neo Grid computers that
run the model and on Neocloud pods: each computer builds the kernel for the GPU it meets,
checks that the kernel answers, measures its speed and serves it, or falls back to vLLM and
says why in the model's health.

```text
yougori model optimize ENV --launch megakernel --runner D:/kernels/fast-qwen
yougori model optimize ENV --runner hf:acme/fast-qwen@0123456789abcdef0123456789abcdef01234567
yougori model optimize ENV --launch speculative        # back to vLLM at the next start
yougori model status ENV                               # runner, launch, megakernel facts
```

The runner takes effect at the model's next start. A folder on this computer is bound
read-only into the model's container; a public Hugging Face repository pinned to a commit is
downloaded there once and is the only form a Neocloud pod takes (`--runner` alone means
`--launch megakernel`).

## What a runner folder holds

`runner.json`

| Field | Meaning |
| --- | --- |
| `name` | Up to 64 letters, digits, dots, dashes or underscores. |
| `version` | A short string; a new version builds again. |
| `module` | The Python file beside it with `load()` (default `runner.py`). |
| `models` | Optional: the Hugging Face model ids this runner serves; others are refused. |
| `architectures` | Optional: `config.json` architectures it serves; others are refused. |
| `gpu` | Optional: `{"computeCapability": "8.0", "memoryGb": 2}` it needs at least. |
| `parallel` | Conversations generated at once (1-16, default 1); `generate()` is then called from that many threads. |
| `sampling` | `true` when `generate()` honours temperature and top_p (default `false`: greedy, and the two are ignored). |
| `context` | The longest conversation plus reply, in tokens (default 4096). |
| `precision` | Shown in the model's health, for example `Q4` or `BF16`. |
| `check` | `{"prompt": ..., "expect": ...}`: the question the runner must answer at start, greedy, with the expected text somewhere in its reply (default: the capital of France, Paris); `null` skips it. |

`runner.py`

```python
import yougori_runner

def load(model_dir, settings):
    # model_dir: the verified checkpoint (config.json, tokenizer, safetensors).
    # settings: model, revision, device, gpu, computeCapability [major, minor],
    #           multiprocessors, totalMemoryBytes, freeMemoryBytes, buildDir (kept per GPU,
    #           runner version and checkpoint: packed weights and compiled kernels go there),
    #           context, parallel, say (a function for progress lines).
    return Runner(model_dir, settings)

class Runner:
    def generate(self, tokens, max_tokens, stop, temperature=0.0, top_p=1.0):
        # tokens: the whole conversation as token ids (Yougori applies the chat template).
        # Yields the reply's token ids one by one; returns at a token in `stop` (a set of
        # ids), after max_tokens, or when the generator is closed (the caller went away).
        ...
    def close(self):   # optional
        ...
```

`yougori_runner`, provided by Yougori (no install):

- `device()`: the settings' GPU facts.
- `compile(source, name="kernel", options=(), include_dirs=())`: CUDA C++ compiled with NVRTC
  for this GPU (a cubin, or PTX when NVRTC predates the GPU), cached in `buildDir` by its
  source and options. Kernels are plain `extern "C" __global__` functions; `cuda_fp16.h` and
  `cuda_bf16.h` are found.
- `load(image)`: a module; `module.function(name)` a function with `max_dynamic_shared(bytes)`,
  `blocks_per_multiprocessor(block, shared)` and `launch(grid, block, shared, params, stream=0)`,
  where `params` is a `ctypes.Structure` passed by value as the kernel's one parameter;
  `launch()` returns after the kernel ends, with the GPU's own errors raised.
- `synchronize()`.

The runner's process has PyTorch and Transformers (the pinned vLLM image), the checkpoint's
files, the build folder and the GPU; it has none of the model's credentials, and nothing it
prints is kept once requests arrive.

## What Yougori does with it

1. Resolves the runner (a bound folder or the pinned repository) and checks the manifest.
2. Refuses a checkpoint or GPU the manifest excludes, before anything is built.
3. Calls `load()` with a build folder kept per GPU, runner version and checkpoint, so a
   first start builds and a later one reuses.
4. Asks the check question and compares the greedy answer with `expect`.
5. Warms the GPU up and measures one conversation's speed (`tokensPerSecond` in health).
6. Serves the model through the usual chat API: streaming, usage, stop strings, the model's
   chat template, `parallel` conversations at once. Tool calling and LoRA adapters are not
   served by a megakernel launch; a KV reset changes nothing (the runner reads each request's
   whole conversation).

When any step fails, the model's health shows `megakernel.refused` with the reason, vLLM
serves the model with its own launch, and the runner is not tried again until the model
restarts.

The engine side lives in `src-tauri/src/model_runner/engine_backends.py` (`load_megakernel`),
the host in `src-tauri/src/model_runner/megakernel_host.py` (`python3 megakernel_host.py
contract` prints the contract), and the tests in `scripts/megakernel-host.test.py`.
