# Model Server: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or blocked checks are recorded as such. Use a disposable Yougori state directory and a small public GGUF model.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| MS-P01 | `yougori template check ./examples/hub/model-server --format text` with a 1.2.0 candidate | No errors |
| MS-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| MS-P03 | Publish scan | Clean |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| MS-L01 | `answers/small-gguf.json` | One `model` resource with the model and quantization |
| MS-L02 | `model: hf.co/owner` | Refused by the pattern |
| MS-L03 | `gpu: none` with a safetensors model | Refused before download: processor runs need GGUF |
| MS-L04 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 14)

| ID | Scenario | Pass when |
| --- | --- | --- |
| MS-R01 | Small GGUF model on the processor | Ready only after the model loads; `/v1/models` lists it; a chat completion answers with the key |
| MS-R02 | Request without the key | Refused |
| MS-R03 | Two requests at once | The second gets 429 |
| MS-R04 | Unsupported model | Setup stops before download; nothing created |
| MS-R05 | `model usage` after requests | Counts match |
| MS-R06 | Stop the model, then remove the setup | Stopped, then removed; nothing left running |
| MS-R07 | Run twice on one computer | Separate sandboxes and keys |
| MS-R08 | Published download through the desktop app and the CLI | Both serve the model |
