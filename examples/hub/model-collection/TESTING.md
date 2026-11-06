# Model Collection: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or blocked checks are recorded as such. Use a disposable Yougori state directory on a computer with a supported NVIDIA GPU, plus a processor-only computer, and two small public GGUF models.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| MC-P01 | `yougori template check ./examples/hub/model-collection --format text` with a 1.2.0 candidate | No errors |
| MC-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| MC-P03 | Publish scan | Clean |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| MC-L01 | `answers/two-small.json` | `first` and `second`; no third questions asked |
| MC-L02 | `third: true` | `third` added |
| MC-L03 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 15: model-collection)

| ID | Scenario | Pass when |
| --- | --- | --- |
| MC-R01 | GPU computer, ask model one, then model two | Model two loads after model one's reply finishes; neither reply is cut off |
| MC-R02 | Pin model one, ask model two | Model two waits or reports that the GPU is pinned; model one stays loaded |
| MC-R03 | Idle time 60 seconds | The model unloads after a minute unused |
| MC-R04 | Processor-only computer | Both models loaded; both answer |
| MC-R05 | Remove the setup | All model sandboxes removed |
