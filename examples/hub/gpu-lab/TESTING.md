# GPU Lab: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or blocked checks are recorded as such. Use a disposable Yougori state directory on a Windows x64 computer with a supported NVIDIA GPU and a test token.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| GL-P01 | `yougori template check ./examples/hub/gpu-lab --format text` with a 1.2.0 candidate | No errors |
| GL-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| GL-P03 | Publish scan | Clean; no token in any file |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| GL-L01 | `answers/private.json` | `lab` and `notebook` with access none |
| GL-L02 | Computer without a supported GPU | Refused before anything is created |
| GL-L03 | Token shorter than 16 characters | Refused |
| GL-L04 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 14)

| ID | Scenario | Pass when |
| --- | --- | --- |
| GL-R01 | Run `answers/private.json` | Ready only after `/api` answers; the lab opens only with the token |
| GL-R02 | `torch.cuda.is_available()` in a notebook | True, with the GPU's name |
| GL-R03 | Save a notebook under `/workspace`, stop, start, update | The notebook survives all three |
| GL-R04 | Wrong token | No access |
| GL-R05 | `access: quick` | Opens through the link with the token; local and public readiness shown separately |
| GL-R06 | Remove the setup | Sandbox removed; `/workspace` volume kept until deleted separately |
